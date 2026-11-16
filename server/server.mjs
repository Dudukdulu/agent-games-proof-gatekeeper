// Live Proof Gatekeeper agent server — zkVerify Agent Games Season 01.
// Local build only: no dashboard registration, no API keys, no transactions,
// no wallet touched. Kurier submission is OUT of scope (proof goes inline
// in the response, per the event spec).
//
// Endpoints:
//   GET  /            -> {"ok":true}
//   GET  /health      -> {"ok":true}
//   POST /  | /agent  -> preflight or proof-gatekeeper task envelope
//
// Security:
//   - When AGENT_GAMES_HMAC_SECRET is set, the HMAC-SHA256 hex of the RAW
//     request body is verified against the x-agent-games-signature header
//     BEFORE parsing JSON (401 on mismatch/missing). Every response is
//     signed the same way (HMAC of the raw response body).
//   - When the secret is UNSET the server runs in TEST MODE: all requests
//     are accepted and a clear warning is logged on every request. The
//     secret is never invented, never defaulted, never logged.
//   - Decisions fail closed: any error/uncertainty -> REJECT.
//   - Salt (Poseidon commitment input) comes from AGENT_GAMES_SALT, else a
//     random per-agent salt is generated once and persisted to
//     <DATA_DIR>/salt.json (0600). Never logged, never returned.
//
// Decision logic + circuit input mapping are REUSED from
// ../src/gatekeeper.js (empirically derived from the official circuit;
// see BUILD_NOTES.md). Proof: real Groth16 via snarkjs with the official
// gatekeeper.wasm / gatekeeper_final.zkey; proving is capped at 30 s —
// on timeout/failure the server responds decision+reason_code only
// (never times out the 60 s platform deadline).
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { execFile } from "node:child_process";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const SNARKJS = path.join(ROOT, "node_modules", ".bin", "snarkjs");
const ZKEY = path.join(ROOT, "circuits", "gatekeeper_final.zkey");

const BN128_PRIME = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const PROVE_TIMEOUT_MS = 30_000;
const MAX_BODY_BYTES = 1_000_000;

// ---------------------------------------------------------------- .env
function loadDotEnv(file) {
    if (!fs.existsSync(file)) return;
    for (const line of fs.readFileSync(file, "utf8").split("\n")) {
        const t = line.trim();
        if (!t || t.startsWith("#")) continue;
        const i = t.indexOf("=");
        if (i < 0) continue;
        const k = t.slice(0, i).trim();
        const v = t.slice(i + 1).trim().replace(/^["']|["']$/g, "");
        if (k && !(k in process.env)) process.env[k] = v;
    }
}
loadDotEnv(path.join(__dirname, ".env"));

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.AGENTGAMES_DATA_DIR || __dirname;
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const TEST_MODE = !HMAC_SECRET;
fs.mkdirSync(DATA_DIR, { recursive: true });

// ------------------------------------------------------- gatekeeper reuse
const { decide, taskToInputs, computeWitness, witnessToWtns } = require(path.join(ROOT, "src", "gatekeeper.js"));
const HASH_TABLE = JSON.parse(fs.readFileSync(path.join(ROOT, "runs", "hash_table.json"), "utf8"));
const HASH_BY_FIELD8 = {};
for (const e of HASH_TABLE) HASH_BY_FIELD8[e.field8] = e.hash;

function inputsToValuesByHash(inputsByField8) {
    const out = {};
    for (const [f8, v] of Object.entries(inputsByField8)) out[HASH_BY_FIELD8[f8]] = String(v);
    return out;
}

// ------------------------------------------------------------------ state
const SEEN_PATH = path.join(DATA_DIR, "seen.json");
const SALT_PATH = path.join(DATA_DIR, "salt.json");

function loadSeen() {
    try {
        const arr = JSON.parse(fs.readFileSync(SEEN_PATH, "utf8"));
        return new Set(Array.isArray(arr) ? arr.map(String) : []);
    } catch {
        return new Set();
    }
}
const seen = loadSeen();
function saveSeen() {
    fs.writeFileSync(SEEN_PATH, JSON.stringify([...seen].sort(), null, 2));
}

function loadSalt() {
    if (process.env.AGENT_GAMES_SALT) {
        return (BigInt(process.env.AGENT_GAMES_SALT) % BN128_PRIME).toString();
    }
    try {
        const s = JSON.parse(fs.readFileSync(SALT_PATH, "utf8")).salt;
        return (BigInt(s) % BN128_PRIME).toString();
    } catch {
        const salt = (BigInt("0x" + crypto.randomBytes(32).toString("hex")) % BN128_PRIME).toString();
        fs.writeFileSync(SALT_PATH, JSON.stringify({ salt, note: "per-agent Poseidon salt — private, never share, never log" }, null, 2), { mode: 0o600 });
        return salt;
    }
}
const SALT = loadSalt();

// ------------------------------------------------------------------- hmac
function hmacHex(secret, body) {
    return crypto.createHmac("sha256", secret).update(body).digest("hex");
}
function verifySignature(rawBody, sigHeader) {
    if (TEST_MODE) return true;
    if (!sigHeader) return false;
    const expected = hmacHex(HMAC_SECRET, rawBody);
    const a = Buffer.from(expected, "utf8");
    const b = Buffer.from(String(sigHeader).trim(), "utf8");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ------------------------------------------------------------- task helpers
function taskIdField(taskId) {
    const s = String(taskId);
    if (/^\d+$/.test(s)) return (BigInt(s) % BN128_PRIME).toString();
    const h = crypto.createHash("sha256").update(s).digest("hex");
    return (BigInt("0x" + h) % BN128_PRIME).toString();
}

const HEX_RE = /^0x[0-9a-fA-F]+$/;
const INT_RE = /^-?\d+$/;
function isInt(v) {
    return (typeof v === "number" && Number.isInteger(v)) || (typeof v === "string" && INT_RE.test(v));
}
function isHex(v) {
    return typeof v === "string" && HEX_RE.test(v);
}
// Returns {task} or {error} — strict validation, fail closed (400, not a guess).
function parseTaskInput(body) {
    const input = body && body.input;
    if (!input || typeof input !== "object") return { error: "missing input object" };
    const need = ["registered_vk", "proof_vk", "minimum", "public_balance", "expiry_block", "current_block", "recipient", "condition_recipient", "amount", "max_transfer", "proof_tx"];
    for (const k of need) {
        if (input[k] === undefined || input[k] === null || input[k] === "") return { error: `missing field: ${k}` };
    }
    if (!isHex(input.registered_vk) || !isHex(input.proof_vk)) return { error: "registered_vk/proof_vk must be 0x hex" };
    if (!isHex(input.recipient) || !isHex(input.condition_recipient)) return { error: "recipient/condition_recipient must be 0x hex" };
    for (const k of ["minimum", "public_balance", "amount", "max_transfer", "expiry_block", "current_block"]) {
        if (!isInt(input[k])) return { error: `field not an integer: ${k}` };
    }
    if (typeof input.proof_tx !== "string" || !input.proof_tx.trim()) return { error: "proof_tx must be a non-empty string" };
    const task = {
        registeredVk: input.registered_vk,
        proofVk: input.proof_vk,
        minimum: String(input.minimum),
        publicBalance: String(input.public_balance),
        amount: String(input.amount),
        maxTransfer: String(input.max_transfer),
        currentBlock: String(input.current_block),
        expiryBlock: String(input.expiry_block),
        recipient: input.recipient,
        conditionRecipient: input.condition_recipient,
        proofUnused: true, // set by the caller from the seen-set before decide()
    };
    return { task, proofTx: String(input.proof_tx) };
}

// --------------------------------------------------------------- proving
function execFileP(file, args, opts) {
    return new Promise((resolve, reject) => {
        execFile(file, args, opts, (err, stdout, stderr) => {
            if (err) reject(Object.assign(err, { stdout, stderr }));
            else resolve({ stdout, stderr });
        });
    });
}

async function prove(task, decision, taskId) {
    const t0 = Date.now();
    const inputs = taskToInputs(task, decision, taskIdField(taskId), SALT);
    const wit = await computeWitness(inputsToValuesByHash(inputs));
    const tmp = await fs.promises.mkdtemp(path.join(os.tmpdir(), "gk-prove-"));
    const wtnsPath = path.join(tmp, "witness.wtns");
    const proofPath = path.join(tmp, "proof.json");
    const publicPath = path.join(tmp, "public.json");
    try {
        await fs.promises.writeFile(wtnsPath, witnessToWtns(wit));
        await execFileP(SNARKJS, ["groth16", "prove", ZKEY, wtnsPath, proofPath, publicPath], { timeout: PROVE_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 });
        const proof = JSON.parse(await fs.promises.readFile(proofPath, "utf8"));
        const publicSignals = JSON.parse(await fs.promises.readFile(publicPath, "utf8"));
        return { proof, publicSignals, proveMs: Date.now() - t0 };
    } finally {
        await fs.promises.rm(tmp, { recursive: true, force: true }).catch(() => {});
    }
}

// ------------------------------------------------------------------ server
function log(...args) {
    console.log(new Date().toISOString(), ...args);
}
function warnTestMode() {
    if (TEST_MODE) log("WARN test mode: no AGENT_GAMES_HMAC_SECRET set — accepting unsigned requests (do NOT register this endpoint publicly like this)");
}

function sendJson(res, status, obj) {
    const raw = JSON.stringify(obj);
    if (!TEST_MODE) res.setHeader("x-agent-games-signature", hmacHex(HMAC_SECRET, raw));
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(raw);
}

async function handleTask(body, res) {
    const taskId = body.task_id !== undefined && body.task_id !== null ? String(body.task_id) : null;
    const { task, proofTx, error } = parseTaskInput(body);
    if (error) {
        log(`task ${taskId ?? "?"}: 400 ${error}`);
        return sendJson(res, 400, { ok: false, error });
    }
    const tid = taskId ?? proofTx;

    // Proof-reuse check FIRST (trap taxonomy: a reused proof is its own
    // trap type). Mark the reference seen immediately, synchronously, so
    // concurrent deliveries of the same proof_tx cannot both pass.
    if (seen.has(proofTx)) {
        log(`task ${tid}: REJECT PROOF_REUSED (proof_tx already seen, no proof to submit)`);
        return sendJson(res, 200, { decision: "REJECT", reason_code: "PROOF_REUSED" });
    }
    seen.add(proofTx);
    saveSeen();

    let dec;
    try {
        dec = decide(task);
    } catch (e) {
        // Decision evaluation itself failed: fail closed, never approve.
        log(`task ${tid}: ERROR decision evaluation failed (${String(e && e.message || e).slice(0, 120)}) — fail-closed REJECT`);
        return sendJson(res, 200, { decision: "REJECT", reason_code: "VK_SUBSTITUTION" });
    }

    if (dec.decision === "APPROVE") {
        // Sanity: an APPROVE whose witness the circuit rejects cannot be
        // proven — prove() throws, and we fall through to no-proof reply.
    }
    try {
        const { proof, publicSignals, proveMs } = await prove(task, dec.decision, tid);
        log(`task ${tid}: ${dec.decision} ${dec.reason_code} | proof ok | prove ${proveMs} ms`);
        return sendJson(res, 200, { decision: dec.decision, reason_code: dec.reason_code, proof, public_signals: publicSignals });
    } catch (e) {
        const msg = String(e && e.message || e).replace(/\n/g, " ").slice(0, 200);
        const timedOut = e && (e.killed || /ETIMEDOUT/i.test(String(e.code || "")));
        log(`task ${tid}: ${dec.decision} ${dec.reason_code} | PROOF FAILED${timedOut ? " (timeout >30s)" : ""}: ${msg} — responding decision+reason_code only`);
        return sendJson(res, 200, { decision: dec.decision, reason_code: dec.reason_code });
    }
}

const server = http.createServer((req, res) => {
    const url = new URL(req.url || "/", "http://localhost");
    const p = url.pathname;

    if (req.method === "GET" && (p === "/" || p === "/health")) {
        return sendJson(res, 200, { ok: true });
    }
    if (req.method !== "POST" || (p !== "/" && p !== "/agent")) {
        return sendJson(res, 404, { ok: false, error: "not_found" });
    }

    const chunks = [];
    let tooBig = false;
    req.on("data", (c) => {
        if (tooBig) return;
        chunks.push(c);
        if (Buffer.concat(chunks).length > MAX_BODY_BYTES) { tooBig = true; }
    });
    req.on("end", async () => {
        if (tooBig) return sendJson(res, 413, { ok: false, error: "body_too_large" });
        const raw = Buffer.concat(chunks);
        warnTestMode();
        if (!verifySignature(raw, req.headers["x-agent-games-signature"])) {
            log(`${req.method} ${p}: 401 bad/missing x-agent-games-signature`);
            return sendJson(res, 401, { ok: false, error: "bad_signature" });
        }
        let body;
        try {
            body = JSON.parse(raw.toString("utf8"));
        } catch {
            return sendJson(res, 400, { ok: false, error: "invalid_json" });
        }
        if (body && body.type === "agent-games.preflight.v1") {
            return sendJson(res, 200, { ok: true, protocolVersion: "v1" });
        }
        if (body && body.type === "agent-games.proof-gatekeeper.v1") {
            try {
                return await handleTask(body, res);
            } catch (e) {
                // Last-resort fail closed: never leave the platform hanging.
                log(`task ?: ERROR unhandled (${String(e && e.message || e).slice(0, 120)}) — fail-closed REJECT`);
                return sendJson(res, 200, { decision: "REJECT", reason_code: "VK_SUBSTITUTION" });
            }
        }
        return sendJson(res, 400, { ok: false, error: "unknown_type" });
    });
});

server.listen(PORT, () => {
    log(`gatekeeper server listening on :${PORT} (POST /agent, GET /health)`);
    log(`mode: ${TEST_MODE ? "TEST MODE — no HMAC secret (unsigned requests accepted)" : "HMAC verification ON"}`);
    log(`data dir: ${DATA_DIR} | seen set: ${seen.size} proof_tx | zkey: ${path.basename(ZKEY)}`);
});
