// Test harness for server/server.mjs — starts the server, replays the
// sample task envelope from the event page + local scenarios, checks
// decisions/reason codes, verifies every returned Groth16 proof with
// snarkjs against runs/vk.json, and tests preflight + HMAC reject paths.
// Usage: node test/test-server.mjs   (exit 0 = all PASS, 1 = any FAIL)
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, execFileSync } from "node:child_process";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(ROOT, "server", "server.mjs");
const SNARKJS = path.join(ROOT, "node_modules", ".bin", "snarkjs");
const VK = path.join(ROOT, "runs", "vk.json");

const VKH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const VKH_FIELD = "4836144126773920907502496244340012141761656471453348073975163706578152814510";
const RECIP = "0x6E8f6B9c2E1F3a5D8c4B7a1E2d3F4a5B6c7D8e9";
const OTHER_RECIP = "0x1111111111111111111111111111111111111111";
const BN128_PRIME = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

const results = [];
function check(name, ok, detail = "") {
    results.push({ name, ok, detail });
    console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
}

let txCounter = 0;
function freshTx() {
    txCounter += 1;
    return "0x" + txCounter.toString(16).padStart(64, "0");
}

function envelope(overrides = {}, taskId = "gk_24_9d1", proofTx = freshTx()) {
    return {
        type: "agent-games.proof-gatekeeper.v1",
        task_id: taskId,
        mode: "competition",
        issued_at: new Date().toISOString(),
        deadline_at: new Date(Date.now() + 60000).toISOString(),
        input: {
            registered_vk: VKH,
            proof_vk: VKH,
            minimum: "1000",
            public_balance: "1460",
            expiry_block: 19842201,
            current_block: 19832000,
            recipient: RECIP,
            condition_recipient: RECIP,
            amount: "500",
            max_transfer: "1000",
            proof_tx: proofTx,
            ...overrides,
        },
    };
}

function expectedTaskIdField(taskId) {
    const s = String(taskId);
    if (/^\d+$/.test(s)) return (BigInt(s) % BN128_PRIME).toString();
    return (BigInt("0x" + crypto.createHash("sha256").update(s).digest("hex")) % BN128_PRIME).toString();
}

function verifyProof(proof, publicSignals) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "gk-verify-"));
    try {
        const proofPath = path.join(tmp, "proof.json");
        const publicPath = path.join(tmp, "public.json");
        fs.writeFileSync(proofPath, JSON.stringify(proof));
        fs.writeFileSync(publicPath, JSON.stringify(publicSignals));
        const out = execFileSync(SNARKJS, ["groth16", "verify", VK, publicPath, proofPath], { encoding: "utf8", timeout: 30000 });
        return /OK!/.test(out);
    } catch (e) {
        return false;
    } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
}

function checkProofShape(name, body, taskId, expectDecision, registeredVkHex = VKH, proofVkHex = VKH) {
    const ps = body.public_signals;
    const p = body.proof;
    if (!p || !Array.isArray(ps)) return check(name, false, "missing proof/public_signals");
    const shapeOk = p.pi_a && p.pi_b && p.pi_c && p.protocol === "groth16" && p.curve === "bn128";
    const hexField = (h) => (BigInt(h) % BN128_PRIME).toString();
    const sigOk = ps.length === 13
        && ps[1] === hexField(registeredVkHex) && ps[2] === hexField(proofVkHex)
        && ps[5] === (expectDecision === "APPROVE" ? "1" : "0")
        && ps[11] === (expectDecision === "APPROVE" ? "1" : "0")
        && ps[12] === expectedTaskIdField(taskId);
    if (!shapeOk || !sigOk) {
        return check(name, false, `bad proof shape/signals (shapeOk=${shapeOk} sigOk=${sigOk} nPublic=${ps.length})`);
    }
    const ok = verifyProof(p, ps);
    return check(name, ok, ok ? "snarkjs verify OK!" : "snarkjs verify FAILED");
}

async function startServer(port, extraEnv) {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "gk-data-"));
    const proc = spawn("node", [SERVER], {
        env: { ...process.env, PORT: String(port), AGENTGAMES_DATA_DIR: dataDir, ...extraEnv },
        stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    proc.stdout.on("data", (d) => { out += d; });
    proc.stderr.on("data", (d) => { out += d; });
    const base = `http://127.0.0.1:${port}`;
    const t0 = Date.now();
    while (Date.now() - t0 < 15000) {
        try {
            const r = await fetch(base + "/health");
            if (r.status === 200) return { proc, base, dataDir, out: () => out };
        } catch { /* not up yet */ }
        await new Promise((r) => setTimeout(r, 250));
    }
    proc.kill();
    throw new Error(`server did not come up on :${port}\n${out}`);
}

function stopServer(proc) {
    try { proc.kill("SIGTERM"); } catch { /* already dead */ }
}

function hmac(secret, body) {
    return crypto.createHmac("sha256", secret).update(body).digest("hex");
}

async function postJson(base, path, obj, secret) {
    const raw = typeof obj === "string" ? obj : JSON.stringify(obj);
    const headers = { "Content-Type": "application/json" };
    if (secret) headers["x-agent-games-signature"] = hmac(secret, raw);
    const res = await fetch(base + path, { method: "POST", headers, body: raw });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* non-JSON */ }
    return { status: res.status, json, text, sig: res.headers.get("x-agent-games-signature") };
}

// ------------------------------------------------------------------ phase A
async function phaseA() {
    console.log("\n== Phase A: TEST MODE (no HMAC secret) ==");
    const { proc, base } = await startServer(3100, {});
    try {
        // GET /
        let r = await fetch(base + "/");
        check("GET / returns {ok:true}", r.status === 200 && (await r.json()).ok === true);
        // GET /health
        r = await fetch(base + "/health");
        check("GET /health returns {ok:true}", r.status === 200 && (await r.json()).ok === true);
        // Preflight, unsigned
        let p = await postJson(base, "/agent", { type: "agent-games.preflight.v1" });
        check("preflight unsigned -> {ok:true, protocolVersion:v1}",
            p.status === 200 && p.json && p.json.ok === true && p.json.protocolVersion === "v1", JSON.stringify(p.json));
        check("preflight in test mode carries NO signature header", p.sig === null);

        // 1. Sample envelope (event page shape, real values) -> APPROVE
        const validTx = freshTx();
        const validEnv = envelope({}, "gk_24_9d1", validTx);
        p = await postJson(base, "/agent", validEnv);
        check("sample task -> APPROVE / VALID_CONDITION",
            p.status === 200 && p.json && p.json.decision === "APPROVE" && p.json.reason_code === "VALID_CONDITION",
            JSON.stringify(p.json && { decision: p.json.decision, reason_code: p.json.reason_code }));
        checkProofShape("sample task proof verifies (snarkjs vs runs/vk.json)", p.json, "gk_24_9d1", "APPROVE");

        // 2. Trap: recipient mismatch -> REJECT
        p = await postJson(base, "/agent", envelope({ condition_recipient: OTHER_RECIP }));
        check("trap recipient mismatch -> REJECT / RECIPIENT_MISMATCH",
            p.status === 200 && p.json && p.json.decision === "REJECT" && p.json.reason_code === "RECIPIENT_MISMATCH",
            JSON.stringify(p.json && { decision: p.json.decision, reason_code: p.json.reason_code }));
        checkProofShape("trap recipient proof verifies", p.json, "gk_24_9d1", "REJECT");

        // 3. Replay of the valid task's proof_tx -> PROOF_REUSED, no proof
        p = await postJson(base, "/agent", envelope({}, "gk_24_9d1-replay", validTx));
        check("replay proof_tx -> REJECT / PROOF_REUSED, no proof fields",
            p.status === 200 && p.json && p.json.decision === "REJECT" && p.json.reason_code === "PROOF_REUSED"
            && !("proof" in p.json) && !("public_signals" in p.json),
            JSON.stringify(p.json));

        // 4. VK substitution (proof_vk differs from registered_vk — the two
        //    public vk signals must DIFFER, that is the trap)
        const subVk = "0x" + "22".repeat(32);
        p = await postJson(base, "/agent", envelope({ proof_vk: subVk }));
        check("VK substitution -> REJECT / VK_SUBSTITUTION",
            p.status === 200 && p.json && p.json.decision === "REJECT" && p.json.reason_code === "VK_SUBSTITUTION");
        checkProofShape("VK substitution proof verifies", p.json, "gk_24_9d1", "REJECT", VKH, subVk);

        // 5. Threshold mismatch
        p = await postJson(base, "/agent", envelope({ public_balance: "500" }));
        check("threshold mismatch -> REJECT / THRESHOLD_MISMATCH",
            p.status === 200 && p.json && p.json.decision === "REJECT" && p.json.reason_code === "THRESHOLD_MISMATCH");
        checkProofShape("threshold mismatch proof verifies", p.json, "gk_24_9d1", "REJECT");

        // 6. Expired
        p = await postJson(base, "/agent", envelope({ current_block: 19850000 }));
        check("expired condition -> REJECT / EXPIRED_CONDITION",
            p.status === 200 && p.json && p.json.decision === "REJECT" && p.json.reason_code === "EXPIRED_CONDITION");
        checkProofShape("expired condition proof verifies", p.json, "gk_24_9d1", "REJECT");

        // 7. Amount overflow
        p = await postJson(base, "/agent", envelope({ amount: "1500" }));
        check("amount overflow -> REJECT / AMOUNT_OVERFLOW",
            p.status === 200 && p.json && p.json.decision === "REJECT" && p.json.reason_code === "AMOUNT_OVERFLOW");
        checkProofShape("amount overflow proof verifies", p.json, "gk_24_9d1", "REJECT");

        // 8. Numeric task_id branch -> APPROVE
        p = await postJson(base, "/agent", envelope({}, "20261116001"));
        check("numeric task_id -> APPROVE / VALID_CONDITION",
            p.status === 200 && p.json && p.json.decision === "APPROVE" && p.json.reason_code === "VALID_CONDITION");
        checkProofShape("numeric task_id proof verifies", p.json, "20261116001", "APPROVE");

        // 9. Malformed JSON -> 400
        p = await postJson(base, "/agent", "{not json");
        check("malformed JSON -> 400", p.status === 400, `status=${p.status}`);
        // 10. Unknown type -> 400
        p = await postJson(base, "/agent", { type: "agent-games.unknown.v9" });
        check("unknown type -> 400", p.status === 400, `status=${p.status}`);
        // 11. Missing field -> 400
        const bad = envelope({});
        delete bad.input.proof_tx;
        p = await postJson(base, "/agent", bad);
        check("missing proof_tx -> 400", p.status === 400, `status=${p.status}`);
    } finally {
        stopServer(proc);
    }
}

// ------------------------------------------------------------------ phase B
async function phaseB() {
    console.log("\n== Phase B: HMAC MODE (AGENT_GAMES_HMAC_SECRET set) ==");
    const SECRET = "test-hmac-secret-do-not-use-in-prod";
    const { proc, base } = await startServer(3101, { AGENT_GAMES_HMAC_SECRET: SECRET });
    try {
        const validEnv = envelope({}, "gk_hmac_001");

        // Correct signature -> 200, response signed + verifiable
        let p = await postJson(base, "/agent", validEnv, SECRET);
        check("valid task + correct HMAC -> 200 APPROVE",
            p.status === 200 && p.json && p.json.decision === "APPROVE" && p.json.reason_code === "VALID_CONDITION",
            `status=${p.status}`);
        const respRaw = JSON.stringify(p.json);
        check("response carries a valid HMAC signature",
            p.sig !== null && p.sig === hmac(SECRET, respRaw), `sig=${String(p.sig).slice(0, 16)}…`);
        checkProofShape("HMAC-mode proof verifies", p.json, "gk_hmac_001", "APPROVE");

        // Wrong signature -> 401
        p = await postJson(base, "/agent", validEnv, "wrong-secret");
        check("valid task + wrong HMAC -> 401", p.status === 401, `status=${p.status}`);

        // Missing signature -> 401
        p = await postJson(base, "/agent", validEnv);
        check("valid task + no HMAC -> 401", p.status === 401, `status=${p.status}`);

        // Preflight signed -> 200, signed response
        p = await postJson(base, "/agent", { type: "agent-games.preflight.v1" }, SECRET);
        check("preflight + correct HMAC -> 200 {ok:true, protocolVersion:v1}",
            p.status === 200 && p.json && p.json.ok === true && p.json.protocolVersion === "v1");
        check("preflight response is signed",
            p.sig !== null && p.sig === hmac(SECRET, JSON.stringify(p.json)));

        // Preflight wrong signature -> 401
        p = await postJson(base, "/agent", { type: "agent-games.preflight.v1" }, "wrong-secret");
        check("preflight + wrong HMAC -> 401", p.status === 401, `status=${p.status}`);

        // GET /health in HMAC mode: unsigned GET allowed, response signed
        const r = await fetch(base + "/health");
        const body = await r.text();
        check("GET /health in HMAC mode -> 200 + signed response",
            r.status === 200 && r.headers.get("x-agent-games-signature") === hmac(SECRET, body));
    } finally {
        stopServer(proc);
    }
}

// ---------------------------------------------------------------------- main
(async () => {
    try {
        await phaseA();
        await phaseB();
    } catch (e) {
        console.error("HARNESS ERROR:", e);
        results.push({ name: "harness itself", ok: false, detail: String(e && e.message || e) });
    }
    const passed = results.filter((r) => r.ok).length;
    const failed = results.filter((r) => !r.ok);
    console.log(`\n== SUMMARY: ${passed}/${results.length} PASS ==`);
    if (failed.length) {
        for (const f of failed) console.log(`  FAILED: ${f.name} — ${f.detail}`);
        process.exit(1);
    }
    console.log("All checks passed.");
    process.exit(0);
})();
