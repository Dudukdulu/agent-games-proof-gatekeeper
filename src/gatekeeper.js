// Local Proof Gatekeeper (demo) — zkVerify Agent Games Season 01, Creator Track.
// Deterministic decision function over a sample task, then a REAL Groth16 proof
// with the tournament's official circuit (snarkjs), verified against the
// official verification key exported from the official zkey.
//
// INPUT ROLE MAP (derived from the circuit, NOT from published names — the
// official pages do not publish input signal names; the wasm stores only
// FNV-1a hashes of the names, which are one-way. Roles below were determined
// empirically by varying one input at a time and observing which witness
// signals / asserts changed. See BUILD_NOTES.md for the full evidence.
//   field8 is the input's wire position in the witness (wit[field8]).
//   f2  = registered_vk (vk hash, field element)   -- must equal f3
//   f3  = proof_vk (vk hash, field element)        -- must equal f2
//   f4  = minimum                                  -- check f4 <= f5
//   f5  = public_balance                           -- check f4 <= f5
//   f6  = decision (boolean 0/1)                   -- must equal f12
//   f7  = proof-reuse flag (0 = fresh/unused)      -- must be 0 to approve
//   f8  = recipient (address as field element)     -- must equal f9
//   f9  = condition_recipient                      -- must equal f8
//   f10 = current_block                            -- check f10 <= f11
//   f11 = expiry_block                             -- check f10 <= f11
//   f12 = decision duplicate (boolean 0/1)         -- must equal f6
//   f13 = task_id (public; Poseidon input 1)
//   f14 = salt (PRIVATE; Poseidon input 2; not in public signals)
// Public signals (13): [Poseidon(f13,f14), f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13]
// NOTE: amount / max_transfer have no dedicated circuit input in this
// mapping; the amount<=cap check is enforced by this gatekeeper off-circuit
// (see decide()) and the platform re-checks it from the task envelope.
// VERIFIED BEHAVIOUR (see runs/isolate_checks + decisive_test logs):
//  - APPROVE (f6=f12=1) builds a witness ONLY if every in-circuit check passes.
//    A wrong APPROVE (any check failing) FAILS witness generation (assert,
//    GatekeeperEvaluation line 102) — no proof can be produced. Fail-closed.
//  - REJECT (f6=f12=0) always builds a witness (checks passing or failing);
//    a wrong REJECT is caught by the platform's scoring (-3), not the circuit.
const { WitnessCalculatorBuilder } = require("circom_runtime");
const ff = require("ffjavascript");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const BN128_PRIME = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const N32 = 8;
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"; // gatekeeper vkHash, /api/circuit-info
function normalize(n) { let r = BigInt(n) % BN128_PRIME; if (r < 0n) r += BN128_PRIME; return r; }
function toArray32(s, size) {
    const res = []; let rem = BigInt(s); const radix = BigInt(0x100000000);
    while (rem) { res.unshift(Number(rem % radix)); rem = rem / radix; }
    if (size) { let i = size - res.length; while (i > 0) { res.unshift(0); i--; } }
    return res;
}
function hexToField(hex) { return normalize(BigInt(hex)).toString(); }

const TABLE = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "runs", "hash_table.json"), "utf8"));
const HASH_BY_FIELD8 = {};
for (const e of TABLE) HASH_BY_FIELD8[e.field8] = e.hash;
const WASM = path.join(__dirname, "..", "circuits", "gatekeeper.wasm");
const ZKEY = path.join(__dirname, "..", "circuits", "gatekeeper_final.zkey");
const VK = path.join(__dirname, "..", "runs", "vk.json");
const SNARKJS = path.join(__dirname, "..", "node_modules", ".bin", "snarkjs");

// --- decision function (pure, deterministic) ---
// task: {registeredVk, proofVk, minimum, publicBalance, amount, maxTransfer,
//        currentBlock, expiryBlock, recipient, conditionRecipient, proofUnused}
// Returns {decision: 'APPROVE'|'REJECT', reason_code, checks: {...}}
function decide(task) {
    const checks = {
        vk_match: normalize(task.registeredVk) === normalize(task.proofVk),
        balance_sufficient: BigInt(task.minimum) <= BigInt(task.publicBalance),
        recipient_match: normalize(task.recipient) === normalize(task.conditionRecipient),
        amount_within_cap: BigInt(task.amount) <= BigInt(task.maxTransfer),
        not_expired: BigInt(task.currentBlock) <= BigInt(task.expiryBlock),
        proof_unused: task.proofUnused === true,
    };
    const failed = Object.entries(checks).filter(([, v]) => !v).map(([k]) => k);
    const reasonMap = {
        vk_match: "VK_SUBSTITUTION",
        balance_sufficient: "THRESHOLD_MISMATCH",
        recipient_match: "RECIPIENT_MISMATCH",
        amount_within_cap: "AMOUNT_OVERFLOW",
        not_expired: "EXPIRED_CONDITION",
        proof_unused: "PROOF_REUSED",
    };
    if (failed.length === 0) return { decision: "APPROVE", reason_code: "VALID_CONDITION", checks };
    return { decision: "REJECT", reason_code: reasonMap[failed[0]], checks, failed };
}

// --- map a task + decision to the 13 circuit inputs (by field8) ---
function taskToInputs(task, decision, taskId, salt) {
    const d = decision === "APPROVE" ? "1" : "0";
    return {
        2: hexToField(task.registeredVk),
        3: hexToField(task.proofVk),
        4: String(task.minimum),
        5: String(task.publicBalance),
        6: d,
        7: task.proofUnused ? "0" : "1",
        8: hexToField(task.recipient),
        9: hexToField(task.conditionRecipient),
        10: String(task.currentBlock),
        11: String(task.expiryBlock),
        12: d,
        13: String(taskId),
        14: String(salt),
    };
}
function inputsToValuesByHash(inputsByField8) {
    const out = {};
    for (const [f8, v] of Object.entries(inputsByField8)) out[HASH_BY_FIELD8[f8]] = String(v);
    return out;
}

// --- witness via hash (no signal names needed) ---
async function computeWitness(valuesByHash) {
    const buffer = fs.readFileSync(WASM);
    const wc = await WitnessCalculatorBuilder(buffer, { sanityCheck: false });
    const inst = wc.instance;
    inst.exports.init(0);
    for (const e of TABLE) {
        const h = e.hash.slice(2);
        const v = valuesByHash[e.hash] !== undefined ? String(valuesByHash[e.hash]) : "0";
        const arrFr = toArray32(normalize(v), N32);
        for (let j = 0; j < N32; j++) inst.exports.writeSharedRWMemory(j, arrFr[N32 - 1 - j]);
        inst.exports.setInputSignal(parseInt(h.slice(0, 8), 16), parseInt(h.slice(8, 16), 16), 0);
    }
    const n = inst.exports.getWitnessSize();
    const wit = [];
    for (let i = 0; i < n; i++) {
        inst.exports.getWitness(i);
        const arr = new Uint32Array(N32);
        for (let j = 0; j < N32; j++) arr[N32 - 1 - j] = inst.exports.readSharedRWMemory(j);
        wit.push(ff.Scalar.fromArray(arr, 0x100000000).toString());
    }
    return wit;
}
function witnessToWtns(wit) {
    const nVars = wit.length;
    const toLE = (v, mod = true) => {
        const b = Buffer.alloc(32);
        let x = mod ? (BigInt(v) % BN128_PRIME) : BigInt(v);
        for (let i = 0; i < 32; i++) { b[i] = Number(x & 0xffn); x >>= 8n; }
        return b;
    };
    const sec1 = Buffer.concat([Buffer.from([32, 0, 0, 0]), toLE(BN128_PRIME, false), Buffer.from([(nVars & 0xff), (nVars >> 8) & 0xff, (nVars >> 16) & 0xff, (nVars >> 24) & 0xff])]);
    const sec1Full = Buffer.concat([Buffer.from([1, 0, 0, 0]), (() => { const l = Buffer.alloc(8); l.writeBigUInt64LE(BigInt(sec1.length)); return l; })(), sec1]);
    const witBuf = Buffer.concat(wit.map((v) => toLE(v, true)));
    const sec2Full = Buffer.concat([Buffer.from([2, 0, 0, 0]), (() => { const l = Buffer.alloc(8); l.writeBigUInt64LE(BigInt(witBuf.length)); return l; })(), witBuf]);
    return Buffer.concat([Buffer.from("wtns"), Buffer.from([2, 0, 0, 0]), Buffer.from([2, 0, 0, 0]), sec1Full, sec2Full]);
}

// --- full pipeline for one scenario: decide -> witness -> prove -> verify ---
async function runScenario(name, task, taskId, salt) {
    const t0 = Date.now();
    const dec = decide(task);
    const inputs = taskToInputs(task, dec.decision, taskId, salt);
    const valuesByHash = inputsToValuesByHash(inputs);
    const dir = path.join(__dirname, "..", "proofs", name);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(__dirname, "..", "inputs", name + ".json"), JSON.stringify({ task, taskId, salt, decision: dec, inputsByField8: inputs }, null, 2));
    let wit;
    try {
        wit = await computeWitness(valuesByHash);
    } catch (e) {
        const msg = String(e && e.message ? e.message : e).replace(/\n/g, " ").slice(0, 200);
        const rec = { scenario: name, decision: dec, inputsByField8: inputs, witness: "FAILED: " + msg, proof: null, verify: null, note: "Circuit rejected this assignment (assert). No proof produced — this is the fail-closed behaviour for an inconsistent/wrong APPROVE." };
        fs.writeFileSync(path.join(dir, "result.json"), JSON.stringify(rec, null, 2));
        console.log(`[${name}] decision=${dec.decision} (${dec.reason_code}) | witness FAILED: ${msg}`);
        return rec;
    }
    const witPath = path.join(dir, "witness.json");
    const wtnsPath = path.join(dir, "witness.wtns");
    fs.writeFileSync(witPath, JSON.stringify(wit));
    fs.writeFileSync(wtnsPath, witnessToWtns(wit));
    const proofPath = path.join(dir, "proof.json");
    const publicPath = path.join(dir, "public.json");
    const proveStart = Date.now();
    execFileSync(SNARKJS, ["groth16", "prove", ZKEY, wtnsPath, proofPath, publicPath], { stdio: "pipe" });
    const proveMs = Date.now() - proveStart;
    const verifyOut = execFileSync(SNARKJS, ["groth16", "verify", VK, publicPath, proofPath], { encoding: "utf8" });
    const verifyOk = /OK!/.test(verifyOut);
    const proofBytes = fs.statSync(proofPath).size;
    const publicSignals = JSON.parse(fs.readFileSync(publicPath, "utf8"));
    const rec = {
        scenario: name, decision: dec, inputsByField8: inputs,
        witnessSignals: wit.length, witness1Poseidon: wit[1],
        publicSignals, proofBytes, proveMs, verifyOk,
        verifyOutput: verifyOut.trim().replace(/\x1b\[[0-9;]*m/g, ""),
        totalMs: Date.now() - t0,
    };
    fs.writeFileSync(path.join(dir, "result.json"), JSON.stringify(rec, null, 2));
    console.log(`[${name}] decision=${dec.decision} (${dec.reason_code}) | witness ${wit.length} signals | proof ${proofBytes} B | prove ${proveMs} ms | verify ${verifyOk ? "OK!" : "FAILED"}`);
    return rec;
}

module.exports = { decide, taskToInputs, computeWitness, witnessToWtns, runScenario, VK_HASH, hexToField };
if (require.main === module) {
    (async () => {
        const recipient = "0x6E8f6B9c2E1F3a5D8c4B7a1E2d3F4a5B6c7D8e9";
        const otherRecipient = "0x1111111111111111111111111111111111111111";
        const baseTask = {
            registeredVk: VK_HASH, proofVk: VK_HASH,
            minimum: "1000", publicBalance: "1460",
            amount: "500", maxTransfer: "1000",
            currentBlock: "19832000", expiryBlock: "19842201",
            recipient, conditionRecipient: recipient, proofUnused: true,
        };
        const taskId = 20261115001, salt = "98765432109876543210";
        await runScenario("valid_approve", baseTask, taskId, salt);
        const trapTask = { ...baseTask, conditionRecipient: otherRecipient };
        await runScenario("trap_recipient_mismatch", trapTask, taskId, salt);
        // Wrong-approve attempt: same trap task but force decision APPROVE -> must fail witness
        const forced = { ...trapTask };
        const forcedInputs = taskToInputs(forced, "APPROVE", taskId, salt);
        const dir = path.join(__dirname, "..", "proofs", "trap_wrong_approve_attempt");
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(__dirname, "..", "inputs", "trap_wrong_approve_attempt.json"), JSON.stringify({ task: forced, taskId, salt, decision: { decision: "APPROVE", reason_code: "FORCED (wrong)", checks: decide(forced).checks }, inputsByField8: forcedInputs }, null, 2));
        try {
            await computeWitness(inputsToValuesByHash(forcedInputs));
            console.log("[trap_wrong_approve_attempt] UNEXPECTED: witness built for a wrong APPROVE");
            fs.writeFileSync(path.join(dir, "result.json"), JSON.stringify({ scenario: "trap_wrong_approve_attempt", witness: "UNEXPECTEDLY BUILT" }, null, 2));
        } catch (e) {
            const msg = String(e && e.message ? e.message : e).replace(/\n/g, " ").slice(0, 200);
            console.log(`[trap_wrong_approve_attempt] witness FAILED as expected: ${msg}`);
            fs.writeFileSync(path.join(dir, "result.json"), JSON.stringify({ scenario: "trap_wrong_approve_attempt", decision: "APPROVE (forced, wrong)", witness: "FAILED: " + msg, note: "Correct: a wrong APPROVE cannot produce a proof (fail-closed)." }, null, 2));
        }
    })().catch((e) => { console.error(e); process.exit(1); });
}
