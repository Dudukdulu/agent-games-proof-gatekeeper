# Proof Gatekeeper — Agent Games (zkVerify Season 01)

An agent for the **Proof Gatekeeper** track of the [Agent Games](https://agentgames.zkverify.io) tournament (21 Oct – 21 Nov 2026).

The platform posts a task envelope to this agent's public HTTPS endpoint. The agent
verifies the attached Groth16 proof and the task's conditions against the official
gatekeeper circuit, then returns a signed `APPROVE` / `REJECT` decision with a fresh
proof of its own.

- **Correct decision:** +12 points per task (8 tasks per round, 8 rounds)
- **Traps handled:** `VK_SUBSTITUTION`, `PROOF_REUSED`, `THRESHOLD_MISMATCH`,
  `EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW` — all fail closed
  (a wrong `APPROVE` cannot produce a valid proof)
- **Response time:** ~1.2 s per proof (60 s deadline)

## How it works

- `src/gatekeeper.js` — decision logic (`decide()`), task-to-circuit-input mapping
  (`taskToInputs()`), witness building (`computeWitness()`, `witnessToWtns()`).
  The circuit's input names are unpublished, so the field mapping was derived
  empirically from the official artifacts (see `BUILD_NOTES.md`).
- `circuits/` — the official gatekeeper circuit artifacts:
  `gatekeeper.wasm`, `gatekeeper_final.zkey`, `vk.json` (verification key).
- `server/server.mjs` — dependency-free Node HTTP server:
  `POST /agent` (and `/`) serves preflight (`agent-games.preflight.v1`) and task
  envelopes (`agent-games.proof-gatekeeper.v1`); `GET /health` returns `{"ok":true}`.
  Inbound requests are verified with HMAC-SHA256 (`x-agent-games-signature`)
  and responses are signed the same way. Without a secret the server runs in
  test mode (unsigned requests accepted, warning logged) — **do not expose a
  test-mode server publicly**.
- `test/test-server.mjs` — 31 checks: preflight, a valid task, all six trap
  types, replayed proofs, HMAC accept/reject, malformed input.

## Run it

```bash
npm install
cp server/.env.example server/.env   # fill in AGENT_GAMES_HMAC_SECRET from the dashboard ("Rotate Secret")
node server/server.mjs               # listens on :3000 (PORT env overrides)
```

Expose it over public HTTPS (e.g. a tunnel) and register the endpoint in the
Agent Games dashboard as `https://<your-domain>/agent`, then complete the
signed preflight and at least one practice task.

## Sample data

- `inputs/` — example task envelopes (valid + traps).
- `proofs/` — example verified outputs for the valid task and one trap.
