# Proof Gatekeeper agent server

Live agent endpoint for zkVerify Agent Games Season 01 (Proof Gatekeeper).
Local build only — no dashboard registration, no API keys, no transactions,
no wallet touched. Kurier submission is OUT of scope (the Groth16 proof goes
inline in the response).

## Run

```sh
cd ~/workspace/agentgames
node server/server.mjs            # PORT 3000 by default
PORT=3000 node server/server.mjs  # explicit
```

Currently RUNNING in the background on :3000 (started 2026-11-16 ~14:46 WIB,
PID 6720, logs in `server/server.log`). It is in TEST MODE (see below).

## Configure

Copy `server/.env.example` to `server/.env` (or export env vars — process
env wins):

- `AGENT_GAMES_HMAC_SECRET` — from the dashboard ("Rotate Secret", My Agents).
  **Blank = TEST MODE: unsigned requests are accepted and a warning is logged
  on every request. Never register the test-mode endpoint publicly.**
  With the secret set, inbound HMAC-SHA256 (hex, over the raw body, header
  `x-agent-games-signature`) is verified before JSON parsing (401 on
  mismatch), and every response is signed the same way.
- `AGENT_GAMES_SALT` — optional per-agent Poseidon salt (decimal). If blank,
  a random salt is generated once and persisted to `server/salt.json` (0600).
- `PORT` — default 3000. `AGENTGAMES_DATA_DIR` — state dir, default `server/`.

## Endpoints

- `GET /`, `GET /health` → `{"ok":true}`
- `POST /` or `POST /agent`
  - `{"type":"agent-games.preflight.v1"}` → `{"ok":true,"protocolVersion":"v1"}`
  - `{"type":"agent-games.proof-gatekeeper.v1", "task_id", "input": {...}}`
    → `{"decision":"APPROVE"|"REJECT","reason_code":"...","proof":{...},"public_signals":[...]}`
    (proof/public_signals omitted for `PROOF_REUSED` and if proving fails)

Decision logic + circuit input mapping are reused from
`../src/gatekeeper.js` (see `../BUILD_NOTES.md`); proofs are real Groth16
via snarkjs with the official `circuits/gatekeeper.wasm` /
`circuits/gatekeeper_final.zkey`. Proving is capped at 30 s — on timeout the
server answers decision+reason_code only, never breaching the 60 s deadline.
Decisions fail closed (any error → REJECT). Proof reuse is tracked in the
persistent `server/seen.json` (proof_tx values).

## Tests

```sh
node test/test-server.mjs   # 31/31 PASS (2026-11-16)
```

Starts throwaway servers on :3100 (test mode) and :3101 (HMAC mode),
replays the sample envelope + all 7 trap/valid scenarios, verifies every
returned proof with snarkjs against `runs/vk.json`, and checks the HMAC
401 paths. Test state lives in temp dirs; the production `server/seen.json`
is untouched by the harness.
