# BUILD NOTES — Local Proof Gatekeeper (zkVerify Agent Games Season 01, Creator Track)

Local demo only. No public endpoint, no live arena submission, no VFY spent,
no mainnet transaction, no account registered, no user wallet/key touched.
Everything below was actually run on this machine; outputs are quoted from the
real runs. Receipts live in this workdir (`~/workspace/agentgames/`).

## 0. What this is

A minimal Node.js gatekeeper that, for a sample task envelope, (1) runs a
deterministic decision function (APPROVE/REJECT + reason_code) over the six
checks in the tournament's decision checklist, (2) generates a REAL Groth16
proof with the tournament's own official circuit via snarkjs, and (3) verifies
that proof with `snarkjs groth16 verify` against the verification key exported
from the official zkey.

Main entry: `src/gatekeeper.js` — `node src/gatekeeper.js` runs all three
scenarios and writes `inputs/*.json` + `proofs/<scenario>/{witness.json,
witness.wtns, proof.json, public.json, result.json}`.

## 1. Official sources read

- https://agentgames.zkverify.io/build
- https://agentgames.zkverify.io/events/proof-gatekeeper
- https://agentgames.zkverify.io/rules
- https://agentgames.zkverify.io/api/circuit-info
  - gatekeeper vkHash `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
  - vfyPolicy vkHash `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`
  - artifacts `https://agentgames.zkverify.io/circuits/gatekeeper.wasm` and
    `.../gatekeeper_final.zkey`

The official pages do NOT publish the circuit's input signal names or an input
JSON schema. The decision checklist is published (vk matches registered key;
public balance >= minimum; recipient matches condition; amount <= cap; not
expired; proof reference unused), but no wire format is given.

## 2. Circuit artifacts (downloaded from the official site)

| file | bytes | sha256 |
|---|---|---|
| `circuits/gatekeeper.wasm` | 1,755,820 | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `circuits/gatekeeper_final.zkey` | 309,750 | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |

Both match the sizes in a participant writeup (1,755,820 / 309,750). Commands:

```
curl -sL -o circuits/gatekeeper.wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm
curl -sL -o circuits/gatekeeper_final.zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
sha256sum circuits/gatekeeper.wasm circuits/gatekeeper_final.zkey
```

Verification key exported from the official zkey (`runs/vk.json`):

```
./node_modules/.bin/snarkjs zkey export verificationkey circuits/gatekeeper_final.zkey runs/vk.json
# protocol groth16, curve bn128, nPublic 13, IC length 14
./node_modules/.bin/snarkjs zkey export json circuits/gatekeeper_final.zkey runs/zkey.json
# protocol groth16, nVars 647, nPublic 13, power 10
```

NOTE on vkHash: the published gatekeeper vkHash
`0x6b79c6…d77b0` was NOT reproduced from the exported vk with any of 7
keccak256 encodings tried (`src/vkhash_try.py`: canonical sorted JSON, JSON
as-is, IC-only, all-points c0c1/c1c0, abcd-only, IC skip-0). This is recorded
honestly and is NOT blocking: the proof verifies against the vk exported from
the same official zkey, which is the authoritative check. The exact vkHash
derivation the platform uses is unpublished.

## 3. Tooling

- snarkjs 0.7.6, installed locally: `npm i snarkjs@0.7.6` (plus
  `circom_runtime`, `ffjavascript`, `circomlibjs` for the witness driver and
  the Poseidon cross-check). `node_modules/` in this workdir.
- circom 2.2.3 binary at `tools/circom` (used only to validate the probing
  method on a self-compiled test circuit, `runs/test/mult.circom`).

## 4. Input format — how it was derived (no names were invented)

The wasm stores input signal names only as FNV-1a 64-bit hashes (a one-way
function). There is no name table in the artifact. A brute-force over
~5,300,000 candidate names (task-payload names in snake/camel case, decision /
reuse / check booleans, hash variants, single letters, array-style names,
affixes, abbreviations, numeric names, 2- and 3-word domain combos, a 10k-word
list, a 370k-word alpha list, zkVerify-tutorial vocabulary, isXxx names,
envelope/preflight vocabulary) matched **0 of 13**. The names are therefore
NOT recoverable from the artifact, and no input name in this repo is claimed
to be the official one.

What IS recoverable, and was recovered:

(a) The hash table was extracted from the wasm data section (segment 18,
memory offset 2032, 256 slots x 16 bytes; entry = i64 FNV hash @0, u32
field8 @8, u32 size @12; slot = hash & 0xFF; all 13 at home slots, no
collisions). Saved in `runs/hash_table.json`. All 13 inputs are scalars
(size 1). In witness-wire (field8) order 2..14, the FNV hashes are:

```
2:  0x14418c3ee75f7a4e   3:  0x3b2514e2617cb386   4:  0xc92fe3ad0447b657
5:  0x9c9aac1639b93cc4   6:  0x9cef1f487868b4fb   7:  0xbab23a24475d685f
8:  0x3d0abea328337078   9:  0xacbdf1453659f53d  10:  0x8113fe7ea2b16969
11: 0x12eb7fd2c76a4dda  12:  0x4065e278cd7560a3  13:  0x0a29366601e1e7e1
14: 0x097f5318bf97c581
```

(b) Inputs are set WITHOUT names, via the hash: the witness is computed by
`setInputSignal(hMSB, hLSB, 0)` after writing the value (mod the BN128 prime)
as little-endian 32-bit limbs to shared RW memory. Driver:
`src/witness_by_hash.js` (usage: `node src/witness_by_hash.js <values.json>
<out_witness.json>`, where values.json keys are the 13 table hashes).
The method was validated first on a self-compiled test circuit (circom 2.2.3):
`getInputSignalSize` via FNV-1a returns size >= 1 iff the name exists.

(c) The .wtns writer (`src/witness_to_wtns.js`) writes the snarkjs binary
witness format: magic `wtns`, version 2, section 1 (n8=32, prime, nVars),
section 2 (nVars x 32-byte LE field elements). One bug was found and fixed
during the build: the prime itself must be written WITHOUT the mod reduction
(`PRIME % PRIME` = 0 produced an all-zero prime header and the error
"Curve of the witness does not match the curve of the proving key"). The
correct prime bytes (LE) are
`010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430`.

(d) Roles were determined EMPIRICALLY, by varying one input at a time
(and in pairs) and observing which witness signals changed and which
assignments fail the circuit's assert (`runs/vary_inputs.json`,
`runs/sweep_inputs.json`, `src/map_comparisons.js`, `src/map_blockC.js`,
`src/isolate_checks.js`, `src/decisive_test.js`). The resulting role map
(field8 = witness wire position) is:

| wire | role (inferred from circuit behaviour) | constraint (verified) |
|---|---|---|
| 2 | registered_vk (vk hash) | must equal wire 3 |
| 3 | proof_vk (vk hash) | must equal wire 2 |
| 4 | minimum | check wire 4 <= wire 5 |
| 5 | public_balance | check wire 4 <= wire 5 |
| 6 | decision (boolean 0/1) | must equal wire 12 |
| 7 | proof-reuse flag (0 = fresh/unused) | must be 0 to APPROVE |
| 8 | recipient | must equal wire 9 |
| 9 | condition_recipient | must equal wire 8 |
| 10 | current_block | check wire 10 <= wire 11 |
| 11 | expiry_block | check wire 10 <= wire 11 |
| 12 | decision duplicate (boolean 0/1) | must equal wire 6 |
| 13 | task_id (public; Poseidon input 2) | any field element |
| 14 | salt (PRIVATE; Poseidon input 1) | any field element; NOT in public signals |

Public signals (13): `[Poseidon(wire14, wire13), wire2, wire3, wire4, wire5,
wire6, wire7, wire8, wire9, wire10, wire11, wire12, wire13]`.
Wire 1 (the first public signal) is the Poseidon commitment, confirmed by an
independent cross-check with circomlibjs: `Poseidon([0,0])` equals the
all-zero witness[1] exactly, `Poseidon([salt, taskId])` equals the
valid-scenario witness[1] exactly (salt FIRST, taskId second), and the two
single-input variations match `Poseidon([0,1])` / `Poseidon([1,0])`
respectively. The circuit uses Poseidon(2).

Range bounds (verified by sweep, `runs/sweep_inputs.json`): wires 5, 7, 11
fail at 2^32 (32-bit); wires 4, 10 pass 2^32 but fail at 2^100; wires 2, 3, 8,
9, 13, 14 accept values up to 2^100. Wires 6 and 12 are boolean (0/1) and
must be equal (both 1, or both 0); setting either alone to 1, or both to 2,
fails the assert at `GatekeeperEvaluation_79 line: 102`.

NOTE: the semantic labels above (registered_vk, minimum, recipient, etc.)
are INFERENCES from the constraint structure, not published names. The
amount / max_transfer pair has no separately identifiable circuit input in
this mapping, so the amount<=cap check is enforced by the gatekeeper's
decision function off-circuit (and the platform re-checks it from the task
envelope). This is stated explicitly rather than pretending the mapping is
complete.

## 5. Verified decision behaviour (the important finding)

The circuit enforces the decision fail-closed on APPROVE, permissive on
REJECT (verified in `src/isolate_checks.js` and `src/decisive_test.js`):

- APPROVE (wires 6 and 12 = 1) builds a witness ONLY if every in-circuit
  check passes: wire2 == wire3 (vk match), wire8 == wire9 (recipient
  match), wire4 <= wire5 (minimum <= balance), wire10 <= wire11
  (current <= expiry, i.e. not expired), wire7 == 0 (proof unused).
  A WRONG APPROVE (any check failing) FAILS witness generation with
  `Assert Failed. Error in template GatekeeperEvaluation_79 line: 102` —
  no proof can be produced. Demonstrated by
  `proofs/trap_wrong_approve_attempt/result.json`.
- REJECT (wires 6 and 12 = 0) always builds a witness, whether the checks
  pass or fail. A wrong REJECT is therefore caught by the platform's
  scoring (-3), not by the circuit. This is a sensible design (reject is
  always safe; approve authorises a transfer, so it is fail-closed).

Two participant Medium writeups that were found during research claim input
names (registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision,
taskId, salt) and claim that a wrong REJECT also fails proof generation.
Both claims are FALSE against this circuit: none of those names matches the
hash table, and a wrong REJECT builds a witness fine (all-zero baseline).
Those writeups' technical claims are fabricated; do not cite them.

## 6. Scenarios run (all with `node src/gatekeeper.js`)

Sample task (from the official event page's sample fields):
registered_vk = proof_vk = gatekeeper vkHash
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
(minimum 1000, public_balance 1460, amount 500, max_transfer 1000,
current_block 19832000, expiry_block 19842201, recipient
`0x6E8f6B9c2E1F3a5D8c4B7a1E2d3F4a5B6c7D8e9`, proof unused). taskId
`20261115001`, salt `98765432109876543210` (demo values).

### (a) VALID — `proofs/valid_approve/` — APPROVE, proof verifies OK

```
[valid_approve] decision=APPROVE (VALID_CONDITION) | witness 647 signals | proof 804 B | prove 1723 ms | verify OK!
```

- `proofs/valid_approve/proof.json` — 804 bytes (matches the 804-byte proof
  size quoted in a participant writeup).
- `proofs/valid_approve/public.json` — 427 bytes, 13 public signals:
  `[2521724612541549964155591225912040805039299054988619156991119926731661558607,
   4836144126773920907502496244340012141761656471453348073975163706578152814510,
   4836144126773920907502496244340012141761656471453348073975163706578152814510,
   1000, 1460, 1, 0,
   39449210344622674849237056640300794180190853353,
   39449210344622674849237056640300794180190853353,
   19832000, 19842201, 1, 20261115001]`
  (vkHash mod prime, twice; minimum; balance; decision 1; reuse flag 0;
  recipient twice; current; expiry; decision 1; taskId. The salt is absent —
  private, as expected. Public[0] is Poseidon(salt, taskId), cross-checked
  independently with circomlibjs.)
- Exact verify output (re-run independently after the build):
  `[INFO]  snarkJS: OK!`

### (b) TRAP — `proofs/trap_recipient_mismatch/` — REJECT, proof verifies OK

Same task but condition_recipient changed to
`0x1111111111111111111111111111111111111111` (recipient mismatch).

```
[trap_recipient_mismatch] decision=REJECT (RECIPIENT_MISMATCH) | witness 647 signals | proof 806 B | prove 1431 ms | verify OK!
```

- `proofs/trap_recipient_mismatch/proof.json` — 806 bytes.
- Public signals identical to (a) except decision wires 0 and the
  condition_recipient value differs
  (`97433442488726861213578988847752201310395502865`).
- The proof attests to the evaluation; the gatekeeper correctly REJECTs.
  Exact verify output (re-run independently): `[INFO]  snarkJS: OK!`

### (c) Wrong-APPROVE attempt — `proofs/trap_wrong_approve_attempt/` — no proof

Same trap task but with the decision forced to APPROVE:

```
[trap_wrong_approve_attempt] witness FAILED as expected: Assert Failed. Error in template GatekeeperEvaluation_79 line: 102
```

No proof.json is produced. This is the circuit's fail-closed behaviour: a
decision that contradicts the checks cannot be proven.

## 7. Proof sizes and timings (this machine)

| scenario | decision | proof bytes | public.json bytes | witness signals | proving time | verify |
|---|---|---|---|---|---|---|
| valid_approve | APPROVE | 804 | 427 | 647 | 1,723 ms | OK! |
| trap_recipient_mismatch | REJECT | 806 | 427 | 647 | 1,431 ms | OK! |
| trap_wrong_approve_attempt | APPROVE (forced, wrong) | — (no proof) | — | assert fails | — | n/a |
| all-zero smoke test | — | 803 | — | 647 | ~1,370 ms | OK! |

The 2-byte difference between the two real proofs (804 vs 806) is JSON
number-length formatting, not a different proof structure (both are Groth16
proofs: pi_a, pi_b, pi_c over bn128).

## 8. File map

```
circuits/gatekeeper.wasm            official wasm (1,755,820 B)
circuits/gatekeeper_final.zkey     official zkey (309,750 B)
src/gatekeeper.js                  gatekeeper + decision function + prove/verify pipeline
src/witness_by_hash.js             witness driver (sets inputs by FNV hash)
src/witness_to_wtns.js             witness JSON -> .wtns converter (prime bug fixed)
src/probe_signals*.js, src/probe3.js, src/probe4.js, src/parse_wasm.js
                                   signal probing + wasm hash-table extraction
src/bruteforce*.js                 ~5.3M candidate-name brute force (0/13 matched)
src/vary_inputs.js, src/sweep_inputs.js, src/map_comparisons.js,
src/map_blockC.js, src/test_pairs.js, src/isolate_checks.js,
src/decisive_test.js, src/witness_diff.js
                                   empirical role-mapping experiments
src/vkhash_try.py                  vkHash reproduction attempts (7 encodings, none matched)
inputs/valid_approve.json          valid scenario task + decision + inputs by wire
inputs/trap_recipient_mismatch.json
inputs/trap_wrong_approve_attempt.json
proofs/valid_approve/{witness.json, witness.wtns, proof.json, public.json, result.json}
proofs/trap_recipient_mismatch/{...}
proofs/trap_wrong_approve_attempt/result.json   (witness-failure record only)
runs/vk.json                       verification key exported from the official zkey
runs/zkey.json                     zkey metadata (nVars 647, nPublic 13, power 10)
runs/hash_table.json               the 13 FNV input hashes + wire positions
runs/gatekeeper.wat                wasm disassembly (11.9 MB)
runs/wit_zero.json / runs/wit_zero.wtns   all-zero smoke-test witness
runs/proof_zero.json / runs/public_zero.json  all-zero smoke-test proof (verifies OK!)
runs/test/                         self-compiled validation circuit (method check)
tools/circom                       circom 2.2.3 binary
package.json / package-lock.json   snarkjs 0.7.6, circom_runtime, ffjavascript, circomlibjs
```

## 9. Honest limits

- LOCAL DEMO ONLY. There is no public HTTPS endpoint, no live arena
  submission, no VFY spent, no mainnet transaction, and no account
  registration. This workdir proves the gatekeeper logic and the proof
  pipeline; it does not enter the tournament.
- Input signal NAMES are unpublished and unrecoverable from the artifact
  (FNV-1a hashes are one-way; 5.3M+ candidates matched 0/13). The role map
  in section 4 is derived from observed circuit behaviour and is labelled
  as inference. Do not present those names as official.
- The amount / max_transfer pair has no separately identifiable circuit
  input in this mapping; amount<=cap is enforced by the gatekeeper's
  decision function off-circuit.
- The published gatekeeper vkHash was not reproduced from the exported vk
  (section 2). The proof still verifies against the vk from the same
  official zkey.
- The circuit permits a wrong REJECT (decision 0 with all checks passing)
  to produce a valid proof; only a wrong APPROVE is blocked in-circuit.
  The platform's scoring, not the circuit, catches a wrong REJECT.
- The salt in the scenarios is a fixed demo value. In a real deployment
  the salt must be a per-agent secret, never published, and the taskId must
  come from the platform's signed task envelope (not chosen locally).
- The Poseidon commitment is Poseidon(salt, taskId) — salt first. If the
  platform expects a different argument order, the commitment would not
  match its expectation; the order here is what the circuit computes.
