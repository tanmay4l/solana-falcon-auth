# solana-falcon-auth

Solana program for **Falcon-512 application authorization**.

- Stores one prepared Falcon-512 pubkey per Solana authority in a PDA.
- Verifies 666-byte Falcon signatures with `solana-falcon512`.
- Chunked 1024-byte prepared-pubkey writes (`register/rotate -> write chunks -> finalize`) to stay under Solana's transaction packet limit.
- Canonical signed payload binds registered cluster/deployment domain, auth program id, authority, Falcon key account, nonce, expiry slot, action domain, and action hash.
- Monotonic nonce replay protection; pending key accounts cannot verify actions.
- Authority-controlled key rotation and close.
- Falcon vault program proves CPI-gated SOL withdrawals.
- PQ quorum program proves Falcon + Winternitz approval for the same app action.
- 2-of-3 quorum paths add ML-DSA-44: Falcon + Winternitz, Falcon + ML-DSA, and Winternitz + ML-DSA.
- Chunked Winternitz, Falcon-signature, and prepared ML-DSA buffers keep large signatures/pubkeys out of final instruction data.
- Split ML-DSA proof PDAs move the four heavy matrix rows into separate row-proof transactions, then final quorum verification checks the completed proof.
- PQ smart account program holds SOL and controls classic SPL token accounts through 2-of-3 PQ quorum auth over CPI.
- Current SBF measurements: `verify_action` **~184k CU**, Falcon vault withdraw **~198k CU**.

This does **not** replace Solana transaction signatures. It is an app-level authorization layer.
The Falcon + Winternitz quorum path consumes each Winternitz root once and rotates to the next signed root. It uses a base-16 Winternitz checksum verifier with a 2,144-byte signature buffer and measures about **~307k CU** in SBF tests. The PQ smart-account path measures about **~290k CU** for SOL, **~310k CU** for direct SPL, and **~318k CU** for buffered SPL in SBF tests. The ML-DSA proof setup is split into devnet-sized transactions: challenge prep is about **~51k CU**, each z-column prep is about **~55k CU**, each matrix-column proof is about **~87k CU**, and each row finalize is about **~57k CU**. Final smart-account SPL verification measures about **~356k CU** for buffered Falcon + ML-DSA and **~250k CU** for Winternitz + ML-DSA in SBF tests. Classic SPL token transfers are devnet-smoked for Falcon + Winternitz (**304,493 CU**), Falcon + ML-DSA (**346,713 CU**), and Winternitz + ML-DSA (**246,410 CU**).

## Program model

```text
FalconKeyAccount
  discriminator: [u8; 8] = b"FALKYA02"
  version: u8
  bump: u8
  cluster: u8
  reserved: u8       # keeps prepared_pubkey 2-byte aligned
  authority: [u8; 32]
  next_nonce: u64
  prepared_pubkey: [u8; 1024]
```

```text
PDA seeds = [b"falcon-key", authority_pubkey.as_ref()]
```

## Instructions

| Tag | Instruction       | Purpose                                      |
| --- | ----------------- | -------------------------------------------- |
| 0   | `register_key`    | Create Falcon key PDA with cluster binding.  |
| 1   | `verify_action`   | Verify Falcon signature and increment nonce. |
| 2   | `rotate_key`      | Reset active key account to pending state.   |
| 3   | `close_key`       | Close key account back to authority.         |
| 4   | `write_key_chunk` | Write part of the prepared pubkey.           |
| 5   | `finalize_key`    | Validate prepared pubkey and activate key.   |

Pending state is `next_nonce = u64::MAX`. `verify_action` rejects pending state.

## Signed payload

```text
FalconActionV1
  magic: [u8; 16] = b"SOL_FALCON_ACT1!"
  cluster: u8
  program_id: [u8; 32]
  authority: [u8; 32]
  falcon_key_account: [u8; 32]
  nonce: u64 little-endian
  expires_slot: u64 little-endian
  action_domain: [u8; 32]
  action_hash: [u8; 32]
```

The auth program checks `cluster` against the value stored at registration, verifies this payload, and advances the nonce. It does not parse application-specific action data.

## Project layout

- `programs/falcon-auth/` — core auth program.
- `programs/falcon-vault/` — SOL vault gated by Falcon auth CPI.
- `programs/pq-quorum-auth/` — Falcon, Winternitz, and ML-DSA quorum auth.
- `programs/pq-smart-account/` — SOL and classic SPL token smart account gated by PQ quorum auth CPI.
- `programs/falcon-auth/tests/` — Mollusk/SBF tests.
- `programs/pq-quorum-auth/tests/` — Mollusk/SBF quorum tests.
- `programs/pq-smart-account/tests/` — Mollusk/SBF smart-account tests.

## Testing

```sh
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo-build-sbf --manifest-path programs/falcon-auth/Cargo.toml
cargo-build-sbf --manifest-path programs/falcon-vault/Cargo.toml
cargo-build-sbf --manifest-path programs/pq-quorum-auth/Cargo.toml
cargo-build-sbf --manifest-path programs/pq-smart-account/Cargo.toml
cargo test --workspace
cargo test-sbf
```
