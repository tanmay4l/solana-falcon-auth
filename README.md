# solana-falcon-auth

Solana program for **Falcon-512 application authorization**.

- Stores one prepared Falcon-512 pubkey per Solana authority in a PDA.
- Verifies 666-byte Falcon signatures with `solana-falcon512`.
- Chunked 1024-byte prepared-pubkey writes (`register/rotate -> write chunks -> finalize`) to stay under Solana's transaction packet limit.
- Canonical signed payload binds cluster, auth program id, authority, Falcon key account, nonce, expiry slot, action domain, and action hash.
- Monotonic nonce replay protection; pending key accounts cannot verify actions.
- Authority-controlled key rotation and close.
- Example consumer program proves CPI-gated state mutation.
- Current SBF measurements: `verify_action` **322,965 CU**, consumer CPI increment **326,169 CU**.

This does **not** replace Solana transaction signatures. It is an app-level authorization layer.

## Program model

```text
FalconKeyAccount
  discriminator: [u8; 8] = b"FALKYA01"
  version: u8
  bump: u8
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
| 0   | `register_key`    | Create Falcon key PDA in pending state.      |
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

The auth program verifies this payload and advances the nonce. It does not parse application-specific action data.

## Project layout

- `programs/falcon-auth/` — core auth program.
- `programs/example-consumer/` — minimal CPI consumer program.
- `programs/falcon-auth/tests/` — Mollusk/SBF tests.

## Testing

```sh
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo-build-sbf --manifest-path programs/falcon-auth/Cargo.toml
cargo-build-sbf --manifest-path programs/example-consumer/Cargo.toml
cargo test --workspace
cargo test-sbf
```

Localnet smoke test:

```sh
FALCON_AUTH_RPC_URL=http://127.0.0.1:8899 \
FALCON_AUTH_PROGRAM_ID=<falcon-auth-program> \
EXAMPLE_CONSUMER_PROGRAM_ID=<example-consumer-program> \
cargo test --workspace localnet_smoke_register_rotate_and_consumer_cpi -- --ignored --nocapture
```

