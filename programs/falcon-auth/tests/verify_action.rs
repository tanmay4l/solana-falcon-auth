use {
    mollusk_svm::{Mollusk, result::ProgramResult as SvmResult},
    pqcrypto_falcon::falcon512,
    pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _},
    solana_account::Account,
    solana_falcon512::{FALCON_512_SIGNATURE_LEN, Falcon512Pubkey},
    solana_instruction::{AccountMeta, Instruction},
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
};

const TAG_VERIFY_ACTION: u8 = 1;
const FALCON_KEY_SEED: &[u8] = b"falcon-key";
const FALCON_KEY_DISCRIMINATOR: [u8; 8] = *b"FALKYA01";
const FALCON_ACTION_MAGIC: [u8; 16] = *b"SOL_FALCON_ACT1!";
const VERSION_OFFSET: usize = 8;
const BUMP_OFFSET: usize = 9;
const AUTHORITY_OFFSET: usize = 10;
const NEXT_NONCE_OFFSET: usize = 42;
const PREPARED_PUBKEY_OFFSET: usize = 50;
const FALCON_KEY_ACCOUNT_LEN: usize = PREPARED_PUBKEY_OFFSET + 1024;
const FALCON_ACTION_PAYLOAD_LEN: usize = 193;
const VERIFY_ACTION_MAX_CU: u64 = 400_000;

struct Fixture {
    mollusk: Mollusk,
    program_id: Pubkey,
    authority: Pubkey,
    falcon_key: Pubkey,
    falcon_account: Account,
    secret_key: falcon512::SecretKey,
}

fn make_fixture(next_nonce: u64) -> Fixture {
    let program_id = Pubkey::new_unique();
    let mollusk = Mollusk::new(&program_id, "../../target/deploy/falcon_auth");
    let authority = Pubkey::new_unique();
    let (falcon_key, bump) =
        Pubkey::find_program_address(&[FALCON_KEY_SEED, authority.as_ref()], &program_id);
    let (public_key, secret_key) = falcon512::keypair();

    let mut pk_bytes = [0u8; 897];
    pk_bytes.copy_from_slice(public_key.as_bytes());
    let prepared = Falcon512Pubkey::from(pk_bytes)
        .try_prepare_pubkey()
        .unwrap();

    let lamports = mollusk.sysvars.rent.minimum_balance(FALCON_KEY_ACCOUNT_LEN);
    let mut data = vec![0u8; FALCON_KEY_ACCOUNT_LEN];
    data[..8].copy_from_slice(&FALCON_KEY_DISCRIMINATOR);
    data[VERSION_OFFSET] = 1;
    data[BUMP_OFFSET] = bump;
    data[AUTHORITY_OFFSET..NEXT_NONCE_OFFSET].copy_from_slice(authority.as_ref());
    data[NEXT_NONCE_OFFSET..PREPARED_PUBKEY_OFFSET].copy_from_slice(&next_nonce.to_le_bytes());
    data[PREPARED_PUBKEY_OFFSET..].copy_from_slice(prepared.as_bytes());

    Fixture {
        mollusk,
        program_id,
        authority,
        falcon_key,
        falcon_account: Account {
            lamports,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
        secret_key,
    }
}

fn build_payload(
    cluster: u8,
    program_id: Pubkey,
    authority: Pubkey,
    falcon_key: Pubkey,
    nonce: u64,
    expires_slot: u64,
    action_domain: &[u8; 32],
    action_hash: &[u8; 32],
) -> [u8; FALCON_ACTION_PAYLOAD_LEN] {
    let mut out = [0u8; FALCON_ACTION_PAYLOAD_LEN];
    out[0..16].copy_from_slice(&FALCON_ACTION_MAGIC);
    out[16] = cluster;
    out[17..49].copy_from_slice(program_id.as_ref());
    out[49..81].copy_from_slice(authority.as_ref());
    out[81..113].copy_from_slice(falcon_key.as_ref());
    out[113..121].copy_from_slice(&nonce.to_le_bytes());
    out[121..129].copy_from_slice(&expires_slot.to_le_bytes());
    out[129..161].copy_from_slice(action_domain);
    out[161..193].copy_from_slice(action_hash);
    out
}

fn sign_payload(
    payload: &[u8],
    secret_key: &falcon512::SecretKey,
) -> [u8; FALCON_512_SIGNATURE_LEN] {
    let signature = falcon512::detached_sign(payload, secret_key);
    let mut out = [0u8; FALCON_512_SIGNATURE_LEN];
    out[..signature.as_bytes().len()].copy_from_slice(signature.as_bytes());
    out
}

fn verify_ix(
    fixture: &Fixture,
    nonce: u64,
    expires_slot: u64,
    action_domain: [u8; 32],
    action_hash: [u8; 32],
    signature: [u8; FALCON_512_SIGNATURE_LEN],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 32 + 32 + FALCON_512_SIGNATURE_LEN);
    data.push(TAG_VERIFY_ACTION);
    data.push(0);
    data.extend_from_slice(&nonce.to_le_bytes());
    data.extend_from_slice(&expires_slot.to_le_bytes());
    data.extend_from_slice(&action_domain);
    data.extend_from_slice(&action_hash);
    data.extend_from_slice(&signature);

    Instruction::new_with_bytes(
        fixture.program_id,
        &data,
        vec![
            AccountMeta::new_readonly(fixture.authority, false),
            AccountMeta::new(fixture.falcon_key, false),
        ],
    )
}

fn signed_verify_ix(
    fixture: &Fixture,
    nonce: u64,
    expires_slot: u64,
    action_domain: [u8; 32],
    action_hash: [u8; 32],
) -> Instruction {
    let payload = build_payload(
        0,
        fixture.program_id,
        fixture.authority,
        fixture.falcon_key,
        nonce,
        expires_slot,
        &action_domain,
        &action_hash,
    );
    let signature = sign_payload(&payload, &fixture.secret_key);
    verify_ix(
        fixture,
        nonce,
        expires_slot,
        action_domain,
        action_hash,
        signature,
    )
}

fn authority_account() -> Account {
    Account::new(1_000_000_000, 0, &solana_sdk_ids::system_program::id())
}

#[test]
fn verify_action_accepts_valid_signature_and_increments_nonce() {
    let fixture = make_fixture(0);
    let action_domain = [7u8; 32];
    let action_hash = [9u8; 32];
    let ix = signed_verify_ix(&fixture, 0, 100, action_domain, action_hash);

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, authority_account()),
            (fixture.falcon_key, fixture.falcon_account),
        ],
    );

    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    println!("verify_action CU: {}", result.compute_units_consumed);
    assert!(result.compute_units_consumed <= VERIFY_ACTION_MAX_CU);
    let (_, account) = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| *key == fixture.falcon_key)
        .unwrap();
    assert_eq!(
        u64::from_le_bytes(
            account.data[NEXT_NONCE_OFFSET..PREPARED_PUBKEY_OFFSET]
                .try_into()
                .unwrap()
        ),
        1
    );
}

#[test]
fn verify_action_rejects_replayed_nonce() {
    let fixture = make_fixture(1);
    let ix = signed_verify_ix(&fixture, 0, 100, [7u8; 32], [9u8; 32]);
    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, authority_account()),
            (fixture.falcon_key, fixture.falcon_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(9))
    );
}

#[test]
fn verify_action_rejects_wrong_nonce() {
    let fixture = make_fixture(0);
    let ix = signed_verify_ix(&fixture, 1, 100, [7u8; 32], [9u8; 32]);
    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, authority_account()),
            (fixture.falcon_key, fixture.falcon_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(9))
    );
}

#[test]
fn verify_action_rejects_expired_payload() {
    let mut fixture = make_fixture(0);
    fixture.mollusk.sysvars.clock.slot = 50;
    let ix = signed_verify_ix(&fixture, 0, 49, [7u8; 32], [9u8; 32]);
    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, authority_account()),
            (fixture.falcon_key, fixture.falcon_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(10))
    );
}

#[test]
fn verify_action_rejects_modified_action_hash() {
    let fixture = make_fixture(0);
    let action_domain = [7u8; 32];
    let signed_hash = [9u8; 32];
    let submitted_hash = [10u8; 32];
    let payload = build_payload(
        0,
        fixture.program_id,
        fixture.authority,
        fixture.falcon_key,
        0,
        100,
        &action_domain,
        &signed_hash,
    );
    let signature = sign_payload(&payload, &fixture.secret_key);
    let ix = verify_ix(&fixture, 0, 100, action_domain, submitted_hash, signature);
    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, authority_account()),
            (fixture.falcon_key, fixture.falcon_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(8))
    );
}

#[test]
fn verify_action_rejects_modified_action_domain() {
    let fixture = make_fixture(0);
    let signed_domain = [7u8; 32];
    let submitted_domain = [8u8; 32];
    let action_hash = [9u8; 32];
    let payload = build_payload(
        0,
        fixture.program_id,
        fixture.authority,
        fixture.falcon_key,
        0,
        100,
        &signed_domain,
        &action_hash,
    );
    let signature = sign_payload(&payload, &fixture.secret_key);
    let ix = verify_ix(&fixture, 0, 100, submitted_domain, action_hash, signature);
    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, authority_account()),
            (fixture.falcon_key, fixture.falcon_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(8))
    );
}

#[test]
fn verify_action_rejects_modified_signature() {
    let fixture = make_fixture(0);
    let mut ix = signed_verify_ix(&fixture, 0, 100, [7u8; 32], [9u8; 32]);
    let last = ix.data.len() - 1;
    ix.data[last] ^= 1;

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, authority_account()),
            (fixture.falcon_key, fixture.falcon_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(8))
    );
}

#[test]
fn verify_action_rejects_wrong_program_id_in_signed_payload() {
    let fixture = make_fixture(0);
    let action_domain = [7u8; 32];
    let action_hash = [9u8; 32];
    let payload = build_payload(
        0,
        Pubkey::new_unique(),
        fixture.authority,
        fixture.falcon_key,
        0,
        100,
        &action_domain,
        &action_hash,
    );
    let signature = sign_payload(&payload, &fixture.secret_key);
    let ix = verify_ix(&fixture, 0, 100, action_domain, action_hash, signature);
    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, authority_account()),
            (fixture.falcon_key, fixture.falcon_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(8))
    );
}

#[test]
fn verify_action_rejects_wrong_authority_account() {
    let fixture = make_fixture(0);
    let wrong_authority = Pubkey::new_unique();
    let mut ix = signed_verify_ix(&fixture, 0, 100, [7u8; 32], [9u8; 32]);
    ix.accounts[0].pubkey = wrong_authority;

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (wrong_authority, authority_account()),
            (fixture.falcon_key, fixture.falcon_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(6))
    );
}

#[test]
fn verify_action_rejects_wrong_falcon_key_pda() {
    let fixture = make_fixture(0);
    let wrong_falcon_key = Pubkey::new_unique();
    let mut ix = signed_verify_ix(&fixture, 0, 100, [7u8; 32], [9u8; 32]);
    ix.accounts[1].pubkey = wrong_falcon_key;

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, authority_account()),
            (wrong_falcon_key, fixture.falcon_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(3))
    );
}
