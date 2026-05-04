use {
    mollusk_svm::{Mollusk, result::ProgramResult as SvmResult},
    pqcrypto_falcon::falcon512,
    pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _},
    solana_account::Account,
    solana_falcon512::{
        FALCON_512_PREPARED_PUBKEY_LEN, FALCON_512_PUBKEY_LEN, FALCON_512_SIGNATURE_LEN,
        Falcon512Pubkey,
    },
    solana_instruction::{AccountMeta, Instruction},
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
};

const TAG_VERIFY_ACTION: u8 = 1;
const TAG_ROTATE_KEY: u8 = 2;
const TAG_CLOSE_KEY: u8 = 3;
const TAG_WRITE_KEY_CHUNK: u8 = 4;
const TAG_FINALIZE_KEY: u8 = 5;
const FALCON_KEY_SEED: &[u8] = b"falcon-key";
const FALCON_KEY_DISCRIMINATOR: [u8; 8] = *b"FALKYA02";
const CLOSED_DISCRIMINATOR: [u8; 8] = [0xff; 8];
const FALCON_ACTION_MAGIC: [u8; 16] = *b"SOL_FALCON_ACT1!";
const PENDING_NONCE: u64 = u64::MAX;
const VERSION_OFFSET: usize = 8;
const BUMP_OFFSET: usize = 9;
const CLUSTER_OFFSET: usize = 10;
const RESERVED_OFFSET: usize = 11;
const AUTHORITY_OFFSET: usize = 12;
const NEXT_NONCE_OFFSET: usize = 44;
const PREPARED_PUBKEY_OFFSET: usize = 52;
const FALCON_KEY_ACCOUNT_LEN: usize = PREPARED_PUBKEY_OFFSET + 1024;
const FALCON_ACTION_PAYLOAD_LEN: usize = 193;
const CLUSTER: u8 = 0;

struct Fixture {
    mollusk: Mollusk,
    program_id: Pubkey,
    authority: Pubkey,
    falcon_key: Pubkey,
    falcon_account: Account,
}

fn prepared_pubkey_bytes() -> [u8; FALCON_512_PREPARED_PUBKEY_LEN] {
    falcon_keypair().0
}

fn falcon_keypair() -> ([u8; FALCON_512_PREPARED_PUBKEY_LEN], falcon512::SecretKey) {
    let (public_key, secret_key) = falcon512::keypair();
    let mut pk_bytes = [0u8; FALCON_512_PUBKEY_LEN];
    pk_bytes.copy_from_slice(public_key.as_bytes());
    let pubkey = Falcon512Pubkey::from(pk_bytes);
    (*pubkey.try_prepare_pubkey().unwrap().as_bytes(), secret_key)
}

fn make_fixture(next_nonce: u64, prepared_pubkey: [u8; FALCON_512_PREPARED_PUBKEY_LEN]) -> Fixture {
    let program_id = Pubkey::new_unique();
    let mollusk = Mollusk::new(&program_id, "../../target/deploy/falcon_auth");
    let authority = Pubkey::new_unique();
    let (falcon_key, bump) =
        Pubkey::find_program_address(&[FALCON_KEY_SEED, authority.as_ref()], &program_id);

    let lamports = mollusk.sysvars.rent.minimum_balance(FALCON_KEY_ACCOUNT_LEN);
    let mut data = vec![0u8; FALCON_KEY_ACCOUNT_LEN];
    data[..8].copy_from_slice(&FALCON_KEY_DISCRIMINATOR);
    data[VERSION_OFFSET] = 2;
    data[BUMP_OFFSET] = bump;
    data[CLUSTER_OFFSET] = CLUSTER;
    data[RESERVED_OFFSET] = 0;
    data[AUTHORITY_OFFSET..NEXT_NONCE_OFFSET].copy_from_slice(authority.as_ref());
    data[NEXT_NONCE_OFFSET..PREPARED_PUBKEY_OFFSET].copy_from_slice(&next_nonce.to_le_bytes());
    data[PREPARED_PUBKEY_OFFSET..].copy_from_slice(&prepared_pubkey);

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
    }
}

fn authority_account(lamports: u64) -> Account {
    Account::new(lamports, 0, &solana_sdk_ids::system_program::id())
}

fn rotate_ix(fixture: &Fixture) -> Instruction {
    Instruction::new_with_bytes(
        fixture.program_id,
        &[TAG_ROTATE_KEY],
        vec![
            AccountMeta::new(fixture.authority, true),
            AccountMeta::new(fixture.falcon_key, false),
        ],
    )
}

fn write_chunk_ix(fixture: &Fixture, offset: u16, chunk: &[u8]) -> Instruction {
    let mut data = Vec::with_capacity(1 + 2 + chunk.len());
    data.push(TAG_WRITE_KEY_CHUNK);
    data.extend_from_slice(&offset.to_le_bytes());
    data.extend_from_slice(chunk);

    Instruction::new_with_bytes(
        fixture.program_id,
        &data,
        vec![
            AccountMeta::new(fixture.authority, true),
            AccountMeta::new(fixture.falcon_key, false),
        ],
    )
}

fn finalize_ix(fixture: &Fixture) -> Instruction {
    Instruction::new_with_bytes(
        fixture.program_id,
        &[TAG_FINALIZE_KEY],
        vec![
            AccountMeta::new(fixture.authority, true),
            AccountMeta::new(fixture.falcon_key, false),
        ],
    )
}

fn close_ix(fixture: &Fixture) -> Instruction {
    Instruction::new_with_bytes(
        fixture.program_id,
        &[TAG_CLOSE_KEY],
        vec![
            AccountMeta::new(fixture.authority, true),
            AccountMeta::new(fixture.falcon_key, false),
        ],
    )
}

fn build_payload(
    program_id: Pubkey,
    authority: Pubkey,
    falcon_key: Pubkey,
    nonce: u64,
) -> [u8; FALCON_ACTION_PAYLOAD_LEN] {
    let action_domain = [7u8; 32];
    let action_hash = [9u8; 32];
    let mut out = [0u8; FALCON_ACTION_PAYLOAD_LEN];
    out[0..16].copy_from_slice(&FALCON_ACTION_MAGIC);
    out[16] = CLUSTER;
    out[17..49].copy_from_slice(program_id.as_ref());
    out[49..81].copy_from_slice(authority.as_ref());
    out[81..113].copy_from_slice(falcon_key.as_ref());
    out[113..121].copy_from_slice(&nonce.to_le_bytes());
    out[121..129].copy_from_slice(&100u64.to_le_bytes());
    out[129..161].copy_from_slice(&action_domain);
    out[161..193].copy_from_slice(&action_hash);
    out
}

fn verify_ix(fixture: &Fixture, secret_key: &falcon512::SecretKey, nonce: u64) -> Instruction {
    let payload = build_payload(
        fixture.program_id,
        fixture.authority,
        fixture.falcon_key,
        nonce,
    );
    let signature = falcon512::detached_sign(&payload, secret_key);
    let mut signature_bytes = [0u8; FALCON_512_SIGNATURE_LEN];
    signature_bytes[..signature.as_bytes().len()].copy_from_slice(signature.as_bytes());

    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 32 + 32 + FALCON_512_SIGNATURE_LEN);
    data.push(TAG_VERIFY_ACTION);
    data.push(CLUSTER);
    data.extend_from_slice(&nonce.to_le_bytes());
    data.extend_from_slice(&100u64.to_le_bytes());
    data.extend_from_slice(&[7u8; 32]);
    data.extend_from_slice(&[9u8; 32]);
    data.extend_from_slice(&signature_bytes);

    Instruction::new_with_bytes(
        fixture.program_id,
        &data,
        vec![
            AccountMeta::new_readonly(fixture.authority, false),
            AccountMeta::new(fixture.falcon_key, false),
        ],
    )
}

fn nonce(account: &Account) -> u64 {
    u64::from_le_bytes(
        account.data[NEXT_NONCE_OFFSET..PREPARED_PUBKEY_OFFSET]
            .try_into()
            .unwrap(),
    )
}

fn resulting_falcon_account(
    result: &mollusk_svm::result::InstructionResult,
    falcon_key: Pubkey,
) -> Account {
    result
        .resulting_accounts
        .iter()
        .find(|(key, _)| *key == falcon_key)
        .expect("falcon key account returned")
        .1
        .clone()
}

fn begin_rotation(fixture: &Fixture) -> Account {
    let result = fixture.mollusk.process_instruction(
        &rotate_ix(fixture),
        &[
            (fixture.authority, authority_account(1_000_000_000)),
            (fixture.falcon_key, fixture.falcon_account.clone()),
        ],
    );

    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    resulting_falcon_account(&result, fixture.falcon_key)
}

fn write_key_chunks(
    fixture: &Fixture,
    pending_account: Account,
    prepared_pubkey: [u8; FALCON_512_PREPARED_PUBKEY_LEN],
) -> Account {
    let first = fixture.mollusk.process_instruction(
        &write_chunk_ix(fixture, 0, &prepared_pubkey[..512]),
        &[
            (fixture.authority, authority_account(1_000_000_000)),
            (fixture.falcon_key, pending_account),
        ],
    );
    assert!(first.program_result.is_ok(), "{:?}", first.program_result);
    let half_written = resulting_falcon_account(&first, fixture.falcon_key);

    let second = fixture.mollusk.process_instruction(
        &write_chunk_ix(fixture, 512, &prepared_pubkey[512..]),
        &[
            (fixture.authority, authority_account(1_000_000_000)),
            (fixture.falcon_key, half_written),
        ],
    );
    assert!(second.program_result.is_ok(), "{:?}", second.program_result);
    resulting_falcon_account(&second, fixture.falcon_key)
}

fn finalize_key(fixture: &Fixture, written_account: Account) -> (SvmResult, Option<Account>) {
    let result = fixture.mollusk.process_instruction(
        &finalize_ix(fixture),
        &[
            (fixture.authority, authority_account(1_000_000_000)),
            (fixture.falcon_key, written_account),
        ],
    );
    let account = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| *key == fixture.falcon_key)
        .map(|(_, account)| account.clone());
    (result.program_result, account)
}

fn finish_pending_key(
    fixture: &Fixture,
    pending_account: Account,
    prepared_pubkey: [u8; FALCON_512_PREPARED_PUBKEY_LEN],
) -> Account {
    let written_account = write_key_chunks(fixture, pending_account, prepared_pubkey);
    let (program_result, account) = finalize_key(fixture, written_account);
    assert!(program_result.is_ok(), "{program_result:?}");
    account.expect("finalized falcon key account returned")
}

#[test]
fn rotate_key_replaces_prepared_pubkey_and_resets_nonce() {
    let old_prepared = prepared_pubkey_bytes();
    let new_prepared = prepared_pubkey_bytes();
    let fixture = make_fixture(42, old_prepared);

    let pending_account = begin_rotation(&fixture);
    assert_eq!(nonce(&pending_account), PENDING_NONCE);
    assert!(
        pending_account.data[PREPARED_PUBKEY_OFFSET..]
            .iter()
            .all(|byte| *byte == 0xff)
    );

    let account = finish_pending_key(&fixture, pending_account, new_prepared);
    assert_eq!(nonce(&account), 0);
    assert_eq!(&account.data[PREPARED_PUBKEY_OFFSET..], &new_prepared[..]);
}

#[test]
fn rotate_key_new_key_verifies_and_old_key_fails() {
    let (old_prepared, old_secret_key) = falcon_keypair();
    let (new_prepared, new_secret_key) = falcon_keypair();
    let fixture = make_fixture(42, old_prepared);

    let pending_account = begin_rotation(&fixture);
    let rotated_account = finish_pending_key(&fixture, pending_account, new_prepared);

    let old_key_verify = verify_ix(&fixture, &old_secret_key, 0);
    let old_key_result = fixture.mollusk.process_instruction(
        &old_key_verify,
        &[
            (fixture.authority, authority_account(1_000_000_000)),
            (fixture.falcon_key, rotated_account.clone()),
        ],
    );

    assert_eq!(
        old_key_result.program_result,
        SvmResult::Failure(ProgramError::Custom(8))
    );

    let new_key_verify = verify_ix(&fixture, &new_secret_key, 0);
    let new_key_result = fixture.mollusk.process_instruction(
        &new_key_verify,
        &[
            (fixture.authority, authority_account(1_000_000_000)),
            (fixture.falcon_key, rotated_account),
        ],
    );

    assert!(
        new_key_result.program_result.is_ok(),
        "{:?}",
        new_key_result.program_result
    );
}

#[test]
fn rotate_key_rejects_falcon_verification_while_pending() {
    let (old_prepared, old_secret_key) = falcon_keypair();
    let fixture = make_fixture(42, old_prepared);
    let pending_account = begin_rotation(&fixture);

    let verify = verify_ix(&fixture, &old_secret_key, 42);
    let result = fixture.mollusk.process_instruction(
        &verify,
        &[
            (fixture.authority, authority_account(1_000_000_000)),
            (fixture.falcon_key, pending_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(6))
    );
}

#[test]
fn rotate_key_requires_authority_signature() {
    let fixture = make_fixture(0, prepared_pubkey_bytes());
    let mut ix = rotate_ix(&fixture);
    ix.accounts[0].is_signer = false;

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, authority_account(1_000_000_000)),
            (fixture.falcon_key, fixture.falcon_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::MissingRequiredSignature)
    );
}

#[test]
fn rotate_key_rejects_malformed_prepared_pubkey_on_finalize() {
    let fixture = make_fixture(0, prepared_pubkey_bytes());
    let mut malformed = prepared_pubkey_bytes();
    malformed[0] = 0x01;
    malformed[1] = 0x30;
    let pending_account = begin_rotation(&fixture);
    let written_account = write_key_chunks(&fixture, pending_account, malformed);
    let (program_result, _) = finalize_key(&fixture, written_account);

    assert_eq!(program_result, SvmResult::Failure(ProgramError::Custom(7)));
}

#[test]
fn rotate_key_rejects_wrong_authority() {
    let fixture = make_fixture(0, prepared_pubkey_bytes());
    let wrong_authority = Pubkey::new_unique();
    let mut ix = rotate_ix(&fixture);
    ix.accounts[0].pubkey = wrong_authority;

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (wrong_authority, authority_account(1_000_000_000)),
            (fixture.falcon_key, fixture.falcon_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(6))
    );
}

#[test]
fn close_key_marks_closed_and_returns_lamports() {
    let fixture = make_fixture(0, prepared_pubkey_bytes());
    let authority_lamports = 1_000_000_000;
    let falcon_lamports = fixture.falcon_account.lamports;
    let ix = close_ix(&fixture);

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, authority_account(authority_lamports)),
            (fixture.falcon_key, fixture.falcon_account),
        ],
    );

    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    let (_, authority_account) = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| *key == fixture.authority)
        .unwrap();
    let (_, falcon_account) = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| *key == fixture.falcon_key)
        .unwrap();
    assert_eq!(
        authority_account.lamports,
        authority_lamports + falcon_lamports
    );
    assert_eq!(falcon_account.lamports, 0);
    assert_eq!(&falcon_account.data[..8], &CLOSED_DISCRIMINATOR);
}

#[test]
fn close_key_rejects_wrong_authority() {
    let fixture = make_fixture(0, prepared_pubkey_bytes());
    let wrong_authority = Pubkey::new_unique();
    let mut ix = close_ix(&fixture);
    ix.accounts[0].pubkey = wrong_authority;

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (wrong_authority, authority_account(1_000_000_000)),
            (fixture.falcon_key, fixture.falcon_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(6))
    );
}

#[test]
fn close_key_requires_authority_signature() {
    let fixture = make_fixture(0, prepared_pubkey_bytes());
    let mut ix = close_ix(&fixture);
    ix.accounts[0].is_signer = false;

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, authority_account(1_000_000_000)),
            (fixture.falcon_key, fixture.falcon_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::MissingRequiredSignature)
    );
}

#[test]
fn close_key_rejects_already_closed_account() {
    let mut fixture = make_fixture(0, prepared_pubkey_bytes());
    fixture.falcon_account.data[..8].copy_from_slice(&CLOSED_DISCRIMINATOR);
    let ix = close_ix(&fixture);

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, authority_account(1_000_000_000)),
            (fixture.falcon_key, fixture.falcon_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(12))
    );
}
