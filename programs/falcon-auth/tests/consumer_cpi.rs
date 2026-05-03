use {
    mollusk_svm::{
        Mollusk, program::keyed_account_for_system_program, result::ProgramResult as SvmResult,
    },
    pqcrypto_falcon::falcon512,
    pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _},
    solana_account::Account,
    solana_falcon512::{
        FALCON_512_PREPARED_PUBKEY_LEN, FALCON_512_PUBKEY_LEN, FALCON_512_SIGNATURE_LEN,
        Falcon512Pubkey,
    },
    solana_instruction::{AccountMeta, Instruction},
    solana_program::hash::hashv,
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
};

const TAG_INIT_COUNTER: u8 = 0;
const TAG_INCREMENT_WITH_FALCON: u8 = 1;
const FALCON_KEY_SEED: &[u8] = b"falcon-key";
const COUNTER_SEED: &[u8] = b"counter";
const FALCON_KEY_DISCRIMINATOR: [u8; 8] = *b"FALKYA01";
const FALCON_ACTION_MAGIC: [u8; 16] = *b"SOL_FALCON_ACT1!";
const COUNTER_DISCRIMINATOR: [u8; 8] = *b"EXCNTR01";
const VERSION_OFFSET: usize = 8;
const FALCON_AUTH_BUMP_OFFSET: usize = 9;
const FALCON_AUTH_AUTHORITY_OFFSET: usize = 10;
const FALCON_AUTH_NEXT_NONCE_OFFSET: usize = 42;
const FALCON_AUTH_PREPARED_PUBKEY_OFFSET: usize = 50;
const FALCON_KEY_ACCOUNT_LEN: usize = FALCON_AUTH_PREPARED_PUBKEY_OFFSET + 1024;
const COUNTER_VALUE_OFFSET: usize = 73;
const FALCON_ACTION_PAYLOAD_LEN: usize = 193;
const CONSUMER_INCREMENT_MAX_CU: u64 = 250_000;

struct Fixture {
    mollusk: Mollusk,
    consumer_program_id: Pubkey,
    falcon_auth_program_id: Pubkey,
    authority: Pubkey,
    falcon_key: Pubkey,
    counter: Pubkey,
    counter_bump: u8,
    falcon_account: Account,
    falcon_auth_program_account: Account,
    secret_key: falcon512::SecretKey,
}

fn make_fixture(next_nonce: u64) -> Fixture {
    let consumer_program_id = Pubkey::new_unique();
    let falcon_auth_program_id = Pubkey::new_unique();
    let mut mollusk = Mollusk::new(&consumer_program_id, "../../target/deploy/example_consumer");
    mollusk.add_program(&falcon_auth_program_id, "../../target/deploy/falcon_auth");

    let authority = Pubkey::new_unique();
    let (falcon_key, bump) = Pubkey::find_program_address(
        &[FALCON_KEY_SEED, authority.as_ref()],
        &falcon_auth_program_id,
    );
    let (counter, counter_bump) = Pubkey::find_program_address(
        &[
            COUNTER_SEED,
            authority.as_ref(),
            falcon_auth_program_id.as_ref(),
        ],
        &consumer_program_id,
    );
    let (prepared_pubkey, secret_key) = falcon_keypair();

    Fixture {
        mollusk,
        consumer_program_id,
        falcon_auth_program_id,
        authority,
        falcon_key,
        counter,
        counter_bump,
        falcon_account: falcon_account(
            falcon_auth_program_id,
            authority,
            bump,
            next_nonce,
            prepared_pubkey,
        ),
        falcon_auth_program_account: executable_program_account(),
        secret_key,
    }
}

fn falcon_keypair() -> ([u8; FALCON_512_PREPARED_PUBKEY_LEN], falcon512::SecretKey) {
    let (public_key, secret_key) = falcon512::keypair();
    let mut pk_bytes = [0u8; FALCON_512_PUBKEY_LEN];
    pk_bytes.copy_from_slice(public_key.as_bytes());
    let pubkey = Falcon512Pubkey::from(pk_bytes);
    (*pubkey.try_prepare_pubkey().unwrap().as_bytes(), secret_key)
}

fn falcon_account(
    program_id: Pubkey,
    authority: Pubkey,
    bump: u8,
    next_nonce: u64,
    prepared_pubkey: [u8; FALCON_512_PREPARED_PUBKEY_LEN],
) -> Account {
    let mut data = vec![0u8; FALCON_KEY_ACCOUNT_LEN];
    data[..8].copy_from_slice(&FALCON_KEY_DISCRIMINATOR);
    data[VERSION_OFFSET] = 1;
    data[FALCON_AUTH_BUMP_OFFSET] = bump;
    data[FALCON_AUTH_AUTHORITY_OFFSET..FALCON_AUTH_NEXT_NONCE_OFFSET]
        .copy_from_slice(authority.as_ref());
    data[FALCON_AUTH_NEXT_NONCE_OFFSET..FALCON_AUTH_PREPARED_PUBKEY_OFFSET]
        .copy_from_slice(&next_nonce.to_le_bytes());
    data[FALCON_AUTH_PREPARED_PUBKEY_OFFSET..].copy_from_slice(&prepared_pubkey);

    Account {
        lamports: 1_000_000_000,
        data,
        owner: program_id,
        executable: false,
        rent_epoch: 0,
    }
}

fn executable_program_account() -> Account {
    Account {
        lamports: 1_000_000_000,
        data: Vec::new(),
        owner: solana_sdk_ids::bpf_loader_upgradeable::id(),
        executable: true,
        rent_epoch: 0,
    }
}

fn empty_counter_account() -> Account {
    Account::new(0, 0, &solana_sdk_ids::system_program::id())
}

fn authority_account() -> Account {
    Account::new(1_000_000_000, 0, &solana_sdk_ids::system_program::id())
}

fn init_counter_ix(fixture: &Fixture) -> Instruction {
    Instruction::new_with_bytes(
        fixture.consumer_program_id,
        &[TAG_INIT_COUNTER, fixture.counter_bump],
        vec![
            AccountMeta::new(fixture.authority, true),
            AccountMeta::new(fixture.counter, false),
            AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
    )
}

fn consumer_ix(
    fixture: &Fixture,
    amount: u64,
    signed_amount: u64,
    nonce: u64,
    current_counter: u64,
) -> Instruction {
    let expires_slot = 100;
    let action_domain = counter_increment_domain();
    let action_hash = counter_increment_hash(
        &fixture.consumer_program_id,
        &fixture.counter,
        &fixture.authority,
        signed_amount,
        current_counter,
    );
    let payload = build_falcon_payload(
        fixture.falcon_auth_program_id,
        fixture.authority,
        fixture.falcon_key,
        nonce,
        expires_slot,
        &action_domain,
        &action_hash,
    );
    let signature = falcon_signature_bytes(&payload, &fixture.secret_key);

    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + FALCON_512_SIGNATURE_LEN);
    data.push(TAG_INCREMENT_WITH_FALCON);
    data.push(0);
    data.extend_from_slice(&nonce.to_le_bytes());
    data.extend_from_slice(&expires_slot.to_le_bytes());
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&signature);

    Instruction::new_with_bytes(
        fixture.consumer_program_id,
        &data,
        vec![
            AccountMeta::new_readonly(fixture.authority, false),
            AccountMeta::new(fixture.falcon_key, false),
            AccountMeta::new(fixture.counter, false),
            AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
        ],
    )
}

fn build_falcon_payload(
    falcon_auth_program_id: Pubkey,
    authority: Pubkey,
    falcon_key: Pubkey,
    nonce: u64,
    expires_slot: u64,
    action_domain: &[u8; 32],
    action_hash: &[u8; 32],
) -> [u8; FALCON_ACTION_PAYLOAD_LEN] {
    let mut out = [0u8; FALCON_ACTION_PAYLOAD_LEN];
    out[0..16].copy_from_slice(&FALCON_ACTION_MAGIC);
    out[16] = 0;
    out[17..49].copy_from_slice(falcon_auth_program_id.as_ref());
    out[49..81].copy_from_slice(authority.as_ref());
    out[81..113].copy_from_slice(falcon_key.as_ref());
    out[113..121].copy_from_slice(&nonce.to_le_bytes());
    out[121..129].copy_from_slice(&expires_slot.to_le_bytes());
    out[129..161].copy_from_slice(action_domain);
    out[161..193].copy_from_slice(action_hash);
    out
}

fn falcon_signature_bytes(
    payload: &[u8],
    secret_key: &falcon512::SecretKey,
) -> [u8; FALCON_512_SIGNATURE_LEN] {
    let signature = falcon512::detached_sign(payload, secret_key);
    let mut out = [0u8; FALCON_512_SIGNATURE_LEN];
    out[..signature.as_bytes().len()].copy_from_slice(signature.as_bytes());
    out
}

fn counter_increment_domain() -> [u8; 32] {
    hashv(&[b"example-consumer", b"counter.increment.v1"]).to_bytes()
}

fn counter_increment_hash(
    program_id: &Pubkey,
    counter: &Pubkey,
    authority: &Pubkey,
    amount: u64,
    current_counter: u64,
) -> [u8; 32] {
    let amount_bytes = amount.to_le_bytes();
    let current_counter_bytes = current_counter.to_le_bytes();
    hashv(&[
        b"example-counter-action-v1",
        program_id.as_ref(),
        counter.as_ref(),
        authority.as_ref(),
        &amount_bytes,
        &current_counter_bytes,
    ])
    .to_bytes()
}

fn counter_value(account: &Account) -> u64 {
    u64::from_le_bytes(
        account.data[COUNTER_VALUE_OFFSET..COUNTER_VALUE_OFFSET + 8]
            .try_into()
            .unwrap(),
    )
}

fn falcon_next_nonce(account: &Account) -> u64 {
    u64::from_le_bytes(
        account.data[FALCON_AUTH_NEXT_NONCE_OFFSET..FALCON_AUTH_PREPARED_PUBKEY_OFFSET]
            .try_into()
            .unwrap(),
    )
}

fn result_account(result: &mollusk_svm::result::InstructionResult, key: Pubkey) -> Account {
    result
        .resulting_accounts
        .iter()
        .find(|(account_key, _)| *account_key == key)
        .expect("result account exists")
        .1
        .clone()
}

fn init_counter(fixture: &Fixture) -> Account {
    let result = fixture.mollusk.process_instruction(
        &init_counter_ix(fixture),
        &[
            (fixture.authority, authority_account()),
            (fixture.counter, empty_counter_account()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            keyed_account_for_system_program(),
        ],
    );
    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    result_account(&result, fixture.counter)
}

fn process_consumer_ix(
    fixture: &Fixture,
    ix: &Instruction,
    counter_account: Account,
) -> mollusk_svm::result::InstructionResult {
    fixture.mollusk.process_instruction(
        ix,
        &[
            (fixture.authority, Account::default()),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (fixture.counter, counter_account),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
        ],
    )
}

#[test]
fn consumer_init_counter_creates_program_owned_state() {
    let fixture = make_fixture(0);
    let result = fixture.mollusk.process_instruction(
        &init_counter_ix(&fixture),
        &[
            (fixture.authority, authority_account()),
            (fixture.counter, empty_counter_account()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            keyed_account_for_system_program(),
        ],
    );

    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    let counter = result_account(&result, fixture.counter);
    assert_eq!(counter.owner, fixture.consumer_program_id);
    assert_eq!(&counter.data[..8], &COUNTER_DISCRIMINATOR);
    assert_eq!(counter_value(&counter), 0);
}

#[test]
fn consumer_cpi_increments_counter_after_falcon_auth() {
    let fixture = make_fixture(0);
    let counter_account = init_counter(&fixture);
    let ix = consumer_ix(&fixture, 7, 7, 0, 0);

    let result = process_consumer_ix(&fixture, &ix, counter_account);

    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    println!(
        "consumer increment via Falcon CPI CU: {}",
        result.compute_units_consumed
    );
    assert!(result.compute_units_consumed <= CONSUMER_INCREMENT_MAX_CU);
    let counter = result_account(&result, fixture.counter);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(counter_value(&counter), 7);
    assert_eq!(falcon_next_nonce(&falcon_key), 1);
}

#[test]
fn consumer_cpi_rejects_tampered_action_amount() {
    let fixture = make_fixture(0);
    let counter_account = init_counter(&fixture);
    let ix = consumer_ix(&fixture, 8, 7, 0, 0);

    let result = process_consumer_ix(&fixture, &ix, counter_account);

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(8))
    );
    let counter = result_account(&result, fixture.counter);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(counter_value(&counter), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn consumer_cpi_rejects_replayed_falcon_signature() {
    let fixture = make_fixture(0);
    let counter_account = init_counter(&fixture);
    let ix = consumer_ix(&fixture, 7, 7, 0, 0);
    let first = process_consumer_ix(&fixture, &ix, counter_account);
    assert!(first.program_result.is_ok(), "{:?}", first.program_result);

    let replay = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, Account::default()),
            (
                fixture.falcon_key,
                result_account(&first, fixture.falcon_key),
            ),
            (fixture.counter, result_account(&first, fixture.counter)),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
        ],
    );

    assert_eq!(
        replay.program_result,
        SvmResult::Failure(ProgramError::Custom(9))
    );
    let counter = result_account(&replay, fixture.counter);
    let falcon_key = result_account(&replay, fixture.falcon_key);
    assert_eq!(counter_value(&counter), 7);
    assert_eq!(falcon_next_nonce(&falcon_key), 1);
}

#[test]
fn consumer_cpi_rejects_wrong_falcon_auth_program() {
    let fixture = make_fixture(0);
    let counter_account = init_counter(&fixture);
    let mut ix = consumer_ix(&fixture, 7, 7, 0, 0);
    let wrong_program = Pubkey::new_unique();
    ix.accounts[3].pubkey = wrong_program;

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, Account::default()),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (fixture.counter, counter_account),
            (wrong_program, executable_program_account()),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(4))
    );
    let counter = result_account(&result, fixture.counter);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(counter_value(&counter), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn consumer_cpi_rejects_wrong_counter_pda() {
    let fixture = make_fixture(0);
    let counter_account = init_counter(&fixture);
    let wrong_counter = Pubkey::new_unique();
    let mut ix = consumer_ix(&fixture, 7, 7, 0, 0);
    ix.accounts[2].pubkey = wrong_counter;

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, Account::default()),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (wrong_counter, counter_account),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(3))
    );
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}
