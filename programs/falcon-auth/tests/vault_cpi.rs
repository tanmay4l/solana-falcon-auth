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

const TAG_INIT_VAULT: u8 = 0;
const TAG_DEPOSIT: u8 = 1;
const TAG_WITHDRAW_WITH_FALCON: u8 = 2;
const FALCON_KEY_SEED: &[u8] = b"falcon-key";
const VAULT_SEED: &[u8] = b"vault";
const FALCON_KEY_DISCRIMINATOR: [u8; 8] = *b"FALKYA02";
const FALCON_ACTION_MAGIC: [u8; 16] = *b"SOL_FALCON_ACT1!";
const VAULT_DISCRIMINATOR: [u8; 8] = *b"FALVLT01";
const VERSION_OFFSET: usize = 8;
const FALCON_AUTH_BUMP_OFFSET: usize = 9;
const FALCON_AUTH_CLUSTER_OFFSET: usize = 10;
const FALCON_AUTH_RESERVED_OFFSET: usize = 11;
const FALCON_AUTH_AUTHORITY_OFFSET: usize = 12;
const FALCON_AUTH_NEXT_NONCE_OFFSET: usize = 44;
const FALCON_AUTH_PREPARED_PUBKEY_OFFSET: usize = 52;
const FALCON_KEY_ACCOUNT_LEN: usize = FALCON_AUTH_PREPARED_PUBKEY_OFFSET + 1024;
const VAULT_WITHDRAW_COUNT_OFFSET: usize = 74;
const VAULT_ACCOUNT_LEN: usize = 82;
const FALCON_ACTION_PAYLOAD_LEN: usize = 193;
const VAULT_WITHDRAW_MAX_CU: u64 = 230_000;
const CLUSTER: u8 = 0;

struct Fixture {
    mollusk: Mollusk,
    vault_program_id: Pubkey,
    falcon_auth_program_id: Pubkey,
    authority: Pubkey,
    depositor: Pubkey,
    destination: Pubkey,
    falcon_key: Pubkey,
    vault: Pubkey,
    vault_bump: u8,
    falcon_account: Account,
    falcon_auth_program_account: Account,
    secret_key: falcon512::SecretKey,
}

fn make_fixture(next_nonce: u64) -> Fixture {
    let vault_program_id = Pubkey::new_unique();
    let falcon_auth_program_id = Pubkey::new_unique();
    let mut mollusk = Mollusk::new(&vault_program_id, "../../target/deploy/falcon_vault");
    mollusk.add_program(&falcon_auth_program_id, "../../target/deploy/falcon_auth");

    let authority = Pubkey::new_unique();
    let depositor = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let (falcon_key, bump) = Pubkey::find_program_address(
        &[FALCON_KEY_SEED, authority.as_ref()],
        &falcon_auth_program_id,
    );
    let (vault, vault_bump) = Pubkey::find_program_address(
        &[
            VAULT_SEED,
            authority.as_ref(),
            falcon_auth_program_id.as_ref(),
        ],
        &vault_program_id,
    );
    let (prepared_pubkey, secret_key) = falcon_keypair();

    Fixture {
        mollusk,
        vault_program_id,
        falcon_auth_program_id,
        authority,
        depositor,
        destination,
        falcon_key,
        vault,
        vault_bump,
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
    data[VERSION_OFFSET] = 2;
    data[FALCON_AUTH_BUMP_OFFSET] = bump;
    data[FALCON_AUTH_CLUSTER_OFFSET] = CLUSTER;
    data[FALCON_AUTH_RESERVED_OFFSET] = 0;
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

fn vault_account(
    program_id: Pubkey,
    authority: Pubkey,
    falcon_auth_program_id: Pubkey,
    bump: u8,
    lamports: u64,
    withdraw_count: u64,
) -> Account {
    let mut data = vec![0u8; VAULT_ACCOUNT_LEN];
    data[..8].copy_from_slice(&VAULT_DISCRIMINATOR);
    data[VERSION_OFFSET] = 1;
    data[9] = bump;
    data[10..42].copy_from_slice(authority.as_ref());
    data[42..74].copy_from_slice(falcon_auth_program_id.as_ref());
    data[VAULT_WITHDRAW_COUNT_OFFSET..VAULT_WITHDRAW_COUNT_OFFSET + 8]
        .copy_from_slice(&withdraw_count.to_le_bytes());
    Account {
        lamports,
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

fn empty_vault_account() -> Account {
    Account::new(0, 0, &solana_sdk_ids::system_program::id())
}

fn system_account(lamports: u64) -> Account {
    Account::new(lamports, 0, &solana_sdk_ids::system_program::id())
}

fn init_vault_ix(fixture: &Fixture) -> Instruction {
    Instruction::new_with_bytes(
        fixture.vault_program_id,
        &[TAG_INIT_VAULT, fixture.vault_bump],
        vec![
            AccountMeta::new(fixture.authority, true),
            AccountMeta::new(fixture.vault, false),
            AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
    )
}

fn deposit_ix(fixture: &Fixture, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(1 + 8);
    data.push(TAG_DEPOSIT);
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction::new_with_bytes(
        fixture.vault_program_id,
        &data,
        vec![
            AccountMeta::new(fixture.depositor, true),
            AccountMeta::new(fixture.vault, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
    )
}

fn withdraw_ix(
    fixture: &Fixture,
    lamports: u64,
    signed_lamports: u64,
    nonce: u64,
    withdraw_count: u64,
    destination: Pubkey,
    signed_destination: Pubkey,
) -> Instruction {
    let expires_slot = 100;
    let action_domain = vault_withdraw_domain();
    let action_hash = vault_withdraw_hash(
        &fixture.vault_program_id,
        &fixture.vault,
        &fixture.authority,
        &signed_destination,
        signed_lamports,
        withdraw_count,
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
    data.push(TAG_WITHDRAW_WITH_FALCON);
    data.push(CLUSTER);
    data.extend_from_slice(&nonce.to_le_bytes());
    data.extend_from_slice(&expires_slot.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&signature);

    Instruction::new_with_bytes(
        fixture.vault_program_id,
        &data,
        vec![
            AccountMeta::new_readonly(fixture.authority, false),
            AccountMeta::new(fixture.falcon_key, false),
            AccountMeta::new(fixture.vault, false),
            AccountMeta::new(destination, false),
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
    out[16] = CLUSTER;
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

fn vault_withdraw_domain() -> [u8; 32] {
    hashv(&[b"falcon-vault", b"withdraw.v1"]).to_bytes()
}

fn vault_withdraw_hash(
    program_id: &Pubkey,
    vault: &Pubkey,
    authority: &Pubkey,
    destination: &Pubkey,
    lamports: u64,
    withdraw_count: u64,
) -> [u8; 32] {
    let lamports_bytes = lamports.to_le_bytes();
    let withdraw_count_bytes = withdraw_count.to_le_bytes();
    hashv(&[
        b"falcon-vault-withdraw-v1",
        program_id.as_ref(),
        vault.as_ref(),
        authority.as_ref(),
        destination.as_ref(),
        &lamports_bytes,
        &withdraw_count_bytes,
    ])
    .to_bytes()
}

fn withdraw_count(account: &Account) -> u64 {
    u64::from_le_bytes(
        account.data[VAULT_WITHDRAW_COUNT_OFFSET..VAULT_WITHDRAW_COUNT_OFFSET + 8]
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

fn init_vault(fixture: &Fixture) -> Account {
    let result = fixture.mollusk.process_instruction(
        &init_vault_ix(fixture),
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.vault, empty_vault_account()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            keyed_account_for_system_program(),
        ],
    );
    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    result_account(&result, fixture.vault)
}

fn deposit_to_vault(fixture: &Fixture, vault_account: Account, lamports: u64) -> Account {
    let result = fixture.mollusk.process_instruction(
        &deposit_ix(fixture, lamports),
        &[
            (fixture.depositor, system_account(1_000_000_000)),
            (fixture.vault, vault_account),
            keyed_account_for_system_program(),
        ],
    );
    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    result_account(&result, fixture.vault)
}

fn process_withdraw_ix(
    fixture: &Fixture,
    ix: &Instruction,
    vault_account: Account,
    destination_account: Account,
) -> mollusk_svm::result::InstructionResult {
    fixture.mollusk.process_instruction(
        ix,
        &[
            (ix.accounts[0].pubkey, Account::default()),
            (ix.accounts[1].pubkey, fixture.falcon_account.clone()),
            (ix.accounts[2].pubkey, vault_account),
            (ix.accounts[3].pubkey, destination_account),
            (
                ix.accounts[4].pubkey,
                fixture.falcon_auth_program_account.clone(),
            ),
        ],
    )
}

#[test]
fn vault_init_creates_program_owned_state() {
    let fixture = make_fixture(0);
    let result = fixture.mollusk.process_instruction(
        &init_vault_ix(&fixture),
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.vault, empty_vault_account()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            keyed_account_for_system_program(),
        ],
    );

    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    let vault = result_account(&result, fixture.vault);
    assert_eq!(vault.owner, fixture.vault_program_id);
    assert_eq!(&vault.data[..8], &VAULT_DISCRIMINATOR);
    assert_eq!(withdraw_count(&vault), 0);
}

#[test]
fn vault_init_rejects_wrong_vault_pda() {
    let fixture = make_fixture(0);
    let wrong_vault = Pubkey::new_unique();
    let mut ix = init_vault_ix(&fixture);
    ix.accounts[1].pubkey = wrong_vault;

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (wrong_vault, empty_vault_account()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            keyed_account_for_system_program(),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(3))
    );
}

#[test]
fn vault_deposit_moves_lamports_into_vault() {
    let fixture = make_fixture(0);
    let vault = init_vault(&fixture);
    let before_lamports = vault.lamports;

    let vault = deposit_to_vault(&fixture, vault, 50_000);

    assert_eq!(vault.lamports, before_lamports + 50_000);
    assert_eq!(withdraw_count(&vault), 0);
}

#[test]
fn vault_deposit_requires_depositor_signature() {
    let fixture = make_fixture(0);
    let vault = init_vault(&fixture);
    let mut ix = deposit_ix(&fixture, 50_000);
    ix.accounts[0].is_signer = false;

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.depositor, system_account(1_000_000_000)),
            (fixture.vault, vault),
            keyed_account_for_system_program(),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::MissingRequiredSignature)
    );
}

#[test]
fn vault_withdraw_moves_lamports_after_falcon_auth() {
    let fixture = make_fixture(0);
    let vault = deposit_to_vault(&fixture, init_vault(&fixture), 100_000);
    let before_vault_lamports = vault.lamports;
    let ix = withdraw_ix(
        &fixture,
        40_000,
        40_000,
        0,
        0,
        fixture.destination,
        fixture.destination,
    );

    let result = process_withdraw_ix(&fixture, &ix, vault, system_account(7));

    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    println!(
        "vault withdraw via Falcon CPI CU: {}",
        result.compute_units_consumed
    );
    assert!(result.compute_units_consumed <= VAULT_WITHDRAW_MAX_CU);
    let vault = result_account(&result, fixture.vault);
    let destination = result_account(&result, fixture.destination);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(vault.lamports, before_vault_lamports - 40_000);
    assert_eq!(destination.lamports, 40_007);
    assert_eq!(withdraw_count(&vault), 1);
    assert_eq!(falcon_next_nonce(&falcon_key), 1);
}

#[test]
fn vault_withdraw_supports_multiple_sequential_withdrawals() {
    let fixture = make_fixture(0);
    let vault = deposit_to_vault(&fixture, init_vault(&fixture), 140_000);
    let first_ix = withdraw_ix(
        &fixture,
        40_000,
        40_000,
        0,
        0,
        fixture.destination,
        fixture.destination,
    );
    let first = process_withdraw_ix(&fixture, &first_ix, vault, system_account(7));
    assert!(first.program_result.is_ok(), "{:?}", first.program_result);

    let second_ix = withdraw_ix(
        &fixture,
        30_000,
        30_000,
        1,
        1,
        fixture.destination,
        fixture.destination,
    );
    let second = fixture.mollusk.process_instruction(
        &second_ix,
        &[
            (fixture.authority, Account::default()),
            (
                fixture.falcon_key,
                result_account(&first, fixture.falcon_key),
            ),
            (fixture.vault, result_account(&first, fixture.vault)),
            (
                fixture.destination,
                result_account(&first, fixture.destination),
            ),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
        ],
    );

    assert!(second.program_result.is_ok(), "{:?}", second.program_result);
    let vault = result_account(&second, fixture.vault);
    let destination = result_account(&second, fixture.destination);
    let falcon_key = result_account(&second, fixture.falcon_key);
    assert_eq!(destination.lamports, 70_007);
    assert_eq!(withdraw_count(&vault), 2);
    assert_eq!(falcon_next_nonce(&falcon_key), 2);
}

#[test]
fn vault_withdraw_rejects_zero_amount() {
    let fixture = make_fixture(0);
    let vault = deposit_to_vault(&fixture, init_vault(&fixture), 100_000);
    let ix = withdraw_ix(
        &fixture,
        0,
        0,
        0,
        0,
        fixture.destination,
        fixture.destination,
    );

    let result = process_withdraw_ix(&fixture, &ix, vault, system_account(7));

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(1))
    );
    let vault = result_account(&result, fixture.vault);
    let destination = result_account(&result, fixture.destination);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(destination.lamports, 7);
    assert_eq!(withdraw_count(&vault), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn vault_withdraw_rejects_tampered_lamports() {
    let fixture = make_fixture(0);
    let vault = deposit_to_vault(&fixture, init_vault(&fixture), 100_000);
    let before_vault_lamports = vault.lamports;
    let ix = withdraw_ix(
        &fixture,
        50_000,
        40_000,
        0,
        0,
        fixture.destination,
        fixture.destination,
    );

    let result = process_withdraw_ix(&fixture, &ix, vault, system_account(7));

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(8))
    );
    let vault = result_account(&result, fixture.vault);
    let destination = result_account(&result, fixture.destination);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(vault.lamports, before_vault_lamports);
    assert_eq!(destination.lamports, 7);
    assert_eq!(withdraw_count(&vault), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn vault_withdraw_rejects_stale_withdraw_count_signature() {
    let fixture = make_fixture(0);
    let vault = deposit_to_vault(&fixture, init_vault(&fixture), 100_000);
    let mut stale_vault = vault.clone();
    stale_vault.data[VAULT_WITHDRAW_COUNT_OFFSET..VAULT_WITHDRAW_COUNT_OFFSET + 8]
        .copy_from_slice(&1u64.to_le_bytes());
    let ix = withdraw_ix(
        &fixture,
        40_000,
        40_000,
        0,
        0,
        fixture.destination,
        fixture.destination,
    );

    let result = process_withdraw_ix(&fixture, &ix, stale_vault, system_account(7));

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(8))
    );
    let vault = result_account(&result, fixture.vault);
    let destination = result_account(&result, fixture.destination);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(destination.lamports, 7);
    assert_eq!(withdraw_count(&vault), 1);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn vault_withdraw_rejects_unregistered_cluster() {
    let fixture = make_fixture(0);
    let vault = deposit_to_vault(&fixture, init_vault(&fixture), 100_000);
    let mut ix = withdraw_ix(
        &fixture,
        40_000,
        40_000,
        0,
        0,
        fixture.destination,
        fixture.destination,
    );
    ix.data[1] = 1;

    let result = process_withdraw_ix(&fixture, &ix, vault, system_account(7));

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(13))
    );
    let vault = result_account(&result, fixture.vault);
    let destination = result_account(&result, fixture.destination);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(destination.lamports, 7);
    assert_eq!(withdraw_count(&vault), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn vault_withdraw_rejects_wrong_authority_account() {
    let fixture = make_fixture(0);
    let vault = deposit_to_vault(&fixture, init_vault(&fixture), 100_000);
    let wrong_authority = Pubkey::new_unique();
    let mut ix = withdraw_ix(
        &fixture,
        40_000,
        40_000,
        0,
        0,
        fixture.destination,
        fixture.destination,
    );
    ix.accounts[0].pubkey = wrong_authority;

    let result = process_withdraw_ix(&fixture, &ix, vault, system_account(7));

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(3))
    );
    let vault = result_account(&result, fixture.vault);
    let destination = result_account(&result, fixture.destination);
    assert_eq!(destination.lamports, 7);
    assert_eq!(withdraw_count(&vault), 0);
}

#[test]
fn vault_withdraw_rejects_wrong_falcon_key_pda() {
    let fixture = make_fixture(0);
    let vault = deposit_to_vault(&fixture, init_vault(&fixture), 100_000);
    let wrong_falcon_key = Pubkey::new_unique();
    let mut ix = withdraw_ix(
        &fixture,
        40_000,
        40_000,
        0,
        0,
        fixture.destination,
        fixture.destination,
    );
    ix.accounts[1].pubkey = wrong_falcon_key;

    let result = process_withdraw_ix(&fixture, &ix, vault, system_account(7));

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(3))
    );
    let vault = result_account(&result, fixture.vault);
    let destination = result_account(&result, fixture.destination);
    let falcon_key = result_account(&result, wrong_falcon_key);
    assert_eq!(destination.lamports, 7);
    assert_eq!(withdraw_count(&vault), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn vault_withdraw_requires_writable_destination() {
    let fixture = make_fixture(0);
    let vault = deposit_to_vault(&fixture, init_vault(&fixture), 100_000);
    let mut ix = withdraw_ix(
        &fixture,
        40_000,
        40_000,
        0,
        0,
        fixture.destination,
        fixture.destination,
    );
    ix.accounts[3].is_writable = false;

    let result = process_withdraw_ix(&fixture, &ix, vault, system_account(7));

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::InvalidAccountData)
    );
    let vault = result_account(&result, fixture.vault);
    let destination = result_account(&result, fixture.destination);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(destination.lamports, 7);
    assert_eq!(withdraw_count(&vault), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn vault_withdraw_rejects_tampered_destination() {
    let fixture = make_fixture(0);
    let vault = deposit_to_vault(&fixture, init_vault(&fixture), 100_000);
    let wrong_destination = Pubkey::new_unique();
    let ix = withdraw_ix(
        &fixture,
        40_000,
        40_000,
        0,
        0,
        wrong_destination,
        fixture.destination,
    );

    let result = process_withdraw_ix(&fixture, &ix, vault, system_account(7));

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(8))
    );
    let vault = result_account(&result, fixture.vault);
    let destination = result_account(&result, wrong_destination);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(destination.lamports, 7);
    assert_eq!(withdraw_count(&vault), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn vault_withdraw_rejects_replayed_falcon_signature() {
    let fixture = make_fixture(0);
    let vault = deposit_to_vault(&fixture, init_vault(&fixture), 100_000);
    let ix = withdraw_ix(
        &fixture,
        40_000,
        40_000,
        0,
        0,
        fixture.destination,
        fixture.destination,
    );
    let first = process_withdraw_ix(&fixture, &ix, vault, system_account(7));
    assert!(first.program_result.is_ok(), "{:?}", first.program_result);

    let replay = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, Account::default()),
            (
                fixture.falcon_key,
                result_account(&first, fixture.falcon_key),
            ),
            (fixture.vault, result_account(&first, fixture.vault)),
            (
                fixture.destination,
                result_account(&first, fixture.destination),
            ),
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
    let vault = result_account(&replay, fixture.vault);
    let destination = result_account(&replay, fixture.destination);
    let falcon_key = result_account(&replay, fixture.falcon_key);
    assert_eq!(destination.lamports, 40_007);
    assert_eq!(withdraw_count(&vault), 1);
    assert_eq!(falcon_next_nonce(&falcon_key), 1);
}

#[test]
fn vault_withdraw_rejects_wrong_falcon_auth_program() {
    let fixture = make_fixture(0);
    let vault = deposit_to_vault(&fixture, init_vault(&fixture), 100_000);
    let mut ix = withdraw_ix(
        &fixture,
        40_000,
        40_000,
        0,
        0,
        fixture.destination,
        fixture.destination,
    );
    let wrong_program = Pubkey::new_unique();
    ix.accounts[4].pubkey = wrong_program;

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, Account::default()),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (fixture.vault, vault),
            (fixture.destination, system_account(7)),
            (wrong_program, executable_program_account()),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(4))
    );
    let vault = result_account(&result, fixture.vault);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(withdraw_count(&vault), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn vault_withdraw_rejects_wrong_vault_pda() {
    let fixture = make_fixture(0);
    let vault = deposit_to_vault(&fixture, init_vault(&fixture), 100_000);
    let wrong_vault = Pubkey::new_unique();
    let mut ix = withdraw_ix(
        &fixture,
        40_000,
        40_000,
        0,
        0,
        fixture.destination,
        fixture.destination,
    );
    ix.accounts[2].pubkey = wrong_vault;

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, Account::default()),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (wrong_vault, vault),
            (fixture.destination, system_account(7)),
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

#[test]
fn vault_withdraw_rejects_rent_unsafe_withdrawal() {
    let fixture = make_fixture(0);
    let vault = deposit_to_vault(&fixture, init_vault(&fixture), 10_000);
    let ix = withdraw_ix(
        &fixture,
        10_001,
        10_001,
        0,
        0,
        fixture.destination,
        fixture.destination,
    );

    let result = process_withdraw_ix(&fixture, &ix, vault, system_account(7));

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(6))
    );
    let vault = result_account(&result, fixture.vault);
    let destination = result_account(&result, fixture.destination);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(destination.lamports, 7);
    assert_eq!(withdraw_count(&vault), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn vault_deposit_rejects_uninitialized_vault() {
    let fixture = make_fixture(0);
    let result = fixture.mollusk.process_instruction(
        &deposit_ix(&fixture, 10_000),
        &[
            (fixture.depositor, system_account(1_000_000_000)),
            (fixture.vault, empty_vault_account()),
            keyed_account_for_system_program(),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(2))
    );
}

#[test]
fn vault_validation_rejects_wrong_stored_authority() {
    let fixture = make_fixture(0);
    let vault = vault_account(
        fixture.vault_program_id,
        Pubkey::new_unique(),
        fixture.falcon_auth_program_id,
        fixture.vault_bump,
        1_000_000,
        0,
    );
    let ix = withdraw_ix(
        &fixture,
        40_000,
        40_000,
        0,
        0,
        fixture.destination,
        fixture.destination,
    );

    let result = process_withdraw_ix(&fixture, &ix, vault, system_account(7));

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(3))
    );
}
