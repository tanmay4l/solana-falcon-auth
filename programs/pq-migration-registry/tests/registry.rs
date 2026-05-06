use {
    mollusk_svm::{
        Mollusk, program::keyed_account_for_system_program, result::ProgramResult as SvmResult,
    },
    solana_account::Account,
    solana_instruction::{AccountMeta, Instruction},
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
};

const TAG_BIND: u8 = 0;
const VERSION: u8 = 1;
const REGISTRY_SEED: &[u8] = b"pq-migrate";
const SMART_ACCOUNT_SEED: &[u8] = b"pq-smart";
const REGISTRY_DISCRIMINATOR: [u8; 8] = *b"PQREG001";
const SMART_ACCOUNT_DISCRIMINATOR: [u8; 8] = *b"PQSMRT01";
const REGISTRY_VERSION_OFFSET: usize = 8;
const REGISTRY_BUMP_OFFSET: usize = 9;
const REGISTRY_LEGACY_WALLET_OFFSET: usize = 12;
const REGISTRY_SMART_PROGRAM_OFFSET: usize = 44;
const REGISTRY_SMART_ACCOUNT_OFFSET: usize = 76;
const REGISTRY_PQ_QUORUM_PROGRAM_OFFSET: usize = 108;
const REGISTRY_QUORUM_OFFSET: usize = 140;
const REGISTRY_ACCOUNT_LEN: usize = 172;
const SMART_VERSION_OFFSET: usize = 8;
const SMART_BUMP_OFFSET: usize = 9;
const SMART_AUTHORITY_OFFSET: usize = 12;
const SMART_PQ_QUORUM_PROGRAM_OFFSET: usize = 44;
const SMART_QUORUM_OFFSET: usize = 76;
const SMART_SPEND_COUNT_OFFSET: usize = 108;
const SMART_ACCOUNT_LEN: usize = 116;

struct Fixture {
    mollusk: Mollusk,
    registry_program: Pubkey,
    legacy_wallet: Pubkey,
    registry: Pubkey,
    registry_bump: u8,
    smart_program: Pubkey,
    smart_account: Pubkey,
    smart_bump: u8,
    quorum_program: Pubkey,
    quorum: Pubkey,
}

fn make_fixture() -> Fixture {
    let registry_program = Pubkey::new_unique();
    let mollusk = Mollusk::new(
        &registry_program,
        "../../target/deploy/pq_migration_registry",
    );
    let legacy_wallet = Pubkey::new_unique();
    let smart_program = Pubkey::new_unique();
    let quorum_program = Pubkey::new_unique();
    let quorum = Pubkey::new_unique();
    let (registry, registry_bump) =
        Pubkey::find_program_address(&[REGISTRY_SEED, legacy_wallet.as_ref()], &registry_program);
    let (smart_account, smart_bump) = Pubkey::find_program_address(
        &[
            SMART_ACCOUNT_SEED,
            legacy_wallet.as_ref(),
            quorum_program.as_ref(),
            quorum.as_ref(),
        ],
        &smart_program,
    );

    Fixture {
        mollusk,
        registry_program,
        legacy_wallet,
        registry,
        registry_bump,
        smart_program,
        smart_account,
        smart_bump,
        quorum_program,
        quorum,
    }
}

fn bind_ix(fixture: &Fixture) -> Instruction {
    Instruction::new_with_bytes(
        fixture.registry_program,
        &[TAG_BIND, fixture.registry_bump],
        vec![
            AccountMeta::new(fixture.legacy_wallet, true),
            AccountMeta::new(fixture.registry, false),
            AccountMeta::new_readonly(fixture.smart_account, false),
            AccountMeta::new_readonly(fixture.smart_program, false),
            AccountMeta::new_readonly(fixture.quorum_program, false),
            AccountMeta::new_readonly(fixture.quorum, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
    )
}

fn bind_accounts(fixture: &Fixture, registry_account: Account) -> Vec<(Pubkey, Account)> {
    vec![
        (
            fixture.legacy_wallet,
            Account::new(1_000_000_000, 0, &solana_sdk_ids::system_program::id()),
        ),
        (fixture.registry, registry_account),
        (
            fixture.smart_account,
            smart_account(
                fixture.smart_program,
                fixture.smart_bump,
                fixture.legacy_wallet,
                fixture.quorum_program,
                fixture.quorum,
            ),
        ),
        (fixture.smart_program, executable_program_account()),
        (fixture.quorum_program, executable_program_account()),
        (
            fixture.quorum,
            Account::new(1_000_000, 0, &fixture.quorum_program),
        ),
        keyed_account_for_system_program(),
    ]
}

fn smart_account(
    owner: Pubkey,
    bump: u8,
    authority: Pubkey,
    quorum_program: Pubkey,
    quorum: Pubkey,
) -> Account {
    let mut data = vec![0u8; SMART_ACCOUNT_LEN];
    data[..8].copy_from_slice(&SMART_ACCOUNT_DISCRIMINATOR);
    data[SMART_VERSION_OFFSET] = VERSION;
    data[SMART_BUMP_OFFSET] = bump;
    data[SMART_AUTHORITY_OFFSET..SMART_PQ_QUORUM_PROGRAM_OFFSET]
        .copy_from_slice(authority.as_ref());
    data[SMART_PQ_QUORUM_PROGRAM_OFFSET..SMART_QUORUM_OFFSET]
        .copy_from_slice(quorum_program.as_ref());
    data[SMART_QUORUM_OFFSET..SMART_SPEND_COUNT_OFFSET].copy_from_slice(quorum.as_ref());
    Account {
        lamports: 1_000_000,
        data,
        owner,
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

fn empty_registry_account() -> Account {
    Account::new(0, 0, &solana_sdk_ids::system_program::id())
}

fn registry_account_for(fixture: &Fixture, smart_account: Pubkey) -> Account {
    let mut data = vec![0u8; REGISTRY_ACCOUNT_LEN];
    data[..8].copy_from_slice(&REGISTRY_DISCRIMINATOR);
    data[REGISTRY_VERSION_OFFSET] = VERSION;
    data[REGISTRY_BUMP_OFFSET] = fixture.registry_bump;
    data[REGISTRY_LEGACY_WALLET_OFFSET..REGISTRY_SMART_PROGRAM_OFFSET]
        .copy_from_slice(fixture.legacy_wallet.as_ref());
    data[REGISTRY_SMART_PROGRAM_OFFSET..REGISTRY_SMART_ACCOUNT_OFFSET]
        .copy_from_slice(fixture.smart_program.as_ref());
    data[REGISTRY_SMART_ACCOUNT_OFFSET..REGISTRY_PQ_QUORUM_PROGRAM_OFFSET]
        .copy_from_slice(smart_account.as_ref());
    data[REGISTRY_PQ_QUORUM_PROGRAM_OFFSET..REGISTRY_QUORUM_OFFSET]
        .copy_from_slice(fixture.quorum_program.as_ref());
    data[REGISTRY_QUORUM_OFFSET..REGISTRY_ACCOUNT_LEN].copy_from_slice(fixture.quorum.as_ref());
    Account {
        lamports: 1_000_000,
        data,
        owner: fixture.registry_program,
        executable: false,
        rent_epoch: 0,
    }
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

#[test]
fn bind_creates_wallet_to_pq_smart_account_registry() {
    let fixture = make_fixture();
    let result = fixture.mollusk.process_instruction(
        &bind_ix(&fixture),
        &bind_accounts(&fixture, empty_registry_account()),
    );

    assert_eq!(result.program_result, SvmResult::Success);
    let registry = result_account(&result, fixture.registry);
    assert_eq!(registry.owner, fixture.registry_program);
    assert_eq!(registry.data.len(), REGISTRY_ACCOUNT_LEN);
    assert_eq!(&registry.data[..8], &REGISTRY_DISCRIMINATOR);
    assert_eq!(registry.data[REGISTRY_VERSION_OFFSET], VERSION);
    assert_eq!(registry.data[REGISTRY_BUMP_OFFSET], fixture.registry_bump);
    assert_eq!(
        &registry.data[REGISTRY_LEGACY_WALLET_OFFSET..REGISTRY_SMART_PROGRAM_OFFSET],
        fixture.legacy_wallet.as_ref()
    );
    assert_eq!(
        &registry.data[REGISTRY_SMART_PROGRAM_OFFSET..REGISTRY_SMART_ACCOUNT_OFFSET],
        fixture.smart_program.as_ref()
    );
    assert_eq!(
        &registry.data[REGISTRY_SMART_ACCOUNT_OFFSET..REGISTRY_PQ_QUORUM_PROGRAM_OFFSET],
        fixture.smart_account.as_ref()
    );
    assert_eq!(
        &registry.data[REGISTRY_PQ_QUORUM_PROGRAM_OFFSET..REGISTRY_QUORUM_OFFSET],
        fixture.quorum_program.as_ref()
    );
    assert_eq!(
        &registry.data[REGISTRY_QUORUM_OFFSET..REGISTRY_ACCOUNT_LEN],
        fixture.quorum.as_ref()
    );
}

#[test]
fn bind_requires_legacy_wallet_signature() {
    let fixture = make_fixture();
    let mut ix = bind_ix(&fixture);
    ix.accounts[0].is_signer = false;
    let result = fixture
        .mollusk
        .process_instruction(&ix, &bind_accounts(&fixture, empty_registry_account()));

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::MissingRequiredSignature)
    );
}

#[test]
fn bind_rejects_wrong_registry_pda() {
    let fixture = make_fixture();
    let wrong_registry = Pubkey::new_unique();
    let mut ix = bind_ix(&fixture);
    ix.accounts[1].pubkey = wrong_registry;
    let mut accounts = bind_accounts(&fixture, empty_registry_account());
    accounts[1].0 = wrong_registry;

    let result = fixture.mollusk.process_instruction(&ix, &accounts);

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(4))
    );
}

#[test]
fn bind_rejects_smart_account_not_owned_by_smart_program() {
    let fixture = make_fixture();
    let mut accounts = bind_accounts(&fixture, empty_registry_account());
    accounts[2].1.owner = Pubkey::new_unique();
    let result = fixture
        .mollusk
        .process_instruction(&bind_ix(&fixture), &accounts);

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(2))
    );
}

#[test]
fn bind_rejects_smart_account_for_different_legacy_wallet() {
    let fixture = make_fixture();
    let mut accounts = bind_accounts(&fixture, empty_registry_account());
    accounts[2].1 = smart_account(
        fixture.smart_program,
        fixture.smart_bump,
        Pubkey::new_unique(),
        fixture.quorum_program,
        fixture.quorum,
    );
    let result = fixture
        .mollusk
        .process_instruction(&bind_ix(&fixture), &accounts);

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(5))
    );
}

#[test]
fn bind_updates_existing_registry_for_same_wallet() {
    let fixture = make_fixture();
    let old_smart_account = Pubkey::new_unique();
    let result = fixture.mollusk.process_instruction(
        &bind_ix(&fixture),
        &bind_accounts(&fixture, registry_account_for(&fixture, old_smart_account)),
    );

    assert_eq!(result.program_result, SvmResult::Success);
    let registry = result_account(&result, fixture.registry);
    assert_eq!(
        &registry.data[REGISTRY_SMART_ACCOUNT_OFFSET..REGISTRY_PQ_QUORUM_PROGRAM_OFFSET],
        fixture.smart_account.as_ref()
    );
}

#[test]
fn bind_rejects_existing_registry_with_wrong_stored_bump() {
    let fixture = make_fixture();
    let mut existing_registry = registry_account_for(&fixture, fixture.smart_account);
    existing_registry.data[REGISTRY_BUMP_OFFSET] = fixture.registry_bump.wrapping_sub(1);

    let result = fixture.mollusk.process_instruction(
        &bind_ix(&fixture),
        &bind_accounts(&fixture, existing_registry),
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(3))
    );
}
