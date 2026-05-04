use {
    mollusk_svm::{
        Mollusk, program::keyed_account_for_system_program, result::ProgramResult as SvmResult,
    },
    pqcrypto_falcon::falcon512,
    pqcrypto_traits::sign::PublicKey as _,
    solana_account::Account,
    solana_falcon512::{FALCON_512_PREPARED_PUBKEY_LEN, FALCON_512_PUBKEY_LEN, Falcon512Pubkey},
    solana_instruction::{AccountMeta, Instruction},
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
};

const TAG_REGISTER_KEY: u8 = 0;
const TAG_WRITE_KEY_CHUNK: u8 = 4;
const TAG_FINALIZE_KEY: u8 = 5;
const FALCON_KEY_SEED: &[u8] = b"falcon-key";
const FALCON_KEY_DISCRIMINATOR: [u8; 8] = *b"FALKYA02";
const PENDING_NONCE: u64 = u64::MAX;
const VERSION_OFFSET: usize = 8;
const BUMP_OFFSET: usize = 9;
const CLUSTER_OFFSET: usize = 10;
const RESERVED_OFFSET: usize = 11;
const AUTHORITY_OFFSET: usize = 12;
const NEXT_NONCE_OFFSET: usize = 44;
const PREPARED_PUBKEY_OFFSET: usize = 52;
const FALCON_KEY_ACCOUNT_LEN: usize = PREPARED_PUBKEY_OFFSET + 1024;
const CLUSTER: u8 = 0;

fn make_mollusk() -> (Mollusk, Pubkey) {
    let program_id = Pubkey::new_unique();
    (
        Mollusk::new(&program_id, "../../target/deploy/falcon_auth"),
        program_id,
    )
}

fn prepared_pubkey_bytes() -> [u8; FALCON_512_PREPARED_PUBKEY_LEN] {
    let (pk, _) = falcon512::keypair();
    let mut bytes = [0u8; FALCON_512_PUBKEY_LEN];
    bytes.copy_from_slice(pk.as_bytes());
    let pubkey = Falcon512Pubkey::from(bytes);
    *pubkey.try_prepare_pubkey().unwrap().as_bytes()
}

fn register_ix(program_id: Pubkey, authority: Pubkey, falcon_key: Pubkey, bump: u8) -> Instruction {
    Instruction::new_with_bytes(
        program_id,
        &[TAG_REGISTER_KEY, bump, CLUSTER],
        vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(falcon_key, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
    )
}

fn write_chunk_ix(
    program_id: Pubkey,
    authority: Pubkey,
    falcon_key: Pubkey,
    offset: u16,
    chunk: &[u8],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 2 + chunk.len());
    data.push(TAG_WRITE_KEY_CHUNK);
    data.extend_from_slice(&offset.to_le_bytes());
    data.extend_from_slice(chunk);

    Instruction::new_with_bytes(
        program_id,
        &data,
        vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(falcon_key, false),
        ],
    )
}

fn finalize_ix(program_id: Pubkey, authority: Pubkey, falcon_key: Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        program_id,
        &[TAG_FINALIZE_KEY],
        vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(falcon_key, false),
        ],
    )
}

fn system_account(lamports: u64) -> Account {
    Account::new(lamports, 0, &solana_sdk_ids::system_program::id())
}

fn init_key_account(
    mollusk: &Mollusk,
    program_id: Pubkey,
    authority: Pubkey,
    falcon_key: Pubkey,
    bump: u8,
) -> Account {
    let result = mollusk.process_instruction(
        &register_ix(program_id, authority, falcon_key, bump),
        &[
            (authority, system_account(1_000_000_000)),
            (falcon_key, system_account(0)),
            keyed_account_for_system_program(),
        ],
    );
    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    result
        .resulting_accounts
        .iter()
        .find(|(key, _)| *key == falcon_key)
        .expect("falcon key account returned")
        .1
        .clone()
}

fn write_key_chunks(
    mollusk: &Mollusk,
    program_id: Pubkey,
    authority: Pubkey,
    falcon_key: Pubkey,
    pending_account: Account,
    prepared_pubkey: [u8; FALCON_512_PREPARED_PUBKEY_LEN],
) -> Account {
    let first = mollusk.process_instruction(
        &write_chunk_ix(
            program_id,
            authority,
            falcon_key,
            0,
            &prepared_pubkey[..512],
        ),
        &[
            (authority, system_account(1_000_000_000)),
            (falcon_key, pending_account),
        ],
    );
    assert!(first.program_result.is_ok(), "{:?}", first.program_result);
    let half_written = first
        .resulting_accounts
        .iter()
        .find(|(key, _)| *key == falcon_key)
        .unwrap()
        .1
        .clone();

    let second = mollusk.process_instruction(
        &write_chunk_ix(
            program_id,
            authority,
            falcon_key,
            512,
            &prepared_pubkey[512..],
        ),
        &[
            (authority, system_account(1_000_000_000)),
            (falcon_key, half_written),
        ],
    );
    assert!(second.program_result.is_ok(), "{:?}", second.program_result);
    second
        .resulting_accounts
        .iter()
        .find(|(key, _)| *key == falcon_key)
        .unwrap()
        .1
        .clone()
}

fn finalize_key_account(
    mollusk: &Mollusk,
    program_id: Pubkey,
    authority: Pubkey,
    falcon_key: Pubkey,
    written_account: Account,
) -> (SvmResult, Option<Account>) {
    let result = mollusk.process_instruction(
        &finalize_ix(program_id, authority, falcon_key),
        &[
            (authority, system_account(1_000_000_000)),
            (falcon_key, written_account),
        ],
    );
    let account = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| *key == falcon_key)
        .map(|(_, account)| account.clone());
    (result.program_result, account)
}

#[test]
fn register_key_stores_prepared_pubkey_state() {
    let (mollusk, program_id) = make_mollusk();
    let authority = Pubkey::new_unique();
    let (falcon_key, bump) =
        Pubkey::find_program_address(&[FALCON_KEY_SEED, authority.as_ref()], &program_id);
    let expected_prepared = prepared_pubkey_bytes();

    let pending_account = init_key_account(&mollusk, program_id, authority, falcon_key, bump);
    assert_eq!(
        u64::from_le_bytes(
            pending_account.data[NEXT_NONCE_OFFSET..PREPARED_PUBKEY_OFFSET]
                .try_into()
                .unwrap()
        ),
        PENDING_NONCE
    );

    let written_account = write_key_chunks(
        &mollusk,
        program_id,
        authority,
        falcon_key,
        pending_account,
        expected_prepared,
    );
    let (program_result, account) =
        finalize_key_account(&mollusk, program_id, authority, falcon_key, written_account);
    assert!(program_result.is_ok(), "{program_result:?}");
    let account = account.unwrap();

    assert_eq!(account.owner, program_id);
    assert_eq!(account.data.len(), FALCON_KEY_ACCOUNT_LEN);
    assert_eq!(&account.data[..8], &FALCON_KEY_DISCRIMINATOR);
    assert_eq!(account.data[VERSION_OFFSET], 2);
    assert_eq!(account.data[BUMP_OFFSET], bump);
    assert_eq!(account.data[CLUSTER_OFFSET], CLUSTER);
    assert_eq!(account.data[RESERVED_OFFSET], 0);
    assert_eq!(
        &account.data[AUTHORITY_OFFSET..NEXT_NONCE_OFFSET],
        authority.as_ref()
    );
    assert_eq!(
        u64::from_le_bytes(
            account.data[NEXT_NONCE_OFFSET..PREPARED_PUBKEY_OFFSET]
                .try_into()
                .unwrap()
        ),
        0
    );
    assert_eq!(
        &account.data[PREPARED_PUBKEY_OFFSET..],
        &expected_prepared[..]
    );
}

#[test]
fn register_key_requires_authority_signature() {
    let (mollusk, program_id) = make_mollusk();
    let authority = Pubkey::new_unique();
    let (falcon_key, bump) =
        Pubkey::find_program_address(&[FALCON_KEY_SEED, authority.as_ref()], &program_id);

    let mut ix = register_ix(program_id, authority, falcon_key, bump);
    ix.accounts[0].is_signer = false;

    let result = mollusk.process_instruction(
        &ix,
        &[
            (authority, system_account(1_000_000_000)),
            (falcon_key, system_account(0)),
            keyed_account_for_system_program(),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::MissingRequiredSignature)
    );
}

#[test]
fn register_key_rejects_missing_cluster() {
    let (mollusk, program_id) = make_mollusk();
    let authority = Pubkey::new_unique();
    let (falcon_key, bump) =
        Pubkey::find_program_address(&[FALCON_KEY_SEED, authority.as_ref()], &program_id);
    let ix = Instruction::new_with_bytes(
        program_id,
        &[TAG_REGISTER_KEY, bump],
        vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(falcon_key, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
    );

    let result = mollusk.process_instruction(
        &ix,
        &[
            (authority, system_account(1_000_000_000)),
            (falcon_key, system_account(0)),
            keyed_account_for_system_program(),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(1))
    );
}

#[test]
fn register_key_rejects_wrong_pda() {
    let (mollusk, program_id) = make_mollusk();
    let authority = Pubkey::new_unique();
    let wrong_key = Pubkey::new_unique();
    let (_, bump) =
        Pubkey::find_program_address(&[FALCON_KEY_SEED, authority.as_ref()], &program_id);

    let result = mollusk.process_instruction(
        &register_ix(program_id, authority, wrong_key, bump),
        &[
            (authority, system_account(1_000_000_000)),
            (wrong_key, system_account(0)),
            keyed_account_for_system_program(),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(3))
    );
}

#[test]
fn register_key_rejects_malformed_falcon_pubkey_on_finalize() {
    let (mollusk, program_id) = make_mollusk();
    let authority = Pubkey::new_unique();
    let (falcon_key, bump) =
        Pubkey::find_program_address(&[FALCON_KEY_SEED, authority.as_ref()], &program_id);
    let mut prepared_pubkey = prepared_pubkey_bytes();
    prepared_pubkey[0] = 0x01;
    prepared_pubkey[1] = 0x30;

    let pending_account = init_key_account(&mollusk, program_id, authority, falcon_key, bump);
    let written_account = write_key_chunks(
        &mollusk,
        program_id,
        authority,
        falcon_key,
        pending_account,
        prepared_pubkey,
    );
    let (program_result, _) =
        finalize_key_account(&mollusk, program_id, authority, falcon_key, written_account);

    assert_eq!(program_result, SvmResult::Failure(ProgramError::Custom(7)));
}

#[test]
fn register_key_rejects_reinitialization() {
    let (mollusk, program_id) = make_mollusk();
    let authority = Pubkey::new_unique();
    let (falcon_key, bump) =
        Pubkey::find_program_address(&[FALCON_KEY_SEED, authority.as_ref()], &program_id);

    let rent_lamports = mollusk.sysvars.rent.minimum_balance(FALCON_KEY_ACCOUNT_LEN);
    let mut initialized_data = vec![0u8; FALCON_KEY_ACCOUNT_LEN];
    initialized_data[..8].copy_from_slice(&FALCON_KEY_DISCRIMINATOR);
    let initialized_account = Account {
        lamports: rent_lamports,
        data: initialized_data,
        owner: program_id,
        executable: false,
        rent_epoch: 0,
    };

    let result = mollusk.process_instruction(
        &register_ix(program_id, authority, falcon_key, bump),
        &[
            (authority, system_account(1_000_000_000)),
            (falcon_key, initialized_account),
            keyed_account_for_system_program(),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(5))
    );
}
