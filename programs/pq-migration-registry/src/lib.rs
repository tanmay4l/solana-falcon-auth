#![cfg_attr(target_os = "solana", no_std)]

use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint::ProgramResult,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};
use solana_system_interface::{instruction as system_instruction, program as system_program};

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

pub const TAG_BIND: u8 = 0;
pub const VERSION: u8 = 1;
pub const REGISTRY_SEED: &[u8] = b"pq-migrate";
pub const SMART_ACCOUNT_SEED: &[u8] = b"pq-smart";
pub const REGISTRY_DISCRIMINATOR: [u8; 8] = *b"PQREG001";
pub const SMART_ACCOUNT_DISCRIMINATOR: [u8; 8] = *b"PQSMRT01";

const REGISTRY_VERSION_OFFSET: usize = 8;
const REGISTRY_BUMP_OFFSET: usize = 9;
const REGISTRY_RESERVED_OFFSET: usize = 10;
const REGISTRY_LEGACY_WALLET_OFFSET: usize = 12;
const REGISTRY_SMART_PROGRAM_OFFSET: usize = 44;
const REGISTRY_SMART_ACCOUNT_OFFSET: usize = 76;
const REGISTRY_PQ_QUORUM_PROGRAM_OFFSET: usize = 108;
const REGISTRY_QUORUM_OFFSET: usize = 140;
const REGISTRY_ACCOUNT_LEN: usize = 172;

const SMART_VERSION_OFFSET: usize = 8;
const SMART_AUTHORITY_OFFSET: usize = 12;
const SMART_PQ_QUORUM_PROGRAM_OFFSET: usize = 44;
const SMART_QUORUM_OFFSET: usize = 76;
const SMART_SPEND_COUNT_OFFSET: usize = 108;
const SMART_ACCOUNT_LEN: usize = 116;

const BIND_REGISTRY_BUMP_DATA_LEN: usize = 1;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PqMigrationRegistryError {
    InvalidInstructionData = 1,
    InvalidAccountOwner = 2,
    InvalidAccountData = 3,
    InvalidPda = 4,
    InvalidSmartAccount = 5,
    InvalidProgram = 6,
}

impl From<PqMigrationRegistryError> for ProgramError {
    fn from(value: PqMigrationRegistryError) -> Self {
        ProgramError::Custom(value as u32)
    }
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let Some((&tag, rest)) = instruction_data.split_first() else {
        return Err(PqMigrationRegistryError::InvalidInstructionData.into());
    };

    match tag {
        TAG_BIND => process_bind(program_id, accounts, rest),
        _ => Err(PqMigrationRegistryError::InvalidInstructionData.into()),
    }
}

fn process_bind(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != BIND_REGISTRY_BUMP_DATA_LEN {
        return Err(PqMigrationRegistryError::InvalidInstructionData.into());
    }
    let registry_bump = data[0];

    let account_iter = &mut accounts.iter();
    let legacy_wallet = next_account_info(account_iter)?;
    let registry = next_account_info(account_iter)?;
    let smart_account = next_account_info(account_iter)?;
    let smart_program = next_account_info(account_iter)?;
    let pq_quorum_program = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let system_program_account = next_account_info(account_iter)?;

    if !legacy_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !legacy_wallet.is_writable || !registry.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !smart_program.executable || !pq_quorum_program.executable {
        return Err(PqMigrationRegistryError::InvalidProgram.into());
    }
    if smart_account.owner != smart_program.key || quorum.owner != pq_quorum_program.key {
        return Err(PqMigrationRegistryError::InvalidAccountOwner.into());
    }
    if !system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    reject_duplicate_runtime_accounts(&[
        legacy_wallet.key,
        registry.key,
        smart_account.key,
        smart_program.key,
        pq_quorum_program.key,
        quorum.key,
        system_program_account.key,
    ])?;
    validate_registry_pda(program_id, legacy_wallet.key, registry.key, registry_bump)?;
    validate_smart_account_binding(
        smart_program.key,
        legacy_wallet.key,
        smart_account.key,
        &smart_account.try_borrow_data()?,
        pq_quorum_program.key,
        quorum.key,
    )?;

    if system_program::check_id(registry.owner) && registry.data_is_empty() {
        let rent = Rent::get()?;
        let lamports = rent.minimum_balance(REGISTRY_ACCOUNT_LEN);
        let create_account_ix = system_instruction::create_account(
            legacy_wallet.key,
            registry.key,
            lamports,
            REGISTRY_ACCOUNT_LEN as u64,
            program_id,
        );
        invoke_signed(
            &create_account_ix,
            &[
                legacy_wallet.clone(),
                registry.clone(),
                system_program_account.clone(),
            ],
            &[&[REGISTRY_SEED, legacy_wallet.key.as_ref(), &[registry_bump]]],
        )?;
    } else if registry.owner != program_id {
        return Err(PqMigrationRegistryError::InvalidAccountOwner.into());
    } else if registry.data_len() != REGISTRY_ACCOUNT_LEN {
        return Err(PqMigrationRegistryError::InvalidAccountData.into());
    } else {
        let registry_data = registry.try_borrow_data()?;
        validate_existing_registry_header(legacy_wallet.key, &registry_data, registry_bump)?;
    }

    let mut registry_data = registry.try_borrow_mut_data()?;
    write_registry_state(
        &mut registry_data,
        registry_bump,
        legacy_wallet.key.as_ref(),
        smart_program.key.as_ref(),
        smart_account.key.as_ref(),
        pq_quorum_program.key.as_ref(),
        quorum.key.as_ref(),
    )
}

fn validate_smart_account_binding(
    smart_program: &Pubkey,
    legacy_wallet: &Pubkey,
    smart_account: &Pubkey,
    data: &[u8],
    pq_quorum_program: &Pubkey,
    quorum: &Pubkey,
) -> ProgramResult {
    if data.len() != SMART_ACCOUNT_LEN
        || data[..8] != SMART_ACCOUNT_DISCRIMINATOR
        || data[SMART_VERSION_OFFSET] != VERSION
        || &data[SMART_AUTHORITY_OFFSET..SMART_PQ_QUORUM_PROGRAM_OFFSET] != legacy_wallet.as_ref()
        || &data[SMART_PQ_QUORUM_PROGRAM_OFFSET..SMART_QUORUM_OFFSET] != pq_quorum_program.as_ref()
        || &data[SMART_QUORUM_OFFSET..SMART_SPEND_COUNT_OFFSET] != quorum.as_ref()
    {
        return Err(PqMigrationRegistryError::InvalidSmartAccount.into());
    }
    let bump = data[9];
    validate_smart_account_pda(
        smart_program,
        legacy_wallet,
        pq_quorum_program,
        quorum,
        smart_account,
        bump,
    )
}

fn validate_existing_registry_header(
    legacy_wallet: &Pubkey,
    data: &[u8],
    registry_bump: u8,
) -> ProgramResult {
    if data[..8] != REGISTRY_DISCRIMINATOR
        || data[REGISTRY_VERSION_OFFSET] != VERSION
        || data[REGISTRY_BUMP_OFFSET] != registry_bump
        || &data[REGISTRY_LEGACY_WALLET_OFFSET..REGISTRY_SMART_PROGRAM_OFFSET]
            != legacy_wallet.as_ref()
    {
        return Err(PqMigrationRegistryError::InvalidAccountData.into());
    }
    Ok(())
}

fn validate_registry_pda(
    program_id: &Pubkey,
    legacy_wallet: &Pubkey,
    registry: &Pubkey,
    bump: u8,
) -> ProgramResult {
    let expected = Pubkey::create_program_address(
        &[REGISTRY_SEED, legacy_wallet.as_ref(), &[bump]],
        program_id,
    )
    .map_err(|_| PqMigrationRegistryError::InvalidPda)?;
    if expected != *registry {
        return Err(PqMigrationRegistryError::InvalidPda.into());
    }
    Ok(())
}

fn validate_smart_account_pda(
    smart_program: &Pubkey,
    legacy_wallet: &Pubkey,
    pq_quorum_program: &Pubkey,
    quorum: &Pubkey,
    smart_account: &Pubkey,
    bump: u8,
) -> ProgramResult {
    let expected = Pubkey::create_program_address(
        &[
            SMART_ACCOUNT_SEED,
            legacy_wallet.as_ref(),
            pq_quorum_program.as_ref(),
            quorum.as_ref(),
            &[bump],
        ],
        smart_program,
    )
    .map_err(|_| PqMigrationRegistryError::InvalidPda)?;
    if expected != *smart_account {
        return Err(PqMigrationRegistryError::InvalidPda.into());
    }
    Ok(())
}

fn write_registry_state(
    data: &mut [u8],
    bump: u8,
    legacy_wallet: &[u8],
    smart_program: &[u8],
    smart_account: &[u8],
    pq_quorum_program: &[u8],
    quorum: &[u8],
) -> ProgramResult {
    if data.len() != REGISTRY_ACCOUNT_LEN
        || legacy_wallet.len() != 32
        || smart_program.len() != 32
        || smart_account.len() != 32
        || pq_quorum_program.len() != 32
        || quorum.len() != 32
    {
        return Err(PqMigrationRegistryError::InvalidAccountData.into());
    }
    data[..8].copy_from_slice(&REGISTRY_DISCRIMINATOR);
    data[REGISTRY_VERSION_OFFSET] = VERSION;
    data[REGISTRY_BUMP_OFFSET] = bump;
    data[REGISTRY_RESERVED_OFFSET..REGISTRY_LEGACY_WALLET_OFFSET].fill(0);
    data[REGISTRY_LEGACY_WALLET_OFFSET..REGISTRY_SMART_PROGRAM_OFFSET]
        .copy_from_slice(legacy_wallet);
    data[REGISTRY_SMART_PROGRAM_OFFSET..REGISTRY_SMART_ACCOUNT_OFFSET]
        .copy_from_slice(smart_program);
    data[REGISTRY_SMART_ACCOUNT_OFFSET..REGISTRY_PQ_QUORUM_PROGRAM_OFFSET]
        .copy_from_slice(smart_account);
    data[REGISTRY_PQ_QUORUM_PROGRAM_OFFSET..REGISTRY_QUORUM_OFFSET]
        .copy_from_slice(pq_quorum_program);
    data[REGISTRY_QUORUM_OFFSET..REGISTRY_ACCOUNT_LEN].copy_from_slice(quorum);
    Ok(())
}

fn reject_duplicate_runtime_accounts(accounts: &[&Pubkey]) -> ProgramResult {
    for index in 0..accounts.len() {
        for other_index in index + 1..accounts.len() {
            if accounts[index] == accounts[other_index] {
                return Err(ProgramError::InvalidArgument);
            }
        }
    }
    Ok(())
}
