#![cfg_attr(target_os = "solana", no_std)]

#[cfg(target_os = "solana")]
extern crate alloc;

#[cfg(target_os = "solana")]
use alloc::{vec, vec::Vec};

use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint::ProgramResult,
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};
use solana_system_interface::{instruction as system_instruction, program as system_program};

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

pub const TAG_INIT_VAULT: u8 = 0;
pub const TAG_DEPOSIT: u8 = 1;
pub const TAG_WITHDRAW_WITH_FALCON: u8 = 2;
pub const FALCON_AUTH_TAG_VERIFY_ACTION: u8 = 1;
pub const VERSION: u8 = 1;
pub const VAULT_SEED: &[u8] = b"vault";
pub const VAULT_DISCRIMINATOR: [u8; 8] = *b"FALVLT01";
pub const FALCON_512_SIGNATURE_LEN: usize = 666;

const VERSION_OFFSET: usize = 8;
const BUMP_OFFSET: usize = 9;
const AUTHORITY_OFFSET: usize = 10;
const FALCON_AUTH_PROGRAM_OFFSET: usize = 42;
const WITHDRAW_COUNT_OFFSET: usize = 74;
const VAULT_ACCOUNT_LEN: usize = 82;
const INIT_VAULT_DATA_LEN: usize = 1 + 1;
const DEPOSIT_DATA_LEN: usize = 1 + 8;
const WITHDRAW_DATA_LEN: usize = 1 + 1 + 8 + 8 + 8 + FALCON_512_SIGNATURE_LEN;

#[repr(u32)]
pub enum FalconVaultError {
    InvalidInstructionData = 1,
    InvalidAccountOwner = 2,
    InvalidAccountData = 3,
    InvalidFalconAuthProgram = 4,
    ArithmeticOverflow = 5,
    InsufficientVaultFunds = 6,
}

impl From<FalconVaultError> for ProgramError {
    fn from(value: FalconVaultError) -> Self {
        ProgramError::Custom(value as u32)
    }
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let Some((&tag, rest)) = instruction_data.split_first() else {
        return Err(FalconVaultError::InvalidInstructionData.into());
    };

    match tag {
        TAG_INIT_VAULT => process_init_vault(program_id, accounts, rest),
        TAG_DEPOSIT => process_deposit(program_id, accounts, rest),
        TAG_WITHDRAW_WITH_FALCON => process_withdraw_with_falcon(program_id, accounts, rest),
        _ => Err(FalconVaultError::InvalidInstructionData.into()),
    }
}

fn process_init_vault(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != INIT_VAULT_DATA_LEN - 1 {
        return Err(FalconVaultError::InvalidInstructionData.into());
    }

    let bump = data[0];

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let vault = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;
    let system_program_account = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable || !vault.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !falcon_auth_program.executable {
        return Err(FalconVaultError::InvalidFalconAuthProgram.into());
    }
    if !system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if vault.key == authority.key || vault.key == falcon_auth_program.key {
        return Err(ProgramError::InvalidArgument);
    }

    let seeds: [&[u8]; 3] = [
        VAULT_SEED,
        authority.key.as_ref(),
        falcon_auth_program.key.as_ref(),
    ];
    let Some((expected_vault, canonical_bump)) = Pubkey::derive_program_address(&seeds, program_id)
    else {
        return Err(FalconVaultError::InvalidAccountData.into());
    };
    if expected_vault != *vault.key || canonical_bump != bump {
        return Err(FalconVaultError::InvalidAccountData.into());
    }
    if !system_program::check_id(vault.owner) || !vault.data_is_empty() {
        return Err(FalconVaultError::InvalidAccountData.into());
    }

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(VAULT_ACCOUNT_LEN);
    let create_account_ix = system_instruction::create_account(
        authority.key,
        vault.key,
        lamports,
        VAULT_ACCOUNT_LEN as u64,
        program_id,
    );
    invoke_signed(
        &create_account_ix,
        &[
            authority.clone(),
            vault.clone(),
            system_program_account.clone(),
        ],
        &[&[
            VAULT_SEED,
            authority.key.as_ref(),
            falcon_auth_program.key.as_ref(),
            &[bump],
        ]],
    )?;

    let mut vault_data = vault.try_borrow_mut_data()?;
    write_vault_state(
        &mut vault_data,
        bump,
        authority.key.as_ref(),
        falcon_auth_program.key.as_ref(),
        0,
    )
}

fn process_deposit(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != DEPOSIT_DATA_LEN - 1 {
        return Err(FalconVaultError::InvalidInstructionData.into());
    }

    let lamports = read_u64(data, 0)?;
    if lamports == 0 {
        return Err(FalconVaultError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let depositor = next_account_info(account_iter)?;
    let vault = next_account_info(account_iter)?;
    let system_program_account = next_account_info(account_iter)?;

    if !depositor.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !depositor.is_writable || !vault.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if vault.owner != program_id {
        return Err(FalconVaultError::InvalidAccountOwner.into());
    }
    if !system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }

    {
        let vault_data = vault.try_borrow_data()?;
        validate_vault_account(program_id, vault.key, &vault_data, None, None)?;
    }

    let transfer_ix = system_instruction::transfer(depositor.key, vault.key, lamports);
    invoke(
        &transfer_ix,
        &[
            depositor.clone(),
            vault.clone(),
            system_program_account.clone(),
        ],
    )
}

fn process_withdraw_with_falcon(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != WITHDRAW_DATA_LEN - 1 {
        return Err(FalconVaultError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;
    let vault = next_account_info(account_iter)?;
    let destination = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;

    if !falcon_key.is_writable || !vault.is_writable || !destination.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if vault.key == authority.key
        || vault.key == falcon_key.key
        || vault.key == destination.key
        || vault.key == falcon_auth_program.key
    {
        return Err(ProgramError::InvalidArgument);
    }
    if vault.owner != program_id {
        return Err(FalconVaultError::InvalidAccountOwner.into());
    }

    let cluster = data[0];
    let nonce = read_u64(data, 1)?;
    let expires_slot = read_u64(data, 9)?;
    let lamports = read_u64(data, 17)?;
    let signature = read_array::<FALCON_512_SIGNATURE_LEN>(data, 25)?;
    if lamports == 0 {
        return Err(FalconVaultError::InvalidInstructionData.into());
    }

    let withdraw_count = {
        let vault_data = vault.try_borrow_data()?;
        validate_vault_account(
            program_id,
            vault.key,
            &vault_data,
            Some(authority.key),
            Some(falcon_auth_program.key),
        )?;
        if !falcon_auth_program.executable {
            return Err(FalconVaultError::InvalidFalconAuthProgram.into());
        }
        read_u64(&vault_data, WITHDRAW_COUNT_OFFSET)?
    };

    let action_domain = vault_withdraw_domain();
    let action_hash = vault_withdraw_hash(
        program_id,
        vault.key,
        authority.key,
        destination.key,
        lamports,
        withdraw_count,
    );

    let rent_exempt_minimum = Rent::get()?.minimum_balance(VAULT_ACCOUNT_LEN);
    let vault_lamports = **vault.try_borrow_lamports()?;
    let remaining_lamports = vault_lamports
        .checked_sub(lamports)
        .ok_or(FalconVaultError::InsufficientVaultFunds)?;
    if remaining_lamports < rent_exempt_minimum {
        return Err(FalconVaultError::InsufficientVaultFunds.into());
    }
    let destination_lamports = **destination.try_borrow_lamports()?;
    let next_destination_lamports = destination_lamports
        .checked_add(lamports)
        .ok_or(FalconVaultError::ArithmeticOverflow)?;

    invoke_falcon_auth(FalconAuthCpi {
        falcon_auth_program,
        authority,
        falcon_key,
        cluster,
        nonce,
        expires_slot,
        action_domain: &action_domain,
        action_hash: &action_hash,
        signature,
    })?;

    let next_withdraw_count = withdraw_count
        .checked_add(1)
        .ok_or(FalconVaultError::ArithmeticOverflow)?;

    {
        let mut vault_data = vault.try_borrow_mut_data()?;
        validate_vault_account(
            program_id,
            vault.key,
            &vault_data,
            Some(authority.key),
            Some(falcon_auth_program.key),
        )?;
        if read_u64(&vault_data, WITHDRAW_COUNT_OFFSET)? != withdraw_count {
            return Err(FalconVaultError::InvalidAccountData.into());
        }
        vault_data[WITHDRAW_COUNT_OFFSET..WITHDRAW_COUNT_OFFSET + 8]
            .copy_from_slice(&next_withdraw_count.to_le_bytes());
    }

    **vault.try_borrow_mut_lamports()? = remaining_lamports;
    **destination.try_borrow_mut_lamports()? = next_destination_lamports;
    Ok(())
}

fn write_vault_state(
    data: &mut [u8],
    bump: u8,
    authority: &[u8],
    falcon_auth_program: &[u8],
    withdraw_count: u64,
) -> ProgramResult {
    if data.len() != VAULT_ACCOUNT_LEN || authority.len() != 32 || falcon_auth_program.len() != 32 {
        return Err(ProgramError::AccountDataTooSmall);
    }
    data[..8].copy_from_slice(&VAULT_DISCRIMINATOR);
    data[VERSION_OFFSET] = VERSION;
    data[BUMP_OFFSET] = bump;
    data[AUTHORITY_OFFSET..FALCON_AUTH_PROGRAM_OFFSET].copy_from_slice(authority);
    data[FALCON_AUTH_PROGRAM_OFFSET..WITHDRAW_COUNT_OFFSET].copy_from_slice(falcon_auth_program);
    data[WITHDRAW_COUNT_OFFSET..WITHDRAW_COUNT_OFFSET + 8]
        .copy_from_slice(&withdraw_count.to_le_bytes());
    Ok(())
}

struct FalconAuthCpi<'info, 'accounts, 'data> {
    falcon_auth_program: &'accounts AccountInfo<'info>,
    authority: &'accounts AccountInfo<'info>,
    falcon_key: &'accounts AccountInfo<'info>,
    cluster: u8,
    nonce: u64,
    expires_slot: u64,
    action_domain: &'data [u8; 32],
    action_hash: &'data [u8; 32],
    signature: &'data [u8; FALCON_512_SIGNATURE_LEN],
}

fn invoke_falcon_auth(cpi: FalconAuthCpi<'_, '_, '_>) -> ProgramResult {
    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 32 + 32 + FALCON_512_SIGNATURE_LEN);
    data.push(FALCON_AUTH_TAG_VERIFY_ACTION);
    data.push(cpi.cluster);
    data.extend_from_slice(&cpi.nonce.to_le_bytes());
    data.extend_from_slice(&cpi.expires_slot.to_le_bytes());
    data.extend_from_slice(cpi.action_domain);
    data.extend_from_slice(cpi.action_hash);
    data.extend_from_slice(cpi.signature);

    let instruction = Instruction::new_with_bytes(
        *cpi.falcon_auth_program.key,
        &data,
        vec![
            AccountMeta::new_readonly(*cpi.authority.key, false),
            AccountMeta::new(*cpi.falcon_key.key, false),
        ],
    );
    invoke(
        &instruction,
        &[
            cpi.authority.clone(),
            cpi.falcon_key.clone(),
            cpi.falcon_auth_program.clone(),
        ],
    )
}

fn validate_vault_account(
    program_id: &Pubkey,
    vault: &Pubkey,
    data: &[u8],
    expected_authority: Option<&Pubkey>,
    expected_falcon_auth_program: Option<&Pubkey>,
) -> ProgramResult {
    if data.len() != VAULT_ACCOUNT_LEN {
        return Err(FalconVaultError::InvalidAccountData.into());
    }
    if data[..8] != VAULT_DISCRIMINATOR || data[VERSION_OFFSET] != VERSION {
        return Err(FalconVaultError::InvalidAccountData.into());
    }

    let authority = read_array::<32>(data, AUTHORITY_OFFSET)?;
    let falcon_auth_program = read_array::<32>(data, FALCON_AUTH_PROGRAM_OFFSET)?;
    if expected_authority.is_some_and(|key| authority != key.as_ref()) {
        return Err(FalconVaultError::InvalidAccountData.into());
    }
    if expected_falcon_auth_program.is_some_and(|key| falcon_auth_program != key.as_ref()) {
        return Err(FalconVaultError::InvalidFalconAuthProgram.into());
    }

    let seeds: [&[u8]; 3] = [VAULT_SEED, authority, falcon_auth_program];
    let Some((expected_vault, canonical_bump)) = Pubkey::derive_program_address(&seeds, program_id)
    else {
        return Err(FalconVaultError::InvalidAccountData.into());
    };
    if expected_vault != *vault || canonical_bump != data[BUMP_OFFSET] {
        return Err(FalconVaultError::InvalidAccountData.into());
    }
    Ok(())
}

pub fn vault_withdraw_domain() -> [u8; 32] {
    hashv(&[b"falcon-vault", b"withdraw.v1"]).to_bytes()
}

pub fn vault_withdraw_hash(
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

fn read_u64(data: &[u8], offset: usize) -> Result<u64, ProgramError> {
    let bytes = read_array::<8>(data, offset)?;
    Ok(u64::from_le_bytes(*bytes))
}

fn read_array<const N: usize>(data: &[u8], offset: usize) -> Result<&[u8; N], ProgramError> {
    data.get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| FalconVaultError::InvalidInstructionData.into())
}
