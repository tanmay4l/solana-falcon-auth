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

pub const TAG_INIT_COUNTER: u8 = 0;
pub const TAG_INCREMENT_WITH_FALCON: u8 = 1;
pub const FALCON_AUTH_TAG_VERIFY_ACTION: u8 = 1;
pub const VERSION: u8 = 1;
pub const COUNTER_SEED: &[u8] = b"counter";
pub const COUNTER_DISCRIMINATOR: [u8; 8] = *b"EXCNTR01";
pub const COUNTER_ACCOUNT_LEN: usize = 81;
pub const FALCON_512_SIGNATURE_LEN: usize = 666;

const VERSION_OFFSET: usize = 8;
const AUTHORITY_OFFSET: usize = 9;
const FALCON_AUTH_PROGRAM_OFFSET: usize = 41;
const COUNTER_OFFSET: usize = 73;
const INIT_COUNTER_DATA_LEN: usize = 1 + 1;
const INCREMENT_DATA_LEN: usize = 1 + 1 + 8 + 8 + 8 + FALCON_512_SIGNATURE_LEN;

#[repr(u32)]
pub enum ExampleConsumerError {
    InvalidInstructionData = 1,
    InvalidAccountOwner = 2,
    InvalidAccountData = 3,
    InvalidFalconAuthProgram = 4,
    ArithmeticOverflow = 5,
}

impl From<ExampleConsumerError> for ProgramError {
    fn from(value: ExampleConsumerError) -> Self {
        ProgramError::Custom(value as u32)
    }
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let Some((&tag, rest)) = instruction_data.split_first() else {
        return Err(ExampleConsumerError::InvalidInstructionData.into());
    };

    match tag {
        TAG_INIT_COUNTER => process_init_counter(program_id, accounts, rest),
        TAG_INCREMENT_WITH_FALCON => process_increment_with_falcon(program_id, accounts, rest),
        _ => Err(ExampleConsumerError::InvalidInstructionData.into()),
    }
}

fn process_init_counter(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != INIT_COUNTER_DATA_LEN - 1 {
        return Err(ExampleConsumerError::InvalidInstructionData.into());
    }

    let (&bump, extra) = data
        .split_first()
        .ok_or(ExampleConsumerError::InvalidInstructionData)?;
    if !extra.is_empty() {
        return Err(ExampleConsumerError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let counter = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;
    let system_program_account = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable || !counter.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !falcon_auth_program.executable {
        return Err(ExampleConsumerError::InvalidFalconAuthProgram.into());
    }
    if !system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if counter.key == authority.key || counter.key == falcon_auth_program.key {
        return Err(ProgramError::InvalidArgument);
    }

    let seeds: [&[u8]; 3] = [
        COUNTER_SEED,
        authority.key.as_ref(),
        falcon_auth_program.key.as_ref(),
    ];
    let Some((expected_counter, canonical_bump)) =
        Pubkey::derive_program_address(&seeds, program_id)
    else {
        return Err(ExampleConsumerError::InvalidAccountData.into());
    };
    if expected_counter != *counter.key || canonical_bump != bump {
        return Err(ExampleConsumerError::InvalidAccountData.into());
    }
    if !system_program::check_id(counter.owner) || !counter.data_is_empty() {
        return Err(ExampleConsumerError::InvalidAccountData.into());
    }

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(COUNTER_ACCOUNT_LEN);
    let create_account_ix = system_instruction::create_account(
        authority.key,
        counter.key,
        lamports,
        COUNTER_ACCOUNT_LEN as u64,
        program_id,
    );
    invoke_signed(
        &create_account_ix,
        &[
            authority.clone(),
            counter.clone(),
            system_program_account.clone(),
        ],
        &[&[
            COUNTER_SEED,
            authority.key.as_ref(),
            falcon_auth_program.key.as_ref(),
            &[bump],
        ]],
    )?;

    let mut counter_data = counter.try_borrow_mut_data()?;
    write_counter_state(
        &mut counter_data,
        authority.key.as_ref(),
        falcon_auth_program.key.as_ref(),
        0,
    )
}

fn process_increment_with_falcon(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != INCREMENT_DATA_LEN - 1 {
        return Err(ExampleConsumerError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;
    let counter = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;

    if !falcon_key.is_writable || !counter.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if counter.key == authority.key || counter.key == falcon_key.key {
        return Err(ProgramError::InvalidArgument);
    }
    if counter.owner != program_id {
        return Err(ExampleConsumerError::InvalidAccountOwner.into());
    }

    let cluster = data[0];
    let nonce = read_u64(data, 1)?;
    let expires_slot = read_u64(data, 9)?;
    let amount = read_u64(data, 17)?;
    let signature = read_array::<FALCON_512_SIGNATURE_LEN>(data, 25)?;

    let current_counter = {
        let counter_data = counter.try_borrow_data()?;
        validate_counter_account(
            program_id,
            counter.key,
            &counter_data,
            authority.key,
            falcon_auth_program.key,
            falcon_auth_program.executable,
        )?;
        read_u64(&counter_data, COUNTER_OFFSET)?
    };

    let action_domain = counter_increment_domain();
    let action_hash = counter_increment_hash(
        program_id,
        counter.key,
        authority.key,
        amount,
        current_counter,
    );
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

    let mut counter_data = counter.try_borrow_mut_data()?;
    validate_counter_account(
        program_id,
        counter.key,
        &counter_data,
        authority.key,
        falcon_auth_program.key,
        falcon_auth_program.executable,
    )?;
    if read_u64(&counter_data, COUNTER_OFFSET)? != current_counter {
        return Err(ExampleConsumerError::InvalidAccountData.into());
    }
    let next_counter = current_counter
        .checked_add(amount)
        .ok_or(ExampleConsumerError::ArithmeticOverflow)?;
    counter_data[COUNTER_OFFSET..COUNTER_OFFSET + 8].copy_from_slice(&next_counter.to_le_bytes());
    Ok(())
}

fn write_counter_state(
    data: &mut [u8],
    authority: &[u8],
    falcon_auth_program: &[u8],
    counter: u64,
) -> ProgramResult {
    if data.len() != COUNTER_ACCOUNT_LEN || authority.len() != 32 || falcon_auth_program.len() != 32
    {
        return Err(ProgramError::AccountDataTooSmall);
    }
    data[..8].copy_from_slice(&COUNTER_DISCRIMINATOR);
    data[VERSION_OFFSET] = VERSION;
    data[AUTHORITY_OFFSET..FALCON_AUTH_PROGRAM_OFFSET].copy_from_slice(authority);
    data[FALCON_AUTH_PROGRAM_OFFSET..COUNTER_OFFSET].copy_from_slice(falcon_auth_program);
    data[COUNTER_OFFSET..COUNTER_OFFSET + 8].copy_from_slice(&counter.to_le_bytes());
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

fn validate_counter_account(
    program_id: &Pubkey,
    counter: &Pubkey,
    data: &[u8],
    authority: &Pubkey,
    falcon_auth_program: &Pubkey,
    falcon_auth_program_executable: bool,
) -> ProgramResult {
    if data.len() != COUNTER_ACCOUNT_LEN {
        return Err(ExampleConsumerError::InvalidAccountData.into());
    }
    if data[..8] != COUNTER_DISCRIMINATOR || data[VERSION_OFFSET] != VERSION {
        return Err(ExampleConsumerError::InvalidAccountData.into());
    }
    if &data[AUTHORITY_OFFSET..FALCON_AUTH_PROGRAM_OFFSET] != authority.as_ref() {
        return Err(ExampleConsumerError::InvalidAccountData.into());
    }
    if &data[FALCON_AUTH_PROGRAM_OFFSET..COUNTER_OFFSET] != falcon_auth_program.as_ref()
        || !falcon_auth_program_executable
    {
        return Err(ExampleConsumerError::InvalidFalconAuthProgram.into());
    }
    let seeds: [&[u8]; 3] = [
        COUNTER_SEED,
        authority.as_ref(),
        falcon_auth_program.as_ref(),
    ];
    let Some((expected_counter, _)) = Pubkey::derive_program_address(&seeds, program_id) else {
        return Err(ExampleConsumerError::InvalidAccountData.into());
    };
    if expected_counter != *counter {
        return Err(ExampleConsumerError::InvalidAccountData.into());
    }
    Ok(())
}

pub fn counter_increment_domain() -> [u8; 32] {
    hashv(&[b"example-consumer", b"counter.increment.v1"]).to_bytes()
}

pub fn counter_increment_hash(
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

fn read_u64(data: &[u8], offset: usize) -> Result<u64, ProgramError> {
    let bytes = read_array::<8>(data, offset)?;
    Ok(u64::from_le_bytes(*bytes))
}

fn read_array<const N: usize>(data: &[u8], offset: usize) -> Result<&[u8; N], ProgramError> {
    data.get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| ExampleConsumerError::InvalidInstructionData.into())
}
