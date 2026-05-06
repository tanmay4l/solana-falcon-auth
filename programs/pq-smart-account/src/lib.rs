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

pub const TAG_INIT_ACCOUNT: u8 = 0;
pub const TAG_DEPOSIT: u8 = 1;
pub const TAG_TRANSFER_FALCON_WINTERNITZ: u8 = 2;
pub const TAG_TRANSFER_FALCON_MLDSA_PROOF: u8 = 3;
pub const TAG_TRANSFER_WINTERNITZ_MLDSA_PROOF: u8 = 4;
pub const TAG_INIT_FALCON_SIGNATURE: u8 = 5;
pub const TAG_WRITE_FALCON_SIGNATURE_CHUNK: u8 = 6;
pub const TAG_TRANSFER_FALCON_MLDSA_PROOF_BUFFERED: u8 = 7;
pub const TAG_TRANSFER_SPL_TOKEN_FALCON_WINTERNITZ: u8 = 8;
pub const TAG_TRANSFER_SPL_TOKEN_FALCON_WINTERNITZ_BUFFERED: u8 = 9;
pub const TAG_TRANSFER_SPL_TOKEN_FALCON_MLDSA_PROOF_BUFFERED: u8 = 10;
pub const TAG_TRANSFER_SPL_TOKEN_WINTERNITZ_MLDSA_PROOF: u8 = 11;
pub const PQ_QUORUM_TAG_VERIFY_FALCON_WINTERNITZ: u8 = 1;
pub const PQ_QUORUM_TAG_VERIFY_FALCON_MLDSA_PROOF: u8 = 14;
pub const PQ_QUORUM_TAG_VERIFY_WINTERNITZ_MLDSA_PROOF: u8 = 15;
pub const VERSION: u8 = 1;
pub const SMART_ACCOUNT_SEED: &[u8] = b"pq-smart";
pub const FALCON_SIGNATURE_SEED: &[u8] = b"falcon-sig";
pub const SMART_ACCOUNT_DISCRIMINATOR: [u8; 8] = *b"PQSMRT01";
pub const FALCON_SIGNATURE_DISCRIMINATOR: [u8; 8] = *b"FALCSIG1";
pub const SMART_TRANSFER_DOMAIN: [u8; 32] = *b"PQ_SMART_TRANSFER_SOL_V1________";
pub const SMART_TOKEN_TRANSFER_DOMAIN: [u8; 32] = *b"PQ_SMART_TRANSFER_SPL_V1________";
pub const SPL_TOKEN_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const FALCON_512_SIGNATURE_LEN: usize = 666;

const VERSION_OFFSET: usize = 8;
const BUMP_OFFSET: usize = 9;
const RESERVED_OFFSET: usize = 10;
const AUTHORITY_OFFSET: usize = 12;
const PQ_QUORUM_PROGRAM_OFFSET: usize = 44;
const QUORUM_OFFSET: usize = 76;
const SPEND_COUNT_OFFSET: usize = 108;
const SMART_ACCOUNT_LEN: usize = 116;
const SIGBUF_VERSION_OFFSET: usize = 8;
const SIGBUF_BUMP_OFFSET: usize = 9;
const SIGBUF_RESERVED_OFFSET: usize = 10;
const SIGBUF_AUTHORITY_OFFSET: usize = 12;
const SIGBUF_SMART_ACCOUNT_OFFSET: usize = 44;
const SIGBUF_QUORUM_OFFSET: usize = 76;
const SIGBUF_QUORUM_NONCE_OFFSET: usize = 108;
const SIGBUF_WRITTEN_OFFSET: usize = 116;
const SIGBUF_DATA_OFFSET: usize = 118;
const FALCON_SIGNATURE_BUFFER_LEN: usize = SIGBUF_DATA_OFFSET + FALCON_512_SIGNATURE_LEN;
const TOKEN_ACCOUNT_MINT_OFFSET: usize = 0;
const TOKEN_ACCOUNT_OWNER_OFFSET: usize = 32;
const TOKEN_ACCOUNT_AMOUNT_OFFSET: usize = 64;
const TOKEN_ACCOUNT_STATE_OFFSET: usize = 108;
const TOKEN_ACCOUNT_LEN: usize = 165;
const MINT_DECIMALS_OFFSET: usize = 44;
const MINT_INITIALIZED_OFFSET: usize = 45;
const MINT_LEN: usize = 82;
const SPL_TOKEN_TRANSFER_CHECKED_TAG: u8 = 12;

const INIT_ACCOUNT_DATA_LEN: usize = 1 + 1;
const DEPOSIT_DATA_LEN: usize = 1 + 8;
const INIT_FALCON_SIGNATURE_DATA_LEN: usize = 1 + 1 + 8;
const WRITE_FALCON_SIGNATURE_CHUNK_MIN_DATA_LEN: usize = 1 + 8 + 2;
const TRANSFER_FALCON_WINTERNITZ_DATA_LEN: usize =
    1 + 1 + 8 + 8 + 8 + 8 + 32 + FALCON_512_SIGNATURE_LEN;
const TRANSFER_FALCON_MLDSA_PROOF_DATA_LEN: usize =
    1 + 1 + 8 + 8 + 8 + 8 + FALCON_512_SIGNATURE_LEN;
const TRANSFER_WINTERNITZ_MLDSA_PROOF_DATA_LEN: usize = 1 + 1 + 8 + 8 + 8 + 32;
const TRANSFER_FALCON_MLDSA_PROOF_BUFFERED_DATA_LEN: usize = 1 + 1 + 8 + 8 + 8 + 8;
const TRANSFER_SPL_TOKEN_FALCON_WINTERNITZ_DATA_LEN: usize =
    1 + 1 + 8 + 8 + 8 + 8 + 1 + 32 + FALCON_512_SIGNATURE_LEN;
const TRANSFER_SPL_TOKEN_FALCON_WINTERNITZ_BUFFERED_DATA_LEN: usize =
    1 + 1 + 8 + 8 + 8 + 8 + 1 + 32;
const TRANSFER_SPL_TOKEN_FALCON_MLDSA_PROOF_BUFFERED_DATA_LEN: usize = 1 + 1 + 8 + 8 + 8 + 8 + 1;
const TRANSFER_SPL_TOKEN_WINTERNITZ_MLDSA_PROOF_DATA_LEN: usize = 1 + 1 + 8 + 8 + 8 + 1 + 32;

#[repr(u32)]
pub enum PqSmartAccountError {
    InvalidInstructionData = 1,
    InvalidAccountOwner = 2,
    InvalidAccountData = 3,
    InvalidPda = 4,
    InvalidQuorumProgram = 5,
    ArithmeticOverflow = 6,
    InsufficientSmartAccountFunds = 7,
    InvalidSignatureBuffer = 8,
    InvalidTokenProgram = 9,
    InvalidTokenAccount = 10,
}

impl From<PqSmartAccountError> for ProgramError {
    fn from(value: PqSmartAccountError) -> Self {
        ProgramError::Custom(value as u32)
    }
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let Some((&tag, rest)) = instruction_data.split_first() else {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    };

    match tag {
        TAG_INIT_ACCOUNT => process_init_account(program_id, accounts, rest),
        TAG_DEPOSIT => process_deposit(program_id, accounts, rest),
        TAG_TRANSFER_FALCON_WINTERNITZ => {
            process_transfer_falcon_winternitz(program_id, accounts, rest)
        }
        TAG_TRANSFER_FALCON_MLDSA_PROOF => {
            process_transfer_falcon_mldsa_proof(program_id, accounts, rest)
        }
        TAG_TRANSFER_WINTERNITZ_MLDSA_PROOF => {
            process_transfer_winternitz_mldsa_proof(program_id, accounts, rest)
        }
        TAG_INIT_FALCON_SIGNATURE => process_init_falcon_signature(program_id, accounts, rest),
        TAG_WRITE_FALCON_SIGNATURE_CHUNK => {
            process_write_falcon_signature_chunk(program_id, accounts, rest)
        }
        TAG_TRANSFER_FALCON_MLDSA_PROOF_BUFFERED => {
            process_transfer_falcon_mldsa_proof_buffered(program_id, accounts, rest)
        }
        TAG_TRANSFER_SPL_TOKEN_FALCON_WINTERNITZ => {
            process_transfer_spl_token_falcon_winternitz(program_id, accounts, rest)
        }
        TAG_TRANSFER_SPL_TOKEN_FALCON_WINTERNITZ_BUFFERED => {
            process_transfer_spl_token_falcon_winternitz_buffered(program_id, accounts, rest)
        }
        TAG_TRANSFER_SPL_TOKEN_FALCON_MLDSA_PROOF_BUFFERED => {
            process_transfer_spl_token_falcon_mldsa_proof_buffered(program_id, accounts, rest)
        }
        TAG_TRANSFER_SPL_TOKEN_WINTERNITZ_MLDSA_PROOF => {
            process_transfer_spl_token_winternitz_mldsa_proof(program_id, accounts, rest)
        }
        _ => Err(PqSmartAccountError::InvalidInstructionData.into()),
    }
}

fn process_init_account(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != INIT_ACCOUNT_DATA_LEN - 1 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let bump = data[0];
    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let smart_account = next_account_info(account_iter)?;
    let pq_quorum_program = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let system_program_account = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable || !smart_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !pq_quorum_program.executable {
        return Err(PqSmartAccountError::InvalidQuorumProgram.into());
    }
    if quorum.owner != pq_quorum_program.key {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    if !system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    reject_duplicate_runtime_accounts(&[
        authority.key,
        smart_account.key,
        pq_quorum_program.key,
        quorum.key,
        system_program_account.key,
    ])?;
    validate_smart_account_pda(
        program_id,
        authority.key,
        pq_quorum_program.key,
        quorum.key,
        smart_account.key,
        bump,
    )?;
    if !system_program::check_id(smart_account.owner) || !smart_account.data_is_empty() {
        return Err(PqSmartAccountError::InvalidAccountData.into());
    }

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(SMART_ACCOUNT_LEN);
    let create_account_ix = system_instruction::create_account(
        authority.key,
        smart_account.key,
        lamports,
        SMART_ACCOUNT_LEN as u64,
        program_id,
    );
    invoke_signed(
        &create_account_ix,
        &[
            authority.clone(),
            smart_account.clone(),
            system_program_account.clone(),
        ],
        &[&[
            SMART_ACCOUNT_SEED,
            authority.key.as_ref(),
            pq_quorum_program.key.as_ref(),
            quorum.key.as_ref(),
            &[bump],
        ]],
    )?;

    let mut account_data = smart_account.try_borrow_mut_data()?;
    write_smart_account_state(
        &mut account_data,
        bump,
        authority.key.as_ref(),
        pq_quorum_program.key.as_ref(),
        quorum.key.as_ref(),
        0,
    )
}

fn process_deposit(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != DEPOSIT_DATA_LEN - 1 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let lamports = read_u64(data, 0)?;
    if lamports == 0 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let depositor = next_account_info(account_iter)?;
    let smart_account = next_account_info(account_iter)?;
    let system_program_account = next_account_info(account_iter)?;

    if !depositor.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !depositor.is_writable || !smart_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if smart_account.owner != program_id {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    if !system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if depositor.key == smart_account.key || smart_account.key == system_program_account.key {
        return Err(ProgramError::InvalidArgument);
    }

    {
        let account_data = smart_account.try_borrow_data()?;
        validate_smart_account_state(program_id, smart_account.key, &account_data, None, None)?;
    }

    let transfer_ix = system_instruction::transfer(depositor.key, smart_account.key, lamports);
    invoke(
        &transfer_ix,
        &[
            depositor.clone(),
            smart_account.clone(),
            system_program_account.clone(),
        ],
    )
}

fn process_init_falcon_signature(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != INIT_FALCON_SIGNATURE_DATA_LEN - 1 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let bump = data[0];
    let quorum_nonce = read_u64(data, 1)?;
    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let smart_account = next_account_info(account_iter)?;
    let pq_quorum_program = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let signature_buffer = next_account_info(account_iter)?;
    let system_program_account = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable || !signature_buffer.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if smart_account.owner != program_id {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    if quorum.owner != pq_quorum_program.key {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    if !pq_quorum_program.executable {
        return Err(PqSmartAccountError::InvalidQuorumProgram.into());
    }
    if !system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    reject_duplicate_runtime_accounts(&[
        authority.key,
        smart_account.key,
        pq_quorum_program.key,
        quorum.key,
        signature_buffer.key,
        system_program_account.key,
    ])?;
    {
        let account_data = smart_account.try_borrow_data()?;
        validate_smart_account_state(
            program_id,
            smart_account.key,
            &account_data,
            Some(authority.key),
            Some((pq_quorum_program.key, quorum.key)),
        )?;
    }
    validate_falcon_signature_buffer_pda(
        program_id,
        authority.key,
        smart_account.key,
        quorum.key,
        quorum_nonce,
        signature_buffer.key,
        bump,
    )?;
    if !system_program::check_id(signature_buffer.owner) || !signature_buffer.data_is_empty() {
        return Err(PqSmartAccountError::InvalidAccountData.into());
    }

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(FALCON_SIGNATURE_BUFFER_LEN);
    let create_account_ix = system_instruction::create_account(
        authority.key,
        signature_buffer.key,
        lamports,
        FALCON_SIGNATURE_BUFFER_LEN as u64,
        program_id,
    );
    invoke_signed(
        &create_account_ix,
        &[
            authority.clone(),
            signature_buffer.clone(),
            system_program_account.clone(),
        ],
        &[&[
            FALCON_SIGNATURE_SEED,
            authority.key.as_ref(),
            smart_account.key.as_ref(),
            quorum.key.as_ref(),
            &quorum_nonce.to_le_bytes(),
            &[bump],
        ]],
    )?;

    let mut buffer_data = signature_buffer.try_borrow_mut_data()?;
    write_falcon_signature_buffer_header(
        &mut buffer_data,
        bump,
        authority.key.as_ref(),
        smart_account.key.as_ref(),
        quorum.key.as_ref(),
        quorum_nonce,
    )
}

fn process_write_falcon_signature_chunk(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() < WRITE_FALCON_SIGNATURE_CHUNK_MIN_DATA_LEN - 1 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let quorum_nonce = read_u64(data, 0)?;
    let offset = read_u16(data, 8)? as usize;
    let chunk = &data[10..];
    if chunk.is_empty() {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let smart_account = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let signature_buffer = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !signature_buffer.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if smart_account.owner != program_id || signature_buffer.owner != program_id {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    reject_duplicate_runtime_accounts(&[
        authority.key,
        smart_account.key,
        quorum.key,
        signature_buffer.key,
    ])?;

    let mut buffer_data = signature_buffer.try_borrow_mut_data()?;
    validate_falcon_signature_buffer_header(
        program_id,
        signature_buffer.key,
        &buffer_data,
        authority.key,
        smart_account.key,
        quorum.key,
        quorum_nonce,
    )?;
    let written = read_u16(&buffer_data, SIGBUF_WRITTEN_OFFSET)? as usize;
    if offset != written {
        return Err(PqSmartAccountError::InvalidSignatureBuffer.into());
    }
    let next_written = written
        .checked_add(chunk.len())
        .ok_or(PqSmartAccountError::ArithmeticOverflow)?;
    if next_written > FALCON_512_SIGNATURE_LEN {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let account_offset = SIGBUF_DATA_OFFSET
        .checked_add(written)
        .ok_or(PqSmartAccountError::ArithmeticOverflow)?;
    buffer_data[account_offset..account_offset + chunk.len()].copy_from_slice(chunk);
    buffer_data[SIGBUF_WRITTEN_OFFSET..SIGBUF_WRITTEN_OFFSET + 2]
        .copy_from_slice(&(next_written as u16).to_le_bytes());
    Ok(())
}

fn process_transfer_falcon_winternitz(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != TRANSFER_FALCON_WINTERNITZ_DATA_LEN - 1 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let smart_account = next_account_info(account_iter)?;
    let destination = next_account_info(account_iter)?;
    let pq_quorum_program = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;
    let winternitz_signature = next_account_info(account_iter)?;

    if !authority.is_writable
        || !smart_account.is_writable
        || !destination.is_writable
        || !quorum.is_writable
        || !falcon_key.is_writable
        || !winternitz_signature.is_writable
    {
        return Err(ProgramError::InvalidAccountData);
    }
    if smart_account.owner != program_id {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    if quorum.owner != pq_quorum_program.key {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    if !pq_quorum_program.executable || !falcon_auth_program.executable {
        return Err(PqSmartAccountError::InvalidQuorumProgram.into());
    }
    reject_duplicate_runtime_accounts(&[
        authority.key,
        smart_account.key,
        destination.key,
        pq_quorum_program.key,
        quorum.key,
        falcon_key.key,
        falcon_auth_program.key,
        winternitz_signature.key,
    ])?;

    let cluster = data[0];
    let quorum_nonce = read_u64(data, 1)?;
    let falcon_nonce = read_u64(data, 9)?;
    let expires_slot = read_u64(data, 17)?;
    let lamports = read_u64(data, 25)?;
    let next_winternitz_root = read_array::<32>(data, 33)?;
    let falcon_signature = read_array::<FALCON_512_SIGNATURE_LEN>(data, 65)?;
    if lamports == 0 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let spend_count = {
        let account_data = smart_account.try_borrow_data()?;
        validate_smart_account_state(
            program_id,
            smart_account.key,
            &account_data,
            Some(authority.key),
            Some((pq_quorum_program.key, quorum.key)),
        )?;
        read_u64(&account_data, SPEND_COUNT_OFFSET)?
    };

    let action_domain = smart_transfer_domain();
    let action_hash = smart_transfer_hash(
        program_id,
        smart_account.key,
        authority.key,
        destination.key,
        lamports,
        spend_count,
    );

    let rent_exempt_minimum = Rent::get()?.minimum_balance(SMART_ACCOUNT_LEN);
    let smart_lamports = **smart_account.try_borrow_lamports()?;
    let remaining_lamports = smart_lamports
        .checked_sub(lamports)
        .ok_or(PqSmartAccountError::InsufficientSmartAccountFunds)?;
    if remaining_lamports < rent_exempt_minimum {
        return Err(PqSmartAccountError::InsufficientSmartAccountFunds.into());
    }
    let destination_lamports = **destination.try_borrow_lamports()?;
    let next_destination_lamports = destination_lamports
        .checked_add(lamports)
        .ok_or(PqSmartAccountError::ArithmeticOverflow)?;

    invoke_pq_quorum_falcon_winternitz(PqQuorumFalconWinternitzCpi {
        pq_quorum_program,
        authority,
        quorum,
        falcon_key,
        falcon_auth_program,
        winternitz_signature,
        cluster,
        quorum_nonce,
        falcon_nonce,
        expires_slot,
        action_domain: &action_domain,
        action_hash: &action_hash,
        next_winternitz_root,
        falcon_signature,
    })?;

    let next_spend_count = spend_count
        .checked_add(1)
        .ok_or(PqSmartAccountError::ArithmeticOverflow)?;
    smart_account.try_borrow_mut_data()?[SPEND_COUNT_OFFSET..SPEND_COUNT_OFFSET + 8]
        .copy_from_slice(&next_spend_count.to_le_bytes());

    **smart_account.try_borrow_mut_lamports()? = remaining_lamports;
    **destination.try_borrow_mut_lamports()? = next_destination_lamports;
    Ok(())
}

fn process_transfer_falcon_mldsa_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != TRANSFER_FALCON_MLDSA_PROOF_DATA_LEN - 1 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let smart_account = next_account_info(account_iter)?;
    let destination = next_account_info(account_iter)?;
    let pq_quorum_program = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;
    let mldsa_public_key = next_account_info(account_iter)?;
    let mldsa_signature = next_account_info(account_iter)?;
    let mldsa_proof = next_account_info(account_iter)?;

    if !authority.is_writable
        || !smart_account.is_writable
        || !destination.is_writable
        || !quorum.is_writable
        || !falcon_key.is_writable
        || !mldsa_signature.is_writable
        || !mldsa_proof.is_writable
    {
        return Err(ProgramError::InvalidAccountData);
    }
    validate_transfer_program_accounts(
        program_id,
        authority,
        smart_account,
        destination,
        pq_quorum_program,
        quorum,
        falcon_auth_program,
    )?;
    reject_duplicate_runtime_accounts(&[
        authority.key,
        smart_account.key,
        destination.key,
        pq_quorum_program.key,
        quorum.key,
        falcon_key.key,
        falcon_auth_program.key,
        mldsa_public_key.key,
        mldsa_signature.key,
        mldsa_proof.key,
    ])?;

    let cluster = data[0];
    let quorum_nonce = read_u64(data, 1)?;
    let falcon_nonce = read_u64(data, 9)?;
    let expires_slot = read_u64(data, 17)?;
    let lamports = read_u64(data, 25)?;
    let falcon_signature = read_array::<FALCON_512_SIGNATURE_LEN>(data, 33)?;

    let transfer = prepare_transfer(program_id, authority, smart_account, destination, lamports)?;
    invoke_pq_quorum_falcon_mldsa_proof(PqQuorumFalconMldsaCpi {
        pq_quorum_program,
        authority,
        quorum,
        falcon_key,
        falcon_auth_program,
        mldsa_public_key,
        mldsa_signature,
        mldsa_proof,
        cluster,
        quorum_nonce,
        falcon_nonce,
        expires_slot,
        action_domain: &transfer.action_domain,
        action_hash: &transfer.action_hash,
        falcon_signature,
    })?;
    finish_transfer(smart_account, destination, transfer)
}

fn process_transfer_falcon_mldsa_proof_buffered(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != TRANSFER_FALCON_MLDSA_PROOF_BUFFERED_DATA_LEN - 1 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let smart_account = next_account_info(account_iter)?;
    let destination = next_account_info(account_iter)?;
    let pq_quorum_program = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;
    let mldsa_public_key = next_account_info(account_iter)?;
    let mldsa_signature = next_account_info(account_iter)?;
    let mldsa_proof = next_account_info(account_iter)?;
    let falcon_signature_buffer = next_account_info(account_iter)?;

    if !authority.is_writable
        || !smart_account.is_writable
        || !destination.is_writable
        || !quorum.is_writable
        || !falcon_key.is_writable
        || !mldsa_signature.is_writable
        || !mldsa_proof.is_writable
        || !falcon_signature_buffer.is_writable
    {
        return Err(ProgramError::InvalidAccountData);
    }
    validate_transfer_program_accounts(
        program_id,
        authority,
        smart_account,
        destination,
        pq_quorum_program,
        quorum,
        falcon_auth_program,
    )?;
    if falcon_signature_buffer.owner != program_id {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    reject_duplicate_runtime_accounts(&[
        authority.key,
        smart_account.key,
        destination.key,
        pq_quorum_program.key,
        quorum.key,
        falcon_key.key,
        falcon_auth_program.key,
        mldsa_public_key.key,
        mldsa_signature.key,
        mldsa_proof.key,
        falcon_signature_buffer.key,
    ])?;

    let cluster = data[0];
    let quorum_nonce = read_u64(data, 1)?;
    let falcon_nonce = read_u64(data, 9)?;
    let expires_slot = read_u64(data, 17)?;
    let lamports = read_u64(data, 25)?;
    let falcon_signature = read_falcon_signature_buffer(
        program_id,
        falcon_signature_buffer,
        authority.key,
        smart_account.key,
        quorum.key,
        quorum_nonce,
    )?;

    let transfer = prepare_transfer(program_id, authority, smart_account, destination, lamports)?;
    invoke_pq_quorum_falcon_mldsa_proof(PqQuorumFalconMldsaCpi {
        pq_quorum_program,
        authority,
        quorum,
        falcon_key,
        falcon_auth_program,
        mldsa_public_key,
        mldsa_signature,
        mldsa_proof,
        cluster,
        quorum_nonce,
        falcon_nonce,
        expires_slot,
        action_domain: &transfer.action_domain,
        action_hash: &transfer.action_hash,
        falcon_signature: &falcon_signature,
    })?;
    close_falcon_signature_buffer(falcon_signature_buffer, authority)?;
    finish_transfer(smart_account, destination, transfer)
}

fn process_transfer_winternitz_mldsa_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != TRANSFER_WINTERNITZ_MLDSA_PROOF_DATA_LEN - 1 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let smart_account = next_account_info(account_iter)?;
    let destination = next_account_info(account_iter)?;
    let pq_quorum_program = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;
    let winternitz_signature = next_account_info(account_iter)?;
    let mldsa_public_key = next_account_info(account_iter)?;
    let mldsa_signature = next_account_info(account_iter)?;
    let mldsa_proof = next_account_info(account_iter)?;

    if !authority.is_writable
        || !smart_account.is_writable
        || !destination.is_writable
        || !quorum.is_writable
        || !winternitz_signature.is_writable
        || !mldsa_signature.is_writable
        || !mldsa_proof.is_writable
    {
        return Err(ProgramError::InvalidAccountData);
    }
    validate_transfer_program_accounts(
        program_id,
        authority,
        smart_account,
        destination,
        pq_quorum_program,
        quorum,
        falcon_auth_program,
    )?;
    reject_duplicate_runtime_accounts(&[
        authority.key,
        smart_account.key,
        destination.key,
        pq_quorum_program.key,
        quorum.key,
        falcon_key.key,
        falcon_auth_program.key,
        winternitz_signature.key,
        mldsa_public_key.key,
        mldsa_signature.key,
        mldsa_proof.key,
    ])?;

    let cluster = data[0];
    let quorum_nonce = read_u64(data, 1)?;
    let expires_slot = read_u64(data, 9)?;
    let lamports = read_u64(data, 17)?;
    let next_winternitz_root = read_array::<32>(data, 25)?;

    let transfer = prepare_transfer(program_id, authority, smart_account, destination, lamports)?;
    invoke_pq_quorum_winternitz_mldsa_proof(PqQuorumWinternitzMldsaCpi {
        pq_quorum_program,
        authority,
        quorum,
        falcon_key,
        falcon_auth_program,
        winternitz_signature,
        mldsa_public_key,
        mldsa_signature,
        mldsa_proof,
        cluster,
        quorum_nonce,
        expires_slot,
        action_domain: &transfer.action_domain,
        action_hash: &transfer.action_hash,
        next_winternitz_root,
    })?;
    finish_transfer(smart_account, destination, transfer)
}

fn process_transfer_spl_token_falcon_winternitz(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != TRANSFER_SPL_TOKEN_FALCON_WINTERNITZ_DATA_LEN - 1 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let smart_account = next_account_info(account_iter)?;
    let token_program = next_account_info(account_iter)?;
    let source_token = next_account_info(account_iter)?;
    let mint = next_account_info(account_iter)?;
    let destination_token = next_account_info(account_iter)?;
    let pq_quorum_program = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;
    let winternitz_signature = next_account_info(account_iter)?;

    if !authority.is_writable
        || !smart_account.is_writable
        || !source_token.is_writable
        || !destination_token.is_writable
        || !quorum.is_writable
        || !falcon_key.is_writable
        || !winternitz_signature.is_writable
    {
        return Err(ProgramError::InvalidAccountData);
    }
    if *token_program.key != SPL_TOKEN_PROGRAM_ID || !token_program.executable {
        return Err(PqSmartAccountError::InvalidTokenProgram.into());
    }
    if source_token.owner != token_program.key
        || mint.owner != token_program.key
        || destination_token.owner != token_program.key
    {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    validate_transfer_program_accounts(
        program_id,
        authority,
        smart_account,
        destination_token,
        pq_quorum_program,
        quorum,
        falcon_auth_program,
    )?;
    reject_duplicate_runtime_accounts(&[
        authority.key,
        smart_account.key,
        token_program.key,
        source_token.key,
        mint.key,
        destination_token.key,
        pq_quorum_program.key,
        quorum.key,
        falcon_key.key,
        falcon_auth_program.key,
        winternitz_signature.key,
    ])?;

    let cluster = data[0];
    let quorum_nonce = read_u64(data, 1)?;
    let falcon_nonce = read_u64(data, 9)?;
    let expires_slot = read_u64(data, 17)?;
    let amount = read_u64(data, 25)?;
    let decimals = data[33];
    let next_winternitz_root = read_array::<32>(data, 34)?;
    let falcon_signature = read_array::<FALCON_512_SIGNATURE_LEN>(data, 66)?;
    if amount == 0 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let transfer = prepare_token_transfer(
        program_id,
        authority,
        smart_account,
        token_program,
        source_token,
        mint,
        destination_token,
        amount,
        decimals,
    )?;

    invoke_pq_quorum_falcon_winternitz(PqQuorumFalconWinternitzCpi {
        pq_quorum_program,
        authority,
        quorum,
        falcon_key,
        falcon_auth_program,
        winternitz_signature,
        cluster,
        quorum_nonce,
        falcon_nonce,
        expires_slot,
        action_domain: &transfer.action_domain,
        action_hash: &transfer.action_hash,
        next_winternitz_root,
        falcon_signature,
    })?;

    invoke_spl_token_transfer_checked(TokenTransferCpi {
        token_program,
        source_token,
        mint,
        destination_token,
        smart_account,
        smart_bump: transfer.smart_bump,
        authority: transfer.authority,
        pq_quorum_program: transfer.pq_quorum_program,
        quorum: transfer.quorum,
        amount,
        decimals,
    })?;
    finish_token_transfer(smart_account, transfer)
}

fn process_transfer_spl_token_falcon_winternitz_buffered(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != TRANSFER_SPL_TOKEN_FALCON_WINTERNITZ_BUFFERED_DATA_LEN - 1 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let smart_account = next_account_info(account_iter)?;
    let token_program = next_account_info(account_iter)?;
    let source_token = next_account_info(account_iter)?;
    let mint = next_account_info(account_iter)?;
    let destination_token = next_account_info(account_iter)?;
    let pq_quorum_program = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;
    let winternitz_signature = next_account_info(account_iter)?;
    let falcon_signature_buffer = next_account_info(account_iter)?;

    if !authority.is_writable
        || !smart_account.is_writable
        || !source_token.is_writable
        || !destination_token.is_writable
        || !quorum.is_writable
        || !falcon_key.is_writable
        || !winternitz_signature.is_writable
        || !falcon_signature_buffer.is_writable
    {
        return Err(ProgramError::InvalidAccountData);
    }
    if *token_program.key != SPL_TOKEN_PROGRAM_ID || !token_program.executable {
        return Err(PqSmartAccountError::InvalidTokenProgram.into());
    }
    if source_token.owner != token_program.key
        || mint.owner != token_program.key
        || destination_token.owner != token_program.key
    {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    if falcon_signature_buffer.owner != program_id {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    validate_transfer_program_accounts(
        program_id,
        authority,
        smart_account,
        destination_token,
        pq_quorum_program,
        quorum,
        falcon_auth_program,
    )?;
    reject_duplicate_runtime_accounts(&[
        authority.key,
        smart_account.key,
        token_program.key,
        source_token.key,
        mint.key,
        destination_token.key,
        pq_quorum_program.key,
        quorum.key,
        falcon_key.key,
        falcon_auth_program.key,
        winternitz_signature.key,
        falcon_signature_buffer.key,
    ])?;

    let cluster = data[0];
    let quorum_nonce = read_u64(data, 1)?;
    let falcon_nonce = read_u64(data, 9)?;
    let expires_slot = read_u64(data, 17)?;
    let amount = read_u64(data, 25)?;
    let decimals = data[33];
    let next_winternitz_root = read_array::<32>(data, 34)?;
    if amount == 0 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }
    let falcon_signature = read_falcon_signature_buffer(
        program_id,
        falcon_signature_buffer,
        authority.key,
        smart_account.key,
        quorum.key,
        quorum_nonce,
    )?;

    let transfer = prepare_token_transfer(
        program_id,
        authority,
        smart_account,
        token_program,
        source_token,
        mint,
        destination_token,
        amount,
        decimals,
    )?;

    invoke_pq_quorum_falcon_winternitz(PqQuorumFalconWinternitzCpi {
        pq_quorum_program,
        authority,
        quorum,
        falcon_key,
        falcon_auth_program,
        winternitz_signature,
        cluster,
        quorum_nonce,
        falcon_nonce,
        expires_slot,
        action_domain: &transfer.action_domain,
        action_hash: &transfer.action_hash,
        next_winternitz_root,
        falcon_signature: &falcon_signature,
    })?;

    invoke_spl_token_transfer_checked(TokenTransferCpi {
        token_program,
        source_token,
        mint,
        destination_token,
        smart_account,
        smart_bump: transfer.smart_bump,
        authority: transfer.authority,
        pq_quorum_program: transfer.pq_quorum_program,
        quorum: transfer.quorum,
        amount,
        decimals,
    })?;
    close_falcon_signature_buffer(falcon_signature_buffer, authority)?;
    finish_token_transfer(smart_account, transfer)
}

fn process_transfer_spl_token_falcon_mldsa_proof_buffered(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != TRANSFER_SPL_TOKEN_FALCON_MLDSA_PROOF_BUFFERED_DATA_LEN - 1 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let smart_account = next_account_info(account_iter)?;
    let token_program = next_account_info(account_iter)?;
    let source_token = next_account_info(account_iter)?;
    let mint = next_account_info(account_iter)?;
    let destination_token = next_account_info(account_iter)?;
    let pq_quorum_program = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;
    let mldsa_public_key = next_account_info(account_iter)?;
    let mldsa_signature = next_account_info(account_iter)?;
    let mldsa_proof = next_account_info(account_iter)?;
    let falcon_signature_buffer = next_account_info(account_iter)?;

    if !authority.is_writable
        || !smart_account.is_writable
        || !source_token.is_writable
        || !destination_token.is_writable
        || !quorum.is_writable
        || !falcon_key.is_writable
        || !mldsa_signature.is_writable
        || !mldsa_proof.is_writable
        || !falcon_signature_buffer.is_writable
    {
        return Err(ProgramError::InvalidAccountData);
    }
    if *token_program.key != SPL_TOKEN_PROGRAM_ID || !token_program.executable {
        return Err(PqSmartAccountError::InvalidTokenProgram.into());
    }
    if source_token.owner != token_program.key
        || mint.owner != token_program.key
        || destination_token.owner != token_program.key
    {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    if falcon_signature_buffer.owner != program_id {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    validate_transfer_program_accounts(
        program_id,
        authority,
        smart_account,
        destination_token,
        pq_quorum_program,
        quorum,
        falcon_auth_program,
    )?;
    reject_duplicate_runtime_accounts(&[
        authority.key,
        smart_account.key,
        token_program.key,
        source_token.key,
        mint.key,
        destination_token.key,
        pq_quorum_program.key,
        quorum.key,
        falcon_key.key,
        falcon_auth_program.key,
        mldsa_public_key.key,
        mldsa_signature.key,
        mldsa_proof.key,
        falcon_signature_buffer.key,
    ])?;

    let cluster = data[0];
    let quorum_nonce = read_u64(data, 1)?;
    let falcon_nonce = read_u64(data, 9)?;
    let expires_slot = read_u64(data, 17)?;
    let amount = read_u64(data, 25)?;
    let decimals = data[33];
    if amount == 0 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }
    let falcon_signature = read_falcon_signature_buffer(
        program_id,
        falcon_signature_buffer,
        authority.key,
        smart_account.key,
        quorum.key,
        quorum_nonce,
    )?;

    let transfer = prepare_token_transfer(
        program_id,
        authority,
        smart_account,
        token_program,
        source_token,
        mint,
        destination_token,
        amount,
        decimals,
    )?;

    invoke_pq_quorum_falcon_mldsa_proof(PqQuorumFalconMldsaCpi {
        pq_quorum_program,
        authority,
        quorum,
        falcon_key,
        falcon_auth_program,
        mldsa_public_key,
        mldsa_signature,
        mldsa_proof,
        cluster,
        quorum_nonce,
        falcon_nonce,
        expires_slot,
        action_domain: &transfer.action_domain,
        action_hash: &transfer.action_hash,
        falcon_signature: &falcon_signature,
    })?;

    invoke_spl_token_transfer_checked(TokenTransferCpi {
        token_program,
        source_token,
        mint,
        destination_token,
        smart_account,
        smart_bump: transfer.smart_bump,
        authority: transfer.authority,
        pq_quorum_program: transfer.pq_quorum_program,
        quorum: transfer.quorum,
        amount,
        decimals,
    })?;
    close_falcon_signature_buffer(falcon_signature_buffer, authority)?;
    finish_token_transfer(smart_account, transfer)
}

fn process_transfer_spl_token_winternitz_mldsa_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != TRANSFER_SPL_TOKEN_WINTERNITZ_MLDSA_PROOF_DATA_LEN - 1 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let smart_account = next_account_info(account_iter)?;
    let token_program = next_account_info(account_iter)?;
    let source_token = next_account_info(account_iter)?;
    let mint = next_account_info(account_iter)?;
    let destination_token = next_account_info(account_iter)?;
    let pq_quorum_program = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;
    let winternitz_signature = next_account_info(account_iter)?;
    let mldsa_public_key = next_account_info(account_iter)?;
    let mldsa_signature = next_account_info(account_iter)?;
    let mldsa_proof = next_account_info(account_iter)?;

    if !authority.is_writable
        || !smart_account.is_writable
        || !source_token.is_writable
        || !destination_token.is_writable
        || !quorum.is_writable
        || !winternitz_signature.is_writable
        || !mldsa_signature.is_writable
        || !mldsa_proof.is_writable
    {
        return Err(ProgramError::InvalidAccountData);
    }
    if *token_program.key != SPL_TOKEN_PROGRAM_ID || !token_program.executable {
        return Err(PqSmartAccountError::InvalidTokenProgram.into());
    }
    if source_token.owner != token_program.key
        || mint.owner != token_program.key
        || destination_token.owner != token_program.key
    {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    validate_transfer_program_accounts(
        program_id,
        authority,
        smart_account,
        destination_token,
        pq_quorum_program,
        quorum,
        falcon_auth_program,
    )?;
    reject_duplicate_runtime_accounts(&[
        authority.key,
        smart_account.key,
        token_program.key,
        source_token.key,
        mint.key,
        destination_token.key,
        pq_quorum_program.key,
        quorum.key,
        falcon_key.key,
        falcon_auth_program.key,
        winternitz_signature.key,
        mldsa_public_key.key,
        mldsa_signature.key,
        mldsa_proof.key,
    ])?;

    let cluster = data[0];
    let quorum_nonce = read_u64(data, 1)?;
    let expires_slot = read_u64(data, 9)?;
    let amount = read_u64(data, 17)?;
    let decimals = data[25];
    let next_winternitz_root = read_array::<32>(data, 26)?;
    if amount == 0 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let transfer = prepare_token_transfer(
        program_id,
        authority,
        smart_account,
        token_program,
        source_token,
        mint,
        destination_token,
        amount,
        decimals,
    )?;

    invoke_pq_quorum_winternitz_mldsa_proof(PqQuorumWinternitzMldsaCpi {
        pq_quorum_program,
        authority,
        quorum,
        falcon_key,
        falcon_auth_program,
        winternitz_signature,
        mldsa_public_key,
        mldsa_signature,
        mldsa_proof,
        cluster,
        quorum_nonce,
        expires_slot,
        action_domain: &transfer.action_domain,
        action_hash: &transfer.action_hash,
        next_winternitz_root,
    })?;

    invoke_spl_token_transfer_checked(TokenTransferCpi {
        token_program,
        source_token,
        mint,
        destination_token,
        smart_account,
        smart_bump: transfer.smart_bump,
        authority: transfer.authority,
        pq_quorum_program: transfer.pq_quorum_program,
        quorum: transfer.quorum,
        amount,
        decimals,
    })?;
    finish_token_transfer(smart_account, transfer)
}

struct PreparedTransfer {
    remaining_lamports: u64,
    next_destination_lamports: u64,
    next_spend_count: u64,
    action_domain: [u8; 32],
    action_hash: [u8; 32],
}

fn validate_transfer_program_accounts(
    program_id: &Pubkey,
    authority: &AccountInfo,
    smart_account: &AccountInfo,
    destination: &AccountInfo,
    pq_quorum_program: &AccountInfo,
    quorum: &AccountInfo,
    falcon_auth_program: &AccountInfo,
) -> ProgramResult {
    if smart_account.owner != program_id {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    if quorum.owner != pq_quorum_program.key {
        return Err(PqSmartAccountError::InvalidAccountOwner.into());
    }
    if !pq_quorum_program.executable || !falcon_auth_program.executable {
        return Err(PqSmartAccountError::InvalidQuorumProgram.into());
    }
    let account_data = smart_account.try_borrow_data()?;
    validate_smart_account_state(
        program_id,
        smart_account.key,
        &account_data,
        Some(authority.key),
        Some((pq_quorum_program.key, quorum.key)),
    )?;
    if smart_account.key == destination.key {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

fn prepare_transfer(
    program_id: &Pubkey,
    authority: &AccountInfo,
    smart_account: &AccountInfo,
    destination: &AccountInfo,
    lamports: u64,
) -> Result<PreparedTransfer, ProgramError> {
    if lamports == 0 {
        return Err(PqSmartAccountError::InvalidInstructionData.into());
    }

    let spend_count = {
        let account_data = smart_account.try_borrow_data()?;
        read_u64(&account_data, SPEND_COUNT_OFFSET)?
    };
    let action_domain = smart_transfer_domain();
    let action_hash = smart_transfer_hash(
        program_id,
        smart_account.key,
        authority.key,
        destination.key,
        lamports,
        spend_count,
    );

    let rent_exempt_minimum = Rent::get()?.minimum_balance(SMART_ACCOUNT_LEN);
    let smart_lamports = **smart_account.try_borrow_lamports()?;
    let remaining_lamports = smart_lamports
        .checked_sub(lamports)
        .ok_or(PqSmartAccountError::InsufficientSmartAccountFunds)?;
    if remaining_lamports < rent_exempt_minimum {
        return Err(PqSmartAccountError::InsufficientSmartAccountFunds.into());
    }
    let destination_lamports = **destination.try_borrow_lamports()?;
    let next_destination_lamports = destination_lamports
        .checked_add(lamports)
        .ok_or(PqSmartAccountError::ArithmeticOverflow)?;
    let next_spend_count = spend_count
        .checked_add(1)
        .ok_or(PqSmartAccountError::ArithmeticOverflow)?;

    Ok(PreparedTransfer {
        remaining_lamports,
        next_destination_lamports,
        next_spend_count,
        action_domain,
        action_hash,
    })
}

fn finish_transfer(
    smart_account: &AccountInfo,
    destination: &AccountInfo,
    transfer: PreparedTransfer,
) -> ProgramResult {
    smart_account.try_borrow_mut_data()?[SPEND_COUNT_OFFSET..SPEND_COUNT_OFFSET + 8]
        .copy_from_slice(&transfer.next_spend_count.to_le_bytes());

    **smart_account.try_borrow_mut_lamports()? = transfer.remaining_lamports;
    **destination.try_borrow_mut_lamports()? = transfer.next_destination_lamports;
    Ok(())
}

struct PreparedTokenTransfer {
    next_spend_count: u64,
    smart_bump: u8,
    authority: [u8; 32],
    pq_quorum_program: [u8; 32],
    quorum: [u8; 32],
    action_domain: [u8; 32],
    action_hash: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
fn prepare_token_transfer(
    program_id: &Pubkey,
    authority: &AccountInfo,
    smart_account: &AccountInfo,
    token_program: &AccountInfo,
    source_token: &AccountInfo,
    mint: &AccountInfo,
    destination_token: &AccountInfo,
    amount: u64,
    decimals: u8,
) -> Result<PreparedTokenTransfer, ProgramError> {
    let (spend_count, smart_bump, authority_bytes, pq_quorum_program_bytes, quorum_bytes) = {
        let account_data = smart_account.try_borrow_data()?;
        let authority_bytes = *read_array::<32>(&account_data, AUTHORITY_OFFSET)?;
        let pq_quorum_program_bytes = *read_array::<32>(&account_data, PQ_QUORUM_PROGRAM_OFFSET)?;
        let quorum_bytes = *read_array::<32>(&account_data, QUORUM_OFFSET)?;
        (
            read_u64(&account_data, SPEND_COUNT_OFFSET)?,
            account_data[BUMP_OFFSET],
            authority_bytes,
            pq_quorum_program_bytes,
            quorum_bytes,
        )
    };
    validate_classic_token_accounts(
        smart_account.key,
        source_token,
        mint,
        destination_token,
        amount,
        decimals,
    )?;

    let next_spend_count = spend_count
        .checked_add(1)
        .ok_or(PqSmartAccountError::ArithmeticOverflow)?;
    let action_domain = smart_token_transfer_domain();
    let action_hash = smart_token_transfer_hash(SmartTokenTransferHashInput {
        program_id,
        smart_account: smart_account.key,
        authority: authority.key,
        token_program: token_program.key,
        source_token: source_token.key,
        mint: mint.key,
        destination_token: destination_token.key,
        amount,
        decimals,
        spend_count,
    });

    Ok(PreparedTokenTransfer {
        next_spend_count,
        smart_bump,
        authority: authority_bytes,
        pq_quorum_program: pq_quorum_program_bytes,
        quorum: quorum_bytes,
        action_domain,
        action_hash,
    })
}

fn finish_token_transfer(
    smart_account: &AccountInfo,
    transfer: PreparedTokenTransfer,
) -> ProgramResult {
    smart_account.try_borrow_mut_data()?[SPEND_COUNT_OFFSET..SPEND_COUNT_OFFSET + 8]
        .copy_from_slice(&transfer.next_spend_count.to_le_bytes());
    Ok(())
}

fn validate_classic_token_accounts(
    smart_account: &Pubkey,
    source_token: &AccountInfo,
    mint: &AccountInfo,
    destination_token: &AccountInfo,
    amount: u64,
    decimals: u8,
) -> ProgramResult {
    let mint_data = mint.try_borrow_data()?;
    if mint_data.len() != MINT_LEN
        || mint_data[MINT_INITIALIZED_OFFSET] != 1
        || mint_data[MINT_DECIMALS_OFFSET] != decimals
    {
        return Err(PqSmartAccountError::InvalidTokenAccount.into());
    }

    let source_data = source_token.try_borrow_data()?;
    let destination_data = destination_token.try_borrow_data()?;
    if source_data.len() != TOKEN_ACCOUNT_LEN
        || destination_data.len() != TOKEN_ACCOUNT_LEN
        || source_data[TOKEN_ACCOUNT_STATE_OFFSET] != 1
        || destination_data[TOKEN_ACCOUNT_STATE_OFFSET] != 1
    {
        return Err(PqSmartAccountError::InvalidTokenAccount.into());
    }
    if read_array::<32>(&source_data, TOKEN_ACCOUNT_MINT_OFFSET)?.as_ref() != mint.key.as_ref()
        || read_array::<32>(&destination_data, TOKEN_ACCOUNT_MINT_OFFSET)?.as_ref()
            != mint.key.as_ref()
        || read_array::<32>(&source_data, TOKEN_ACCOUNT_OWNER_OFFSET)?.as_ref()
            != smart_account.as_ref()
    {
        return Err(PqSmartAccountError::InvalidTokenAccount.into());
    }
    let source_amount = read_u64(&source_data, TOKEN_ACCOUNT_AMOUNT_OFFSET)?;
    if source_amount < amount {
        return Err(PqSmartAccountError::InvalidTokenAccount.into());
    }
    Ok(())
}

struct TokenTransferCpi<'info, 'accounts> {
    token_program: &'accounts AccountInfo<'info>,
    source_token: &'accounts AccountInfo<'info>,
    mint: &'accounts AccountInfo<'info>,
    destination_token: &'accounts AccountInfo<'info>,
    smart_account: &'accounts AccountInfo<'info>,
    smart_bump: u8,
    authority: [u8; 32],
    pq_quorum_program: [u8; 32],
    quorum: [u8; 32],
    amount: u64,
    decimals: u8,
}

fn invoke_spl_token_transfer_checked(cpi: TokenTransferCpi<'_, '_>) -> ProgramResult {
    let mut data = Vec::with_capacity(10);
    data.push(SPL_TOKEN_TRANSFER_CHECKED_TAG);
    data.extend_from_slice(&cpi.amount.to_le_bytes());
    data.push(cpi.decimals);

    let instruction = Instruction {
        program_id: *cpi.token_program.key,
        accounts: vec![
            AccountMeta::new(*cpi.source_token.key, false),
            AccountMeta::new_readonly(*cpi.mint.key, false),
            AccountMeta::new(*cpi.destination_token.key, false),
            AccountMeta::new_readonly(*cpi.smart_account.key, true),
        ],
        data,
    };
    invoke_signed(
        &instruction,
        &[
            cpi.source_token.clone(),
            cpi.mint.clone(),
            cpi.destination_token.clone(),
            cpi.smart_account.clone(),
            cpi.token_program.clone(),
        ],
        &[&[
            SMART_ACCOUNT_SEED,
            &cpi.authority,
            &cpi.pq_quorum_program,
            &cpi.quorum,
            &[cpi.smart_bump],
        ]],
    )
}

struct PqQuorumFalconWinternitzCpi<'info, 'accounts, 'data> {
    pq_quorum_program: &'accounts AccountInfo<'info>,
    authority: &'accounts AccountInfo<'info>,
    quorum: &'accounts AccountInfo<'info>,
    falcon_key: &'accounts AccountInfo<'info>,
    falcon_auth_program: &'accounts AccountInfo<'info>,
    winternitz_signature: &'accounts AccountInfo<'info>,
    cluster: u8,
    quorum_nonce: u64,
    falcon_nonce: u64,
    expires_slot: u64,
    action_domain: &'data [u8; 32],
    action_hash: &'data [u8; 32],
    next_winternitz_root: &'data [u8; 32],
    falcon_signature: &'data [u8; FALCON_512_SIGNATURE_LEN],
}

fn invoke_pq_quorum_falcon_winternitz(
    cpi: PqQuorumFalconWinternitzCpi<'_, '_, '_>,
) -> ProgramResult {
    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 32 + 32 + 32 + FALCON_512_SIGNATURE_LEN);
    data.push(PQ_QUORUM_TAG_VERIFY_FALCON_WINTERNITZ);
    data.push(cpi.cluster);
    data.extend_from_slice(&cpi.quorum_nonce.to_le_bytes());
    data.extend_from_slice(&cpi.falcon_nonce.to_le_bytes());
    data.extend_from_slice(&cpi.expires_slot.to_le_bytes());
    data.extend_from_slice(cpi.action_domain);
    data.extend_from_slice(cpi.action_hash);
    data.extend_from_slice(cpi.next_winternitz_root);
    data.extend_from_slice(cpi.falcon_signature);

    let instruction = Instruction {
        program_id: *cpi.pq_quorum_program.key,
        accounts: vec![
            AccountMeta::new(*cpi.authority.key, false),
            AccountMeta::new(*cpi.quorum.key, false),
            AccountMeta::new(*cpi.falcon_key.key, false),
            AccountMeta::new_readonly(*cpi.falcon_auth_program.key, false),
            AccountMeta::new(*cpi.winternitz_signature.key, false),
        ],
        data,
    };
    invoke(
        &instruction,
        &[
            cpi.authority.clone(),
            cpi.quorum.clone(),
            cpi.falcon_key.clone(),
            cpi.falcon_auth_program.clone(),
            cpi.winternitz_signature.clone(),
            cpi.pq_quorum_program.clone(),
        ],
    )
}

struct PqQuorumFalconMldsaCpi<'info, 'accounts, 'data> {
    pq_quorum_program: &'accounts AccountInfo<'info>,
    authority: &'accounts AccountInfo<'info>,
    quorum: &'accounts AccountInfo<'info>,
    falcon_key: &'accounts AccountInfo<'info>,
    falcon_auth_program: &'accounts AccountInfo<'info>,
    mldsa_public_key: &'accounts AccountInfo<'info>,
    mldsa_signature: &'accounts AccountInfo<'info>,
    mldsa_proof: &'accounts AccountInfo<'info>,
    cluster: u8,
    quorum_nonce: u64,
    falcon_nonce: u64,
    expires_slot: u64,
    action_domain: &'data [u8; 32],
    action_hash: &'data [u8; 32],
    falcon_signature: &'data [u8; FALCON_512_SIGNATURE_LEN],
}

fn invoke_pq_quorum_falcon_mldsa_proof(cpi: PqQuorumFalconMldsaCpi<'_, '_, '_>) -> ProgramResult {
    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 32 + 32 + FALCON_512_SIGNATURE_LEN);
    data.push(PQ_QUORUM_TAG_VERIFY_FALCON_MLDSA_PROOF);
    data.push(cpi.cluster);
    data.extend_from_slice(&cpi.quorum_nonce.to_le_bytes());
    data.extend_from_slice(&cpi.falcon_nonce.to_le_bytes());
    data.extend_from_slice(&cpi.expires_slot.to_le_bytes());
    data.extend_from_slice(cpi.action_domain);
    data.extend_from_slice(cpi.action_hash);
    data.extend_from_slice(cpi.falcon_signature);

    let instruction = Instruction {
        program_id: *cpi.pq_quorum_program.key,
        accounts: vec![
            AccountMeta::new(*cpi.authority.key, false),
            AccountMeta::new(*cpi.quorum.key, false),
            AccountMeta::new(*cpi.falcon_key.key, false),
            AccountMeta::new_readonly(*cpi.falcon_auth_program.key, false),
            AccountMeta::new_readonly(*cpi.mldsa_public_key.key, false),
            AccountMeta::new(*cpi.mldsa_signature.key, false),
            AccountMeta::new(*cpi.mldsa_proof.key, false),
        ],
        data,
    };
    invoke(
        &instruction,
        &[
            cpi.authority.clone(),
            cpi.quorum.clone(),
            cpi.falcon_key.clone(),
            cpi.falcon_auth_program.clone(),
            cpi.mldsa_public_key.clone(),
            cpi.mldsa_signature.clone(),
            cpi.mldsa_proof.clone(),
            cpi.pq_quorum_program.clone(),
        ],
    )
}

struct PqQuorumWinternitzMldsaCpi<'info, 'accounts, 'data> {
    pq_quorum_program: &'accounts AccountInfo<'info>,
    authority: &'accounts AccountInfo<'info>,
    quorum: &'accounts AccountInfo<'info>,
    falcon_key: &'accounts AccountInfo<'info>,
    falcon_auth_program: &'accounts AccountInfo<'info>,
    winternitz_signature: &'accounts AccountInfo<'info>,
    mldsa_public_key: &'accounts AccountInfo<'info>,
    mldsa_signature: &'accounts AccountInfo<'info>,
    mldsa_proof: &'accounts AccountInfo<'info>,
    cluster: u8,
    quorum_nonce: u64,
    expires_slot: u64,
    action_domain: &'data [u8; 32],
    action_hash: &'data [u8; 32],
    next_winternitz_root: &'data [u8; 32],
}

fn invoke_pq_quorum_winternitz_mldsa_proof(
    cpi: PqQuorumWinternitzMldsaCpi<'_, '_, '_>,
) -> ProgramResult {
    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 32 + 32 + 32);
    data.push(PQ_QUORUM_TAG_VERIFY_WINTERNITZ_MLDSA_PROOF);
    data.push(cpi.cluster);
    data.extend_from_slice(&cpi.quorum_nonce.to_le_bytes());
    data.extend_from_slice(&cpi.expires_slot.to_le_bytes());
    data.extend_from_slice(cpi.action_domain);
    data.extend_from_slice(cpi.action_hash);
    data.extend_from_slice(cpi.next_winternitz_root);

    let instruction = Instruction {
        program_id: *cpi.pq_quorum_program.key,
        accounts: vec![
            AccountMeta::new(*cpi.authority.key, false),
            AccountMeta::new(*cpi.quorum.key, false),
            AccountMeta::new_readonly(*cpi.falcon_key.key, false),
            AccountMeta::new_readonly(*cpi.falcon_auth_program.key, false),
            AccountMeta::new(*cpi.winternitz_signature.key, false),
            AccountMeta::new_readonly(*cpi.mldsa_public_key.key, false),
            AccountMeta::new(*cpi.mldsa_signature.key, false),
            AccountMeta::new(*cpi.mldsa_proof.key, false),
        ],
        data,
    };
    invoke(
        &instruction,
        &[
            cpi.authority.clone(),
            cpi.quorum.clone(),
            cpi.falcon_key.clone(),
            cpi.falcon_auth_program.clone(),
            cpi.winternitz_signature.clone(),
            cpi.mldsa_public_key.clone(),
            cpi.mldsa_signature.clone(),
            cpi.mldsa_proof.clone(),
            cpi.pq_quorum_program.clone(),
        ],
    )
}

fn write_smart_account_state(
    data: &mut [u8],
    bump: u8,
    authority: &[u8],
    pq_quorum_program: &[u8],
    quorum: &[u8],
    spend_count: u64,
) -> ProgramResult {
    if data.len() != SMART_ACCOUNT_LEN
        || authority.len() != 32
        || pq_quorum_program.len() != 32
        || quorum.len() != 32
    {
        return Err(ProgramError::AccountDataTooSmall);
    }
    data[..8].copy_from_slice(&SMART_ACCOUNT_DISCRIMINATOR);
    data[VERSION_OFFSET] = VERSION;
    data[BUMP_OFFSET] = bump;
    data[RESERVED_OFFSET] = 0;
    data[RESERVED_OFFSET + 1] = 0;
    data[AUTHORITY_OFFSET..PQ_QUORUM_PROGRAM_OFFSET].copy_from_slice(authority);
    data[PQ_QUORUM_PROGRAM_OFFSET..QUORUM_OFFSET].copy_from_slice(pq_quorum_program);
    data[QUORUM_OFFSET..SPEND_COUNT_OFFSET].copy_from_slice(quorum);
    data[SPEND_COUNT_OFFSET..SPEND_COUNT_OFFSET + 8].copy_from_slice(&spend_count.to_le_bytes());
    Ok(())
}

fn write_falcon_signature_buffer_header(
    data: &mut [u8],
    bump: u8,
    authority: &[u8],
    smart_account: &[u8],
    quorum: &[u8],
    quorum_nonce: u64,
) -> ProgramResult {
    if data.len() != FALCON_SIGNATURE_BUFFER_LEN
        || authority.len() != 32
        || smart_account.len() != 32
        || quorum.len() != 32
    {
        return Err(ProgramError::AccountDataTooSmall);
    }

    data[..8].copy_from_slice(&FALCON_SIGNATURE_DISCRIMINATOR);
    data[SIGBUF_VERSION_OFFSET] = VERSION;
    data[SIGBUF_BUMP_OFFSET] = bump;
    data[SIGBUF_RESERVED_OFFSET] = 0;
    data[SIGBUF_RESERVED_OFFSET + 1] = 0;
    data[SIGBUF_AUTHORITY_OFFSET..SIGBUF_SMART_ACCOUNT_OFFSET].copy_from_slice(authority);
    data[SIGBUF_SMART_ACCOUNT_OFFSET..SIGBUF_QUORUM_OFFSET].copy_from_slice(smart_account);
    data[SIGBUF_QUORUM_OFFSET..SIGBUF_QUORUM_NONCE_OFFSET].copy_from_slice(quorum);
    data[SIGBUF_QUORUM_NONCE_OFFSET..SIGBUF_WRITTEN_OFFSET]
        .copy_from_slice(&quorum_nonce.to_le_bytes());
    data[SIGBUF_WRITTEN_OFFSET..SIGBUF_DATA_OFFSET].copy_from_slice(&0u16.to_le_bytes());
    data[SIGBUF_DATA_OFFSET..].fill(0);
    Ok(())
}

fn read_falcon_signature_buffer(
    program_id: &Pubkey,
    signature_buffer: &AccountInfo,
    authority: &Pubkey,
    smart_account: &Pubkey,
    quorum: &Pubkey,
    quorum_nonce: u64,
) -> Result<[u8; FALCON_512_SIGNATURE_LEN], ProgramError> {
    let buffer_data = signature_buffer.try_borrow_data()?;
    validate_falcon_signature_buffer_header(
        program_id,
        signature_buffer.key,
        &buffer_data,
        authority,
        smart_account,
        quorum,
        quorum_nonce,
    )?;
    if read_u16(&buffer_data, SIGBUF_WRITTEN_OFFSET)? as usize != FALCON_512_SIGNATURE_LEN {
        return Err(PqSmartAccountError::InvalidSignatureBuffer.into());
    }
    let mut signature = [0u8; FALCON_512_SIGNATURE_LEN];
    signature.copy_from_slice(
        &buffer_data[SIGBUF_DATA_OFFSET..SIGBUF_DATA_OFFSET + FALCON_512_SIGNATURE_LEN],
    );
    Ok(signature)
}

fn close_falcon_signature_buffer(
    signature_buffer: &AccountInfo,
    destination: &AccountInfo,
) -> ProgramResult {
    let buffer_lamports = **signature_buffer.try_borrow_lamports()?;
    let destination_lamports = **destination.try_borrow_lamports()?;
    let next_destination_lamports = destination_lamports
        .checked_add(buffer_lamports)
        .ok_or(PqSmartAccountError::ArithmeticOverflow)?;

    **signature_buffer.try_borrow_mut_lamports()? = 0;
    **destination.try_borrow_mut_lamports()? = next_destination_lamports;
    signature_buffer.try_borrow_mut_data()?.fill(0);
    Ok(())
}

fn validate_smart_account_state(
    program_id: &Pubkey,
    smart_account: &Pubkey,
    data: &[u8],
    expected_authority: Option<&Pubkey>,
    expected_quorum: Option<(&Pubkey, &Pubkey)>,
) -> ProgramResult {
    if data.len() != SMART_ACCOUNT_LEN {
        return Err(PqSmartAccountError::InvalidAccountData.into());
    }
    if data[..8] != SMART_ACCOUNT_DISCRIMINATOR || data[VERSION_OFFSET] != VERSION {
        return Err(PqSmartAccountError::InvalidAccountData.into());
    }

    let authority = read_array::<32>(data, AUTHORITY_OFFSET)?;
    let pq_quorum_program = read_array::<32>(data, PQ_QUORUM_PROGRAM_OFFSET)?;
    let quorum = read_array::<32>(data, QUORUM_OFFSET)?;
    if expected_authority.is_some_and(|key| authority != key.as_ref()) {
        return Err(PqSmartAccountError::InvalidAccountData.into());
    }
    if expected_quorum.is_some_and(|(program, quorum_key)| {
        pq_quorum_program != program.as_ref() || quorum != quorum_key.as_ref()
    }) {
        return Err(PqSmartAccountError::InvalidQuorumProgram.into());
    }

    let seeds: [&[u8]; 4] = [SMART_ACCOUNT_SEED, authority, pq_quorum_program, quorum];
    let Some((expected_key, canonical_bump)) = Pubkey::derive_program_address(&seeds, program_id)
    else {
        return Err(PqSmartAccountError::InvalidPda.into());
    };
    if expected_key != *smart_account || canonical_bump != data[BUMP_OFFSET] {
        return Err(PqSmartAccountError::InvalidPda.into());
    }
    Ok(())
}

fn validate_falcon_signature_buffer_header(
    program_id: &Pubkey,
    signature_buffer: &Pubkey,
    data: &[u8],
    authority: &Pubkey,
    smart_account: &Pubkey,
    quorum: &Pubkey,
    quorum_nonce: u64,
) -> ProgramResult {
    if data.len() != FALCON_SIGNATURE_BUFFER_LEN
        || data[..8] != FALCON_SIGNATURE_DISCRIMINATOR
        || data[SIGBUF_VERSION_OFFSET] != VERSION
        || data[SIGBUF_RESERVED_OFFSET] != 0
        || data[SIGBUF_RESERVED_OFFSET + 1] != 0
        || &data[SIGBUF_AUTHORITY_OFFSET..SIGBUF_SMART_ACCOUNT_OFFSET] != authority.as_ref()
        || &data[SIGBUF_SMART_ACCOUNT_OFFSET..SIGBUF_QUORUM_OFFSET] != smart_account.as_ref()
        || &data[SIGBUF_QUORUM_OFFSET..SIGBUF_QUORUM_NONCE_OFFSET] != quorum.as_ref()
        || read_u64(data, SIGBUF_QUORUM_NONCE_OFFSET)? != quorum_nonce
    {
        return Err(PqSmartAccountError::InvalidSignatureBuffer.into());
    }
    validate_falcon_signature_buffer_pda(
        program_id,
        authority,
        smart_account,
        quorum,
        quorum_nonce,
        signature_buffer,
        data[SIGBUF_BUMP_OFFSET],
    )
}

fn validate_falcon_signature_buffer_pda(
    program_id: &Pubkey,
    authority: &Pubkey,
    smart_account: &Pubkey,
    quorum: &Pubkey,
    quorum_nonce: u64,
    signature_buffer: &Pubkey,
    bump: u8,
) -> ProgramResult {
    let nonce_bytes = quorum_nonce.to_le_bytes();
    let seeds: [&[u8]; 5] = [
        FALCON_SIGNATURE_SEED,
        authority.as_ref(),
        smart_account.as_ref(),
        quorum.as_ref(),
        &nonce_bytes,
    ];
    let Some((expected_buffer, canonical_bump)) =
        Pubkey::derive_program_address(&seeds, program_id)
    else {
        return Err(PqSmartAccountError::InvalidPda.into());
    };
    if expected_buffer != *signature_buffer || canonical_bump != bump {
        return Err(PqSmartAccountError::InvalidPda.into());
    }
    Ok(())
}

fn validate_smart_account_pda(
    program_id: &Pubkey,
    authority: &Pubkey,
    pq_quorum_program: &Pubkey,
    quorum: &Pubkey,
    smart_account: &Pubkey,
    bump: u8,
) -> ProgramResult {
    let seeds: [&[u8]; 4] = [
        SMART_ACCOUNT_SEED,
        authority.as_ref(),
        pq_quorum_program.as_ref(),
        quorum.as_ref(),
    ];
    let Some((expected_key, canonical_bump)) = Pubkey::derive_program_address(&seeds, program_id)
    else {
        return Err(PqSmartAccountError::InvalidPda.into());
    };
    if expected_key != *smart_account || canonical_bump != bump {
        return Err(PqSmartAccountError::InvalidPda.into());
    }
    Ok(())
}

pub fn smart_transfer_domain() -> [u8; 32] {
    SMART_TRANSFER_DOMAIN
}

pub fn smart_token_transfer_domain() -> [u8; 32] {
    SMART_TOKEN_TRANSFER_DOMAIN
}

pub fn smart_transfer_hash(
    program_id: &Pubkey,
    smart_account: &Pubkey,
    authority: &Pubkey,
    destination: &Pubkey,
    lamports: u64,
    spend_count: u64,
) -> [u8; 32] {
    let lamports_bytes = lamports.to_le_bytes();
    let spend_count_bytes = spend_count.to_le_bytes();
    hashv(&[
        b"pq-smart-account-transfer-sol-v1",
        program_id.as_ref(),
        smart_account.as_ref(),
        authority.as_ref(),
        destination.as_ref(),
        &lamports_bytes,
        &spend_count_bytes,
    ])
    .to_bytes()
}

pub struct SmartTokenTransferHashInput<'a> {
    pub program_id: &'a Pubkey,
    pub smart_account: &'a Pubkey,
    pub authority: &'a Pubkey,
    pub token_program: &'a Pubkey,
    pub source_token: &'a Pubkey,
    pub mint: &'a Pubkey,
    pub destination_token: &'a Pubkey,
    pub amount: u64,
    pub decimals: u8,
    pub spend_count: u64,
}

pub fn smart_token_transfer_hash(input: SmartTokenTransferHashInput<'_>) -> [u8; 32] {
    let amount_bytes = input.amount.to_le_bytes();
    let decimals_bytes = [input.decimals];
    let spend_count_bytes = input.spend_count.to_le_bytes();
    hashv(&[
        b"pq-smart-account-transfer-spl-v1",
        input.program_id.as_ref(),
        input.smart_account.as_ref(),
        input.authority.as_ref(),
        input.token_program.as_ref(),
        input.source_token.as_ref(),
        input.mint.as_ref(),
        input.destination_token.as_ref(),
        &amount_bytes,
        &decimals_bytes,
        &spend_count_bytes,
    ])
    .to_bytes()
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

fn read_u64(data: &[u8], offset: usize) -> Result<u64, ProgramError> {
    let bytes = read_array::<8>(data, offset)?;
    Ok(u64::from_le_bytes(*bytes))
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, ProgramError> {
    let bytes = read_array::<2>(data, offset)?;
    Ok(u16::from_le_bytes(*bytes))
}

fn read_array<const N: usize>(data: &[u8], offset: usize) -> Result<&[u8; N], ProgramError> {
    data.get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| PqSmartAccountError::InvalidInstructionData.into())
}
