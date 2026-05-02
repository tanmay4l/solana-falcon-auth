#![cfg_attr(target_os = "solana", no_std)]

use solana_falcon512::{
    FALCON_512_PREPARED_PUBKEY_LEN, FALCON_512_SIGNATURE_LEN, Falcon512PreparedPubkey,
    Falcon512Signature,
};
use solana_program::{
    account_info::{AccountInfo, next_account_info},
    clock::Clock,
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

pub const TAG_REGISTER_KEY: u8 = 0;
pub const TAG_VERIFY_ACTION: u8 = 1;
pub const TAG_ROTATE_KEY: u8 = 2;
pub const TAG_CLOSE_KEY: u8 = 3;
pub const TAG_WRITE_KEY_CHUNK: u8 = 4;
pub const TAG_FINALIZE_KEY: u8 = 5;
pub const VERSION: u8 = 1;
pub const FALCON_KEY_SEED: &[u8] = b"falcon-key";
pub const FALCON_KEY_DISCRIMINATOR: [u8; 8] = *b"FALKYA01";
pub const CLOSED_DISCRIMINATOR: [u8; 8] = [0xff; 8];
pub const FALCON_ACTION_MAGIC: [u8; 16] = *b"SOL_FALCON_ACT1!";
pub const PENDING_NONCE: u64 = u64::MAX;

pub const DISCRIMINATOR_OFFSET: usize = 0;
pub const VERSION_OFFSET: usize = 8;
pub const BUMP_OFFSET: usize = 9;
pub const AUTHORITY_OFFSET: usize = 10;
pub const NEXT_NONCE_OFFSET: usize = 42;
pub const PREPARED_PUBKEY_OFFSET: usize = 50;
pub const FALCON_KEY_ACCOUNT_LEN: usize = PREPARED_PUBKEY_OFFSET + FALCON_512_PREPARED_PUBKEY_LEN;

const REGISTER_KEY_DATA_LEN: usize = 1 + 1;
const VERIFY_ACTION_DATA_LEN: usize = 1 + 1 + 8 + 8 + 32 + 32 + FALCON_512_SIGNATURE_LEN;
const ROTATE_KEY_DATA_LEN: usize = 1;
const FALCON_ACTION_PAYLOAD_LEN: usize = 16 + 1 + 32 + 32 + 32 + 8 + 8 + 32 + 32;
const FALCON_Q: u16 = 12_289;

#[repr(u32)]
pub enum FalconAuthError {
    InvalidInstructionData = 1,
    InvalidPda = 3,
    InvalidAccountOwner = 4,
    AccountAlreadyInitialized = 5,
    InvalidAccountData = 6,
    InvalidFalconPubkey = 7,
    InvalidFalconSignature = 8,
    NonceMismatch = 9,
    ExpiredAction = 10,
    ArithmeticOverflow = 11,
    AccountClosed = 12,
}

impl From<FalconAuthError> for ProgramError {
    fn from(value: FalconAuthError) -> Self {
        ProgramError::Custom(value as u32)
    }
}

#[inline(never)]
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let Some((&tag, rest)) = instruction_data.split_first() else {
        return Err(FalconAuthError::InvalidInstructionData.into());
    };

    match tag {
        TAG_REGISTER_KEY => process_register_key(program_id, accounts, rest),
        TAG_VERIFY_ACTION => process_verify_action(program_id, accounts, rest),
        TAG_ROTATE_KEY => process_rotate_key(program_id, accounts, rest),
        TAG_CLOSE_KEY => process_close_key(program_id, accounts, rest),
        TAG_WRITE_KEY_CHUNK => process_write_key_chunk(program_id, accounts, rest),
        TAG_FINALIZE_KEY => process_finalize_key(program_id, accounts, rest),
        _ => Err(FalconAuthError::InvalidInstructionData.into()),
    }
}

#[inline(never)]
fn process_register_key(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != REGISTER_KEY_DATA_LEN - 1 {
        return Err(FalconAuthError::InvalidInstructionData.into());
    }

    let (&bump, extra) = data
        .split_first()
        .ok_or(FalconAuthError::InvalidInstructionData)?;
    if !extra.is_empty() {
        return Err(FalconAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;
    let system_program_account = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable || !falcon_key.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if falcon_key.key == authority.key {
        return Err(ProgramError::InvalidArgument);
    }

    let seeds: [&[u8]; 2] = [FALCON_KEY_SEED, authority.key.as_ref()];
    let Some((expected_key, canonical_bump)) = Pubkey::derive_program_address(&seeds, program_id)
    else {
        return Err(FalconAuthError::InvalidPda.into());
    };
    if expected_key != *falcon_key.key || canonical_bump != bump {
        return Err(FalconAuthError::InvalidPda.into());
    }

    if falcon_key.owner == program_id {
        let data = falcon_key.try_borrow_data()?;
        if data.len() >= FALCON_KEY_DISCRIMINATOR.len()
            && data[DISCRIMINATOR_OFFSET..VERSION_OFFSET] == FALCON_KEY_DISCRIMINATOR
        {
            return Err(FalconAuthError::AccountAlreadyInitialized.into());
        }
        return Err(FalconAuthError::InvalidAccountOwner.into());
    }

    if !system_program::check_id(falcon_key.owner) || !falcon_key.data_is_empty() {
        return Err(FalconAuthError::AccountAlreadyInitialized.into());
    }
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(FALCON_KEY_ACCOUNT_LEN);
    let create_account_ix = system_instruction::create_account(
        authority.key,
        falcon_key.key,
        lamports,
        FALCON_KEY_ACCOUNT_LEN as u64,
        program_id,
    );

    invoke_signed(
        &create_account_ix,
        &[
            authority.clone(),
            falcon_key.clone(),
            system_program_account.clone(),
        ],
        &[&[FALCON_KEY_SEED, authority.key.as_ref(), &[bump]]],
    )?;

    let mut account_data = falcon_key.try_borrow_mut_data()?;
    write_pending_falcon_key_account(&mut account_data, bump, authority.key.as_ref())
}

fn is_valid_prepared_pubkey(bytes: &[u8]) -> bool {
    if bytes.len() != FALCON_512_PREPARED_PUBKEY_LEN {
        return false;
    }
    for chunk in bytes.chunks_exact(2) {
        let coeff = u16::from_le_bytes([chunk[0], chunk[1]]);
        if coeff >= FALCON_Q {
            return false;
        }
    }
    true
}

#[inline(never)]
fn process_verify_action(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != VERIFY_ACTION_DATA_LEN - 1 {
        return Err(FalconAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;

    if !falcon_key.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if falcon_key.owner != program_id {
        return Err(FalconAuthError::InvalidAccountOwner.into());
    }
    if authority.key == falcon_key.key {
        return Err(ProgramError::InvalidArgument);
    }

    let cluster = data[0];
    let nonce = read_u64(data, 1)?;
    let expires_slot = read_u64(data, 9)?;
    let action_domain = read_array::<32>(data, 17)?;
    let action_hash = read_array::<32>(data, 49)?;
    let sig_bytes = read_array::<FALCON_512_SIGNATURE_LEN>(data, 81)?;

    let mut account_data = falcon_key.try_borrow_mut_data()?;
    validate_falcon_key_account(program_id, authority.key, falcon_key.key, &account_data)?;

    let stored_nonce = read_u64(&account_data, NEXT_NONCE_OFFSET)?;
    if stored_nonce == PENDING_NONCE {
        return Err(FalconAuthError::InvalidAccountData.into());
    }
    if nonce != stored_nonce {
        return Err(FalconAuthError::NonceMismatch.into());
    }

    if Clock::get()?.slot > expires_slot {
        return Err(FalconAuthError::ExpiredAction.into());
    }

    let payload = build_action_payload(ActionPayloadParts {
        cluster,
        program_id: program_id.as_ref(),
        authority: authority.key.as_ref(),
        falcon_key: falcon_key.key.as_ref(),
        nonce,
        expires_slot,
        action_domain,
        action_hash,
    });
    let signature = Falcon512Signature::from_ref(sig_bytes);
    let prepared = Falcon512PreparedPubkey::try_from_slice(
        &account_data[PREPARED_PUBKEY_OFFSET..FALCON_KEY_ACCOUNT_LEN],
    )
    .map_err(|_| FalconAuthError::InvalidFalconPubkey)?;

    if !signature.verify_with_prepared(&payload, prepared) {
        return Err(FalconAuthError::InvalidFalconSignature.into());
    }

    let next_nonce = nonce
        .checked_add(1)
        .ok_or(FalconAuthError::ArithmeticOverflow)?;
    account_data[NEXT_NONCE_OFFSET..PREPARED_PUBKEY_OFFSET]
        .copy_from_slice(&next_nonce.to_le_bytes());
    Ok(())
}

#[inline(never)]
fn process_write_key_chunk(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() < 4 {
        return Err(FalconAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable || !falcon_key.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if authority.key == falcon_key.key {
        return Err(ProgramError::InvalidArgument);
    }
    if falcon_key.owner != program_id {
        return Err(FalconAuthError::InvalidAccountOwner.into());
    }

    let offset = u16::from_le_bytes(*read_array::<2>(data, 0)?) as usize;
    let chunk = &data[2..];
    let end = offset
        .checked_add(chunk.len())
        .ok_or(FalconAuthError::ArithmeticOverflow)?;
    if !offset.is_multiple_of(2)
        || !chunk.len().is_multiple_of(2)
        || end > FALCON_512_PREPARED_PUBKEY_LEN
    {
        return Err(FalconAuthError::InvalidInstructionData.into());
    }

    let mut account_data = falcon_key.try_borrow_mut_data()?;
    validate_falcon_key_account(program_id, authority.key, falcon_key.key, &account_data)?;
    if read_u64(&account_data, NEXT_NONCE_OFFSET)? != PENDING_NONCE {
        return Err(FalconAuthError::InvalidAccountData.into());
    }

    let account_offset = PREPARED_PUBKEY_OFFSET
        .checked_add(offset)
        .ok_or(FalconAuthError::ArithmeticOverflow)?;
    account_data[account_offset..account_offset + chunk.len()].copy_from_slice(chunk);
    Ok(())
}

#[inline(never)]
fn process_finalize_key(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(FalconAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable || !falcon_key.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if authority.key == falcon_key.key {
        return Err(ProgramError::InvalidArgument);
    }
    if falcon_key.owner != program_id {
        return Err(FalconAuthError::InvalidAccountOwner.into());
    }

    let mut account_data = falcon_key.try_borrow_mut_data()?;
    validate_falcon_key_account(program_id, authority.key, falcon_key.key, &account_data)?;
    if read_u64(&account_data, NEXT_NONCE_OFFSET)? != PENDING_NONCE {
        return Err(FalconAuthError::InvalidAccountData.into());
    }
    if !is_valid_prepared_pubkey(&account_data[PREPARED_PUBKEY_OFFSET..FALCON_KEY_ACCOUNT_LEN]) {
        return Err(FalconAuthError::InvalidFalconPubkey.into());
    }

    account_data[NEXT_NONCE_OFFSET..PREPARED_PUBKEY_OFFSET].copy_from_slice(&0u64.to_le_bytes());
    Ok(())
}

#[inline(never)]
fn process_rotate_key(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != ROTATE_KEY_DATA_LEN - 1 {
        return Err(FalconAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable || !falcon_key.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if authority.key == falcon_key.key {
        return Err(ProgramError::InvalidArgument);
    }
    if falcon_key.owner != program_id {
        return Err(FalconAuthError::InvalidAccountOwner.into());
    }
    if !data.is_empty() {
        return Err(FalconAuthError::InvalidInstructionData.into());
    }

    let mut account_data = falcon_key.try_borrow_mut_data()?;
    validate_falcon_key_account(program_id, authority.key, falcon_key.key, &account_data)?;
    if read_u64(&account_data, NEXT_NONCE_OFFSET)? == PENDING_NONCE {
        return Err(FalconAuthError::InvalidAccountData.into());
    }
    account_data[NEXT_NONCE_OFFSET..PREPARED_PUBKEY_OFFSET]
        .copy_from_slice(&PENDING_NONCE.to_le_bytes());
    account_data[PREPARED_PUBKEY_OFFSET..FALCON_KEY_ACCOUNT_LEN].fill(0xff);
    Ok(())
}

#[inline(never)]
fn process_close_key(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(FalconAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable || !falcon_key.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if authority.key == falcon_key.key {
        return Err(ProgramError::InvalidArgument);
    }
    if falcon_key.owner != program_id {
        return Err(FalconAuthError::InvalidAccountOwner.into());
    }

    {
        let mut account_data = falcon_key.try_borrow_mut_data()?;
        validate_falcon_key_account(program_id, authority.key, falcon_key.key, &account_data)?;
        account_data[DISCRIMINATOR_OFFSET..VERSION_OFFSET].copy_from_slice(&CLOSED_DISCRIMINATOR);
    }

    let falcon_lamports = **falcon_key.try_borrow_lamports()?;
    let authority_lamports = **authority.try_borrow_lamports()?;
    let new_authority_lamports = authority_lamports
        .checked_add(falcon_lamports)
        .ok_or(FalconAuthError::ArithmeticOverflow)?;
    **authority.try_borrow_mut_lamports()? = new_authority_lamports;
    **falcon_key.try_borrow_mut_lamports()? = 0;
    Ok(())
}

fn validate_falcon_key_account(
    program_id: &Pubkey,
    authority: &Pubkey,
    falcon_key: &Pubkey,
    data: &[u8],
) -> ProgramResult {
    if data.len() != FALCON_KEY_ACCOUNT_LEN {
        return Err(FalconAuthError::InvalidAccountData.into());
    }
    if data[DISCRIMINATOR_OFFSET..VERSION_OFFSET] != FALCON_KEY_DISCRIMINATOR {
        if data[DISCRIMINATOR_OFFSET..VERSION_OFFSET] == CLOSED_DISCRIMINATOR {
            return Err(FalconAuthError::AccountClosed.into());
        }
        return Err(FalconAuthError::InvalidAccountData.into());
    }
    if data[VERSION_OFFSET] != VERSION {
        return Err(FalconAuthError::InvalidAccountData.into());
    }
    if &data[AUTHORITY_OFFSET..NEXT_NONCE_OFFSET] != authority.as_ref() {
        return Err(FalconAuthError::InvalidAccountData.into());
    }

    let stored_bump = data[BUMP_OFFSET];
    let seeds: [&[u8]; 2] = [FALCON_KEY_SEED, authority.as_ref()];
    let Some((expected_key, canonical_bump)) = Pubkey::derive_program_address(&seeds, program_id)
    else {
        return Err(FalconAuthError::InvalidPda.into());
    };
    if expected_key != *falcon_key || canonical_bump != stored_bump {
        return Err(FalconAuthError::InvalidPda.into());
    }

    Ok(())
}

struct ActionPayloadParts<'a> {
    cluster: u8,
    program_id: &'a [u8],
    authority: &'a [u8],
    falcon_key: &'a [u8],
    nonce: u64,
    expires_slot: u64,
    action_domain: &'a [u8; 32],
    action_hash: &'a [u8; 32],
}

fn build_action_payload(parts: ActionPayloadParts<'_>) -> [u8; FALCON_ACTION_PAYLOAD_LEN] {
    let mut out = [0u8; FALCON_ACTION_PAYLOAD_LEN];
    out[0..16].copy_from_slice(&FALCON_ACTION_MAGIC);
    out[16] = parts.cluster;
    out[17..49].copy_from_slice(parts.program_id);
    out[49..81].copy_from_slice(parts.authority);
    out[81..113].copy_from_slice(parts.falcon_key);
    out[113..121].copy_from_slice(&parts.nonce.to_le_bytes());
    out[121..129].copy_from_slice(&parts.expires_slot.to_le_bytes());
    out[129..161].copy_from_slice(parts.action_domain);
    out[161..193].copy_from_slice(parts.action_hash);
    out
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, ProgramError> {
    let bytes = read_array::<8>(data, offset)?;
    Ok(u64::from_le_bytes(*bytes))
}

fn read_array<const N: usize>(data: &[u8], offset: usize) -> Result<&[u8; N], ProgramError> {
    data.get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| FalconAuthError::InvalidInstructionData.into())
}

fn write_pending_falcon_key_account(
    account_data: &mut [u8],
    bump: u8,
    authority: &[u8],
) -> ProgramResult {
    if account_data.len() != FALCON_KEY_ACCOUNT_LEN || authority.len() != 32 {
        return Err(ProgramError::AccountDataTooSmall);
    }

    account_data[DISCRIMINATOR_OFFSET..VERSION_OFFSET].copy_from_slice(&FALCON_KEY_DISCRIMINATOR);
    account_data[VERSION_OFFSET] = VERSION;
    account_data[BUMP_OFFSET] = bump;
    account_data[AUTHORITY_OFFSET..NEXT_NONCE_OFFSET].copy_from_slice(authority);
    account_data[NEXT_NONCE_OFFSET..PREPARED_PUBKEY_OFFSET]
        .copy_from_slice(&PENDING_NONCE.to_le_bytes());
    account_data[PREPARED_PUBKEY_OFFSET..FALCON_KEY_ACCOUNT_LEN].fill(0xff);

    Ok(())
}
