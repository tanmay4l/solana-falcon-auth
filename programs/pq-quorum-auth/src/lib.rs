#![cfg_attr(target_os = "solana", no_std)]

#[cfg(target_os = "solana")]
extern crate alloc;

#[cfg(target_os = "solana")]
use alloc::{vec, vec::Vec};

use solana_nostd_keccak::{hash as keccak_hash, hashv as keccak_hashv};
use solana_program::{
    account_info::{AccountInfo, next_account_info},
    clock::Clock,
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

mod mldsa44;

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

pub const TAG_REGISTER_QUORUM: u8 = 0;
pub const TAG_VERIFY_FALCON_WINTERNITZ: u8 = 1;
pub const TAG_VERIFY_DILITHIUM_UNSUPPORTED: u8 = 2;
pub const TAG_INIT_WINTERNITZ_SIGNATURE: u8 = 3;
pub const TAG_WRITE_WINTERNITZ_SIGNATURE_CHUNK: u8 = 4;
pub const TAG_INIT_MLDSA_PUBLIC_KEY: u8 = 5;
pub const TAG_WRITE_MLDSA_PUBLIC_KEY_CHUNK: u8 = 6;
pub const TAG_INIT_MLDSA_SIGNATURE: u8 = 7;
pub const TAG_WRITE_MLDSA_SIGNATURE_CHUNK: u8 = 8;
pub const TAG_FINALIZE_MLDSA_PUBLIC_KEY: u8 = 11;
pub const TAG_INIT_MLDSA_PROOF: u8 = 12;
pub const TAG_PROVE_MLDSA_COLUMN: u8 = 13;
pub const TAG_VERIFY_FALCON_MLDSA_PROOF: u8 = 14;
pub const TAG_VERIFY_WINTERNITZ_MLDSA_PROOF: u8 = 15;
pub const TAG_PREPARE_MLDSA_PROOF: u8 = 16;
pub const TAG_FINALIZE_MLDSA_ROW: u8 = 17;
pub const TAG_PREPARE_MLDSA_Z_COLUMN: u8 = 18;
pub const FALCON_AUTH_TAG_VERIFY_ACTION: u8 = 1;
pub const VERSION: u8 = 1;
pub const QUORUM_SEED: &[u8] = b"pq-quorum";
pub const FALCON_KEY_SEED: &[u8] = b"falcon-key";
pub const WINTERNITZ_SIGNATURE_SEED: &[u8] = b"wots-sig";
pub const MLDSA_PUBLIC_KEY_SEED: &[u8] = b"mldsa-key";
pub const MLDSA_SIGNATURE_SEED: &[u8] = b"mldsa-sig";
pub const MLDSA_PROOF_SEED: &[u8] = b"mldsa-proof";
pub const QUORUM_DISCRIMINATOR: [u8; 8] = *b"PQQRM001";
pub const WINTERNITZ_SIGNATURE_DISCRIMINATOR: [u8; 8] = *b"WOTSIG01";
pub const MLDSA_PUBLIC_KEY_DISCRIMINATOR: [u8; 8] = *b"MLDSAPK1";
pub const MLDSA_SIGNATURE_DISCRIMINATOR: [u8; 8] = *b"MLDSASG1";
pub const MLDSA_PROOF_DISCRIMINATOR: [u8; 8] = *b"MLDSAPF1";
pub const QUORUM_ACTION_MAGIC: [u8; 16] = *b"PQ_QUORUM_ACT1!!";
pub const QUORUM_ACTION_V2_MAGIC: [u8; 16] = *b"PQ_QUORUM_ACT2!!";
pub const QUORUM_MODE_FALCON_MLDSA: u8 = 0b101;
pub const QUORUM_MODE_WINTERNITZ_MLDSA: u8 = 0b110;
pub const FALCON_512_SIGNATURE_LEN: usize = 666;
pub const WINTERNITZ_SIGNATURE_LEN: usize = WOTS16_LEN * WOTS16_N;

const WOTS16_N: usize = 32;
const WOTS16_W: u8 = 16;
const WOTS16_LEN1: usize = 64;
const WOTS16_LEN2: usize = 3;
const WOTS16_LEN: usize = WOTS16_LEN1 + WOTS16_LEN2;
const WOTS16_MAX_DIGIT: u8 = WOTS16_W - 1;

const VERSION_OFFSET: usize = 8;
const BUMP_OFFSET: usize = 9;
const CLUSTER_OFFSET: usize = 10;
const RESERVED_OFFSET: usize = 11;
const AUTHORITY_OFFSET: usize = 12;
const FALCON_AUTH_PROGRAM_OFFSET: usize = 44;
const FALCON_KEY_OFFSET: usize = 76;
const WINTERNITZ_ROOT_OFFSET: usize = 108;
const NEXT_NONCE_OFFSET: usize = 140;
const QUORUM_ACCOUNT_LEN: usize = 148;

const SIGBUF_VERSION_OFFSET: usize = 8;
const SIGBUF_BUMP_OFFSET: usize = 9;
const SIGBUF_RESERVED_OFFSET: usize = 10;
const SIGBUF_AUTHORITY_OFFSET: usize = 12;
const SIGBUF_QUORUM_OFFSET: usize = 44;
const SIGBUF_NONCE_OFFSET: usize = 76;
const SIGBUF_WRITTEN_OFFSET: usize = 84;
const SIGBUF_DATA_OFFSET: usize = 86;
const WINTERNITZ_SIGNATURE_BUFFER_LEN: usize = SIGBUF_DATA_OFFSET + WINTERNITZ_SIGNATURE_LEN;
const MLDSA_PUBLIC_KEY_BUFFER_LEN: usize =
    SIGBUF_DATA_OFFSET + mldsa44::MLDSA44_PREPARED_PUBLIC_KEY_LEN;
const MLDSA_SIGNATURE_BUFFER_LEN: usize = SIGBUF_DATA_OFFSET + mldsa44::MLDSA44_SIGNATURE_LEN;

const PROOF_VERSION_OFFSET: usize = 8;
const PROOF_BUMP_OFFSET: usize = 9;
const PROOF_ROW_MASK_OFFSET: usize = 10;
const PROOF_MODE_OFFSET: usize = 11;
const PROOF_AUTHORITY_OFFSET: usize = 12;
const PROOF_QUORUM_OFFSET: usize = 44;
const PROOF_NONCE_OFFSET: usize = 76;
const PROOF_MLDSA_PUBLIC_KEY_OFFSET: usize = 84;
const PROOF_MLDSA_SIGNATURE_OFFSET: usize = 116;
const PROOF_PAYLOAD_HASH_OFFSET: usize = 148;
const PROOF_W1_OFFSET: usize = 180;
const PROOF_PREPARED_FLAG_OFFSET: usize = PROOF_W1_OFFSET + mldsa44::MLDSA44_W1_LEN;
const PROOF_Z_MASK_OFFSET: usize = PROOF_PREPARED_FLAG_OFFSET + 1;
const PROOF_COLUMN_MASK_OFFSET: usize = PROOF_Z_MASK_OFFSET + 1;
const PROOF_PREPARED_SIGNATURE_OFFSET: usize = PROOF_COLUMN_MASK_OFFSET + mldsa44::MLDSA44_ROWS;
const PROOF_AZ_OFFSET: usize =
    PROOF_PREPARED_SIGNATURE_OFFSET + mldsa44::MLDSA44_PREPARED_SIGNATURE_LEN;
const MLDSA_PROOF_ACCOUNT_LEN: usize =
    PROOF_AZ_OFFSET + mldsa44::MLDSA44_ROWS * mldsa44::MLDSA44_AZ_ROW_LEN;
const MLDSA_PROOF_COMPLETE_MASK: u8 = (1 << mldsa44::MLDSA44_ROWS) - 1;
const MLDSA_PROOF_COLUMN_COMPLETE_MASK: u8 = (1 << mldsa44::MLDSA44_COLUMNS) - 1;

const REGISTER_QUORUM_DATA_LEN: usize = 1 + 1 + 1 + 32;
const VERIFY_FALCON_WINTERNITZ_DATA_LEN: usize =
    1 + 1 + 8 + 8 + 8 + 32 + 32 + 32 + FALCON_512_SIGNATURE_LEN;
const INIT_WINTERNITZ_SIGNATURE_DATA_LEN: usize = 1 + 1 + 8;
const INIT_MLDSA_PUBLIC_KEY_DATA_LEN: usize = 1 + 1;
const INIT_MLDSA_SIGNATURE_DATA_LEN: usize = 1 + 1 + 8;
const VERIFY_FALCON_MLDSA_DATA_LEN: usize = 1 + 1 + 8 + 8 + 8 + 32 + 32 + FALCON_512_SIGNATURE_LEN;
const VERIFY_WINTERNITZ_MLDSA_DATA_LEN: usize = 1 + 1 + 8 + 8 + 32 + 32 + 32;
const INIT_MLDSA_PROOF_DATA_LEN: usize = 1 + 1 + 1 + 8 + 32;
const PREPARE_MLDSA_PROOF_DATA_LEN: usize = 1;
const PREPARE_MLDSA_Z_COLUMN_DATA_LEN: usize = 1 + 1;
const PROVE_MLDSA_COLUMN_DATA_LEN: usize = 1 + 1 + 1;
const FINALIZE_MLDSA_ROW_DATA_LEN: usize = 1 + 1;
const QUORUM_ACTION_PAYLOAD_LEN: usize = 16 + 1 + 32 + 32 + 32 + 8 + 8 + 32 + 32 + 32;
const QUORUM_ACTION_V2_PAYLOAD_LEN: usize =
    16 + 1 + 1 + 32 + 32 + 32 + 32 + 8 + 8 + 32 + 32 + 32 + 32;

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum PqQuorumAuthError {
    InvalidInstructionData = 1,
    InvalidAccountOwner = 2,
    InvalidAccountData = 3,
    InvalidPda = 4,
    InvalidFalconAuthProgram = 5,
    InvalidWinternitzSignature = 6,
    NonceMismatch = 7,
    ExpiredAction = 8,
    ArithmeticOverflow = 9,
    UnsupportedScheme = 10,
    ClusterMismatch = 11,
    InvalidWinternitzRoot = 12,
    InvalidSignatureBuffer = 13,
    InvalidMldsaPublicKey = 14,
    InvalidMldsaSignature = 15,
    InvalidMldsaProof = 16,
}

impl From<PqQuorumAuthError> for ProgramError {
    fn from(value: PqQuorumAuthError) -> Self {
        ProgramError::Custom(value as u32)
    }
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let Some((&tag, rest)) = instruction_data.split_first() else {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    };

    match tag {
        TAG_REGISTER_QUORUM => process_register_quorum(program_id, accounts, rest),
        TAG_VERIFY_FALCON_WINTERNITZ => {
            process_verify_falcon_winternitz(program_id, accounts, rest)
        }
        TAG_VERIFY_DILITHIUM_UNSUPPORTED => Err(PqQuorumAuthError::UnsupportedScheme.into()),
        TAG_INIT_WINTERNITZ_SIGNATURE => {
            process_init_winternitz_signature(program_id, accounts, rest)
        }
        TAG_WRITE_WINTERNITZ_SIGNATURE_CHUNK => {
            process_write_winternitz_signature_chunk(program_id, accounts, rest)
        }
        TAG_INIT_MLDSA_PUBLIC_KEY => process_init_mldsa_public_key(program_id, accounts, rest),
        TAG_WRITE_MLDSA_PUBLIC_KEY_CHUNK => {
            process_write_mldsa_public_key_chunk(program_id, accounts, rest)
        }
        TAG_INIT_MLDSA_SIGNATURE => process_init_mldsa_signature(program_id, accounts, rest),
        TAG_WRITE_MLDSA_SIGNATURE_CHUNK => {
            process_write_mldsa_signature_chunk(program_id, accounts, rest)
        }
        TAG_FINALIZE_MLDSA_PUBLIC_KEY => {
            process_finalize_mldsa_public_key(program_id, accounts, rest)
        }
        TAG_INIT_MLDSA_PROOF => process_init_mldsa_proof(program_id, accounts, rest),
        TAG_PREPARE_MLDSA_PROOF => process_prepare_mldsa_proof(program_id, accounts, rest),
        TAG_PREPARE_MLDSA_Z_COLUMN => process_prepare_mldsa_z_column(program_id, accounts, rest),
        TAG_PROVE_MLDSA_COLUMN => process_prove_mldsa_column(program_id, accounts, rest),
        TAG_FINALIZE_MLDSA_ROW => process_finalize_mldsa_row(program_id, accounts, rest),
        TAG_VERIFY_FALCON_MLDSA_PROOF => {
            process_verify_falcon_mldsa_proof(program_id, accounts, rest)
        }
        TAG_VERIFY_WINTERNITZ_MLDSA_PROOF => {
            process_verify_winternitz_mldsa_proof(program_id, accounts, rest)
        }
        _ => Err(PqQuorumAuthError::InvalidInstructionData.into()),
    }
}

fn process_register_quorum(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != REGISTER_QUORUM_DATA_LEN - 1 {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let bump = data[0];
    let cluster = data[1];
    let winternitz_root = read_array::<32>(data, 2)?;

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;
    let system_program_account = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable || !quorum.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !falcon_auth_program.executable {
        return Err(PqQuorumAuthError::InvalidFalconAuthProgram.into());
    }
    if !system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if quorum.key == authority.key
        || quorum.key == falcon_key.key
        || quorum.key == falcon_auth_program.key
        || falcon_key.key == falcon_auth_program.key
    {
        return Err(ProgramError::InvalidArgument);
    }

    validate_quorum_pda(
        program_id,
        authority.key,
        falcon_auth_program.key,
        quorum.key,
        bump,
    )?;
    validate_falcon_key_pda(falcon_auth_program.key, authority.key, falcon_key.key)?;
    if falcon_key.owner != falcon_auth_program.key {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }
    if !system_program::check_id(quorum.owner) || !quorum.data_is_empty() {
        return Err(PqQuorumAuthError::InvalidAccountData.into());
    }

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(QUORUM_ACCOUNT_LEN);
    let create_account_ix = system_instruction::create_account(
        authority.key,
        quorum.key,
        lamports,
        QUORUM_ACCOUNT_LEN as u64,
        program_id,
    );
    invoke_signed(
        &create_account_ix,
        &[
            authority.clone(),
            quorum.clone(),
            system_program_account.clone(),
        ],
        &[&[
            QUORUM_SEED,
            authority.key.as_ref(),
            falcon_auth_program.key.as_ref(),
            &[bump],
        ]],
    )?;

    let mut quorum_data = quorum.try_borrow_mut_data()?;
    write_quorum_state(QuorumStateWrite {
        data: &mut quorum_data,
        bump,
        cluster,
        authority: authority.key.as_ref(),
        falcon_auth_program: falcon_auth_program.key.as_ref(),
        falcon_key: falcon_key.key.as_ref(),
        winternitz_root,
        next_nonce: 0,
    })
}

fn process_verify_falcon_winternitz(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != VERIFY_FALCON_WINTERNITZ_DATA_LEN - 1 {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;
    let winternitz_signature = next_account_info(account_iter)?;

    if !authority.is_writable
        || !quorum.is_writable
        || !falcon_key.is_writable
        || !winternitz_signature.is_writable
    {
        return Err(ProgramError::InvalidAccountData);
    }
    if quorum.owner != program_id {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }
    if !falcon_auth_program.executable {
        return Err(PqQuorumAuthError::InvalidFalconAuthProgram.into());
    }
    reject_duplicate_runtime_accounts(&[
        authority.key,
        quorum.key,
        falcon_key.key,
        falcon_auth_program.key,
        winternitz_signature.key,
    ])?;

    let cluster = data[0];
    let quorum_nonce = read_u64(data, 1)?;
    let falcon_nonce = read_u64(data, 9)?;
    let expires_slot = read_u64(data, 17)?;
    let target_action_domain = read_array::<32>(data, 25)?;
    let target_action_hash = read_array::<32>(data, 57)?;
    let next_winternitz_root = read_array::<32>(data, 89)?;
    let falcon_signature = read_array::<FALCON_512_SIGNATURE_LEN>(data, 121)?;

    if Clock::get()?.slot > expires_slot {
        return Err(PqQuorumAuthError::ExpiredAction.into());
    }

    let state = {
        let quorum_data = quorum.try_borrow_data()?;
        validate_quorum_state(
            program_id,
            authority.key,
            quorum.key,
            falcon_auth_program.key,
            falcon_key.key,
            &quorum_data,
        )?
    };
    if state.cluster != cluster {
        return Err(PqQuorumAuthError::ClusterMismatch.into());
    }
    if state.next_nonce != quorum_nonce {
        return Err(PqQuorumAuthError::NonceMismatch.into());
    }
    if next_winternitz_root == &state.winternitz_root {
        return Err(PqQuorumAuthError::InvalidWinternitzRoot.into());
    }

    let payload = build_quorum_action_payload(QuorumPayloadParts {
        cluster,
        program_id: program_id.as_ref(),
        authority: authority.key.as_ref(),
        quorum: quorum.key.as_ref(),
        quorum_nonce,
        expires_slot,
        action_domain: target_action_domain,
        action_hash: target_action_hash,
        next_winternitz_root,
    });
    let close_signature_buffer = verify_winternitz_signature(
        program_id,
        authority.key,
        quorum.key,
        quorum_nonce,
        winternitz_signature,
        &payload,
        &state.winternitz_root,
    )?;

    let falcon_action_domain = pq_quorum_falcon_domain();
    let falcon_action_hash = pq_quorum_falcon_action_hash(&payload);
    invoke_falcon_auth(FalconAuthCpi {
        falcon_auth_program,
        authority,
        falcon_key,
        cluster,
        nonce: falcon_nonce,
        expires_slot,
        action_domain: &falcon_action_domain,
        action_hash: &falcon_action_hash,
        signature: falcon_signature,
    })?;

    let next_nonce = quorum_nonce
        .checked_add(1)
        .ok_or(PqQuorumAuthError::ArithmeticOverflow)?;
    {
        let mut quorum_data = quorum.try_borrow_mut_data()?;
        validate_quorum_state(
            program_id,
            authority.key,
            quorum.key,
            falcon_auth_program.key,
            falcon_key.key,
            &quorum_data,
        )?;
        if read_u64(&quorum_data, NEXT_NONCE_OFFSET)? != quorum_nonce {
            return Err(PqQuorumAuthError::NonceMismatch.into());
        }
        quorum_data[WINTERNITZ_ROOT_OFFSET..NEXT_NONCE_OFFSET]
            .copy_from_slice(next_winternitz_root);
        quorum_data[NEXT_NONCE_OFFSET..NEXT_NONCE_OFFSET + 8]
            .copy_from_slice(&next_nonce.to_le_bytes());
    }

    if close_signature_buffer {
        close_program_account_to_authority(winternitz_signature, authority)?;
    }

    Ok(())
}

fn process_init_winternitz_signature(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != INIT_WINTERNITZ_SIGNATURE_DATA_LEN - 1 {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let bump = data[0];
    let quorum_nonce = read_u64(data, 1)?;

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let signature_buffer = next_account_info(account_iter)?;
    let system_program_account = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable || !signature_buffer.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if quorum.owner != program_id {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }
    validate_quorum_authority(authority.key, quorum)?;
    validate_signature_buffer_pda(
        program_id,
        authority.key,
        quorum.key,
        quorum_nonce,
        signature_buffer.key,
        bump,
    )?;
    if !system_program::check_id(signature_buffer.owner) || !signature_buffer.data_is_empty() {
        return Err(PqQuorumAuthError::InvalidSignatureBuffer.into());
    }

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(WINTERNITZ_SIGNATURE_BUFFER_LEN);
    let create_account_ix = system_instruction::create_account(
        authority.key,
        signature_buffer.key,
        lamports,
        WINTERNITZ_SIGNATURE_BUFFER_LEN as u64,
        program_id,
    );
    let quorum_nonce_bytes = quorum_nonce.to_le_bytes();
    invoke_signed(
        &create_account_ix,
        &[
            authority.clone(),
            signature_buffer.clone(),
            system_program_account.clone(),
        ],
        &[&[
            WINTERNITZ_SIGNATURE_SEED,
            authority.key.as_ref(),
            quorum.key.as_ref(),
            &quorum_nonce_bytes,
            &[bump],
        ]],
    )?;

    let mut buffer_data = signature_buffer.try_borrow_mut_data()?;
    write_signature_buffer_header(
        &mut buffer_data,
        bump,
        authority.key.as_ref(),
        quorum.key.as_ref(),
        quorum_nonce,
    )
}

fn process_write_winternitz_signature_chunk(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() < 10 {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let quorum_nonce = read_u64(data, 0)?;
    let offset = read_u16(data, 8)? as usize;
    let chunk = &data[10..];
    if chunk.is_empty() || chunk.len() > WINTERNITZ_SIGNATURE_LEN {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let signature_buffer = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !signature_buffer.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if quorum.owner != program_id || signature_buffer.owner != program_id {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }

    validate_quorum_authority(authority.key, quorum)?;
    let mut buffer_data = signature_buffer.try_borrow_mut_data()?;
    validate_signature_buffer_header(
        program_id,
        authority.key,
        quorum.key,
        quorum_nonce,
        signature_buffer.key,
        &buffer_data,
    )?;

    let written = read_u16(&buffer_data, SIGBUF_WRITTEN_OFFSET)? as usize;
    let end = offset
        .checked_add(chunk.len())
        .ok_or(PqQuorumAuthError::ArithmeticOverflow)?;
    if offset != written || end > WINTERNITZ_SIGNATURE_LEN {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let account_offset = SIGBUF_DATA_OFFSET
        .checked_add(offset)
        .ok_or(PqQuorumAuthError::ArithmeticOverflow)?;
    buffer_data[account_offset..account_offset + chunk.len()].copy_from_slice(chunk);
    buffer_data[SIGBUF_WRITTEN_OFFSET..SIGBUF_WRITTEN_OFFSET + 2]
        .copy_from_slice(&(end as u16).to_le_bytes());
    Ok(())
}

fn process_init_mldsa_public_key(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != INIT_MLDSA_PUBLIC_KEY_DATA_LEN - 1 {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let bump = data[0];
    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let public_key_buffer = next_account_info(account_iter)?;
    let system_program_account = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable || !public_key_buffer.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if quorum.owner != program_id {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }
    validate_quorum_authority(authority.key, quorum)?;
    validate_mldsa_public_key_pda(
        program_id,
        authority.key,
        quorum.key,
        public_key_buffer.key,
        bump,
    )?;
    if !system_program::check_id(public_key_buffer.owner) || !public_key_buffer.data_is_empty() {
        return Err(PqQuorumAuthError::InvalidMldsaPublicKey.into());
    }

    create_pda_buffer(CreatePdaBuffer {
        program_id,
        payer: authority,
        buffer: public_key_buffer,
        system_program: system_program_account,
        len: MLDSA_PUBLIC_KEY_BUFFER_LEN,
        seeds: &[
            MLDSA_PUBLIC_KEY_SEED,
            authority.key.as_ref(),
            quorum.key.as_ref(),
            &[bump],
        ],
    })?;

    let mut buffer_data = public_key_buffer.try_borrow_mut_data()?;
    write_mldsa_buffer_header(
        &mut buffer_data,
        MLDSA_PUBLIC_KEY_DISCRIMINATOR,
        bump,
        authority.key.as_ref(),
        quorum.key.as_ref(),
        0,
    )
}

fn process_write_mldsa_public_key_chunk(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    process_write_mldsa_buffer_chunk(WriteMldsaBufferChunk {
        program_id,
        accounts,
        data,
        discriminator: MLDSA_PUBLIC_KEY_DISCRIMINATOR,
        seed: MLDSA_PUBLIC_KEY_SEED,
        expected_len: MLDSA_PUBLIC_KEY_BUFFER_LEN,
        payload_len: mldsa44::MLDSA44_PUBLIC_KEY_LEN,
        quorum_nonce: 0,
        require_nonce: false,
        error: PqQuorumAuthError::InvalidMldsaPublicKey,
    })
}

fn process_finalize_mldsa_public_key(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let public_key_buffer = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !public_key_buffer.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if quorum.owner != program_id || public_key_buffer.owner != program_id {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }
    validate_quorum_authority(authority.key, quorum)?;

    let mut buffer_data = public_key_buffer.try_borrow_mut_data()?;
    validate_mldsa_buffer_header(MldsaBufferHeaderCheck {
        program_id,
        authority: authority.key,
        quorum: quorum.key,
        quorum_nonce: 0,
        buffer: public_key_buffer.key,
        data: &buffer_data,
        discriminator: MLDSA_PUBLIC_KEY_DISCRIMINATOR,
        seed: MLDSA_PUBLIC_KEY_SEED,
        expected_len: MLDSA_PUBLIC_KEY_BUFFER_LEN,
        require_nonce: false,
        error: PqQuorumAuthError::InvalidMldsaPublicKey,
    })?;
    if read_u16(&buffer_data, SIGBUF_WRITTEN_OFFSET)? as usize != mldsa44::MLDSA44_PUBLIC_KEY_LEN {
        return Err(PqQuorumAuthError::InvalidMldsaPublicKey.into());
    }

    let raw_public_key: [u8; mldsa44::MLDSA44_PUBLIC_KEY_LEN] = buffer_data
        [SIGBUF_DATA_OFFSET..SIGBUF_DATA_OFFSET + mldsa44::MLDSA44_PUBLIC_KEY_LEN]
        .try_into()
        .map_err(|_| PqQuorumAuthError::InvalidMldsaPublicKey)?;
    let mut prepared = vec![0u8; mldsa44::MLDSA44_PREPARED_PUBLIC_KEY_LEN];
    if !mldsa44::prepare_mldsa44_public_key(&raw_public_key, &mut prepared) {
        return Err(PqQuorumAuthError::InvalidMldsaPublicKey.into());
    }
    buffer_data[SIGBUF_DATA_OFFSET..SIGBUF_DATA_OFFSET + mldsa44::MLDSA44_PREPARED_PUBLIC_KEY_LEN]
        .copy_from_slice(&prepared);
    buffer_data[SIGBUF_WRITTEN_OFFSET..SIGBUF_WRITTEN_OFFSET + 2]
        .copy_from_slice(&(mldsa44::MLDSA44_PREPARED_PUBLIC_KEY_LEN as u16).to_le_bytes());
    Ok(())
}

fn process_init_mldsa_signature(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != INIT_MLDSA_SIGNATURE_DATA_LEN - 1 {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let bump = data[0];
    let quorum_nonce = read_u64(data, 1)?;
    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let signature_buffer = next_account_info(account_iter)?;
    let system_program_account = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable || !signature_buffer.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if quorum.owner != program_id {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }
    validate_quorum_authority(authority.key, quorum)?;
    validate_mldsa_signature_pda(
        program_id,
        authority.key,
        quorum.key,
        quorum_nonce,
        signature_buffer.key,
        bump,
    )?;
    if !system_program::check_id(signature_buffer.owner) || !signature_buffer.data_is_empty() {
        return Err(PqQuorumAuthError::InvalidMldsaSignature.into());
    }

    let nonce_bytes = quorum_nonce.to_le_bytes();
    create_pda_buffer(CreatePdaBuffer {
        program_id,
        payer: authority,
        buffer: signature_buffer,
        system_program: system_program_account,
        len: MLDSA_SIGNATURE_BUFFER_LEN,
        seeds: &[
            MLDSA_SIGNATURE_SEED,
            authority.key.as_ref(),
            quorum.key.as_ref(),
            &nonce_bytes,
            &[bump],
        ],
    })?;

    let mut buffer_data = signature_buffer.try_borrow_mut_data()?;
    write_mldsa_buffer_header(
        &mut buffer_data,
        MLDSA_SIGNATURE_DISCRIMINATOR,
        bump,
        authority.key.as_ref(),
        quorum.key.as_ref(),
        quorum_nonce,
    )
}

fn process_write_mldsa_signature_chunk(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() < 10 {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }
    let quorum_nonce = read_u64(data, 0)?;
    process_write_mldsa_buffer_chunk(WriteMldsaBufferChunk {
        program_id,
        accounts,
        data,
        discriminator: MLDSA_SIGNATURE_DISCRIMINATOR,
        seed: MLDSA_SIGNATURE_SEED,
        expected_len: MLDSA_SIGNATURE_BUFFER_LEN,
        payload_len: mldsa44::MLDSA44_SIGNATURE_LEN,
        quorum_nonce,
        require_nonce: true,
        error: PqQuorumAuthError::InvalidMldsaSignature,
    })
}

fn process_init_mldsa_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != INIT_MLDSA_PROOF_DATA_LEN - 1 {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let bump = data[0];
    let mode = data[1];
    let quorum_nonce = read_u64(data, 2)?;
    let payload_hash = read_array::<32>(data, 10)?;
    if !is_mldsa_quorum_mode(mode) {
        return Err(PqQuorumAuthError::InvalidMldsaProof.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let proof = next_account_info(account_iter)?;
    let mldsa_public_key = next_account_info(account_iter)?;
    let mldsa_signature = next_account_info(account_iter)?;
    let system_program_account = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable || !proof.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if quorum.owner != program_id
        || mldsa_public_key.owner != program_id
        || mldsa_signature.owner != program_id
    {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }
    reject_duplicate_runtime_accounts(&[
        authority.key,
        quorum.key,
        proof.key,
        mldsa_public_key.key,
        mldsa_signature.key,
        system_program_account.key,
    ])?;
    validate_quorum_authority(authority.key, quorum)?;
    validate_mldsa_proof_pda(
        program_id,
        authority.key,
        quorum.key,
        quorum_nonce,
        proof.key,
        bump,
    )?;
    validate_mldsa_buffer_accounts(
        program_id,
        authority.key,
        quorum.key,
        quorum_nonce,
        mldsa_public_key,
        mldsa_signature,
    )?;
    if !system_program::check_id(proof.owner) || !proof.data_is_empty() {
        return Err(PqQuorumAuthError::InvalidMldsaProof.into());
    }

    let nonce_bytes = quorum_nonce.to_le_bytes();
    create_pda_buffer(CreatePdaBuffer {
        program_id,
        payer: authority,
        buffer: proof,
        system_program: system_program_account,
        len: MLDSA_PROOF_ACCOUNT_LEN,
        seeds: &[
            MLDSA_PROOF_SEED,
            authority.key.as_ref(),
            quorum.key.as_ref(),
            &nonce_bytes,
            &[bump],
        ],
    })?;

    let mut proof_data = proof.try_borrow_mut_data()?;
    write_mldsa_proof_state(MldsaProofStateWrite {
        data: &mut proof_data,
        bump,
        mode,
        authority: authority.key.as_ref(),
        quorum: quorum.key.as_ref(),
        quorum_nonce,
        mldsa_public_key: mldsa_public_key.key.as_ref(),
        mldsa_signature: mldsa_signature.key.as_ref(),
        payload_hash,
    })
}

fn process_prepare_mldsa_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != PREPARE_MLDSA_PROOF_DATA_LEN - 1 {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let proof = next_account_info(account_iter)?;
    let mldsa_public_key = next_account_info(account_iter)?;
    let mldsa_signature = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !proof.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if quorum.owner != program_id
        || proof.owner != program_id
        || mldsa_public_key.owner != program_id
        || mldsa_signature.owner != program_id
    {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }
    reject_duplicate_runtime_accounts(&[
        authority.key,
        quorum.key,
        proof.key,
        mldsa_public_key.key,
        mldsa_signature.key,
    ])?;
    validate_quorum_authority(authority.key, quorum)?;

    let public_key_data = mldsa_public_key.try_borrow_data()?;
    let signature_data = mldsa_signature.try_borrow_data()?;
    let mut proof_data = proof.try_borrow_mut_data()?;
    let proof_state = validate_mldsa_proof_header(MldsaProofHeaderCheck {
        program_id,
        authority: authority.key,
        quorum: quorum.key,
        proof: proof.key,
        data: &proof_data,
        expected_mode: None,
        mldsa_public_key: mldsa_public_key.key,
        mldsa_signature: mldsa_signature.key,
        payload_hash: None,
    })?;
    validate_mldsa_buffer_data(MldsaBufferDataCheck {
        program_id,
        authority: authority.key,
        quorum: quorum.key,
        quorum_nonce: proof_state.quorum_nonce,
        public_key: mldsa_public_key.key,
        public_key_data: &public_key_data,
        signature: mldsa_signature.key,
        signature_data: &signature_data,
    })?;
    if proof_state.row_mask != 0
        || proof_data[PROOF_PREPARED_FLAG_OFFSET] != 0
        || proof_data[PROOF_Z_MASK_OFFSET] != 0
    {
        return Err(PqQuorumAuthError::InvalidMldsaProof.into());
    }

    let signature =
        &signature_data[SIGBUF_DATA_OFFSET..SIGBUF_DATA_OFFSET + mldsa44::MLDSA44_SIGNATURE_LEN];
    let prepared = &mut proof_data[PROOF_PREPARED_SIGNATURE_OFFSET
        ..PROOF_PREPARED_SIGNATURE_OFFSET + mldsa44::MLDSA44_PREPARED_SIGNATURE_LEN];
    if !mldsa44::prepare_mldsa44_challenge(signature, prepared) {
        return Err(PqQuorumAuthError::InvalidMldsaSignature.into());
    }
    proof_data[PROOF_PREPARED_FLAG_OFFSET] = 1;
    Ok(())
}

fn process_prepare_mldsa_z_column(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != PREPARE_MLDSA_Z_COLUMN_DATA_LEN - 1 {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }
    let col = usize::from(data[0]);
    if col >= mldsa44::MLDSA44_COLUMNS {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let proof = next_account_info(account_iter)?;
    let mldsa_public_key = next_account_info(account_iter)?;
    let mldsa_signature = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !proof.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if quorum.owner != program_id
        || proof.owner != program_id
        || mldsa_public_key.owner != program_id
        || mldsa_signature.owner != program_id
    {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }
    reject_duplicate_runtime_accounts(&[
        authority.key,
        quorum.key,
        proof.key,
        mldsa_public_key.key,
        mldsa_signature.key,
    ])?;
    validate_quorum_authority(authority.key, quorum)?;

    let public_key_data = mldsa_public_key.try_borrow_data()?;
    let signature_data = mldsa_signature.try_borrow_data()?;
    let mut proof_data = proof.try_borrow_mut_data()?;
    let proof_state = validate_mldsa_proof_header(MldsaProofHeaderCheck {
        program_id,
        authority: authority.key,
        quorum: quorum.key,
        proof: proof.key,
        data: &proof_data,
        expected_mode: None,
        mldsa_public_key: mldsa_public_key.key,
        mldsa_signature: mldsa_signature.key,
        payload_hash: None,
    })?;
    validate_mldsa_buffer_data(MldsaBufferDataCheck {
        program_id,
        authority: authority.key,
        quorum: quorum.key,
        quorum_nonce: proof_state.quorum_nonce,
        public_key: mldsa_public_key.key,
        public_key_data: &public_key_data,
        signature: mldsa_signature.key,
        signature_data: &signature_data,
    })?;

    let col_bit = 1u8 << col;
    if proof_state.row_mask != 0
        || proof_data[PROOF_PREPARED_FLAG_OFFSET] != 1
        || proof_data[PROOF_Z_MASK_OFFSET] & col_bit != 0
    {
        return Err(PqQuorumAuthError::InvalidMldsaProof.into());
    }

    let signature =
        &signature_data[SIGBUF_DATA_OFFSET..SIGBUF_DATA_OFFSET + mldsa44::MLDSA44_SIGNATURE_LEN];
    let prepared = &mut proof_data[PROOF_PREPARED_SIGNATURE_OFFSET
        ..PROOF_PREPARED_SIGNATURE_OFFSET + mldsa44::MLDSA44_PREPARED_SIGNATURE_LEN];
    if !mldsa44::prepare_mldsa44_z_column(signature, col, prepared) {
        return Err(PqQuorumAuthError::InvalidMldsaSignature.into());
    }
    proof_data[PROOF_Z_MASK_OFFSET] |= col_bit;
    Ok(())
}

fn process_prove_mldsa_column(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != PROVE_MLDSA_COLUMN_DATA_LEN - 1 {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }
    let row = usize::from(data[0]);
    let col = usize::from(data[1]);
    if row >= mldsa44::MLDSA44_ROWS || col >= mldsa44::MLDSA44_COLUMNS {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let proof = next_account_info(account_iter)?;
    let mldsa_public_key = next_account_info(account_iter)?;
    let mldsa_signature = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !proof.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if quorum.owner != program_id
        || proof.owner != program_id
        || mldsa_public_key.owner != program_id
        || mldsa_signature.owner != program_id
    {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }
    reject_duplicate_runtime_accounts(&[
        authority.key,
        quorum.key,
        proof.key,
        mldsa_public_key.key,
        mldsa_signature.key,
    ])?;
    validate_quorum_authority(authority.key, quorum)?;

    let public_key_data = mldsa_public_key.try_borrow_data()?;
    let signature_data = mldsa_signature.try_borrow_data()?;
    let mut proof_data = proof.try_borrow_mut_data()?;
    let proof_state = validate_mldsa_proof_header(MldsaProofHeaderCheck {
        program_id,
        authority: authority.key,
        quorum: quorum.key,
        proof: proof.key,
        data: &proof_data,
        expected_mode: None,
        mldsa_public_key: mldsa_public_key.key,
        mldsa_signature: mldsa_signature.key,
        payload_hash: None,
    })?;
    validate_mldsa_buffer_data(MldsaBufferDataCheck {
        program_id,
        authority: authority.key,
        quorum: quorum.key,
        quorum_nonce: proof_state.quorum_nonce,
        public_key: mldsa_public_key.key,
        public_key_data: &public_key_data,
        signature: mldsa_signature.key,
        signature_data: &signature_data,
    })?;

    let row_bit = 1u8 << row;
    if proof_state.row_mask & row_bit != 0 {
        return Err(PqQuorumAuthError::InvalidMldsaProof.into());
    }
    if proof_data[PROOF_PREPARED_FLAG_OFFSET] != 1 {
        return Err(PqQuorumAuthError::InvalidMldsaProof.into());
    }
    let col_bit = 1u8 << col;
    let column_mask_offset = PROOF_COLUMN_MASK_OFFSET + row;
    if proof_data[PROOF_Z_MASK_OFFSET] & col_bit == 0
        || proof_data[column_mask_offset] & col_bit != 0
    {
        return Err(PqQuorumAuthError::InvalidMldsaProof.into());
    }
    let public_key = &public_key_data
        [SIGBUF_DATA_OFFSET..SIGBUF_DATA_OFFSET + mldsa44::MLDSA44_PREPARED_PUBLIC_KEY_LEN];
    let az_start = PROOF_AZ_OFFSET + row * mldsa44::MLDSA44_AZ_ROW_LEN;
    let az_end = az_start + mldsa44::MLDSA44_AZ_ROW_LEN;
    let (proof_prefix, proof_prepared_and_az) =
        proof_data.split_at_mut(PROOF_PREPARED_SIGNATURE_OFFSET);
    let (proof_prepared, proof_az) =
        proof_prepared_and_az.split_at_mut(mldsa44::MLDSA44_PREPARED_SIGNATURE_LEN);
    if !mldsa44::accumulate_mldsa44_column(
        public_key,
        proof_prepared,
        row,
        col,
        &mut proof_az[az_start - PROOF_AZ_OFFSET..az_end - PROOF_AZ_OFFSET],
    ) {
        return Err(PqQuorumAuthError::InvalidMldsaSignature.into());
    }
    proof_prefix[column_mask_offset] |= col_bit;
    Ok(())
}

fn process_finalize_mldsa_row(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != FINALIZE_MLDSA_ROW_DATA_LEN - 1 {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }
    let row = usize::from(data[0]);
    if row >= mldsa44::MLDSA44_ROWS {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let proof = next_account_info(account_iter)?;
    let mldsa_public_key = next_account_info(account_iter)?;
    let mldsa_signature = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !proof.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if quorum.owner != program_id
        || proof.owner != program_id
        || mldsa_public_key.owner != program_id
        || mldsa_signature.owner != program_id
    {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }
    reject_duplicate_runtime_accounts(&[
        authority.key,
        quorum.key,
        proof.key,
        mldsa_public_key.key,
        mldsa_signature.key,
    ])?;
    validate_quorum_authority(authority.key, quorum)?;

    let public_key_data = mldsa_public_key.try_borrow_data()?;
    let signature_data = mldsa_signature.try_borrow_data()?;
    let mut proof_data = proof.try_borrow_mut_data()?;
    let proof_state = validate_mldsa_proof_header(MldsaProofHeaderCheck {
        program_id,
        authority: authority.key,
        quorum: quorum.key,
        proof: proof.key,
        data: &proof_data,
        expected_mode: None,
        mldsa_public_key: mldsa_public_key.key,
        mldsa_signature: mldsa_signature.key,
        payload_hash: None,
    })?;
    validate_mldsa_buffer_data(MldsaBufferDataCheck {
        program_id,
        authority: authority.key,
        quorum: quorum.key,
        quorum_nonce: proof_state.quorum_nonce,
        public_key: mldsa_public_key.key,
        public_key_data: &public_key_data,
        signature: mldsa_signature.key,
        signature_data: &signature_data,
    })?;

    let row_bit = 1u8 << row;
    if proof_state.row_mask & row_bit != 0
        || proof_data[PROOF_PREPARED_FLAG_OFFSET] != 1
        || proof_data[PROOF_Z_MASK_OFFSET] != MLDSA_PROOF_COLUMN_COMPLETE_MASK
        || proof_data[PROOF_COLUMN_MASK_OFFSET + row] != MLDSA_PROOF_COLUMN_COMPLETE_MASK
    {
        return Err(PqQuorumAuthError::InvalidMldsaProof.into());
    }
    let public_key = &public_key_data
        [SIGBUF_DATA_OFFSET..SIGBUF_DATA_OFFSET + mldsa44::MLDSA44_PREPARED_PUBLIC_KEY_LEN];
    let signature =
        &signature_data[SIGBUF_DATA_OFFSET..SIGBUF_DATA_OFFSET + mldsa44::MLDSA44_SIGNATURE_LEN];
    let row_start = PROOF_W1_OFFSET + row * mldsa44::MLDSA44_W1_ROW_LEN;
    let row_end = row_start + mldsa44::MLDSA44_W1_ROW_LEN;
    let az_start = PROOF_AZ_OFFSET + row * mldsa44::MLDSA44_AZ_ROW_LEN;
    let az_end = az_start + mldsa44::MLDSA44_AZ_ROW_LEN;
    let (proof_prefix, proof_prepared_and_az) =
        proof_data.split_at_mut(PROOF_PREPARED_SIGNATURE_OFFSET);
    let (proof_prepared, proof_az) =
        proof_prepared_and_az.split_at_mut(mldsa44::MLDSA44_PREPARED_SIGNATURE_LEN);
    if !mldsa44::finalize_mldsa44_row(
        public_key,
        signature,
        proof_prepared,
        row,
        &proof_az[az_start - PROOF_AZ_OFFSET..az_end - PROOF_AZ_OFFSET],
        &mut proof_prefix[row_start..row_end],
    ) {
        return Err(PqQuorumAuthError::InvalidMldsaSignature.into());
    }
    proof_prefix[PROOF_ROW_MASK_OFFSET] = proof_state.row_mask | row_bit;
    Ok(())
}

fn process_verify_falcon_mldsa_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != VERIFY_FALCON_MLDSA_DATA_LEN - 1 {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;
    let mldsa_public_key = next_account_info(account_iter)?;
    let mldsa_signature = next_account_info(account_iter)?;
    let mldsa_proof = next_account_info(account_iter)?;

    if !authority.is_writable
        || !quorum.is_writable
        || !falcon_key.is_writable
        || !mldsa_signature.is_writable
        || !mldsa_proof.is_writable
    {
        return Err(ProgramError::InvalidAccountData);
    }
    if quorum.owner != program_id {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }
    if !falcon_auth_program.executable {
        return Err(PqQuorumAuthError::InvalidFalconAuthProgram.into());
    }
    reject_duplicate_runtime_accounts(&[
        authority.key,
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
    let target_action_domain = read_array::<32>(data, 25)?;
    let target_action_hash = read_array::<32>(data, 57)?;
    let falcon_signature = read_array::<FALCON_512_SIGNATURE_LEN>(data, 89)?;

    let state = validate_verify_state(VerifyStateInputs {
        program_id,
        authority,
        quorum,
        falcon_auth_program,
        falcon_key,
        cluster,
        quorum_nonce,
        expires_slot,
    })?;
    let payload = build_quorum_action_v2_payload(QuorumPayloadV2Parts {
        mode: QUORUM_MODE_FALCON_MLDSA,
        cluster,
        program_id: program_id.as_ref(),
        authority: authority.key.as_ref(),
        quorum: quorum.key.as_ref(),
        mldsa_public_key: mldsa_public_key.key.as_ref(),
        quorum_nonce,
        expires_slot,
        action_domain: target_action_domain,
        action_hash: target_action_hash,
        current_winternitz_root: &state.winternitz_root,
        next_winternitz_root: &state.winternitz_root,
    });
    verify_mldsa_proof_approval(VerifyMldsaProofApproval {
        program_id,
        authority: authority.key,
        quorum: quorum.key,
        quorum_nonce,
        mode: QUORUM_MODE_FALCON_MLDSA,
        mldsa_public_key,
        mldsa_signature,
        mldsa_proof,
        payload: &payload,
    })?;

    let falcon_action_domain = pq_quorum_falcon_domain_v2();
    let falcon_action_hash = pq_quorum_falcon_action_hash_v2(&payload);
    invoke_falcon_auth(FalconAuthCpi {
        falcon_auth_program,
        authority,
        falcon_key,
        cluster,
        nonce: falcon_nonce,
        expires_slot,
        action_domain: &falcon_action_domain,
        action_hash: &falcon_action_hash,
        signature: falcon_signature,
    })?;

    advance_quorum_nonce(
        program_id,
        authority,
        quorum,
        falcon_auth_program,
        falcon_key,
        quorum_nonce,
        None,
    )?;
    close_program_account_to_authority(mldsa_signature, authority)?;
    close_program_account_to_authority(mldsa_proof, authority)
}

fn process_verify_winternitz_mldsa_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != VERIFY_WINTERNITZ_MLDSA_DATA_LEN - 1 {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut accounts.iter();
    let authority = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let falcon_key = next_account_info(account_iter)?;
    let falcon_auth_program = next_account_info(account_iter)?;
    let winternitz_signature = next_account_info(account_iter)?;
    let mldsa_public_key = next_account_info(account_iter)?;
    let mldsa_signature = next_account_info(account_iter)?;
    let mldsa_proof = next_account_info(account_iter)?;

    if !authority.is_writable
        || !quorum.is_writable
        || !winternitz_signature.is_writable
        || !mldsa_signature.is_writable
        || !mldsa_proof.is_writable
    {
        return Err(ProgramError::InvalidAccountData);
    }
    if quorum.owner != program_id {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }
    if !falcon_auth_program.executable {
        return Err(PqQuorumAuthError::InvalidFalconAuthProgram.into());
    }
    reject_duplicate_runtime_accounts(&[
        authority.key,
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
    let target_action_domain = read_array::<32>(data, 17)?;
    let target_action_hash = read_array::<32>(data, 49)?;
    let next_winternitz_root = read_array::<32>(data, 81)?;

    let state = validate_verify_state(VerifyStateInputs {
        program_id,
        authority,
        quorum,
        falcon_auth_program,
        falcon_key,
        cluster,
        quorum_nonce,
        expires_slot,
    })?;
    if next_winternitz_root == &state.winternitz_root {
        return Err(PqQuorumAuthError::InvalidWinternitzRoot.into());
    }

    let payload = build_quorum_action_v2_payload(QuorumPayloadV2Parts {
        mode: QUORUM_MODE_WINTERNITZ_MLDSA,
        cluster,
        program_id: program_id.as_ref(),
        authority: authority.key.as_ref(),
        quorum: quorum.key.as_ref(),
        mldsa_public_key: mldsa_public_key.key.as_ref(),
        quorum_nonce,
        expires_slot,
        action_domain: target_action_domain,
        action_hash: target_action_hash,
        current_winternitz_root: &state.winternitz_root,
        next_winternitz_root,
    });
    verify_winternitz_signature(
        program_id,
        authority.key,
        quorum.key,
        quorum_nonce,
        winternitz_signature,
        &payload,
        &state.winternitz_root,
    )?;
    verify_mldsa_proof_approval(VerifyMldsaProofApproval {
        program_id,
        authority: authority.key,
        quorum: quorum.key,
        quorum_nonce,
        mode: QUORUM_MODE_WINTERNITZ_MLDSA,
        mldsa_public_key,
        mldsa_signature,
        mldsa_proof,
        payload: &payload,
    })?;

    advance_quorum_nonce(
        program_id,
        authority,
        quorum,
        falcon_auth_program,
        falcon_key,
        quorum_nonce,
        Some(next_winternitz_root),
    )?;
    close_program_account_to_authority(winternitz_signature, authority)?;
    close_program_account_to_authority(mldsa_signature, authority)?;
    close_program_account_to_authority(mldsa_proof, authority)
}

fn verify_winternitz_signature(
    program_id: &Pubkey,
    authority: &Pubkey,
    quorum: &Pubkey,
    quorum_nonce: u64,
    signature_account: &AccountInfo,
    payload: &[u8],
    expected_root: &[u8; 32],
) -> Result<bool, ProgramError> {
    let signature_data = signature_account.try_borrow_data()?;
    let (signature_bytes, close_signature_buffer) = if signature_account.owner == program_id {
        validate_signature_buffer_header(
            program_id,
            authority,
            quorum,
            quorum_nonce,
            signature_account.key,
            &signature_data,
        )?;
        if read_u16(&signature_data, SIGBUF_WRITTEN_OFFSET)? as usize != WINTERNITZ_SIGNATURE_LEN {
            return Err(PqQuorumAuthError::InvalidSignatureBuffer.into());
        }
        (
            &signature_data[SIGBUF_DATA_OFFSET..SIGBUF_DATA_OFFSET + WINTERNITZ_SIGNATURE_LEN],
            true,
        )
    } else {
        (&signature_data[..], false)
    };

    let recovered_root = recover_wots16_root(signature_bytes, payload)?;
    if &recovered_root != expected_root {
        return Err(PqQuorumAuthError::InvalidWinternitzSignature.into());
    }
    Ok(close_signature_buffer)
}

fn recover_wots16_root(signature_data: &[u8], payload: &[u8]) -> Result<[u8; 32], ProgramError> {
    let digits = wots16_digits(payload);
    let mut root = keccak_hash(b"pq-wots16-root-v1");

    if signature_data.len() != WINTERNITZ_SIGNATURE_LEN {
        return Err(PqQuorumAuthError::InvalidWinternitzSignature.into());
    }

    for (index, digit) in digits.iter().enumerate() {
        let offset = index * WOTS16_N;
        let signature_element = read_array::<WOTS16_N>(signature_data, offset)?;
        let public_element = wots16_chain(
            signature_element,
            index as u8,
            *digit,
            WOTS16_MAX_DIGIT - *digit,
        );
        root = wots16_root_step(&root, index as u8, &public_element);
    }

    Ok(root)
}

fn wots16_digits(message: &[u8]) -> [u8; WOTS16_LEN] {
    let digest = keccak_hash(message);
    let mut digits = [0u8; WOTS16_LEN];
    let mut checksum = 0u16;

    for (byte_index, byte) in digest.iter().enumerate() {
        let high = byte >> 4;
        let low = byte & 0x0f;
        let digit_index = byte_index * 2;
        digits[digit_index] = high;
        digits[digit_index + 1] = low;
        checksum += u16::from(WOTS16_MAX_DIGIT - high);
        checksum += u16::from(WOTS16_MAX_DIGIT - low);
    }

    digits[WOTS16_LEN1] = ((checksum >> 8) & 0x0f) as u8;
    digits[WOTS16_LEN1 + 1] = ((checksum >> 4) & 0x0f) as u8;
    digits[WOTS16_LEN1 + 2] = (checksum & 0x0f) as u8;
    digits
}

fn wots16_chain(start: &[u8; WOTS16_N], chain_index: u8, start_step: u8, steps: u8) -> [u8; 32] {
    let mut value = *start;
    let index_bytes = [chain_index];

    for (step, _) in (start_step..).zip(0..steps) {
        let step_bytes = [step];
        value = keccak_hashv(&[b"pq-wots16-chain-v1", &index_bytes, &step_bytes, &value]);
    }

    value
}

fn wots16_root_step(previous_root: &[u8; 32], chain_index: u8, element: &[u8; 32]) -> [u8; 32] {
    let index_bytes = [chain_index];
    keccak_hashv(&[b"pq-wots16-root-v1", &index_bytes, previous_root, element])
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

struct QuorumState {
    cluster: u8,
    next_nonce: u64,
    winternitz_root: [u8; 32],
}

struct VerifyStateInputs<'a, 'info> {
    program_id: &'a Pubkey,
    authority: &'a AccountInfo<'info>,
    quorum: &'a AccountInfo<'info>,
    falcon_auth_program: &'a AccountInfo<'info>,
    falcon_key: &'a AccountInfo<'info>,
    cluster: u8,
    quorum_nonce: u64,
    expires_slot: u64,
}

fn validate_verify_state(input: VerifyStateInputs<'_, '_>) -> Result<QuorumState, ProgramError> {
    if Clock::get()?.slot > input.expires_slot {
        return Err(PqQuorumAuthError::ExpiredAction.into());
    }

    let state = {
        let quorum_data = input.quorum.try_borrow_data()?;
        validate_quorum_state(
            input.program_id,
            input.authority.key,
            input.quorum.key,
            input.falcon_auth_program.key,
            input.falcon_key.key,
            &quorum_data,
        )?
    };
    if state.cluster != input.cluster {
        return Err(PqQuorumAuthError::ClusterMismatch.into());
    }
    if state.next_nonce != input.quorum_nonce {
        return Err(PqQuorumAuthError::NonceMismatch.into());
    }
    Ok(state)
}

fn advance_quorum_nonce(
    program_id: &Pubkey,
    authority: &AccountInfo,
    quorum: &AccountInfo,
    falcon_auth_program: &AccountInfo,
    falcon_key: &AccountInfo,
    quorum_nonce: u64,
    next_winternitz_root: Option<&[u8; 32]>,
) -> ProgramResult {
    let next_nonce = quorum_nonce
        .checked_add(1)
        .ok_or(PqQuorumAuthError::ArithmeticOverflow)?;
    let mut quorum_data = quorum.try_borrow_mut_data()?;
    validate_quorum_state(
        program_id,
        authority.key,
        quorum.key,
        falcon_auth_program.key,
        falcon_key.key,
        &quorum_data,
    )?;
    if read_u64(&quorum_data, NEXT_NONCE_OFFSET)? != quorum_nonce {
        return Err(PqQuorumAuthError::NonceMismatch.into());
    }
    if let Some(next_root) = next_winternitz_root {
        quorum_data[WINTERNITZ_ROOT_OFFSET..NEXT_NONCE_OFFSET].copy_from_slice(next_root);
    }
    quorum_data[NEXT_NONCE_OFFSET..NEXT_NONCE_OFFSET + 8]
        .copy_from_slice(&next_nonce.to_le_bytes());
    Ok(())
}

struct VerifyMldsaProofApproval<'a, 'info> {
    program_id: &'a Pubkey,
    authority: &'a Pubkey,
    quorum: &'a Pubkey,
    quorum_nonce: u64,
    mode: u8,
    mldsa_public_key: &'a AccountInfo<'info>,
    mldsa_signature: &'a AccountInfo<'info>,
    mldsa_proof: &'a AccountInfo<'info>,
    payload: &'a [u8],
}

fn verify_mldsa_proof_approval(input: VerifyMldsaProofApproval<'_, '_>) -> ProgramResult {
    if input.mldsa_public_key.owner != input.program_id
        || input.mldsa_signature.owner != input.program_id
        || input.mldsa_proof.owner != input.program_id
    {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }

    let payload_hash = mldsa_proof_payload_hash(input.payload);
    let public_key_data = input.mldsa_public_key.try_borrow_data()?;
    let signature_data = input.mldsa_signature.try_borrow_data()?;
    let proof_data = input.mldsa_proof.try_borrow_data()?;
    let proof_state = validate_mldsa_proof_header(MldsaProofHeaderCheck {
        program_id: input.program_id,
        authority: input.authority,
        quorum: input.quorum,
        proof: input.mldsa_proof.key,
        data: &proof_data,
        expected_mode: Some(input.mode),
        mldsa_public_key: input.mldsa_public_key.key,
        mldsa_signature: input.mldsa_signature.key,
        payload_hash: Some(&payload_hash),
    })?;
    if proof_state.quorum_nonce != input.quorum_nonce
        || proof_state.row_mask != MLDSA_PROOF_COMPLETE_MASK
        || proof_data[PROOF_PREPARED_FLAG_OFFSET] != 1
    {
        return Err(PqQuorumAuthError::InvalidMldsaProof.into());
    }
    validate_mldsa_buffer_data(MldsaBufferDataCheck {
        program_id: input.program_id,
        authority: input.authority,
        quorum: input.quorum,
        quorum_nonce: input.quorum_nonce,
        public_key: input.mldsa_public_key.key,
        public_key_data: &public_key_data,
        signature: input.mldsa_signature.key,
        signature_data: &signature_data,
    })?;

    let public_key = &public_key_data
        [SIGBUF_DATA_OFFSET..SIGBUF_DATA_OFFSET + mldsa44::MLDSA44_PREPARED_PUBLIC_KEY_LEN];
    let signature =
        &signature_data[SIGBUF_DATA_OFFSET..SIGBUF_DATA_OFFSET + mldsa44::MLDSA44_SIGNATURE_LEN];
    let w1 = &proof_data[PROOF_W1_OFFSET..PROOF_W1_OFFSET + mldsa44::MLDSA44_W1_LEN];
    if !mldsa44::finalize_mldsa44_proof(public_key, signature, input.payload, w1) {
        return Err(PqQuorumAuthError::InvalidMldsaSignature.into());
    }
    Ok(())
}

fn validate_mldsa_buffer_accounts(
    program_id: &Pubkey,
    authority: &Pubkey,
    quorum: &Pubkey,
    quorum_nonce: u64,
    public_key_account: &AccountInfo,
    signature_account: &AccountInfo,
) -> ProgramResult {
    let public_key_data = public_key_account.try_borrow_data()?;
    let signature_data = signature_account.try_borrow_data()?;
    validate_mldsa_buffer_data(MldsaBufferDataCheck {
        program_id,
        authority,
        quorum,
        quorum_nonce,
        public_key: public_key_account.key,
        public_key_data: &public_key_data,
        signature: signature_account.key,
        signature_data: &signature_data,
    })
}

struct MldsaBufferDataCheck<'a> {
    program_id: &'a Pubkey,
    authority: &'a Pubkey,
    quorum: &'a Pubkey,
    quorum_nonce: u64,
    public_key: &'a Pubkey,
    public_key_data: &'a [u8],
    signature: &'a Pubkey,
    signature_data: &'a [u8],
}

fn validate_mldsa_buffer_data(input: MldsaBufferDataCheck<'_>) -> ProgramResult {
    validate_mldsa_buffer_header(MldsaBufferHeaderCheck {
        program_id: input.program_id,
        authority: input.authority,
        quorum: input.quorum,
        quorum_nonce: 0,
        buffer: input.public_key,
        data: input.public_key_data,
        discriminator: MLDSA_PUBLIC_KEY_DISCRIMINATOR,
        seed: MLDSA_PUBLIC_KEY_SEED,
        expected_len: MLDSA_PUBLIC_KEY_BUFFER_LEN,
        require_nonce: false,
        error: PqQuorumAuthError::InvalidMldsaPublicKey,
    })?;
    if read_u16(input.public_key_data, SIGBUF_WRITTEN_OFFSET)? as usize
        != mldsa44::MLDSA44_PREPARED_PUBLIC_KEY_LEN
    {
        return Err(PqQuorumAuthError::InvalidMldsaPublicKey.into());
    }

    validate_mldsa_buffer_header(MldsaBufferHeaderCheck {
        program_id: input.program_id,
        authority: input.authority,
        quorum: input.quorum,
        quorum_nonce: input.quorum_nonce,
        buffer: input.signature,
        data: input.signature_data,
        discriminator: MLDSA_SIGNATURE_DISCRIMINATOR,
        seed: MLDSA_SIGNATURE_SEED,
        expected_len: MLDSA_SIGNATURE_BUFFER_LEN,
        require_nonce: true,
        error: PqQuorumAuthError::InvalidMldsaSignature,
    })?;
    if read_u16(input.signature_data, SIGBUF_WRITTEN_OFFSET)? as usize
        != mldsa44::MLDSA44_SIGNATURE_LEN
    {
        return Err(PqQuorumAuthError::InvalidMldsaSignature.into());
    }
    Ok(())
}

fn validate_quorum_state(
    program_id: &Pubkey,
    authority: &Pubkey,
    quorum: &Pubkey,
    falcon_auth_program: &Pubkey,
    falcon_key: &Pubkey,
    data: &[u8],
) -> Result<QuorumState, ProgramError> {
    if data.len() != QUORUM_ACCOUNT_LEN {
        return Err(PqQuorumAuthError::InvalidAccountData.into());
    }
    if data[..8] != QUORUM_DISCRIMINATOR || data[VERSION_OFFSET] != VERSION {
        return Err(PqQuorumAuthError::InvalidAccountData.into());
    }
    if data[RESERVED_OFFSET] != 0 {
        return Err(PqQuorumAuthError::InvalidAccountData.into());
    }
    if &data[AUTHORITY_OFFSET..FALCON_AUTH_PROGRAM_OFFSET] != authority.as_ref() {
        return Err(PqQuorumAuthError::InvalidAccountData.into());
    }
    if &data[FALCON_AUTH_PROGRAM_OFFSET..FALCON_KEY_OFFSET] != falcon_auth_program.as_ref() {
        return Err(PqQuorumAuthError::InvalidFalconAuthProgram.into());
    }
    if &data[FALCON_KEY_OFFSET..WINTERNITZ_ROOT_OFFSET] != falcon_key.as_ref() {
        return Err(PqQuorumAuthError::InvalidAccountData.into());
    }

    validate_quorum_pda(
        program_id,
        authority,
        falcon_auth_program,
        quorum,
        data[BUMP_OFFSET],
    )?;
    validate_falcon_key_pda(falcon_auth_program, authority, falcon_key)?;

    Ok(QuorumState {
        cluster: data[CLUSTER_OFFSET],
        next_nonce: read_u64(data, NEXT_NONCE_OFFSET)?,
        winternitz_root: *read_array::<32>(data, WINTERNITZ_ROOT_OFFSET)?,
    })
}

fn validate_quorum_authority(authority: &Pubkey, quorum: &AccountInfo) -> ProgramResult {
    let data = quorum.try_borrow_data()?;
    if data.len() != QUORUM_ACCOUNT_LEN
        || data[..8] != QUORUM_DISCRIMINATOR
        || data[VERSION_OFFSET] != VERSION
        || &data[AUTHORITY_OFFSET..FALCON_AUTH_PROGRAM_OFFSET] != authority.as_ref()
    {
        return Err(PqQuorumAuthError::InvalidAccountData.into());
    }
    Ok(())
}

fn validate_quorum_pda(
    program_id: &Pubkey,
    authority: &Pubkey,
    falcon_auth_program: &Pubkey,
    quorum: &Pubkey,
    bump: u8,
) -> ProgramResult {
    let seeds: [&[u8]; 3] = [
        QUORUM_SEED,
        authority.as_ref(),
        falcon_auth_program.as_ref(),
    ];
    let Some((expected_quorum, canonical_bump)) =
        Pubkey::derive_program_address(&seeds, program_id)
    else {
        return Err(PqQuorumAuthError::InvalidPda.into());
    };
    if expected_quorum != *quorum || canonical_bump != bump {
        return Err(PqQuorumAuthError::InvalidPda.into());
    }
    Ok(())
}

fn validate_signature_buffer_pda(
    program_id: &Pubkey,
    authority: &Pubkey,
    quorum: &Pubkey,
    quorum_nonce: u64,
    signature_buffer: &Pubkey,
    bump: u8,
) -> ProgramResult {
    let nonce_bytes = quorum_nonce.to_le_bytes();
    let seeds: [&[u8]; 4] = [
        WINTERNITZ_SIGNATURE_SEED,
        authority.as_ref(),
        quorum.as_ref(),
        &nonce_bytes,
    ];
    let Some((expected_buffer, canonical_bump)) =
        Pubkey::derive_program_address(&seeds, program_id)
    else {
        return Err(PqQuorumAuthError::InvalidPda.into());
    };
    if expected_buffer != *signature_buffer || canonical_bump != bump {
        return Err(PqQuorumAuthError::InvalidPda.into());
    }
    Ok(())
}

fn validate_signature_buffer_header(
    program_id: &Pubkey,
    authority: &Pubkey,
    quorum: &Pubkey,
    quorum_nonce: u64,
    signature_buffer: &Pubkey,
    data: &[u8],
) -> ProgramResult {
    if data.len() != WINTERNITZ_SIGNATURE_BUFFER_LEN
        || data[..8] != WINTERNITZ_SIGNATURE_DISCRIMINATOR
        || data[SIGBUF_VERSION_OFFSET] != VERSION
        || data[SIGBUF_RESERVED_OFFSET] != 0
        || data[SIGBUF_RESERVED_OFFSET + 1] != 0
        || &data[SIGBUF_AUTHORITY_OFFSET..SIGBUF_QUORUM_OFFSET] != authority.as_ref()
        || &data[SIGBUF_QUORUM_OFFSET..SIGBUF_NONCE_OFFSET] != quorum.as_ref()
        || read_u64(data, SIGBUF_NONCE_OFFSET)? != quorum_nonce
    {
        return Err(PqQuorumAuthError::InvalidSignatureBuffer.into());
    }
    validate_signature_buffer_pda(
        program_id,
        authority,
        quorum,
        quorum_nonce,
        signature_buffer,
        data[SIGBUF_BUMP_OFFSET],
    )
}

fn validate_mldsa_public_key_pda(
    program_id: &Pubkey,
    authority: &Pubkey,
    quorum: &Pubkey,
    public_key_buffer: &Pubkey,
    bump: u8,
) -> ProgramResult {
    let seeds: [&[u8]; 3] = [MLDSA_PUBLIC_KEY_SEED, authority.as_ref(), quorum.as_ref()];
    let Some((expected_buffer, canonical_bump)) =
        Pubkey::derive_program_address(&seeds, program_id)
    else {
        return Err(PqQuorumAuthError::InvalidPda.into());
    };
    if expected_buffer != *public_key_buffer || canonical_bump != bump {
        return Err(PqQuorumAuthError::InvalidPda.into());
    }
    Ok(())
}

fn validate_mldsa_signature_pda(
    program_id: &Pubkey,
    authority: &Pubkey,
    quorum: &Pubkey,
    quorum_nonce: u64,
    signature_buffer: &Pubkey,
    bump: u8,
) -> ProgramResult {
    let nonce_bytes = quorum_nonce.to_le_bytes();
    let seeds: [&[u8]; 4] = [
        MLDSA_SIGNATURE_SEED,
        authority.as_ref(),
        quorum.as_ref(),
        &nonce_bytes,
    ];
    let Some((expected_buffer, canonical_bump)) =
        Pubkey::derive_program_address(&seeds, program_id)
    else {
        return Err(PqQuorumAuthError::InvalidPda.into());
    };
    if expected_buffer != *signature_buffer || canonical_bump != bump {
        return Err(PqQuorumAuthError::InvalidPda.into());
    }
    Ok(())
}

fn validate_mldsa_proof_pda(
    program_id: &Pubkey,
    authority: &Pubkey,
    quorum: &Pubkey,
    quorum_nonce: u64,
    proof: &Pubkey,
    bump: u8,
) -> ProgramResult {
    let nonce_bytes = quorum_nonce.to_le_bytes();
    let seeds: [&[u8]; 4] = [
        MLDSA_PROOF_SEED,
        authority.as_ref(),
        quorum.as_ref(),
        &nonce_bytes,
    ];
    let Some((expected_proof, canonical_bump)) = Pubkey::derive_program_address(&seeds, program_id)
    else {
        return Err(PqQuorumAuthError::InvalidPda.into());
    };
    if expected_proof != *proof || canonical_bump != bump {
        return Err(PqQuorumAuthError::InvalidPda.into());
    }
    Ok(())
}

struct MldsaProofState {
    row_mask: u8,
    quorum_nonce: u64,
}

struct MldsaProofHeaderCheck<'a> {
    program_id: &'a Pubkey,
    authority: &'a Pubkey,
    quorum: &'a Pubkey,
    proof: &'a Pubkey,
    data: &'a [u8],
    expected_mode: Option<u8>,
    mldsa_public_key: &'a Pubkey,
    mldsa_signature: &'a Pubkey,
    payload_hash: Option<&'a [u8; 32]>,
}

fn validate_mldsa_proof_header(
    input: MldsaProofHeaderCheck<'_>,
) -> Result<MldsaProofState, ProgramError> {
    if input.data.len() != MLDSA_PROOF_ACCOUNT_LEN
        || input.data[..8] != MLDSA_PROOF_DISCRIMINATOR
        || input.data[PROOF_VERSION_OFFSET] != VERSION
        || !is_mldsa_quorum_mode(input.data[PROOF_MODE_OFFSET])
        || &input.data[PROOF_AUTHORITY_OFFSET..PROOF_QUORUM_OFFSET] != input.authority.as_ref()
        || &input.data[PROOF_QUORUM_OFFSET..PROOF_NONCE_OFFSET] != input.quorum.as_ref()
        || &input.data[PROOF_MLDSA_PUBLIC_KEY_OFFSET..PROOF_MLDSA_SIGNATURE_OFFSET]
            != input.mldsa_public_key.as_ref()
        || &input.data[PROOF_MLDSA_SIGNATURE_OFFSET..PROOF_PAYLOAD_HASH_OFFSET]
            != input.mldsa_signature.as_ref()
    {
        return Err(PqQuorumAuthError::InvalidMldsaProof.into());
    }

    if let Some(expected_mode) = input.expected_mode
        && input.data[PROOF_MODE_OFFSET] != expected_mode
    {
        return Err(PqQuorumAuthError::InvalidMldsaProof.into());
    }
    if let Some(payload_hash) = input.payload_hash
        && &input.data[PROOF_PAYLOAD_HASH_OFFSET..PROOF_W1_OFFSET] != payload_hash
    {
        return Err(PqQuorumAuthError::InvalidMldsaProof.into());
    }

    let row_mask = input.data[PROOF_ROW_MASK_OFFSET];
    if row_mask & !MLDSA_PROOF_COMPLETE_MASK != 0 || input.data[PROOF_PREPARED_FLAG_OFFSET] > 1 {
        return Err(PqQuorumAuthError::InvalidMldsaProof.into());
    }
    if input.data[PROOF_Z_MASK_OFFSET] & !MLDSA_PROOF_COLUMN_COMPLETE_MASK != 0 {
        return Err(PqQuorumAuthError::InvalidMldsaProof.into());
    }
    for row in 0..mldsa44::MLDSA44_ROWS {
        if input.data[PROOF_COLUMN_MASK_OFFSET + row] & !MLDSA_PROOF_COLUMN_COMPLETE_MASK != 0 {
            return Err(PqQuorumAuthError::InvalidMldsaProof.into());
        }
    }
    let quorum_nonce = read_u64(input.data, PROOF_NONCE_OFFSET)?;
    validate_mldsa_proof_pda(
        input.program_id,
        input.authority,
        input.quorum,
        quorum_nonce,
        input.proof,
        input.data[PROOF_BUMP_OFFSET],
    )?;

    Ok(MldsaProofState {
        row_mask,
        quorum_nonce,
    })
}

struct MldsaBufferHeaderCheck<'a> {
    program_id: &'a Pubkey,
    authority: &'a Pubkey,
    quorum: &'a Pubkey,
    quorum_nonce: u64,
    buffer: &'a Pubkey,
    data: &'a [u8],
    discriminator: [u8; 8],
    seed: &'a [u8],
    expected_len: usize,
    require_nonce: bool,
    error: PqQuorumAuthError,
}

fn validate_mldsa_buffer_header(input: MldsaBufferHeaderCheck<'_>) -> ProgramResult {
    if input.data.len() != input.expected_len
        || input.data[..8] != input.discriminator
        || input.data[SIGBUF_VERSION_OFFSET] != VERSION
        || input.data[SIGBUF_RESERVED_OFFSET] != 0
        || input.data[SIGBUF_RESERVED_OFFSET + 1] != 0
        || &input.data[SIGBUF_AUTHORITY_OFFSET..SIGBUF_QUORUM_OFFSET] != input.authority.as_ref()
        || &input.data[SIGBUF_QUORUM_OFFSET..SIGBUF_NONCE_OFFSET] != input.quorum.as_ref()
    {
        return Err(input.error.into());
    }
    if input.require_nonce && read_u64(input.data, SIGBUF_NONCE_OFFSET)? != input.quorum_nonce {
        return Err(input.error.into());
    }

    if input.seed == MLDSA_PUBLIC_KEY_SEED {
        validate_mldsa_public_key_pda(
            input.program_id,
            input.authority,
            input.quorum,
            input.buffer,
            input.data[SIGBUF_BUMP_OFFSET],
        )
    } else {
        validate_mldsa_signature_pda(
            input.program_id,
            input.authority,
            input.quorum,
            input.quorum_nonce,
            input.buffer,
            input.data[SIGBUF_BUMP_OFFSET],
        )
    }
}

fn is_mldsa_quorum_mode(mode: u8) -> bool {
    mode == QUORUM_MODE_FALCON_MLDSA || mode == QUORUM_MODE_WINTERNITZ_MLDSA
}

fn validate_falcon_key_pda(
    falcon_auth_program: &Pubkey,
    authority: &Pubkey,
    falcon_key: &Pubkey,
) -> ProgramResult {
    let seeds: [&[u8]; 2] = [FALCON_KEY_SEED, authority.as_ref()];
    let Some((expected_falcon_key, _)) =
        Pubkey::derive_program_address(&seeds, falcon_auth_program)
    else {
        return Err(PqQuorumAuthError::InvalidPda.into());
    };
    if expected_falcon_key != *falcon_key {
        return Err(PqQuorumAuthError::InvalidPda.into());
    }
    Ok(())
}

fn close_program_account_to_authority(
    account: &AccountInfo,
    authority: &AccountInfo,
) -> ProgramResult {
    let account_lamports = **account.try_borrow_lamports()?;
    let authority_lamports = **authority.try_borrow_lamports()?;
    let new_authority_lamports = authority_lamports
        .checked_add(account_lamports)
        .ok_or(PqQuorumAuthError::ArithmeticOverflow)?;
    **authority.try_borrow_mut_lamports()? = new_authority_lamports;
    **account.try_borrow_mut_lamports()? = 0;
    let mut data = account.try_borrow_mut_data()?;
    let clear_len = data.len().min(8);
    data[..clear_len].fill(0);
    Ok(())
}

fn reject_duplicate_runtime_accounts(keys: &[&Pubkey]) -> ProgramResult {
    for (index, key) in keys.iter().enumerate() {
        if keys[index + 1..].iter().any(|other| other == key) {
            return Err(ProgramError::InvalidArgument);
        }
    }
    Ok(())
}

struct QuorumPayloadParts<'a> {
    cluster: u8,
    program_id: &'a [u8],
    authority: &'a [u8],
    quorum: &'a [u8],
    quorum_nonce: u64,
    expires_slot: u64,
    action_domain: &'a [u8; 32],
    action_hash: &'a [u8; 32],
    next_winternitz_root: &'a [u8; 32],
}

fn build_quorum_action_payload(parts: QuorumPayloadParts<'_>) -> [u8; QUORUM_ACTION_PAYLOAD_LEN] {
    let mut out = [0u8; QUORUM_ACTION_PAYLOAD_LEN];
    out[0..16].copy_from_slice(&QUORUM_ACTION_MAGIC);
    out[16] = parts.cluster;
    out[17..49].copy_from_slice(parts.program_id);
    out[49..81].copy_from_slice(parts.authority);
    out[81..113].copy_from_slice(parts.quorum);
    out[113..121].copy_from_slice(&parts.quorum_nonce.to_le_bytes());
    out[121..129].copy_from_slice(&parts.expires_slot.to_le_bytes());
    out[129..161].copy_from_slice(parts.action_domain);
    out[161..193].copy_from_slice(parts.action_hash);
    out[193..225].copy_from_slice(parts.next_winternitz_root);
    out
}

struct QuorumPayloadV2Parts<'a> {
    mode: u8,
    cluster: u8,
    program_id: &'a [u8],
    authority: &'a [u8],
    quorum: &'a [u8],
    mldsa_public_key: &'a [u8],
    quorum_nonce: u64,
    expires_slot: u64,
    action_domain: &'a [u8; 32],
    action_hash: &'a [u8; 32],
    current_winternitz_root: &'a [u8; 32],
    next_winternitz_root: &'a [u8; 32],
}

fn build_quorum_action_v2_payload(
    parts: QuorumPayloadV2Parts<'_>,
) -> [u8; QUORUM_ACTION_V2_PAYLOAD_LEN] {
    let mut out = [0u8; QUORUM_ACTION_V2_PAYLOAD_LEN];
    out[0..16].copy_from_slice(&QUORUM_ACTION_V2_MAGIC);
    out[16] = parts.mode;
    out[17] = parts.cluster;
    out[18..50].copy_from_slice(parts.program_id);
    out[50..82].copy_from_slice(parts.authority);
    out[82..114].copy_from_slice(parts.quorum);
    out[114..146].copy_from_slice(parts.mldsa_public_key);
    out[146..154].copy_from_slice(&parts.quorum_nonce.to_le_bytes());
    out[154..162].copy_from_slice(&parts.expires_slot.to_le_bytes());
    out[162..194].copy_from_slice(parts.action_domain);
    out[194..226].copy_from_slice(parts.action_hash);
    out[226..258].copy_from_slice(parts.current_winternitz_root);
    out[258..290].copy_from_slice(parts.next_winternitz_root);
    out
}

pub fn pq_quorum_falcon_domain() -> [u8; 32] {
    hashv(&[b"pq-quorum", b"falcon-approval.v1"]).to_bytes()
}

pub fn pq_quorum_falcon_action_hash(payload: &[u8; QUORUM_ACTION_PAYLOAD_LEN]) -> [u8; 32] {
    hashv(&[b"pq-quorum-falcon-action-v1", payload]).to_bytes()
}

pub fn pq_quorum_falcon_domain_v2() -> [u8; 32] {
    hashv(&[b"pq-quorum", b"falcon-approval.v2"]).to_bytes()
}

pub fn pq_quorum_falcon_action_hash_v2(payload: &[u8; QUORUM_ACTION_V2_PAYLOAD_LEN]) -> [u8; 32] {
    hashv(&[b"pq-quorum-falcon-action-v2", payload]).to_bytes()
}

pub fn mldsa_proof_payload_hash(payload: &[u8]) -> [u8; 32] {
    hashv(&[b"pq-quorum-mldsa-proof-payload-v1", payload]).to_bytes()
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
        .ok_or_else(|| PqQuorumAuthError::InvalidInstructionData.into())
}

struct QuorumStateWrite<'a> {
    data: &'a mut [u8],
    bump: u8,
    cluster: u8,
    authority: &'a [u8],
    falcon_auth_program: &'a [u8],
    falcon_key: &'a [u8],
    winternitz_root: &'a [u8; 32],
    next_nonce: u64,
}

fn write_quorum_state(input: QuorumStateWrite<'_>) -> ProgramResult {
    if input.data.len() != QUORUM_ACCOUNT_LEN
        || input.authority.len() != 32
        || input.falcon_auth_program.len() != 32
        || input.falcon_key.len() != 32
    {
        return Err(ProgramError::AccountDataTooSmall);
    }

    input.data[..8].copy_from_slice(&QUORUM_DISCRIMINATOR);
    input.data[VERSION_OFFSET] = VERSION;
    input.data[BUMP_OFFSET] = input.bump;
    input.data[CLUSTER_OFFSET] = input.cluster;
    input.data[RESERVED_OFFSET] = 0;
    input.data[AUTHORITY_OFFSET..FALCON_AUTH_PROGRAM_OFFSET].copy_from_slice(input.authority);
    input.data[FALCON_AUTH_PROGRAM_OFFSET..FALCON_KEY_OFFSET]
        .copy_from_slice(input.falcon_auth_program);
    input.data[FALCON_KEY_OFFSET..WINTERNITZ_ROOT_OFFSET].copy_from_slice(input.falcon_key);
    input.data[WINTERNITZ_ROOT_OFFSET..NEXT_NONCE_OFFSET].copy_from_slice(input.winternitz_root);
    input.data[NEXT_NONCE_OFFSET..NEXT_NONCE_OFFSET + 8]
        .copy_from_slice(&input.next_nonce.to_le_bytes());
    Ok(())
}

fn write_signature_buffer_header(
    data: &mut [u8],
    bump: u8,
    authority: &[u8],
    quorum: &[u8],
    quorum_nonce: u64,
) -> ProgramResult {
    if data.len() != WINTERNITZ_SIGNATURE_BUFFER_LEN || authority.len() != 32 || quorum.len() != 32
    {
        return Err(ProgramError::AccountDataTooSmall);
    }

    data[..8].copy_from_slice(&WINTERNITZ_SIGNATURE_DISCRIMINATOR);
    data[SIGBUF_VERSION_OFFSET] = VERSION;
    data[SIGBUF_BUMP_OFFSET] = bump;
    data[SIGBUF_RESERVED_OFFSET] = 0;
    data[SIGBUF_RESERVED_OFFSET + 1] = 0;
    data[SIGBUF_AUTHORITY_OFFSET..SIGBUF_QUORUM_OFFSET].copy_from_slice(authority);
    data[SIGBUF_QUORUM_OFFSET..SIGBUF_NONCE_OFFSET].copy_from_slice(quorum);
    data[SIGBUF_NONCE_OFFSET..SIGBUF_NONCE_OFFSET + 8].copy_from_slice(&quorum_nonce.to_le_bytes());
    data[SIGBUF_WRITTEN_OFFSET..SIGBUF_WRITTEN_OFFSET + 2].copy_from_slice(&0u16.to_le_bytes());
    data[SIGBUF_DATA_OFFSET..].fill(0);
    Ok(())
}

struct CreatePdaBuffer<'a, 'info> {
    program_id: &'a Pubkey,
    payer: &'a AccountInfo<'info>,
    buffer: &'a AccountInfo<'info>,
    system_program: &'a AccountInfo<'info>,
    len: usize,
    seeds: &'a [&'a [u8]],
}

fn create_pda_buffer(input: CreatePdaBuffer<'_, '_>) -> ProgramResult {
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(input.len);
    let create_account_ix = system_instruction::create_account(
        input.payer.key,
        input.buffer.key,
        lamports,
        input.len as u64,
        input.program_id,
    );
    invoke_signed(
        &create_account_ix,
        &[
            input.payer.clone(),
            input.buffer.clone(),
            input.system_program.clone(),
        ],
        &[input.seeds],
    )
}

fn write_mldsa_buffer_header(
    data: &mut [u8],
    discriminator: [u8; 8],
    bump: u8,
    authority: &[u8],
    quorum: &[u8],
    quorum_nonce: u64,
) -> ProgramResult {
    if authority.len() != 32 || quorum.len() != 32 || data.len() < SIGBUF_DATA_OFFSET {
        return Err(ProgramError::AccountDataTooSmall);
    }

    data[..8].copy_from_slice(&discriminator);
    data[SIGBUF_VERSION_OFFSET] = VERSION;
    data[SIGBUF_BUMP_OFFSET] = bump;
    data[SIGBUF_RESERVED_OFFSET] = 0;
    data[SIGBUF_RESERVED_OFFSET + 1] = 0;
    data[SIGBUF_AUTHORITY_OFFSET..SIGBUF_QUORUM_OFFSET].copy_from_slice(authority);
    data[SIGBUF_QUORUM_OFFSET..SIGBUF_NONCE_OFFSET].copy_from_slice(quorum);
    data[SIGBUF_NONCE_OFFSET..SIGBUF_NONCE_OFFSET + 8].copy_from_slice(&quorum_nonce.to_le_bytes());
    data[SIGBUF_WRITTEN_OFFSET..SIGBUF_WRITTEN_OFFSET + 2].copy_from_slice(&0u16.to_le_bytes());
    data[SIGBUF_DATA_OFFSET..].fill(0);
    Ok(())
}

struct MldsaProofStateWrite<'a> {
    data: &'a mut [u8],
    bump: u8,
    mode: u8,
    authority: &'a [u8],
    quorum: &'a [u8],
    quorum_nonce: u64,
    mldsa_public_key: &'a [u8],
    mldsa_signature: &'a [u8],
    payload_hash: &'a [u8; 32],
}

fn write_mldsa_proof_state(input: MldsaProofStateWrite<'_>) -> ProgramResult {
    if input.data.len() != MLDSA_PROOF_ACCOUNT_LEN
        || input.authority.len() != 32
        || input.quorum.len() != 32
        || input.mldsa_public_key.len() != 32
        || input.mldsa_signature.len() != 32
    {
        return Err(ProgramError::AccountDataTooSmall);
    }

    input.data.fill(0);
    input.data[..8].copy_from_slice(&MLDSA_PROOF_DISCRIMINATOR);
    input.data[PROOF_VERSION_OFFSET] = VERSION;
    input.data[PROOF_BUMP_OFFSET] = input.bump;
    input.data[PROOF_ROW_MASK_OFFSET] = 0;
    input.data[PROOF_MODE_OFFSET] = input.mode;
    input.data[PROOF_AUTHORITY_OFFSET..PROOF_QUORUM_OFFSET].copy_from_slice(input.authority);
    input.data[PROOF_QUORUM_OFFSET..PROOF_NONCE_OFFSET].copy_from_slice(input.quorum);
    input.data[PROOF_NONCE_OFFSET..PROOF_NONCE_OFFSET + 8]
        .copy_from_slice(&input.quorum_nonce.to_le_bytes());
    input.data[PROOF_MLDSA_PUBLIC_KEY_OFFSET..PROOF_MLDSA_SIGNATURE_OFFSET]
        .copy_from_slice(input.mldsa_public_key);
    input.data[PROOF_MLDSA_SIGNATURE_OFFSET..PROOF_PAYLOAD_HASH_OFFSET]
        .copy_from_slice(input.mldsa_signature);
    input.data[PROOF_PAYLOAD_HASH_OFFSET..PROOF_W1_OFFSET].copy_from_slice(input.payload_hash);
    Ok(())
}

struct WriteMldsaBufferChunk<'a, 'info> {
    program_id: &'a Pubkey,
    accounts: &'a [AccountInfo<'info>],
    data: &'a [u8],
    discriminator: [u8; 8],
    seed: &'a [u8],
    expected_len: usize,
    payload_len: usize,
    quorum_nonce: u64,
    require_nonce: bool,
    error: PqQuorumAuthError,
}

fn process_write_mldsa_buffer_chunk(input: WriteMldsaBufferChunk<'_, '_>) -> ProgramResult {
    let data_offset = if input.require_nonce { 10 } else { 2 };
    if input.data.len() < data_offset {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }
    let offset = if input.require_nonce {
        read_u16(input.data, 8)? as usize
    } else {
        read_u16(input.data, 0)? as usize
    };
    let chunk = &input.data[data_offset..];
    if chunk.is_empty() || chunk.len() > input.payload_len {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let account_iter = &mut input.accounts.iter();
    let authority = next_account_info(account_iter)?;
    let quorum = next_account_info(account_iter)?;
    let buffer = next_account_info(account_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !buffer.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if quorum.owner != input.program_id || buffer.owner != input.program_id {
        return Err(PqQuorumAuthError::InvalidAccountOwner.into());
    }

    validate_quorum_authority(authority.key, quorum)?;
    let mut buffer_data = buffer.try_borrow_mut_data()?;
    validate_mldsa_buffer_header(MldsaBufferHeaderCheck {
        program_id: input.program_id,
        authority: authority.key,
        quorum: quorum.key,
        quorum_nonce: input.quorum_nonce,
        buffer: buffer.key,
        data: &buffer_data,
        discriminator: input.discriminator,
        seed: input.seed,
        expected_len: input.expected_len,
        require_nonce: input.require_nonce,
        error: input.error,
    })?;

    let written = read_u16(&buffer_data, SIGBUF_WRITTEN_OFFSET)? as usize;
    let end = offset
        .checked_add(chunk.len())
        .ok_or(PqQuorumAuthError::ArithmeticOverflow)?;
    if offset != written || end > input.payload_len {
        return Err(PqQuorumAuthError::InvalidInstructionData.into());
    }

    let account_offset = SIGBUF_DATA_OFFSET
        .checked_add(offset)
        .ok_or(PqQuorumAuthError::ArithmeticOverflow)?;
    buffer_data[account_offset..account_offset + chunk.len()].copy_from_slice(chunk);
    buffer_data[SIGBUF_WRITTEN_OFFSET..SIGBUF_WRITTEN_OFFSET + 2]
        .copy_from_slice(&(end as u16).to_le_bytes());
    Ok(())
}
