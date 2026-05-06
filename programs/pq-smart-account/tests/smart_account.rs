use {
    fips204_rs::{KeyGen, MlDsa44, SerDes, Signer},
    mollusk_svm::{
        Mollusk, program::keyed_account_for_system_program, result::ProgramResult as SvmResult,
    },
    mollusk_svm_programs_token::token as mollusk_token,
    pqcrypto_falcon::falcon512,
    pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _},
    solana_account::Account,
    solana_falcon512::{
        FALCON_512_PREPARED_PUBKEY_LEN, FALCON_512_PUBKEY_LEN, FALCON_512_SIGNATURE_LEN,
        Falcon512Pubkey,
    },
    solana_instruction::{AccountMeta, Instruction},
    solana_nostd_keccak::{hash as keccak_hash, hashv as keccak_hashv},
    solana_program::hash::hashv,
    solana_program_error::ProgramError,
    solana_program_option::COption,
    solana_program_pack::Pack,
    solana_pubkey::Pubkey,
    spl_token_interface::state::{Account as SplTokenAccount, AccountState, Mint},
};

const TAG_INIT_ACCOUNT: u8 = 0;
const TAG_DEPOSIT: u8 = 1;
const TAG_TRANSFER_FALCON_WINTERNITZ: u8 = 2;
const TAG_TRANSFER_FALCON_MLDSA_PROOF: u8 = 3;
const TAG_TRANSFER_WINTERNITZ_MLDSA_PROOF: u8 = 4;
const TAG_SMART_INIT_FALCON_SIGNATURE: u8 = 5;
const TAG_SMART_WRITE_FALCON_SIGNATURE_CHUNK: u8 = 6;
const TAG_TRANSFER_FALCON_MLDSA_PROOF_BUFFERED: u8 = 7;
const TAG_TRANSFER_SPL_TOKEN_FALCON_WINTERNITZ: u8 = 8;
const TAG_TRANSFER_SPL_TOKEN_FALCON_WINTERNITZ_BUFFERED: u8 = 9;
const TAG_TRANSFER_SPL_TOKEN_FALCON_MLDSA_PROOF_BUFFERED: u8 = 10;
const TAG_TRANSFER_SPL_TOKEN_WINTERNITZ_MLDSA_PROOF: u8 = 11;
const TAG_INIT_MLDSA_PUBLIC_KEY: u8 = 5;
const TAG_WRITE_MLDSA_PUBLIC_KEY_CHUNK: u8 = 6;
const TAG_INIT_MLDSA_SIGNATURE: u8 = 7;
const TAG_WRITE_MLDSA_SIGNATURE_CHUNK: u8 = 8;
const TAG_FINALIZE_MLDSA_PUBLIC_KEY: u8 = 11;
const TAG_INIT_MLDSA_PROOF: u8 = 12;
const TAG_PROVE_MLDSA_COLUMN: u8 = 13;
const TAG_PREPARE_MLDSA_PROOF: u8 = 16;
const TAG_FINALIZE_MLDSA_ROW: u8 = 17;
const TAG_PREPARE_MLDSA_Z_COLUMN: u8 = 18;
const FALCON_KEY_SEED: &[u8] = b"falcon-key";
const QUORUM_SEED: &[u8] = b"pq-quorum";
const SMART_ACCOUNT_SEED: &[u8] = b"pq-smart";
const FALCON_SIGNATURE_SEED: &[u8] = b"falcon-sig";
const MLDSA_PUBLIC_KEY_SEED: &[u8] = b"mldsa-key";
const MLDSA_SIGNATURE_SEED: &[u8] = b"mldsa-sig";
const MLDSA_PROOF_SEED: &[u8] = b"mldsa-proof";
const FALCON_KEY_DISCRIMINATOR: [u8; 8] = *b"FALKYA02";
const QUORUM_DISCRIMINATOR: [u8; 8] = *b"PQQRM001";
const SMART_ACCOUNT_DISCRIMINATOR: [u8; 8] = *b"PQSMRT01";
const FALCON_SIGNATURE_DISCRIMINATOR: [u8; 8] = *b"FALCSIG1";
const SMART_TRANSFER_DOMAIN: [u8; 32] = *b"PQ_SMART_TRANSFER_SOL_V1________";
const SMART_TOKEN_TRANSFER_DOMAIN: [u8; 32] = *b"PQ_SMART_TRANSFER_SPL_V1________";
const WINTERNITZ_SIGNATURE_DISCRIMINATOR: [u8; 8] = *b"WOTSIG01";
const MLDSA_PUBLIC_KEY_DISCRIMINATOR: [u8; 8] = *b"MLDSAPK1";
const MLDSA_PROOF_DISCRIMINATOR: [u8; 8] = *b"MLDSAPF1";
const FALCON_ACTION_MAGIC: [u8; 16] = *b"SOL_FALCON_ACT1!";
const QUORUM_ACTION_MAGIC: [u8; 16] = *b"PQ_QUORUM_ACT1!!";
const QUORUM_ACTION_V2_MAGIC: [u8; 16] = *b"PQ_QUORUM_ACT2!!";
const QUORUM_MODE_FALCON_MLDSA: u8 = 0b101;
const QUORUM_MODE_WINTERNITZ_MLDSA: u8 = 0b110;

const FALCON_AUTH_CLUSTER_OFFSET: usize = 10;
const FALCON_AUTH_AUTHORITY_OFFSET: usize = 12;
const FALCON_AUTH_NEXT_NONCE_OFFSET: usize = 44;
const FALCON_AUTH_PREPARED_PUBKEY_OFFSET: usize = 52;
const FALCON_KEY_ACCOUNT_LEN: usize = FALCON_AUTH_PREPARED_PUBKEY_OFFSET + 1024;
const QUORUM_CLUSTER_OFFSET: usize = 10;
const QUORUM_AUTHORITY_OFFSET: usize = 12;
const QUORUM_FALCON_AUTH_PROGRAM_OFFSET: usize = 44;
const QUORUM_FALCON_KEY_OFFSET: usize = 76;
const QUORUM_WINTERNITZ_ROOT_OFFSET: usize = 108;
const QUORUM_NEXT_NONCE_OFFSET: usize = 140;
const QUORUM_ACCOUNT_LEN: usize = 148;
const SMART_SPEND_COUNT_OFFSET: usize = 108;
const SMART_SIGBUF_AUTHORITY_OFFSET: usize = 12;
const SMART_SIGBUF_SMART_ACCOUNT_OFFSET: usize = 44;
const SMART_SIGBUF_QUORUM_OFFSET: usize = 76;
const SMART_SIGBUF_QUORUM_NONCE_OFFSET: usize = 108;
const SMART_SIGBUF_WRITTEN_OFFSET: usize = 116;
const SMART_SIGBUF_DATA_OFFSET: usize = 118;
const SIGBUF_AUTHORITY_OFFSET: usize = 12;
const SIGBUF_QUORUM_OFFSET: usize = 44;
const SIGBUF_NONCE_OFFSET: usize = 76;
const SIGBUF_WRITTEN_OFFSET: usize = 84;
const SIGBUF_DATA_OFFSET: usize = 86;
const FALCON_ACTION_PAYLOAD_LEN: usize = 193;
const QUORUM_ACTION_PAYLOAD_LEN: usize = 225;
const QUORUM_ACTION_V2_PAYLOAD_LEN: usize = 290;
const SPL_TOKEN_ID: Pubkey = solana_pubkey::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const WOTS16_N: usize = 32;
const WOTS16_W: u8 = 16;
const WOTS16_LEN1: usize = 64;
const WOTS16_LEN2: usize = 3;
const WOTS16_LEN: usize = WOTS16_LEN1 + WOTS16_LEN2;
const WOTS16_MAX_DIGIT: u8 = WOTS16_W - 1;
const WINTERNITZ_SIGNATURE_LEN: usize = WOTS16_LEN * WOTS16_N;
const WINTERNITZ_SIGNATURE_BUFFER_LEN: usize = SIGBUF_DATA_OFFSET + WINTERNITZ_SIGNATURE_LEN;
const FALCON_SIGNATURE_BUFFER_LEN: usize = SMART_SIGBUF_DATA_OFFSET + FALCON_512_SIGNATURE_LEN;
const MLDSA_PUBLIC_KEY_LEN: usize = 1312;
const MLDSA_SIGNATURE_LEN: usize = 2420;
const MLDSA_PREPARED_PUBLIC_KEY_LEN: usize = MLDSA_PUBLIC_KEY_LEN + 64 + 4 * 256 * 4;
const MLDSA_PUBLIC_KEY_BUFFER_LEN: usize = SIGBUF_DATA_OFFSET + MLDSA_PREPARED_PUBLIC_KEY_LEN;
const MLDSA_SIGNATURE_BUFFER_LEN: usize = SIGBUF_DATA_OFFSET + MLDSA_SIGNATURE_LEN;
const MLDSA_ROWS: usize = 4;
const MLDSA_COLUMNS: usize = 4;
const MLDSA_AZ_ROW_LEN: usize = 256 * 4;
const MLDSA_W1_ROW_LEN: usize = 192;
const MLDSA_W1_LEN: usize = MLDSA_ROWS * MLDSA_W1_ROW_LEN;
const PROOF_ROW_MASK_OFFSET: usize = 10;
const PROOF_MODE_OFFSET: usize = 11;
const PROOF_AUTHORITY_OFFSET: usize = 12;
const PROOF_QUORUM_OFFSET: usize = 44;
const PROOF_NONCE_OFFSET: usize = 76;
const PROOF_MLDSA_PUBLIC_KEY_OFFSET: usize = 84;
const PROOF_MLDSA_SIGNATURE_OFFSET: usize = 116;
const PROOF_PAYLOAD_HASH_OFFSET: usize = 148;
const PROOF_W1_OFFSET: usize = 180;
const MLDSA_PREPARED_SIGNATURE_LEN: usize = 5 * 256 * 4;
const PROOF_PREPARED_FLAG_OFFSET: usize = PROOF_W1_OFFSET + MLDSA_W1_LEN;
const PROOF_Z_MASK_OFFSET: usize = PROOF_PREPARED_FLAG_OFFSET + 1;
const PROOF_COLUMN_MASK_OFFSET: usize = PROOF_Z_MASK_OFFSET + 1;
const PROOF_PREPARED_SIGNATURE_OFFSET: usize = PROOF_COLUMN_MASK_OFFSET + MLDSA_ROWS;
const PROOF_AZ_OFFSET: usize = PROOF_PREPARED_SIGNATURE_OFFSET + MLDSA_PREPARED_SIGNATURE_LEN;
const MLDSA_PROOF_ACCOUNT_LEN: usize = PROOF_AZ_OFFSET + MLDSA_ROWS * MLDSA_AZ_ROW_LEN;
const MLDSA_PROOF_COMPLETE_MASK: u8 = (1 << MLDSA_ROWS) - 1;
const MLDSA_PROOF_COLUMN_COMPLETE_MASK: u8 = (1 << MLDSA_COLUMNS) - 1;
const CLUSTER: u8 = 0;
const SMART_TRANSFER_MAX_CU: u64 = 380_000;
const SMART_TOKEN_TRANSFER_MAX_CU: u64 = 450_000;
const SMART_MLDSA_TRANSFER_MAX_CU: u64 = 1_400_000;
const DEVNET_TX_MAX_CU: u64 = 1_400_000;

struct Fixture {
    mollusk: Mollusk,
    smart_program_id: Pubkey,
    quorum_program_id: Pubkey,
    falcon_auth_program_id: Pubkey,
    authority: Pubkey,
    depositor: Pubkey,
    destination: Pubkey,
    falcon_key: Pubkey,
    quorum: Pubkey,
    smart_account: Pubkey,
    smart_bump: u8,
    falcon_account: Account,
    quorum_account: Account,
    quorum_program_account: Account,
    falcon_auth_program_account: Account,
    falcon_secret_key: falcon512::SecretKey,
    winternitz_privkey: Wots16Privkey,
}

fn make_fixture(falcon_nonce: u64, quorum_nonce: u64) -> Fixture {
    let smart_program_id = Pubkey::new_unique();
    let quorum_program_id = Pubkey::new_unique();
    let falcon_auth_program_id = Pubkey::new_unique();
    let mut mollusk = Mollusk::new(&smart_program_id, "../../target/deploy/pq_smart_account");
    mollusk.compute_budget.compute_unit_limit = 20_000_000;
    mollusk.add_program(&quorum_program_id, "../../target/deploy/pq_quorum_auth");
    mollusk.add_program(&falcon_auth_program_id, "../../target/deploy/falcon_auth");
    mollusk_token::add_program(&mut mollusk);

    let authority = Pubkey::new_unique();
    let depositor = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let (falcon_key, falcon_bump) = Pubkey::find_program_address(
        &[FALCON_KEY_SEED, authority.as_ref()],
        &falcon_auth_program_id,
    );
    let (quorum, quorum_bump) = Pubkey::find_program_address(
        &[
            QUORUM_SEED,
            authority.as_ref(),
            falcon_auth_program_id.as_ref(),
        ],
        &quorum_program_id,
    );
    let (smart_account, smart_bump) = Pubkey::find_program_address(
        &[
            SMART_ACCOUNT_SEED,
            authority.as_ref(),
            quorum_program_id.as_ref(),
            quorum.as_ref(),
        ],
        &smart_program_id,
    );
    let (prepared_pubkey, falcon_secret_key) = falcon_keypair();
    let winternitz_privkey = deterministic_winternitz_key();
    let winternitz_root = winternitz_privkey.public_root();

    Fixture {
        mollusk,
        smart_program_id,
        quorum_program_id,
        falcon_auth_program_id,
        authority,
        depositor,
        destination,
        falcon_key,
        quorum,
        smart_account,
        smart_bump,
        falcon_account: falcon_account(
            falcon_auth_program_id,
            authority,
            falcon_bump,
            falcon_nonce,
            prepared_pubkey,
        ),
        quorum_account: quorum_account(
            quorum_program_id,
            authority,
            quorum_bump,
            falcon_auth_program_id,
            falcon_key,
            winternitz_root,
            quorum_nonce,
        ),
        quorum_program_account: executable_program_account(),
        falcon_auth_program_account: executable_program_account(),
        falcon_secret_key,
        winternitz_privkey,
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
    data[8] = 2;
    data[9] = bump;
    data[FALCON_AUTH_CLUSTER_OFFSET] = CLUSTER;
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

fn quorum_account(
    program_id: Pubkey,
    authority: Pubkey,
    bump: u8,
    falcon_auth_program: Pubkey,
    falcon_key: Pubkey,
    winternitz_root: [u8; 32],
    next_nonce: u64,
) -> Account {
    let mut data = vec![0u8; QUORUM_ACCOUNT_LEN];
    data[..8].copy_from_slice(&QUORUM_DISCRIMINATOR);
    data[8] = 1;
    data[9] = bump;
    data[QUORUM_CLUSTER_OFFSET] = CLUSTER;
    data[QUORUM_AUTHORITY_OFFSET..QUORUM_FALCON_AUTH_PROGRAM_OFFSET]
        .copy_from_slice(authority.as_ref());
    data[QUORUM_FALCON_AUTH_PROGRAM_OFFSET..QUORUM_FALCON_KEY_OFFSET]
        .copy_from_slice(falcon_auth_program.as_ref());
    data[QUORUM_FALCON_KEY_OFFSET..QUORUM_WINTERNITZ_ROOT_OFFSET]
        .copy_from_slice(falcon_key.as_ref());
    data[QUORUM_WINTERNITZ_ROOT_OFFSET..QUORUM_NEXT_NONCE_OFFSET].copy_from_slice(&winternitz_root);
    data[QUORUM_NEXT_NONCE_OFFSET..QUORUM_NEXT_NONCE_OFFSET + 8]
        .copy_from_slice(&next_nonce.to_le_bytes());
    Account {
        lamports: 1_000_000_000,
        data,
        owner: program_id,
        executable: false,
        rent_epoch: 0,
    }
}

fn winternitz_signature_account(
    program_id: Pubkey,
    authority: Pubkey,
    quorum: Pubkey,
    quorum_nonce: u64,
    signature: [u8; WINTERNITZ_SIGNATURE_LEN],
) -> (Pubkey, Account) {
    let (key, bump) = Pubkey::find_program_address(
        &[
            b"wots-sig",
            authority.as_ref(),
            quorum.as_ref(),
            &quorum_nonce.to_le_bytes(),
        ],
        &program_id,
    );
    let mut data = vec![0u8; WINTERNITZ_SIGNATURE_BUFFER_LEN];
    data[..8].copy_from_slice(&WINTERNITZ_SIGNATURE_DISCRIMINATOR);
    data[8] = 1;
    data[9] = bump;
    data[SIGBUF_AUTHORITY_OFFSET..SIGBUF_QUORUM_OFFSET].copy_from_slice(authority.as_ref());
    data[SIGBUF_QUORUM_OFFSET..SIGBUF_NONCE_OFFSET].copy_from_slice(quorum.as_ref());
    data[SIGBUF_NONCE_OFFSET..SIGBUF_NONCE_OFFSET + 8].copy_from_slice(&quorum_nonce.to_le_bytes());
    data[SIGBUF_WRITTEN_OFFSET..SIGBUF_WRITTEN_OFFSET + 2]
        .copy_from_slice(&(WINTERNITZ_SIGNATURE_LEN as u16).to_le_bytes());
    data[SIGBUF_DATA_OFFSET..].copy_from_slice(&signature);
    (
        key,
        Account {
            lamports: 1_000_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    )
}

fn falcon_signature_buffer_address(fixture: &Fixture, quorum_nonce: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            FALCON_SIGNATURE_SEED,
            fixture.authority.as_ref(),
            fixture.smart_account.as_ref(),
            fixture.quorum.as_ref(),
            &quorum_nonce.to_le_bytes(),
        ],
        &fixture.smart_program_id,
    )
}

fn init_falcon_signature_buffer_ix(
    fixture: &Fixture,
    signature_buffer: Pubkey,
    bump: u8,
    quorum_nonce: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 1 + 8);
    data.push(TAG_SMART_INIT_FALCON_SIGNATURE);
    data.push(bump);
    data.extend_from_slice(&quorum_nonce.to_le_bytes());
    Instruction::new_with_bytes(
        fixture.smart_program_id,
        &data,
        vec![
            AccountMeta::new(fixture.authority, true),
            AccountMeta::new_readonly(fixture.smart_account, false),
            AccountMeta::new_readonly(fixture.quorum_program_id, false),
            AccountMeta::new_readonly(fixture.quorum, false),
            AccountMeta::new(signature_buffer, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
    )
}

fn write_falcon_signature_chunk_ix(
    fixture: &Fixture,
    signature_buffer: Pubkey,
    quorum_nonce: u64,
    offset: usize,
    chunk: &[u8],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 8 + 2 + chunk.len());
    data.push(TAG_SMART_WRITE_FALCON_SIGNATURE_CHUNK);
    data.extend_from_slice(&quorum_nonce.to_le_bytes());
    data.extend_from_slice(&(offset as u16).to_le_bytes());
    data.extend_from_slice(chunk);
    Instruction::new_with_bytes(
        fixture.smart_program_id,
        &data,
        vec![
            AccountMeta::new_readonly(fixture.authority, true),
            AccountMeta::new_readonly(fixture.smart_account, false),
            AccountMeta::new_readonly(fixture.quorum, false),
            AccountMeta::new(signature_buffer, false),
        ],
    )
}

fn initialized_falcon_signature_buffer(
    fixture: &Fixture,
    smart_account: Account,
    quorum_nonce: u64,
    signature: &[u8; FALCON_512_SIGNATURE_LEN],
) -> (Pubkey, Account) {
    let (signature_buffer, bump) = falcon_signature_buffer_address(fixture, quorum_nonce);
    let result = fixture.mollusk.process_instruction(
        &init_falcon_signature_buffer_ix(fixture, signature_buffer, bump, quorum_nonce),
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.smart_account, smart_account.clone()),
            (
                fixture.quorum_program_id,
                fixture.quorum_program_account.clone(),
            ),
            (fixture.quorum, fixture.quorum_account.clone()),
            (signature_buffer, system_account(0)),
            keyed_account_for_system_program(),
        ],
    );
    assert!(
        result.program_result.is_ok(),
        "{:?} raw={:?} cu={}",
        result.program_result,
        result.raw_result,
        result.compute_units_consumed
    );
    let mut buffer = result_account(&result, signature_buffer);
    assert_eq!(buffer.owner, fixture.smart_program_id);
    assert_eq!(buffer.data.len(), FALCON_SIGNATURE_BUFFER_LEN);
    assert_eq!(&buffer.data[..8], &FALCON_SIGNATURE_DISCRIMINATOR);
    assert_eq!(
        &buffer.data[SMART_SIGBUF_AUTHORITY_OFFSET..SMART_SIGBUF_SMART_ACCOUNT_OFFSET],
        fixture.authority.as_ref()
    );
    assert_eq!(
        &buffer.data[SMART_SIGBUF_SMART_ACCOUNT_OFFSET..SMART_SIGBUF_QUORUM_OFFSET],
        fixture.smart_account.as_ref()
    );
    assert_eq!(
        &buffer.data[SMART_SIGBUF_QUORUM_OFFSET..SMART_SIGBUF_QUORUM_NONCE_OFFSET],
        fixture.quorum.as_ref()
    );

    let mut offset = 0;
    while offset < signature.len() {
        let end = (offset + 512).min(signature.len());
        let result = fixture.mollusk.process_instruction(
            &write_falcon_signature_chunk_ix(
                fixture,
                signature_buffer,
                quorum_nonce,
                offset,
                &signature[offset..end],
            ),
            &[
                (fixture.authority, Account::default()),
                (fixture.smart_account, smart_account.clone()),
                (fixture.quorum, fixture.quorum_account.clone()),
                (signature_buffer, buffer),
            ],
        );
        assert!(result.program_result.is_ok(), "{:?}", result.program_result);
        buffer = result_account(&result, signature_buffer);
        offset = end;
    }
    assert_eq!(
        u16::from_le_bytes(
            buffer.data[SMART_SIGBUF_WRITTEN_OFFSET..SMART_SIGBUF_DATA_OFFSET]
                .try_into()
                .unwrap()
        ) as usize,
        FALCON_512_SIGNATURE_LEN
    );
    (signature_buffer, buffer)
}

fn mldsa_public_key_address(fixture: &Fixture) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            MLDSA_PUBLIC_KEY_SEED,
            fixture.authority.as_ref(),
            fixture.quorum.as_ref(),
        ],
        &fixture.quorum_program_id,
    )
}

fn mldsa_signature_address(fixture: &Fixture, quorum_nonce: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            MLDSA_SIGNATURE_SEED,
            fixture.authority.as_ref(),
            fixture.quorum.as_ref(),
            &quorum_nonce.to_le_bytes(),
        ],
        &fixture.quorum_program_id,
    )
}

fn mldsa_proof_address(fixture: &Fixture, quorum_nonce: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            MLDSA_PROOF_SEED,
            fixture.authority.as_ref(),
            fixture.quorum.as_ref(),
            &quorum_nonce.to_le_bytes(),
        ],
        &fixture.quorum_program_id,
    )
}

fn init_mldsa_public_key_ix(fixture: &Fixture, public_key_buffer: Pubkey, bump: u8) -> Instruction {
    Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &[TAG_INIT_MLDSA_PUBLIC_KEY, bump],
        vec![
            AccountMeta::new(fixture.authority, true),
            AccountMeta::new_readonly(fixture.quorum, false),
            AccountMeta::new(public_key_buffer, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
    )
}

fn write_mldsa_public_key_chunk_ix(
    fixture: &Fixture,
    public_key_buffer: Pubkey,
    offset: usize,
    chunk: &[u8],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 2 + chunk.len());
    data.push(TAG_WRITE_MLDSA_PUBLIC_KEY_CHUNK);
    data.extend_from_slice(&(offset as u16).to_le_bytes());
    data.extend_from_slice(chunk);
    Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &data,
        vec![
            AccountMeta::new_readonly(fixture.authority, true),
            AccountMeta::new_readonly(fixture.quorum, false),
            AccountMeta::new(public_key_buffer, false),
        ],
    )
}

fn finalize_mldsa_public_key_ix(fixture: &Fixture, public_key_buffer: Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &[TAG_FINALIZE_MLDSA_PUBLIC_KEY],
        vec![
            AccountMeta::new_readonly(fixture.authority, true),
            AccountMeta::new_readonly(fixture.quorum, false),
            AccountMeta::new(public_key_buffer, false),
        ],
    )
}

fn init_mldsa_signature_ix(
    fixture: &Fixture,
    signature_buffer: Pubkey,
    bump: u8,
    quorum_nonce: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 1 + 8);
    data.push(TAG_INIT_MLDSA_SIGNATURE);
    data.push(bump);
    data.extend_from_slice(&quorum_nonce.to_le_bytes());
    Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &data,
        vec![
            AccountMeta::new(fixture.authority, true),
            AccountMeta::new_readonly(fixture.quorum, false),
            AccountMeta::new(signature_buffer, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
    )
}

fn write_mldsa_signature_chunk_ix(
    fixture: &Fixture,
    signature_buffer: Pubkey,
    quorum_nonce: u64,
    offset: usize,
    chunk: &[u8],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 8 + 2 + chunk.len());
    data.push(TAG_WRITE_MLDSA_SIGNATURE_CHUNK);
    data.extend_from_slice(&quorum_nonce.to_le_bytes());
    data.extend_from_slice(&(offset as u16).to_le_bytes());
    data.extend_from_slice(chunk);
    Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &data,
        vec![
            AccountMeta::new_readonly(fixture.authority, true),
            AccountMeta::new_readonly(fixture.quorum, false),
            AccountMeta::new(signature_buffer, false),
        ],
    )
}

fn init_mldsa_proof_ix(
    fixture: &Fixture,
    proof: Pubkey,
    bump: u8,
    mode: u8,
    quorum_nonce: u64,
    payload_hash: &[u8; 32],
    mldsa_public_key: Pubkey,
    mldsa_signature: Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 1 + 1 + 8 + 32);
    data.push(TAG_INIT_MLDSA_PROOF);
    data.push(bump);
    data.push(mode);
    data.extend_from_slice(&quorum_nonce.to_le_bytes());
    data.extend_from_slice(payload_hash);
    Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &data,
        vec![
            AccountMeta::new(fixture.authority, true),
            AccountMeta::new_readonly(fixture.quorum, false),
            AccountMeta::new(proof, false),
            AccountMeta::new_readonly(mldsa_public_key, false),
            AccountMeta::new_readonly(mldsa_signature, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
    )
}

fn prepare_mldsa_proof_ix(
    fixture: &Fixture,
    proof: Pubkey,
    mldsa_public_key: Pubkey,
    mldsa_signature: Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &[TAG_PREPARE_MLDSA_PROOF],
        vec![
            AccountMeta::new_readonly(fixture.authority, true),
            AccountMeta::new_readonly(fixture.quorum, false),
            AccountMeta::new(proof, false),
            AccountMeta::new_readonly(mldsa_public_key, false),
            AccountMeta::new_readonly(mldsa_signature, false),
        ],
    )
}

fn prepare_mldsa_z_column_ix(
    fixture: &Fixture,
    proof: Pubkey,
    col: u8,
    mldsa_public_key: Pubkey,
    mldsa_signature: Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &[TAG_PREPARE_MLDSA_Z_COLUMN, col],
        vec![
            AccountMeta::new_readonly(fixture.authority, true),
            AccountMeta::new_readonly(fixture.quorum, false),
            AccountMeta::new(proof, false),
            AccountMeta::new_readonly(mldsa_public_key, false),
            AccountMeta::new_readonly(mldsa_signature, false),
        ],
    )
}

fn prove_mldsa_column_ix(
    fixture: &Fixture,
    proof: Pubkey,
    row: u8,
    col: u8,
    mldsa_public_key: Pubkey,
    mldsa_signature: Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &[TAG_PROVE_MLDSA_COLUMN, row, col],
        vec![
            AccountMeta::new_readonly(fixture.authority, true),
            AccountMeta::new_readonly(fixture.quorum, false),
            AccountMeta::new(proof, false),
            AccountMeta::new_readonly(mldsa_public_key, false),
            AccountMeta::new_readonly(mldsa_signature, false),
        ],
    )
}

fn finalize_mldsa_row_ix(
    fixture: &Fixture,
    proof: Pubkey,
    row: u8,
    mldsa_public_key: Pubkey,
    mldsa_signature: Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &[TAG_FINALIZE_MLDSA_ROW, row],
        vec![
            AccountMeta::new_readonly(fixture.authority, true),
            AccountMeta::new_readonly(fixture.quorum, false),
            AccountMeta::new(proof, false),
            AccountMeta::new_readonly(mldsa_public_key, false),
            AccountMeta::new_readonly(mldsa_signature, false),
        ],
    )
}

fn initialized_mldsa_public_key_buffer(
    fixture: &Fixture,
    quorum: Account,
    public_key_bytes: &[u8; MLDSA_PUBLIC_KEY_LEN],
) -> (Pubkey, Account) {
    let (public_key_buffer, bump) = mldsa_public_key_address(fixture);
    let result = fixture.mollusk.process_instruction(
        &init_mldsa_public_key_ix(fixture, public_key_buffer, bump),
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.quorum, quorum.clone()),
            (public_key_buffer, system_account(0)),
            keyed_account_for_system_program(),
        ],
    );
    assert!(
        result.program_result.is_ok(),
        "{:?} raw={:?} cu={}",
        result.program_result,
        result.raw_result,
        result.compute_units_consumed
    );
    let mut buffer = result_account(&result, public_key_buffer);
    assert_eq!(buffer.data.len(), MLDSA_PUBLIC_KEY_BUFFER_LEN);
    assert_eq!(&buffer.data[..8], &MLDSA_PUBLIC_KEY_DISCRIMINATOR);

    let mut offset = 0;
    while offset < public_key_bytes.len() {
        let end = (offset + 512).min(public_key_bytes.len());
        let result = fixture.mollusk.process_instruction(
            &write_mldsa_public_key_chunk_ix(
                fixture,
                public_key_buffer,
                offset,
                &public_key_bytes[offset..end],
            ),
            &[
                (fixture.authority, Account::default()),
                (fixture.quorum, quorum.clone()),
                (public_key_buffer, buffer),
            ],
        );
        assert!(result.program_result.is_ok(), "{:?}", result.program_result);
        buffer = result_account(&result, public_key_buffer);
        offset = end;
    }

    let result = fixture.mollusk.process_instruction(
        &finalize_mldsa_public_key_ix(fixture, public_key_buffer),
        &[
            (fixture.authority, Account::default()),
            (fixture.quorum, quorum),
            (public_key_buffer, buffer),
        ],
    );
    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    buffer = result_account(&result, public_key_buffer);
    assert_eq!(
        u16::from_le_bytes(
            buffer.data[SIGBUF_WRITTEN_OFFSET..SIGBUF_WRITTEN_OFFSET + 2]
                .try_into()
                .unwrap()
        ) as usize,
        MLDSA_PREPARED_PUBLIC_KEY_LEN
    );
    (public_key_buffer, buffer)
}

fn initialized_mldsa_signature_buffer(
    fixture: &Fixture,
    quorum: Account,
    quorum_nonce: u64,
    signature_bytes: &[u8; MLDSA_SIGNATURE_LEN],
) -> (Pubkey, Account) {
    let (signature_buffer, bump) = mldsa_signature_address(fixture, quorum_nonce);
    let result = fixture.mollusk.process_instruction(
        &init_mldsa_signature_ix(fixture, signature_buffer, bump, quorum_nonce),
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.quorum, quorum.clone()),
            (signature_buffer, system_account(0)),
            keyed_account_for_system_program(),
        ],
    );
    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    let mut buffer = result_account(&result, signature_buffer);
    assert_eq!(buffer.data.len(), MLDSA_SIGNATURE_BUFFER_LEN);

    let mut offset = 0;
    while offset < signature_bytes.len() {
        let end = (offset + 512).min(signature_bytes.len());
        let result = fixture.mollusk.process_instruction(
            &write_mldsa_signature_chunk_ix(
                fixture,
                signature_buffer,
                quorum_nonce,
                offset,
                &signature_bytes[offset..end],
            ),
            &[
                (fixture.authority, Account::default()),
                (fixture.quorum, quorum.clone()),
                (signature_buffer, buffer),
            ],
        );
        assert!(result.program_result.is_ok(), "{:?}", result.program_result);
        buffer = result_account(&result, signature_buffer);
        offset = end;
    }
    (signature_buffer, buffer)
}

struct MldsaProofSetup {
    proof: Pubkey,
    proof_account: Account,
    public_key: Pubkey,
    public_key_account: Account,
    signature: Pubkey,
    signature_account: Account,
    payload: [u8; QUORUM_ACTION_V2_PAYLOAD_LEN],
}

struct MldsaProofSetupInput {
    mode: u8,
    seed: u8,
    quorum_nonce: u64,
    expires_slot: u64,
    action_domain: [u8; 32],
    action_hash: [u8; 32],
    current_winternitz_root: [u8; 32],
    next_winternitz_root: [u8; 32],
}

fn initialized_mldsa_proof(
    fixture: &Fixture,
    quorum: Account,
    input: MldsaProofSetupInput,
) -> MldsaProofSetup {
    let seed = [input.seed; 32];
    let (mldsa_pk, mldsa_sk) = MlDsa44::keygen_from_seed(&seed);
    let mldsa_pk_bytes = mldsa_pk.into_bytes();
    let (public_key, public_key_account) =
        initialized_mldsa_public_key_buffer(fixture, quorum.clone(), &mldsa_pk_bytes);
    let payload = build_quorum_v2_payload(V2PayloadInput {
        mode: input.mode,
        quorum_program_id: fixture.quorum_program_id,
        authority: fixture.authority,
        quorum: fixture.quorum,
        mldsa_public_key: public_key,
        quorum_nonce: input.quorum_nonce,
        expires_slot: input.expires_slot,
        action_domain: &input.action_domain,
        action_hash: &input.action_hash,
        current_winternitz_root: &input.current_winternitz_root,
        next_winternitz_root: &input.next_winternitz_root,
    });
    let signature_bytes = mldsa_sk.try_sign(&payload, &[]).unwrap();
    let (signature, signature_account) = initialized_mldsa_signature_buffer(
        fixture,
        quorum.clone(),
        input.quorum_nonce,
        &signature_bytes,
    );
    let payload_hash = mldsa_proof_payload_hash(&payload);
    let (proof, bump) = mldsa_proof_address(fixture, input.quorum_nonce);

    let init = fixture.mollusk.process_instruction(
        &init_mldsa_proof_ix(
            fixture,
            proof,
            bump,
            input.mode,
            input.quorum_nonce,
            &payload_hash,
            public_key,
            signature,
        ),
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.quorum, quorum.clone()),
            (proof, system_account(0)),
            (public_key, public_key_account.clone()),
            (signature, signature_account.clone()),
            keyed_account_for_system_program(),
        ],
    );
    assert!(
        init.program_result.is_ok(),
        "{:?} raw={:?} cu={}",
        init.program_result,
        init.raw_result,
        init.compute_units_consumed
    );
    let mut proof_account = result_account(&init, proof);
    assert_eq!(proof_account.owner, fixture.quorum_program_id);
    assert_eq!(proof_account.data.len(), MLDSA_PROOF_ACCOUNT_LEN);
    assert_eq!(&proof_account.data[..8], &MLDSA_PROOF_DISCRIMINATOR);
    assert_eq!(proof_account.data[PROOF_MODE_OFFSET], input.mode);
    assert_eq!(proof_account.data[PROOF_ROW_MASK_OFFSET], 0);
    assert_eq!(
        &proof_account.data[PROOF_AUTHORITY_OFFSET..PROOF_QUORUM_OFFSET],
        fixture.authority.as_ref()
    );
    assert_eq!(
        &proof_account.data[PROOF_QUORUM_OFFSET..PROOF_NONCE_OFFSET],
        fixture.quorum.as_ref()
    );
    assert_eq!(
        &proof_account.data[PROOF_MLDSA_PUBLIC_KEY_OFFSET..PROOF_MLDSA_SIGNATURE_OFFSET],
        public_key.as_ref()
    );
    assert_eq!(
        &proof_account.data[PROOF_MLDSA_SIGNATURE_OFFSET..PROOF_PAYLOAD_HASH_OFFSET],
        signature.as_ref()
    );
    assert_eq!(
        &proof_account.data[PROOF_PAYLOAD_HASH_OFFSET..PROOF_W1_OFFSET],
        &payload_hash
    );

    let prepared = fixture.mollusk.process_instruction(
        &prepare_mldsa_proof_ix(fixture, proof, public_key, signature),
        &[
            (fixture.authority, Account::default()),
            (fixture.quorum, quorum.clone()),
            (proof, proof_account),
            (public_key, public_key_account.clone()),
            (signature, signature_account.clone()),
        ],
    );
    assert!(
        prepared.program_result.is_ok(),
        "{:?} raw={:?} cu={}",
        prepared.program_result,
        prepared.raw_result,
        prepared.compute_units_consumed
    );
    assert!(prepared.compute_units_consumed <= DEVNET_TX_MAX_CU);
    proof_account = result_account(&prepared, proof);
    assert_eq!(proof_account.data[PROOF_PREPARED_FLAG_OFFSET], 1);

    for col in 0..MLDSA_COLUMNS {
        let result = fixture.mollusk.process_instruction(
            &prepare_mldsa_z_column_ix(fixture, proof, col as u8, public_key, signature),
            &[
                (fixture.authority, Account::default()),
                (fixture.quorum, quorum.clone()),
                (proof, proof_account),
                (public_key, public_key_account.clone()),
                (signature, signature_account.clone()),
            ],
        );
        assert!(
            result.program_result.is_ok(),
            "z col {} {:?} raw={:?} cu={}",
            col,
            result.program_result,
            result.raw_result,
            result.compute_units_consumed
        );
        assert!(result.compute_units_consumed <= DEVNET_TX_MAX_CU);
        proof_account = result_account(&result, proof);
        assert_eq!(
            proof_account.data[PROOF_Z_MASK_OFFSET],
            (1 << (col + 1)) - 1
        );
    }

    for row in 0..MLDSA_ROWS {
        for col in 0..MLDSA_COLUMNS {
            let result = fixture.mollusk.process_instruction(
                &prove_mldsa_column_ix(fixture, proof, row as u8, col as u8, public_key, signature),
                &[
                    (fixture.authority, Account::default()),
                    (fixture.quorum, quorum.clone()),
                    (proof, proof_account),
                    (public_key, public_key_account.clone()),
                    (signature, signature_account.clone()),
                ],
            );
            assert!(
                result.program_result.is_ok(),
                "row {} col {} {:?} raw={:?} cu={}",
                row,
                col,
                result.program_result,
                result.raw_result,
                result.compute_units_consumed
            );
            assert!(result.compute_units_consumed <= DEVNET_TX_MAX_CU);
            proof_account = result_account(&result, proof);
            assert_eq!(
                proof_account.data[PROOF_COLUMN_MASK_OFFSET + row],
                (1 << (col + 1)) - 1
            );
        }
        let result = fixture.mollusk.process_instruction(
            &finalize_mldsa_row_ix(fixture, proof, row as u8, public_key, signature),
            &[
                (fixture.authority, Account::default()),
                (fixture.quorum, quorum.clone()),
                (proof, proof_account),
                (public_key, public_key_account.clone()),
                (signature, signature_account.clone()),
            ],
        );
        assert!(
            result.program_result.is_ok(),
            "row {} final {:?} raw={:?} cu={}",
            row,
            result.program_result,
            result.raw_result,
            result.compute_units_consumed
        );
        assert!(result.compute_units_consumed <= DEVNET_TX_MAX_CU);
        proof_account = result_account(&result, proof);
        assert_eq!(
            proof_account.data[PROOF_COLUMN_MASK_OFFSET + row],
            MLDSA_PROOF_COLUMN_COMPLETE_MASK
        );
        assert_eq!(
            proof_account.data[PROOF_ROW_MASK_OFFSET],
            (1 << (row + 1)) - 1
        );
    }
    assert_eq!(
        proof_account.data[PROOF_ROW_MASK_OFFSET],
        MLDSA_PROOF_COMPLETE_MASK
    );

    MldsaProofSetup {
        proof,
        proof_account,
        public_key,
        public_key_account,
        signature,
        signature_account,
        payload,
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

fn system_account(lamports: u64) -> Account {
    Account::new(lamports, 0, &solana_sdk_ids::system_program::id())
}

fn empty_smart_account() -> Account {
    Account::new(0, 0, &solana_sdk_ids::system_program::id())
}

fn spl_mint_account(decimals: u8, supply: u64) -> Account {
    let mut data = vec![0; Mint::LEN];
    Mint {
        mint_authority: COption::None,
        supply,
        decimals,
        is_initialized: true,
        freeze_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    Account {
        lamports: 1_000_000_000,
        data,
        owner: SPL_TOKEN_ID,
        executable: false,
        rent_epoch: 0,
    }
}

fn spl_token_account(mint: Pubkey, owner: Pubkey, amount: u64) -> Account {
    let mut data = vec![0; SplTokenAccount::LEN];
    SplTokenAccount {
        mint,
        owner,
        amount,
        delegate: COption::None,
        state: AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    Account {
        lamports: 1_000_000_000,
        data,
        owner: SPL_TOKEN_ID,
        executable: false,
        rent_epoch: 0,
    }
}

fn spl_token_amount(account: &Account) -> u64 {
    SplTokenAccount::unpack(&account.data).unwrap().amount
}

fn init_account_ix(fixture: &Fixture) -> Instruction {
    Instruction::new_with_bytes(
        fixture.smart_program_id,
        &[TAG_INIT_ACCOUNT, fixture.smart_bump],
        vec![
            AccountMeta::new(fixture.authority, true),
            AccountMeta::new(fixture.smart_account, false),
            AccountMeta::new_readonly(fixture.quorum_program_id, false),
            AccountMeta::new_readonly(fixture.quorum, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
    )
}

fn deposit_ix(fixture: &Fixture, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(1 + 8);
    data.push(TAG_DEPOSIT);
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction::new_with_bytes(
        fixture.smart_program_id,
        &data,
        vec![
            AccountMeta::new(fixture.depositor, true),
            AccountMeta::new(fixture.smart_account, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
    )
}

struct TransferIxInput {
    lamports: u64,
    signed_lamports: u64,
    quorum_nonce: u64,
    falcon_nonce: u64,
    spend_count: u64,
    destination: Pubkey,
    signed_destination: Pubkey,
}

fn transfer_ix(
    fixture: &Fixture,
    input: TransferIxInput,
) -> (Instruction, Pubkey, Account, [u8; 32]) {
    let expires_slot = 100;
    let next_winternitz_key = deterministic_next_winternitz_key();
    let next_winternitz_root = next_winternitz_key.public_root();
    let action_domain = smart_transfer_domain();
    let action_hash = smart_transfer_hash(
        &fixture.smart_program_id,
        &fixture.smart_account,
        &fixture.authority,
        &input.signed_destination,
        input.signed_lamports,
        input.spend_count,
    );
    let quorum_payload = build_quorum_payload(
        fixture.quorum_program_id,
        fixture.authority,
        fixture.quorum,
        input.quorum_nonce,
        expires_slot,
        &action_domain,
        &action_hash,
        &next_winternitz_root,
    );
    let winternitz_signature = fixture.winternitz_privkey.sign(&quorum_payload);
    let (winternitz_signature_account_key, winternitz_signature_account) =
        winternitz_signature_account(
            fixture.quorum_program_id,
            fixture.authority,
            fixture.quorum,
            input.quorum_nonce,
            winternitz_signature,
        );
    let falcon_action_domain = pq_quorum_falcon_domain();
    let falcon_action_hash = pq_quorum_falcon_action_hash(&quorum_payload);
    let falcon_payload = build_falcon_payload(
        fixture.falcon_auth_program_id,
        fixture.authority,
        fixture.falcon_key,
        input.falcon_nonce,
        expires_slot,
        &falcon_action_domain,
        &falcon_action_hash,
    );
    let falcon_signature = falcon_signature_bytes(&falcon_payload, &fixture.falcon_secret_key);

    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 8 + 32 + FALCON_512_SIGNATURE_LEN);
    data.push(TAG_TRANSFER_FALCON_WINTERNITZ);
    data.push(CLUSTER);
    data.extend_from_slice(&input.quorum_nonce.to_le_bytes());
    data.extend_from_slice(&input.falcon_nonce.to_le_bytes());
    data.extend_from_slice(&expires_slot.to_le_bytes());
    data.extend_from_slice(&input.lamports.to_le_bytes());
    data.extend_from_slice(&next_winternitz_root);
    data.extend_from_slice(&falcon_signature);

    (
        Instruction::new_with_bytes(
            fixture.smart_program_id,
            &data,
            vec![
                AccountMeta::new(fixture.authority, false),
                AccountMeta::new(fixture.smart_account, false),
                AccountMeta::new(input.destination, false),
                AccountMeta::new_readonly(fixture.quorum_program_id, false),
                AccountMeta::new(fixture.quorum, false),
                AccountMeta::new(fixture.falcon_key, false),
                AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
                AccountMeta::new(winternitz_signature_account_key, false),
            ],
        ),
        winternitz_signature_account_key,
        winternitz_signature_account,
        next_winternitz_root,
    )
}

struct TokenTransferIxInput {
    amount: u64,
    signed_amount: u64,
    decimals: u8,
    signed_decimals: u8,
    quorum_nonce: u64,
    falcon_nonce: u64,
    spend_count: u64,
    source_token: Pubkey,
    signed_source_token: Pubkey,
    mint: Pubkey,
    signed_mint: Pubkey,
    destination_token: Pubkey,
    signed_destination_token: Pubkey,
}

fn token_transfer_falcon_winternitz_ix(
    fixture: &Fixture,
    input: TokenTransferIxInput,
) -> (Instruction, Pubkey, Account, [u8; 32]) {
    let expires_slot = 100;
    let next_winternitz_key = deterministic_next_winternitz_key();
    let next_winternitz_root = next_winternitz_key.public_root();
    let action_domain = smart_token_transfer_domain();
    let action_hash = smart_token_transfer_hash(SmartTokenTransferHashInput {
        program_id: &fixture.smart_program_id,
        smart_account: &fixture.smart_account,
        authority: &fixture.authority,
        token_program: &SPL_TOKEN_ID,
        source_token: &input.signed_source_token,
        mint: &input.signed_mint,
        destination_token: &input.signed_destination_token,
        amount: input.signed_amount,
        decimals: input.signed_decimals,
        spend_count: input.spend_count,
    });
    let quorum_payload = build_quorum_payload(
        fixture.quorum_program_id,
        fixture.authority,
        fixture.quorum,
        input.quorum_nonce,
        expires_slot,
        &action_domain,
        &action_hash,
        &next_winternitz_root,
    );
    let winternitz_signature = fixture.winternitz_privkey.sign(&quorum_payload);
    let (winternitz_signature_account_key, winternitz_signature_account) =
        winternitz_signature_account(
            fixture.quorum_program_id,
            fixture.authority,
            fixture.quorum,
            input.quorum_nonce,
            winternitz_signature,
        );
    let falcon_action_domain = pq_quorum_falcon_domain();
    let falcon_action_hash = pq_quorum_falcon_action_hash(&quorum_payload);
    let falcon_payload = build_falcon_payload(
        fixture.falcon_auth_program_id,
        fixture.authority,
        fixture.falcon_key,
        input.falcon_nonce,
        expires_slot,
        &falcon_action_domain,
        &falcon_action_hash,
    );
    let falcon_signature = falcon_signature_bytes(&falcon_payload, &fixture.falcon_secret_key);

    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 8 + 1 + 32 + FALCON_512_SIGNATURE_LEN);
    data.push(TAG_TRANSFER_SPL_TOKEN_FALCON_WINTERNITZ);
    data.push(CLUSTER);
    data.extend_from_slice(&input.quorum_nonce.to_le_bytes());
    data.extend_from_slice(&input.falcon_nonce.to_le_bytes());
    data.extend_from_slice(&expires_slot.to_le_bytes());
    data.extend_from_slice(&input.amount.to_le_bytes());
    data.push(input.decimals);
    data.extend_from_slice(&next_winternitz_root);
    data.extend_from_slice(&falcon_signature);

    (
        Instruction::new_with_bytes(
            fixture.smart_program_id,
            &data,
            vec![
                AccountMeta::new(fixture.authority, false),
                AccountMeta::new(fixture.smart_account, false),
                AccountMeta::new_readonly(SPL_TOKEN_ID, false),
                AccountMeta::new(input.source_token, false),
                AccountMeta::new_readonly(input.mint, false),
                AccountMeta::new(input.destination_token, false),
                AccountMeta::new_readonly(fixture.quorum_program_id, false),
                AccountMeta::new(fixture.quorum, false),
                AccountMeta::new(fixture.falcon_key, false),
                AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
                AccountMeta::new(winternitz_signature_account_key, false),
            ],
        ),
        winternitz_signature_account_key,
        winternitz_signature_account,
        next_winternitz_root,
    )
}

fn token_transfer_falcon_winternitz_buffered_ix(
    fixture: &Fixture,
    smart_account: Account,
    input: TokenTransferIxInput,
) -> (Instruction, Pubkey, Account, Pubkey, Account, [u8; 32]) {
    let expires_slot = 100;
    let next_winternitz_key = deterministic_next_winternitz_key();
    let next_winternitz_root = next_winternitz_key.public_root();
    let action_domain = smart_token_transfer_domain();
    let action_hash = smart_token_transfer_hash(SmartTokenTransferHashInput {
        program_id: &fixture.smart_program_id,
        smart_account: &fixture.smart_account,
        authority: &fixture.authority,
        token_program: &SPL_TOKEN_ID,
        source_token: &input.signed_source_token,
        mint: &input.signed_mint,
        destination_token: &input.signed_destination_token,
        amount: input.signed_amount,
        decimals: input.signed_decimals,
        spend_count: input.spend_count,
    });
    let quorum_payload = build_quorum_payload(
        fixture.quorum_program_id,
        fixture.authority,
        fixture.quorum,
        input.quorum_nonce,
        expires_slot,
        &action_domain,
        &action_hash,
        &next_winternitz_root,
    );
    let winternitz_signature = fixture.winternitz_privkey.sign(&quorum_payload);
    let (winternitz_signature_account_key, winternitz_signature_account) =
        winternitz_signature_account(
            fixture.quorum_program_id,
            fixture.authority,
            fixture.quorum,
            input.quorum_nonce,
            winternitz_signature,
        );
    let falcon_action_domain = pq_quorum_falcon_domain();
    let falcon_action_hash = pq_quorum_falcon_action_hash(&quorum_payload);
    let falcon_payload = build_falcon_payload(
        fixture.falcon_auth_program_id,
        fixture.authority,
        fixture.falcon_key,
        input.falcon_nonce,
        expires_slot,
        &falcon_action_domain,
        &falcon_action_hash,
    );
    let falcon_signature = falcon_signature_bytes(&falcon_payload, &fixture.falcon_secret_key);
    let (falcon_signature_buffer, falcon_signature_buffer_account) =
        initialized_falcon_signature_buffer(
            fixture,
            smart_account,
            input.quorum_nonce,
            &falcon_signature,
        );

    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 8 + 1 + 32);
    data.push(TAG_TRANSFER_SPL_TOKEN_FALCON_WINTERNITZ_BUFFERED);
    data.push(CLUSTER);
    data.extend_from_slice(&input.quorum_nonce.to_le_bytes());
    data.extend_from_slice(&input.falcon_nonce.to_le_bytes());
    data.extend_from_slice(&expires_slot.to_le_bytes());
    data.extend_from_slice(&input.amount.to_le_bytes());
    data.push(input.decimals);
    data.extend_from_slice(&next_winternitz_root);

    (
        Instruction::new_with_bytes(
            fixture.smart_program_id,
            &data,
            vec![
                AccountMeta::new(fixture.authority, false),
                AccountMeta::new(fixture.smart_account, false),
                AccountMeta::new_readonly(SPL_TOKEN_ID, false),
                AccountMeta::new(input.source_token, false),
                AccountMeta::new_readonly(input.mint, false),
                AccountMeta::new(input.destination_token, false),
                AccountMeta::new_readonly(fixture.quorum_program_id, false),
                AccountMeta::new(fixture.quorum, false),
                AccountMeta::new(fixture.falcon_key, false),
                AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
                AccountMeta::new(winternitz_signature_account_key, false),
                AccountMeta::new(falcon_signature_buffer, false),
            ],
        ),
        winternitz_signature_account_key,
        winternitz_signature_account,
        falcon_signature_buffer,
        falcon_signature_buffer_account,
        next_winternitz_root,
    )
}

fn transfer_falcon_mldsa_ix(
    fixture: &Fixture,
    input: TransferIxInput,
) -> (Instruction, MldsaProofSetup) {
    let expires_slot = 100;
    let current_root = fixture.winternitz_privkey.public_root();
    let action_domain = smart_transfer_domain();
    let action_hash = smart_transfer_hash(
        &fixture.smart_program_id,
        &fixture.smart_account,
        &fixture.authority,
        &input.signed_destination,
        input.signed_lamports,
        input.spend_count,
    );
    let proof_setup = initialized_mldsa_proof(
        fixture,
        fixture.quorum_account.clone(),
        MldsaProofSetupInput {
            mode: QUORUM_MODE_FALCON_MLDSA,
            seed: 61,
            quorum_nonce: input.quorum_nonce,
            expires_slot,
            action_domain,
            action_hash,
            current_winternitz_root: current_root,
            next_winternitz_root: current_root,
        },
    );
    let falcon_domain = pq_quorum_falcon_domain_v2();
    let falcon_action_hash = pq_quorum_falcon_action_hash_v2(&proof_setup.payload);
    let falcon_payload = build_falcon_payload(
        fixture.falcon_auth_program_id,
        fixture.authority,
        fixture.falcon_key,
        input.falcon_nonce,
        expires_slot,
        &falcon_domain,
        &falcon_action_hash,
    );
    let falcon_signature = falcon_signature_bytes(&falcon_payload, &fixture.falcon_secret_key);

    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 8 + FALCON_512_SIGNATURE_LEN);
    data.push(TAG_TRANSFER_FALCON_MLDSA_PROOF);
    data.push(CLUSTER);
    data.extend_from_slice(&input.quorum_nonce.to_le_bytes());
    data.extend_from_slice(&input.falcon_nonce.to_le_bytes());
    data.extend_from_slice(&expires_slot.to_le_bytes());
    data.extend_from_slice(&input.lamports.to_le_bytes());
    data.extend_from_slice(&falcon_signature);

    (
        Instruction::new_with_bytes(
            fixture.smart_program_id,
            &data,
            vec![
                AccountMeta::new(fixture.authority, false),
                AccountMeta::new(fixture.smart_account, false),
                AccountMeta::new(input.destination, false),
                AccountMeta::new_readonly(fixture.quorum_program_id, false),
                AccountMeta::new(fixture.quorum, false),
                AccountMeta::new(fixture.falcon_key, false),
                AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
                AccountMeta::new_readonly(proof_setup.public_key, false),
                AccountMeta::new(proof_setup.signature, false),
                AccountMeta::new(proof_setup.proof, false),
            ],
        ),
        proof_setup,
    )
}

fn transfer_falcon_mldsa_buffered_ix(
    fixture: &Fixture,
    smart_account: Account,
    input: TransferIxInput,
) -> (Instruction, MldsaProofSetup, Pubkey, Account) {
    let expires_slot = 100;
    let current_root = fixture.winternitz_privkey.public_root();
    let action_domain = smart_transfer_domain();
    let action_hash = smart_transfer_hash(
        &fixture.smart_program_id,
        &fixture.smart_account,
        &fixture.authority,
        &input.signed_destination,
        input.signed_lamports,
        input.spend_count,
    );
    let proof_setup = initialized_mldsa_proof(
        fixture,
        fixture.quorum_account.clone(),
        MldsaProofSetupInput {
            mode: QUORUM_MODE_FALCON_MLDSA,
            seed: 63,
            quorum_nonce: input.quorum_nonce,
            expires_slot,
            action_domain,
            action_hash,
            current_winternitz_root: current_root,
            next_winternitz_root: current_root,
        },
    );
    let falcon_domain = pq_quorum_falcon_domain_v2();
    let falcon_action_hash = pq_quorum_falcon_action_hash_v2(&proof_setup.payload);
    let falcon_payload = build_falcon_payload(
        fixture.falcon_auth_program_id,
        fixture.authority,
        fixture.falcon_key,
        input.falcon_nonce,
        expires_slot,
        &falcon_domain,
        &falcon_action_hash,
    );
    let falcon_signature = falcon_signature_bytes(&falcon_payload, &fixture.falcon_secret_key);
    let (falcon_signature_buffer, falcon_signature_account) = initialized_falcon_signature_buffer(
        fixture,
        smart_account,
        input.quorum_nonce,
        &falcon_signature,
    );

    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 8);
    data.push(TAG_TRANSFER_FALCON_MLDSA_PROOF_BUFFERED);
    data.push(CLUSTER);
    data.extend_from_slice(&input.quorum_nonce.to_le_bytes());
    data.extend_from_slice(&input.falcon_nonce.to_le_bytes());
    data.extend_from_slice(&expires_slot.to_le_bytes());
    data.extend_from_slice(&input.lamports.to_le_bytes());

    (
        Instruction::new_with_bytes(
            fixture.smart_program_id,
            &data,
            vec![
                AccountMeta::new(fixture.authority, false),
                AccountMeta::new(fixture.smart_account, false),
                AccountMeta::new(input.destination, false),
                AccountMeta::new_readonly(fixture.quorum_program_id, false),
                AccountMeta::new(fixture.quorum, false),
                AccountMeta::new(fixture.falcon_key, false),
                AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
                AccountMeta::new_readonly(proof_setup.public_key, false),
                AccountMeta::new(proof_setup.signature, false),
                AccountMeta::new(proof_setup.proof, false),
                AccountMeta::new(falcon_signature_buffer, false),
            ],
        ),
        proof_setup,
        falcon_signature_buffer,
        falcon_signature_account,
    )
}

fn transfer_winternitz_mldsa_ix(
    fixture: &Fixture,
    input: TransferIxInput,
) -> (Instruction, Pubkey, Account, MldsaProofSetup, [u8; 32]) {
    let expires_slot = 100;
    let next_winternitz_key = deterministic_next_winternitz_key();
    let next_winternitz_root = next_winternitz_key.public_root();
    let current_root = fixture.winternitz_privkey.public_root();
    let action_domain = smart_transfer_domain();
    let action_hash = smart_transfer_hash(
        &fixture.smart_program_id,
        &fixture.smart_account,
        &fixture.authority,
        &input.signed_destination,
        input.signed_lamports,
        input.spend_count,
    );
    let proof_setup = initialized_mldsa_proof(
        fixture,
        fixture.quorum_account.clone(),
        MldsaProofSetupInput {
            mode: QUORUM_MODE_WINTERNITZ_MLDSA,
            seed: 62,
            quorum_nonce: input.quorum_nonce,
            expires_slot,
            action_domain,
            action_hash,
            current_winternitz_root: current_root,
            next_winternitz_root,
        },
    );
    let winternitz_signature = fixture.winternitz_privkey.sign(&proof_setup.payload);
    let (winternitz_signature_key, winternitz_signature_account) = winternitz_signature_account(
        fixture.quorum_program_id,
        fixture.authority,
        fixture.quorum,
        input.quorum_nonce,
        winternitz_signature,
    );

    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 32);
    data.push(TAG_TRANSFER_WINTERNITZ_MLDSA_PROOF);
    data.push(CLUSTER);
    data.extend_from_slice(&input.quorum_nonce.to_le_bytes());
    data.extend_from_slice(&expires_slot.to_le_bytes());
    data.extend_from_slice(&input.lamports.to_le_bytes());
    data.extend_from_slice(&next_winternitz_root);

    (
        Instruction::new_with_bytes(
            fixture.smart_program_id,
            &data,
            vec![
                AccountMeta::new(fixture.authority, false),
                AccountMeta::new(fixture.smart_account, false),
                AccountMeta::new(input.destination, false),
                AccountMeta::new_readonly(fixture.quorum_program_id, false),
                AccountMeta::new(fixture.quorum, false),
                AccountMeta::new_readonly(fixture.falcon_key, false),
                AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
                AccountMeta::new(winternitz_signature_key, false),
                AccountMeta::new_readonly(proof_setup.public_key, false),
                AccountMeta::new(proof_setup.signature, false),
                AccountMeta::new(proof_setup.proof, false),
            ],
        ),
        winternitz_signature_key,
        winternitz_signature_account,
        proof_setup,
        next_winternitz_root,
    )
}

fn token_transfer_falcon_mldsa_buffered_ix(
    fixture: &Fixture,
    smart_account: Account,
    input: TokenTransferIxInput,
) -> (Instruction, MldsaProofSetup, Pubkey, Account) {
    let expires_slot = 100;
    let current_root = fixture.winternitz_privkey.public_root();
    let action_domain = smart_token_transfer_domain();
    let action_hash = smart_token_transfer_hash(SmartTokenTransferHashInput {
        program_id: &fixture.smart_program_id,
        smart_account: &fixture.smart_account,
        authority: &fixture.authority,
        token_program: &SPL_TOKEN_ID,
        source_token: &input.signed_source_token,
        mint: &input.signed_mint,
        destination_token: &input.signed_destination_token,
        amount: input.signed_amount,
        decimals: input.signed_decimals,
        spend_count: input.spend_count,
    });
    let proof_setup = initialized_mldsa_proof(
        fixture,
        fixture.quorum_account.clone(),
        MldsaProofSetupInput {
            mode: QUORUM_MODE_FALCON_MLDSA,
            seed: 73,
            quorum_nonce: input.quorum_nonce,
            expires_slot,
            action_domain,
            action_hash,
            current_winternitz_root: current_root,
            next_winternitz_root: current_root,
        },
    );
    let falcon_domain = pq_quorum_falcon_domain_v2();
    let falcon_action_hash = pq_quorum_falcon_action_hash_v2(&proof_setup.payload);
    let falcon_payload = build_falcon_payload(
        fixture.falcon_auth_program_id,
        fixture.authority,
        fixture.falcon_key,
        input.falcon_nonce,
        expires_slot,
        &falcon_domain,
        &falcon_action_hash,
    );
    let falcon_signature = falcon_signature_bytes(&falcon_payload, &fixture.falcon_secret_key);
    let (falcon_signature_buffer, falcon_signature_account) = initialized_falcon_signature_buffer(
        fixture,
        smart_account,
        input.quorum_nonce,
        &falcon_signature,
    );

    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 8 + 1);
    data.push(TAG_TRANSFER_SPL_TOKEN_FALCON_MLDSA_PROOF_BUFFERED);
    data.push(CLUSTER);
    data.extend_from_slice(&input.quorum_nonce.to_le_bytes());
    data.extend_from_slice(&input.falcon_nonce.to_le_bytes());
    data.extend_from_slice(&expires_slot.to_le_bytes());
    data.extend_from_slice(&input.amount.to_le_bytes());
    data.push(input.decimals);

    (
        Instruction::new_with_bytes(
            fixture.smart_program_id,
            &data,
            vec![
                AccountMeta::new(fixture.authority, false),
                AccountMeta::new(fixture.smart_account, false),
                AccountMeta::new_readonly(SPL_TOKEN_ID, false),
                AccountMeta::new(input.source_token, false),
                AccountMeta::new_readonly(input.mint, false),
                AccountMeta::new(input.destination_token, false),
                AccountMeta::new_readonly(fixture.quorum_program_id, false),
                AccountMeta::new(fixture.quorum, false),
                AccountMeta::new(fixture.falcon_key, false),
                AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
                AccountMeta::new_readonly(proof_setup.public_key, false),
                AccountMeta::new(proof_setup.signature, false),
                AccountMeta::new(proof_setup.proof, false),
                AccountMeta::new(falcon_signature_buffer, false),
            ],
        ),
        proof_setup,
        falcon_signature_buffer,
        falcon_signature_account,
    )
}

fn token_transfer_winternitz_mldsa_ix(
    fixture: &Fixture,
    input: TokenTransferIxInput,
) -> (Instruction, Pubkey, Account, MldsaProofSetup, [u8; 32]) {
    let expires_slot = 100;
    let next_winternitz_key = deterministic_next_winternitz_key();
    let next_winternitz_root = next_winternitz_key.public_root();
    let current_root = fixture.winternitz_privkey.public_root();
    let action_domain = smart_token_transfer_domain();
    let action_hash = smart_token_transfer_hash(SmartTokenTransferHashInput {
        program_id: &fixture.smart_program_id,
        smart_account: &fixture.smart_account,
        authority: &fixture.authority,
        token_program: &SPL_TOKEN_ID,
        source_token: &input.signed_source_token,
        mint: &input.signed_mint,
        destination_token: &input.signed_destination_token,
        amount: input.signed_amount,
        decimals: input.signed_decimals,
        spend_count: input.spend_count,
    });
    let proof_setup = initialized_mldsa_proof(
        fixture,
        fixture.quorum_account.clone(),
        MldsaProofSetupInput {
            mode: QUORUM_MODE_WINTERNITZ_MLDSA,
            seed: 74,
            quorum_nonce: input.quorum_nonce,
            expires_slot,
            action_domain,
            action_hash,
            current_winternitz_root: current_root,
            next_winternitz_root,
        },
    );
    let winternitz_signature = fixture.winternitz_privkey.sign(&proof_setup.payload);
    let (winternitz_signature_key, winternitz_signature_account) = winternitz_signature_account(
        fixture.quorum_program_id,
        fixture.authority,
        fixture.quorum,
        input.quorum_nonce,
        winternitz_signature,
    );

    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 1 + 32);
    data.push(TAG_TRANSFER_SPL_TOKEN_WINTERNITZ_MLDSA_PROOF);
    data.push(CLUSTER);
    data.extend_from_slice(&input.quorum_nonce.to_le_bytes());
    data.extend_from_slice(&expires_slot.to_le_bytes());
    data.extend_from_slice(&input.amount.to_le_bytes());
    data.push(input.decimals);
    data.extend_from_slice(&next_winternitz_root);

    (
        Instruction::new_with_bytes(
            fixture.smart_program_id,
            &data,
            vec![
                AccountMeta::new(fixture.authority, false),
                AccountMeta::new(fixture.smart_account, false),
                AccountMeta::new_readonly(SPL_TOKEN_ID, false),
                AccountMeta::new(input.source_token, false),
                AccountMeta::new_readonly(input.mint, false),
                AccountMeta::new(input.destination_token, false),
                AccountMeta::new_readonly(fixture.quorum_program_id, false),
                AccountMeta::new(fixture.quorum, false),
                AccountMeta::new_readonly(fixture.falcon_key, false),
                AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
                AccountMeta::new(winternitz_signature_key, false),
                AccountMeta::new_readonly(proof_setup.public_key, false),
                AccountMeta::new(proof_setup.signature, false),
                AccountMeta::new(proof_setup.proof, false),
            ],
        ),
        winternitz_signature_key,
        winternitz_signature_account,
        proof_setup,
        next_winternitz_root,
    )
}

fn build_quorum_payload(
    quorum_program_id: Pubkey,
    authority: Pubkey,
    quorum: Pubkey,
    quorum_nonce: u64,
    expires_slot: u64,
    action_domain: &[u8; 32],
    action_hash: &[u8; 32],
    next_winternitz_root: &[u8; 32],
) -> [u8; QUORUM_ACTION_PAYLOAD_LEN] {
    let mut out = [0u8; QUORUM_ACTION_PAYLOAD_LEN];
    out[0..16].copy_from_slice(&QUORUM_ACTION_MAGIC);
    out[16] = CLUSTER;
    out[17..49].copy_from_slice(quorum_program_id.as_ref());
    out[49..81].copy_from_slice(authority.as_ref());
    out[81..113].copy_from_slice(quorum.as_ref());
    out[113..121].copy_from_slice(&quorum_nonce.to_le_bytes());
    out[121..129].copy_from_slice(&expires_slot.to_le_bytes());
    out[129..161].copy_from_slice(action_domain);
    out[161..193].copy_from_slice(action_hash);
    out[193..225].copy_from_slice(next_winternitz_root);
    out
}

struct V2PayloadInput<'a> {
    mode: u8,
    quorum_program_id: Pubkey,
    authority: Pubkey,
    quorum: Pubkey,
    mldsa_public_key: Pubkey,
    quorum_nonce: u64,
    expires_slot: u64,
    action_domain: &'a [u8; 32],
    action_hash: &'a [u8; 32],
    current_winternitz_root: &'a [u8; 32],
    next_winternitz_root: &'a [u8; 32],
}

fn build_quorum_v2_payload(input: V2PayloadInput<'_>) -> [u8; QUORUM_ACTION_V2_PAYLOAD_LEN] {
    let mut out = [0u8; QUORUM_ACTION_V2_PAYLOAD_LEN];
    out[0..16].copy_from_slice(&QUORUM_ACTION_V2_MAGIC);
    out[16] = input.mode;
    out[17] = CLUSTER;
    out[18..50].copy_from_slice(input.quorum_program_id.as_ref());
    out[50..82].copy_from_slice(input.authority.as_ref());
    out[82..114].copy_from_slice(input.quorum.as_ref());
    out[114..146].copy_from_slice(input.mldsa_public_key.as_ref());
    out[146..154].copy_from_slice(&input.quorum_nonce.to_le_bytes());
    out[154..162].copy_from_slice(&input.expires_slot.to_le_bytes());
    out[162..194].copy_from_slice(input.action_domain);
    out[194..226].copy_from_slice(input.action_hash);
    out[226..258].copy_from_slice(input.current_winternitz_root);
    out[258..290].copy_from_slice(input.next_winternitz_root);
    out
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

struct Wots16Privkey([u8; WINTERNITZ_SIGNATURE_LEN]);

impl From<[u8; WINTERNITZ_SIGNATURE_LEN]> for Wots16Privkey {
    fn from(value: [u8; WINTERNITZ_SIGNATURE_LEN]) -> Self {
        Self(value)
    }
}

impl Wots16Privkey {
    fn sign(&self, message: &[u8]) -> [u8; WINTERNITZ_SIGNATURE_LEN] {
        let digits = wots16_digits(message);
        let mut signature = [0u8; WINTERNITZ_SIGNATURE_LEN];

        for (index, digit) in digits.iter().enumerate() {
            let offset = index * WOTS16_N;
            let seed: &[u8; WOTS16_N] = self.0[offset..offset + WOTS16_N].try_into().unwrap();
            let signature_element = wots16_chain(seed, index as u8, 0, *digit);
            signature[offset..offset + WOTS16_N].copy_from_slice(&signature_element);
        }

        signature
    }

    fn public_root(&self) -> [u8; 32] {
        let mut root = keccak_hash(b"pq-wots16-root-v1");

        for index in 0..WOTS16_LEN {
            let offset = index * WOTS16_N;
            let seed: &[u8; WOTS16_N] = self.0[offset..offset + WOTS16_N].try_into().unwrap();
            let public_element = wots16_chain(seed, index as u8, 0, WOTS16_MAX_DIGIT);
            root = wots16_root_step(&root, index as u8, &public_element);
        }

        root
    }
}

fn deterministic_winternitz_key() -> Wots16Privkey {
    deterministic_key_with_offset(11)
}

fn deterministic_next_winternitz_key() -> Wots16Privkey {
    deterministic_key_with_offset(97)
}

fn deterministic_key_with_offset(offset: u8) -> Wots16Privkey {
    let mut bytes = [0u8; WINTERNITZ_SIGNATURE_LEN];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(17).wrapping_add(offset);
    }
    Wots16Privkey::from(bytes)
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
    let mut step = start_step;

    for _ in 0..steps {
        let step_bytes = [step];
        value = keccak_hashv(&[b"pq-wots16-chain-v1", &index_bytes, &step_bytes, &value]);
        step += 1;
    }

    value
}

fn wots16_root_step(
    previous_root: &[u8; 32],
    chain_index: u8,
    public_element: &[u8; 32],
) -> [u8; 32] {
    let index_bytes = [chain_index];
    keccak_hashv(&[
        b"pq-wots16-root-v1",
        &index_bytes,
        previous_root,
        public_element,
    ])
}

fn smart_transfer_domain() -> [u8; 32] {
    SMART_TRANSFER_DOMAIN
}

fn smart_token_transfer_domain() -> [u8; 32] {
    SMART_TOKEN_TRANSFER_DOMAIN
}

fn smart_transfer_hash(
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

struct SmartTokenTransferHashInput<'a> {
    program_id: &'a Pubkey,
    smart_account: &'a Pubkey,
    authority: &'a Pubkey,
    token_program: &'a Pubkey,
    source_token: &'a Pubkey,
    mint: &'a Pubkey,
    destination_token: &'a Pubkey,
    amount: u64,
    decimals: u8,
    spend_count: u64,
}

fn smart_token_transfer_hash(input: SmartTokenTransferHashInput<'_>) -> [u8; 32] {
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

fn pq_quorum_falcon_domain() -> [u8; 32] {
    hashv(&[b"pq-quorum", b"falcon-approval.v1"]).to_bytes()
}

fn pq_quorum_falcon_action_hash(payload: &[u8; QUORUM_ACTION_PAYLOAD_LEN]) -> [u8; 32] {
    hashv(&[b"pq-quorum-falcon-action-v1", payload]).to_bytes()
}

fn pq_quorum_falcon_domain_v2() -> [u8; 32] {
    hashv(&[b"pq-quorum", b"falcon-approval.v2"]).to_bytes()
}

fn pq_quorum_falcon_action_hash_v2(payload: &[u8; QUORUM_ACTION_V2_PAYLOAD_LEN]) -> [u8; 32] {
    hashv(&[b"pq-quorum-falcon-action-v2", payload]).to_bytes()
}

fn mldsa_proof_payload_hash(payload: &[u8; QUORUM_ACTION_V2_PAYLOAD_LEN]) -> [u8; 32] {
    hashv(&[b"pq-quorum-mldsa-proof-payload-v1", payload]).to_bytes()
}

fn spend_count(account: &Account) -> u64 {
    u64::from_le_bytes(
        account.data[SMART_SPEND_COUNT_OFFSET..SMART_SPEND_COUNT_OFFSET + 8]
            .try_into()
            .unwrap(),
    )
}

fn quorum_next_nonce(account: &Account) -> u64 {
    u64::from_le_bytes(
        account.data[QUORUM_NEXT_NONCE_OFFSET..QUORUM_NEXT_NONCE_OFFSET + 8]
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

fn init_smart_account(fixture: &Fixture) -> Account {
    let result = fixture.mollusk.process_instruction(
        &init_account_ix(fixture),
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.smart_account, empty_smart_account()),
            (
                fixture.quorum_program_id,
                fixture.quorum_program_account.clone(),
            ),
            (fixture.quorum, fixture.quorum_account.clone()),
            keyed_account_for_system_program(),
        ],
    );
    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    result_account(&result, fixture.smart_account)
}

fn deposit_to_smart(fixture: &Fixture, smart_account: Account, lamports: u64) -> Account {
    let result = fixture.mollusk.process_instruction(
        &deposit_ix(fixture, lamports),
        &[
            (fixture.depositor, system_account(1_000_000_000)),
            (fixture.smart_account, smart_account),
            keyed_account_for_system_program(),
        ],
    );
    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    result_account(&result, fixture.smart_account)
}

fn process_transfer(
    fixture: &Fixture,
    ix: &Instruction,
    smart_account: Account,
    destination_account: Account,
    winternitz_signature_key: Pubkey,
    winternitz_signature_account: Account,
) -> mollusk_svm::result::InstructionResult {
    fixture.mollusk.process_instruction(
        ix,
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.smart_account, smart_account),
            (ix.accounts[2].pubkey, destination_account),
            (
                fixture.quorum_program_id,
                fixture.quorum_program_account.clone(),
            ),
            (fixture.quorum, fixture.quorum_account.clone()),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            (winternitz_signature_key, winternitz_signature_account),
        ],
    )
}

fn process_token_transfer_falcon_winternitz(
    fixture: &Fixture,
    ix: &Instruction,
    smart_account: Account,
    source_token_account: Account,
    mint_account: Account,
    destination_token_account: Account,
    winternitz_signature_key: Pubkey,
    winternitz_signature_account: Account,
) -> mollusk_svm::result::InstructionResult {
    fixture.mollusk.process_instruction(
        ix,
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.smart_account, smart_account),
            (SPL_TOKEN_ID, mollusk_token::account()),
            (ix.accounts[3].pubkey, source_token_account),
            (ix.accounts[4].pubkey, mint_account),
            (ix.accounts[5].pubkey, destination_token_account),
            (
                fixture.quorum_program_id,
                fixture.quorum_program_account.clone(),
            ),
            (fixture.quorum, fixture.quorum_account.clone()),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            (winternitz_signature_key, winternitz_signature_account),
        ],
    )
}

fn process_token_transfer_falcon_winternitz_buffered(
    fixture: &Fixture,
    ix: &Instruction,
    smart_account: Account,
    source_token_account: Account,
    mint_account: Account,
    destination_token_account: Account,
    winternitz_signature_key: Pubkey,
    winternitz_signature_account: Account,
    falcon_signature_buffer: Pubkey,
    falcon_signature_buffer_account: Account,
) -> mollusk_svm::result::InstructionResult {
    fixture.mollusk.process_instruction(
        ix,
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.smart_account, smart_account),
            (SPL_TOKEN_ID, mollusk_token::account()),
            (ix.accounts[3].pubkey, source_token_account),
            (ix.accounts[4].pubkey, mint_account),
            (ix.accounts[5].pubkey, destination_token_account),
            (
                fixture.quorum_program_id,
                fixture.quorum_program_account.clone(),
            ),
            (fixture.quorum, fixture.quorum_account.clone()),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            (winternitz_signature_key, winternitz_signature_account),
            (falcon_signature_buffer, falcon_signature_buffer_account),
        ],
    )
}

fn process_token_transfer_falcon_mldsa_buffered(
    fixture: &Fixture,
    ix: &Instruction,
    smart_account: Account,
    source_token_account: Account,
    mint_account: Account,
    destination_token_account: Account,
    proof_setup: MldsaProofSetup,
    falcon_signature_buffer: Pubkey,
    falcon_signature_account: Account,
) -> mollusk_svm::result::InstructionResult {
    fixture.mollusk.process_instruction(
        ix,
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.smart_account, smart_account),
            (SPL_TOKEN_ID, mollusk_token::account()),
            (ix.accounts[3].pubkey, source_token_account),
            (ix.accounts[4].pubkey, mint_account),
            (ix.accounts[5].pubkey, destination_token_account),
            (
                fixture.quorum_program_id,
                fixture.quorum_program_account.clone(),
            ),
            (fixture.quorum, fixture.quorum_account.clone()),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            (proof_setup.public_key, proof_setup.public_key_account),
            (proof_setup.signature, proof_setup.signature_account),
            (proof_setup.proof, proof_setup.proof_account),
            (falcon_signature_buffer, falcon_signature_account),
        ],
    )
}

fn process_token_transfer_winternitz_mldsa(
    fixture: &Fixture,
    ix: &Instruction,
    smart_account: Account,
    source_token_account: Account,
    mint_account: Account,
    destination_token_account: Account,
    winternitz_signature_key: Pubkey,
    winternitz_signature_account: Account,
    proof_setup: MldsaProofSetup,
) -> mollusk_svm::result::InstructionResult {
    fixture.mollusk.process_instruction(
        ix,
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.smart_account, smart_account),
            (SPL_TOKEN_ID, mollusk_token::account()),
            (ix.accounts[3].pubkey, source_token_account),
            (ix.accounts[4].pubkey, mint_account),
            (ix.accounts[5].pubkey, destination_token_account),
            (
                fixture.quorum_program_id,
                fixture.quorum_program_account.clone(),
            ),
            (fixture.quorum, fixture.quorum_account.clone()),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            (winternitz_signature_key, winternitz_signature_account),
            (proof_setup.public_key, proof_setup.public_key_account),
            (proof_setup.signature, proof_setup.signature_account),
            (proof_setup.proof, proof_setup.proof_account),
        ],
    )
}

fn process_transfer_falcon_mldsa(
    fixture: &Fixture,
    ix: &Instruction,
    smart_account: Account,
    destination_account: Account,
    proof_setup: MldsaProofSetup,
) -> mollusk_svm::result::InstructionResult {
    fixture.mollusk.process_instruction(
        ix,
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.smart_account, smart_account),
            (ix.accounts[2].pubkey, destination_account),
            (
                fixture.quorum_program_id,
                fixture.quorum_program_account.clone(),
            ),
            (fixture.quorum, fixture.quorum_account.clone()),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            (proof_setup.public_key, proof_setup.public_key_account),
            (proof_setup.signature, proof_setup.signature_account),
            (proof_setup.proof, proof_setup.proof_account),
        ],
    )
}

fn process_transfer_falcon_mldsa_buffered(
    fixture: &Fixture,
    ix: &Instruction,
    smart_account: Account,
    destination_account: Account,
    proof_setup: MldsaProofSetup,
    falcon_signature_buffer: Pubkey,
    falcon_signature_account: Account,
) -> mollusk_svm::result::InstructionResult {
    fixture.mollusk.process_instruction(
        ix,
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.smart_account, smart_account),
            (ix.accounts[2].pubkey, destination_account),
            (
                fixture.quorum_program_id,
                fixture.quorum_program_account.clone(),
            ),
            (fixture.quorum, fixture.quorum_account.clone()),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            (proof_setup.public_key, proof_setup.public_key_account),
            (proof_setup.signature, proof_setup.signature_account),
            (proof_setup.proof, proof_setup.proof_account),
            (falcon_signature_buffer, falcon_signature_account),
        ],
    )
}

fn process_transfer_winternitz_mldsa(
    fixture: &Fixture,
    ix: &Instruction,
    smart_account: Account,
    destination_account: Account,
    winternitz_signature_key: Pubkey,
    winternitz_signature_account: Account,
    proof_setup: MldsaProofSetup,
) -> mollusk_svm::result::InstructionResult {
    fixture.mollusk.process_instruction(
        ix,
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.smart_account, smart_account),
            (ix.accounts[2].pubkey, destination_account),
            (
                fixture.quorum_program_id,
                fixture.quorum_program_account.clone(),
            ),
            (fixture.quorum, fixture.quorum_account.clone()),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            (winternitz_signature_key, winternitz_signature_account),
            (proof_setup.public_key, proof_setup.public_key_account),
            (proof_setup.signature, proof_setup.signature_account),
            (proof_setup.proof, proof_setup.proof_account),
        ],
    )
}

#[test]
fn init_creates_program_owned_smart_account() {
    let fixture = make_fixture(0, 0);
    let smart_account = init_smart_account(&fixture);

    assert_eq!(smart_account.owner, fixture.smart_program_id);
    assert_eq!(&smart_account.data[..8], &SMART_ACCOUNT_DISCRIMINATOR);
    assert_eq!(spend_count(&smart_account), 0);
}

#[test]
fn deposit_moves_lamports_into_smart_account() {
    let fixture = make_fixture(0, 0);
    let smart_account = init_smart_account(&fixture);
    let before_lamports = smart_account.lamports;

    let smart_account = deposit_to_smart(&fixture, smart_account, 75_000);

    assert_eq!(smart_account.lamports, before_lamports + 75_000);
    assert_eq!(spend_count(&smart_account), 0);
}

#[test]
fn transfer_moves_sol_after_real_falcon_winternitz_quorum() {
    let fixture = make_fixture(0, 0);
    let smart_account = deposit_to_smart(&fixture, init_smart_account(&fixture), 150_000);
    let before_smart_lamports = smart_account.lamports;
    let (ix, winternitz_key, winternitz_account, next_root) = transfer_ix(
        &fixture,
        TransferIxInput {
            lamports: 60_000,
            signed_lamports: 60_000,
            quorum_nonce: 0,
            falcon_nonce: 0,
            spend_count: 0,
            destination: fixture.destination,
            signed_destination: fixture.destination,
        },
    );

    let result = process_transfer(
        &fixture,
        &ix,
        smart_account,
        system_account(9),
        winternitz_key,
        winternitz_account,
    );

    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    println!(
        "pq smart transfer Falcon+Winternitz CU: {}",
        result.compute_units_consumed
    );
    assert!(result.compute_units_consumed <= SMART_TRANSFER_MAX_CU);
    let smart_account = result_account(&result, fixture.smart_account);
    let destination = result_account(&result, fixture.destination);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(smart_account.lamports, before_smart_lamports - 60_000);
    assert_eq!(destination.lamports, 60_009);
    assert_eq!(spend_count(&smart_account), 1);
    assert_eq!(quorum_next_nonce(&quorum), 1);
    assert_eq!(
        &quorum.data[QUORUM_WINTERNITZ_ROOT_OFFSET..QUORUM_NEXT_NONCE_OFFSET],
        &next_root
    );
    assert_eq!(falcon_next_nonce(&falcon_key), 1);
}

#[test]
fn transfer_moves_spl_tokens_after_real_falcon_winternitz_quorum() {
    let fixture = make_fixture(0, 0);
    let smart_account = init_smart_account(&fixture);
    let mint = Pubkey::new_unique();
    let source_token = Pubkey::new_unique();
    let destination_token = Pubkey::new_unique();
    let (ix, winternitz_key, winternitz_account, next_root) = token_transfer_falcon_winternitz_ix(
        &fixture,
        TokenTransferIxInput {
            amount: 250_000,
            signed_amount: 250_000,
            decimals: 6,
            signed_decimals: 6,
            quorum_nonce: 0,
            falcon_nonce: 0,
            spend_count: 0,
            source_token,
            signed_source_token: source_token,
            mint,
            signed_mint: mint,
            destination_token,
            signed_destination_token: destination_token,
        },
    );

    let result = process_token_transfer_falcon_winternitz(
        &fixture,
        &ix,
        smart_account,
        spl_token_account(mint, fixture.smart_account, 1_000_000),
        spl_mint_account(6, 1_000_010),
        spl_token_account(mint, Pubkey::new_unique(), 10),
        winternitz_key,
        winternitz_account,
    );

    assert!(
        result.program_result.is_ok(),
        "{:?} raw={:?} cu={}",
        result.program_result,
        result.raw_result,
        result.compute_units_consumed
    );
    println!(
        "pq smart SPL transfer Falcon+Winternitz CU: {}",
        result.compute_units_consumed
    );
    assert!(result.compute_units_consumed <= SMART_TOKEN_TRANSFER_MAX_CU);
    let smart_account = result_account(&result, fixture.smart_account);
    let source_token = result_account(&result, source_token);
    let destination_token = result_account(&result, destination_token);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(spend_count(&smart_account), 1);
    assert_eq!(spl_token_amount(&source_token), 750_000);
    assert_eq!(spl_token_amount(&destination_token), 250_010);
    assert_eq!(quorum_next_nonce(&quorum), 1);
    assert_eq!(
        &quorum.data[QUORUM_WINTERNITZ_ROOT_OFFSET..QUORUM_NEXT_NONCE_OFFSET],
        &next_root
    );
    assert_eq!(falcon_next_nonce(&falcon_key), 1);
}

#[test]
fn transfer_moves_spl_tokens_after_real_buffered_falcon_winternitz_quorum() {
    let fixture = make_fixture(0, 0);
    let smart_account = init_smart_account(&fixture);
    let mint = Pubkey::new_unique();
    let source_token = Pubkey::new_unique();
    let destination_token = Pubkey::new_unique();
    let (
        ix,
        winternitz_key,
        winternitz_account,
        falcon_signature_buffer,
        falcon_signature_buffer_account,
        next_root,
    ) = token_transfer_falcon_winternitz_buffered_ix(
        &fixture,
        smart_account.clone(),
        TokenTransferIxInput {
            amount: 250_000,
            signed_amount: 250_000,
            decimals: 6,
            signed_decimals: 6,
            quorum_nonce: 0,
            falcon_nonce: 0,
            spend_count: 0,
            source_token,
            signed_source_token: source_token,
            mint,
            signed_mint: mint,
            destination_token,
            signed_destination_token: destination_token,
        },
    );

    let result = process_token_transfer_falcon_winternitz_buffered(
        &fixture,
        &ix,
        smart_account,
        spl_token_account(mint, fixture.smart_account, 1_000_000),
        spl_mint_account(6, 1_000_010),
        spl_token_account(mint, Pubkey::new_unique(), 10),
        winternitz_key,
        winternitz_account,
        falcon_signature_buffer,
        falcon_signature_buffer_account,
    );
    assert!(
        result.program_result.is_ok(),
        "{:?} raw={:?} cu={}",
        result.program_result,
        result.raw_result,
        result.compute_units_consumed
    );
    println!(
        "pq smart SPL transfer buffered Falcon+Winternitz CU: {}",
        result.compute_units_consumed
    );
    assert!(result.compute_units_consumed <= SMART_TOKEN_TRANSFER_MAX_CU);
    let smart_account = result_account(&result, fixture.smart_account);
    let source_token = result_account(&result, source_token);
    let destination_token = result_account(&result, destination_token);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    let falcon_signature_buffer_account = result_account(&result, falcon_signature_buffer);
    assert_eq!(spend_count(&smart_account), 1);
    assert_eq!(spl_token_amount(&source_token), 750_000);
    assert_eq!(spl_token_amount(&destination_token), 250_010);
    assert_eq!(quorum_next_nonce(&quorum), 1);
    assert_eq!(
        &quorum.data[QUORUM_WINTERNITZ_ROOT_OFFSET..QUORUM_NEXT_NONCE_OFFSET],
        &next_root
    );
    assert_eq!(falcon_next_nonce(&falcon_key), 1);
    assert_eq!(falcon_signature_buffer_account.lamports, 0);
    assert_eq!(&falcon_signature_buffer_account.data[..8], &[0u8; 8]);
}

#[test]
fn transfer_buffered_spl_tokens_rejects_tampered_destination() {
    let fixture = make_fixture(0, 0);
    let smart_account = init_smart_account(&fixture);
    let mint = Pubkey::new_unique();
    let source_token = Pubkey::new_unique();
    let signed_destination_token = Pubkey::new_unique();
    let wrong_destination_token = Pubkey::new_unique();
    let (
        ix,
        winternitz_key,
        winternitz_account,
        falcon_signature_buffer,
        falcon_signature_buffer_account,
        _,
    ) = token_transfer_falcon_winternitz_buffered_ix(
        &fixture,
        smart_account.clone(),
        TokenTransferIxInput {
            amount: 250_000,
            signed_amount: 250_000,
            decimals: 6,
            signed_decimals: 6,
            quorum_nonce: 0,
            falcon_nonce: 0,
            spend_count: 0,
            source_token,
            signed_source_token: source_token,
            mint,
            signed_mint: mint,
            destination_token: wrong_destination_token,
            signed_destination_token,
        },
    );

    let result = process_token_transfer_falcon_winternitz_buffered(
        &fixture,
        &ix,
        smart_account,
        spl_token_account(mint, fixture.smart_account, 1_000_000),
        spl_mint_account(6, 1_000_010),
        spl_token_account(mint, Pubkey::new_unique(), 10),
        winternitz_key,
        winternitz_account,
        falcon_signature_buffer,
        falcon_signature_buffer_account,
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(6))
    );
    let smart_account = result_account(&result, fixture.smart_account);
    let source_token = result_account(&result, source_token);
    let wrong_destination_token = result_account(&result, wrong_destination_token);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    let falcon_signature_buffer_account = result_account(&result, falcon_signature_buffer);
    assert_eq!(spend_count(&smart_account), 0);
    assert_eq!(spl_token_amount(&source_token), 1_000_000);
    assert_eq!(spl_token_amount(&wrong_destination_token), 10);
    assert_eq!(quorum_next_nonce(&quorum), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
    assert_eq!(
        &falcon_signature_buffer_account.data[..8],
        &FALCON_SIGNATURE_DISCRIMINATOR
    );
}

#[test]
fn transfer_spl_tokens_rejects_tampered_destination() {
    let fixture = make_fixture(0, 0);
    let smart_account = init_smart_account(&fixture);
    let mint = Pubkey::new_unique();
    let source_token = Pubkey::new_unique();
    let signed_destination_token = Pubkey::new_unique();
    let wrong_destination_token = Pubkey::new_unique();
    let (ix, winternitz_key, winternitz_account, _) = token_transfer_falcon_winternitz_ix(
        &fixture,
        TokenTransferIxInput {
            amount: 250_000,
            signed_amount: 250_000,
            decimals: 6,
            signed_decimals: 6,
            quorum_nonce: 0,
            falcon_nonce: 0,
            spend_count: 0,
            source_token,
            signed_source_token: source_token,
            mint,
            signed_mint: mint,
            destination_token: wrong_destination_token,
            signed_destination_token,
        },
    );

    let result = process_token_transfer_falcon_winternitz(
        &fixture,
        &ix,
        smart_account,
        spl_token_account(mint, fixture.smart_account, 1_000_000),
        spl_mint_account(6, 1_000_010),
        spl_token_account(mint, Pubkey::new_unique(), 10),
        winternitz_key,
        winternitz_account,
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(6))
    );
    let smart_account = result_account(&result, fixture.smart_account);
    let source_token = result_account(&result, source_token);
    let wrong_destination_token = result_account(&result, wrong_destination_token);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(spend_count(&smart_account), 0);
    assert_eq!(spl_token_amount(&source_token), 1_000_000);
    assert_eq!(spl_token_amount(&wrong_destination_token), 10);
    assert_eq!(quorum_next_nonce(&quorum), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn transfer_spl_tokens_rejects_source_not_owned_by_smart_account() {
    let fixture = make_fixture(0, 0);
    let smart_account = init_smart_account(&fixture);
    let mint = Pubkey::new_unique();
    let source_token = Pubkey::new_unique();
    let destination_token = Pubkey::new_unique();
    let (ix, winternitz_key, winternitz_account, _) = token_transfer_falcon_winternitz_ix(
        &fixture,
        TokenTransferIxInput {
            amount: 250_000,
            signed_amount: 250_000,
            decimals: 6,
            signed_decimals: 6,
            quorum_nonce: 0,
            falcon_nonce: 0,
            spend_count: 0,
            source_token,
            signed_source_token: source_token,
            mint,
            signed_mint: mint,
            destination_token,
            signed_destination_token: destination_token,
        },
    );

    let result = process_token_transfer_falcon_winternitz(
        &fixture,
        &ix,
        smart_account,
        spl_token_account(mint, Pubkey::new_unique(), 1_000_000),
        spl_mint_account(6, 1_000_010),
        spl_token_account(mint, Pubkey::new_unique(), 10),
        winternitz_key,
        winternitz_account,
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(10))
    );
    let smart_account = result_account(&result, fixture.smart_account);
    let source_token = result_account(&result, source_token);
    let destination_token = result_account(&result, destination_token);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(spend_count(&smart_account), 0);
    assert_eq!(spl_token_amount(&source_token), 1_000_000);
    assert_eq!(spl_token_amount(&destination_token), 10);
    assert_eq!(quorum_next_nonce(&quorum), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn transfer_moves_spl_tokens_after_real_buffered_falcon_mldsa_quorum() {
    let fixture = make_fixture(0, 0);
    let smart_account = init_smart_account(&fixture);
    let mint = Pubkey::new_unique();
    let source_token = Pubkey::new_unique();
    let destination_token = Pubkey::new_unique();
    let (ix, proof_setup, falcon_signature_buffer, falcon_signature_account) =
        token_transfer_falcon_mldsa_buffered_ix(
            &fixture,
            smart_account.clone(),
            TokenTransferIxInput {
                amount: 250_000,
                signed_amount: 250_000,
                decimals: 6,
                signed_decimals: 6,
                quorum_nonce: 0,
                falcon_nonce: 0,
                spend_count: 0,
                source_token,
                signed_source_token: source_token,
                mint,
                signed_mint: mint,
                destination_token,
                signed_destination_token: destination_token,
            },
        );
    let proof_key = proof_setup.proof;
    let signature_key = proof_setup.signature;

    let result = process_token_transfer_falcon_mldsa_buffered(
        &fixture,
        &ix,
        smart_account,
        spl_token_account(mint, fixture.smart_account, 1_000_000),
        spl_mint_account(6, 1_000_010),
        spl_token_account(mint, Pubkey::new_unique(), 10),
        proof_setup,
        falcon_signature_buffer,
        falcon_signature_account,
    );

    assert!(
        result.program_result.is_ok(),
        "{:?} raw={:?} cu={}",
        result.program_result,
        result.raw_result,
        result.compute_units_consumed
    );
    println!(
        "pq smart SPL transfer buffered Falcon+ML-DSA CU: {}",
        result.compute_units_consumed
    );
    assert!(result.compute_units_consumed <= SMART_MLDSA_TRANSFER_MAX_CU);
    let smart_account = result_account(&result, fixture.smart_account);
    let source_token = result_account(&result, source_token);
    let destination_token = result_account(&result, destination_token);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    let falcon_signature_buffer_account = result_account(&result, falcon_signature_buffer);
    assert_eq!(spend_count(&smart_account), 1);
    assert_eq!(spl_token_amount(&source_token), 750_000);
    assert_eq!(spl_token_amount(&destination_token), 250_010);
    assert_eq!(quorum_next_nonce(&quorum), 1);
    assert_eq!(falcon_next_nonce(&falcon_key), 1);
    assert_eq!(falcon_signature_buffer_account.lamports, 0);
    assert_eq!(&falcon_signature_buffer_account.data[..8], &[0u8; 8]);
    assert_eq!(result_account(&result, signature_key).lamports, 0);
    assert_eq!(result_account(&result, proof_key).lamports, 0);
}

#[test]
fn transfer_moves_spl_tokens_after_real_winternitz_mldsa_quorum() {
    let fixture = make_fixture(0, 0);
    let smart_account = init_smart_account(&fixture);
    let mint = Pubkey::new_unique();
    let source_token = Pubkey::new_unique();
    let destination_token = Pubkey::new_unique();
    let (ix, winternitz_key, winternitz_account, proof_setup, next_root) =
        token_transfer_winternitz_mldsa_ix(
            &fixture,
            TokenTransferIxInput {
                amount: 250_000,
                signed_amount: 250_000,
                decimals: 6,
                signed_decimals: 6,
                quorum_nonce: 0,
                falcon_nonce: 0,
                spend_count: 0,
                source_token,
                signed_source_token: source_token,
                mint,
                signed_mint: mint,
                destination_token,
                signed_destination_token: destination_token,
            },
        );
    let proof_key = proof_setup.proof;
    let signature_key = proof_setup.signature;

    let result = process_token_transfer_winternitz_mldsa(
        &fixture,
        &ix,
        smart_account,
        spl_token_account(mint, fixture.smart_account, 1_000_000),
        spl_mint_account(6, 1_000_010),
        spl_token_account(mint, Pubkey::new_unique(), 10),
        winternitz_key,
        winternitz_account,
        proof_setup,
    );

    assert!(
        result.program_result.is_ok(),
        "{:?} raw={:?} cu={}",
        result.program_result,
        result.raw_result,
        result.compute_units_consumed
    );
    println!(
        "pq smart SPL transfer Winternitz+ML-DSA CU: {}",
        result.compute_units_consumed
    );
    assert!(result.compute_units_consumed <= SMART_MLDSA_TRANSFER_MAX_CU);
    let smart_account = result_account(&result, fixture.smart_account);
    let source_token = result_account(&result, source_token);
    let destination_token = result_account(&result, destination_token);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(spend_count(&smart_account), 1);
    assert_eq!(spl_token_amount(&source_token), 750_000);
    assert_eq!(spl_token_amount(&destination_token), 250_010);
    assert_eq!(quorum_next_nonce(&quorum), 1);
    assert_eq!(
        &quorum.data[QUORUM_WINTERNITZ_ROOT_OFFSET..QUORUM_NEXT_NONCE_OFFSET],
        &next_root
    );
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
    assert_eq!(result_account(&result, winternitz_key).lamports, 0);
    assert_eq!(result_account(&result, signature_key).lamports, 0);
    assert_eq!(result_account(&result, proof_key).lamports, 0);
}

#[test]
fn transfer_spl_tokens_buffered_falcon_mldsa_rejects_tampered_destination() {
    let fixture = make_fixture(0, 0);
    let smart_account = init_smart_account(&fixture);
    let mint = Pubkey::new_unique();
    let source_token = Pubkey::new_unique();
    let signed_destination_token = Pubkey::new_unique();
    let wrong_destination_token = Pubkey::new_unique();
    let (ix, proof_setup, falcon_signature_buffer, falcon_signature_account) =
        token_transfer_falcon_mldsa_buffered_ix(
            &fixture,
            smart_account.clone(),
            TokenTransferIxInput {
                amount: 250_000,
                signed_amount: 250_000,
                decimals: 6,
                signed_decimals: 6,
                quorum_nonce: 0,
                falcon_nonce: 0,
                spend_count: 0,
                source_token,
                signed_source_token: source_token,
                mint,
                signed_mint: mint,
                destination_token: wrong_destination_token,
                signed_destination_token,
            },
        );

    let result = process_token_transfer_falcon_mldsa_buffered(
        &fixture,
        &ix,
        smart_account,
        spl_token_account(mint, fixture.smart_account, 1_000_000),
        spl_mint_account(6, 1_000_010),
        spl_token_account(mint, Pubkey::new_unique(), 10),
        proof_setup,
        falcon_signature_buffer,
        falcon_signature_account,
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(16))
    );
    let smart_account = result_account(&result, fixture.smart_account);
    let source_token = result_account(&result, source_token);
    let wrong_destination_token = result_account(&result, wrong_destination_token);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    let falcon_signature_buffer_account = result_account(&result, falcon_signature_buffer);
    assert_eq!(spend_count(&smart_account), 0);
    assert_eq!(spl_token_amount(&source_token), 1_000_000);
    assert_eq!(spl_token_amount(&wrong_destination_token), 10);
    assert_eq!(quorum_next_nonce(&quorum), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
    assert_ne!(falcon_signature_buffer_account.lamports, 0);
}

#[test]
fn transfer_spl_tokens_winternitz_mldsa_rejects_tampered_destination() {
    let fixture = make_fixture(0, 0);
    let smart_account = init_smart_account(&fixture);
    let mint = Pubkey::new_unique();
    let source_token = Pubkey::new_unique();
    let signed_destination_token = Pubkey::new_unique();
    let wrong_destination_token = Pubkey::new_unique();
    let (ix, winternitz_key, winternitz_account, proof_setup, _) =
        token_transfer_winternitz_mldsa_ix(
            &fixture,
            TokenTransferIxInput {
                amount: 250_000,
                signed_amount: 250_000,
                decimals: 6,
                signed_decimals: 6,
                quorum_nonce: 0,
                falcon_nonce: 0,
                spend_count: 0,
                source_token,
                signed_source_token: source_token,
                mint,
                signed_mint: mint,
                destination_token: wrong_destination_token,
                signed_destination_token,
            },
        );

    let result = process_token_transfer_winternitz_mldsa(
        &fixture,
        &ix,
        smart_account,
        spl_token_account(mint, fixture.smart_account, 1_000_000),
        spl_mint_account(6, 1_000_010),
        spl_token_account(mint, Pubkey::new_unique(), 10),
        winternitz_key,
        winternitz_account,
        proof_setup,
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(6))
    );
    let smart_account = result_account(&result, fixture.smart_account);
    let source_token = result_account(&result, source_token);
    let wrong_destination_token = result_account(&result, wrong_destination_token);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(spend_count(&smart_account), 0);
    assert_eq!(spl_token_amount(&source_token), 1_000_000);
    assert_eq!(spl_token_amount(&wrong_destination_token), 10);
    assert_eq!(quorum_next_nonce(&quorum), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn transfer_moves_sol_after_real_falcon_mldsa_quorum() {
    let fixture = make_fixture(0, 0);
    let smart_account = deposit_to_smart(&fixture, init_smart_account(&fixture), 150_000);
    let before_smart_lamports = smart_account.lamports;
    let (ix, proof_setup) = transfer_falcon_mldsa_ix(
        &fixture,
        TransferIxInput {
            lamports: 60_000,
            signed_lamports: 60_000,
            quorum_nonce: 0,
            falcon_nonce: 0,
            spend_count: 0,
            destination: fixture.destination,
            signed_destination: fixture.destination,
        },
    );
    let proof_key = proof_setup.proof;
    let signature_key = proof_setup.signature;

    let result =
        process_transfer_falcon_mldsa(&fixture, &ix, smart_account, system_account(9), proof_setup);

    assert!(
        result.program_result.is_ok(),
        "{:?} raw={:?} cu={}",
        result.program_result,
        result.raw_result,
        result.compute_units_consumed
    );
    println!(
        "pq smart transfer Falcon+ML-DSA CU: {}",
        result.compute_units_consumed
    );
    assert!(result.compute_units_consumed <= SMART_MLDSA_TRANSFER_MAX_CU);
    let smart_account = result_account(&result, fixture.smart_account);
    let destination = result_account(&result, fixture.destination);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(smart_account.lamports, before_smart_lamports - 60_000);
    assert_eq!(destination.lamports, 60_009);
    assert_eq!(spend_count(&smart_account), 1);
    assert_eq!(quorum_next_nonce(&quorum), 1);
    assert_eq!(falcon_next_nonce(&falcon_key), 1);
    assert_eq!(result_account(&result, signature_key).lamports, 0);
    assert_eq!(result_account(&result, proof_key).lamports, 0);
}

#[test]
fn transfer_moves_sol_after_real_buffered_falcon_mldsa_quorum() {
    let fixture = make_fixture(0, 0);
    let smart_account = deposit_to_smart(&fixture, init_smart_account(&fixture), 150_000);
    let before_smart_lamports = smart_account.lamports;
    let (ix, proof_setup, falcon_signature_buffer, falcon_signature_account) =
        transfer_falcon_mldsa_buffered_ix(
            &fixture,
            smart_account.clone(),
            TransferIxInput {
                lamports: 60_000,
                signed_lamports: 60_000,
                quorum_nonce: 0,
                falcon_nonce: 0,
                spend_count: 0,
                destination: fixture.destination,
                signed_destination: fixture.destination,
            },
        );
    let proof_key = proof_setup.proof;
    let signature_key = proof_setup.signature;

    let result = process_transfer_falcon_mldsa_buffered(
        &fixture,
        &ix,
        smart_account,
        system_account(9),
        proof_setup,
        falcon_signature_buffer,
        falcon_signature_account,
    );

    assert!(
        result.program_result.is_ok(),
        "{:?} raw={:?} cu={}",
        result.program_result,
        result.raw_result,
        result.compute_units_consumed
    );
    println!(
        "pq smart transfer buffered Falcon+ML-DSA CU: {}",
        result.compute_units_consumed
    );
    assert!(result.compute_units_consumed <= SMART_MLDSA_TRANSFER_MAX_CU);
    let smart_account = result_account(&result, fixture.smart_account);
    let destination = result_account(&result, fixture.destination);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    let falcon_signature_buffer_account = result_account(&result, falcon_signature_buffer);
    assert_eq!(smart_account.lamports, before_smart_lamports - 60_000);
    assert_eq!(destination.lamports, 60_009);
    assert_eq!(spend_count(&smart_account), 1);
    assert_eq!(quorum_next_nonce(&quorum), 1);
    assert_eq!(falcon_next_nonce(&falcon_key), 1);
    assert_eq!(falcon_signature_buffer_account.lamports, 0);
    assert_eq!(&falcon_signature_buffer_account.data[..8], &[0u8; 8]);
    assert_eq!(result_account(&result, signature_key).lamports, 0);
    assert_eq!(result_account(&result, proof_key).lamports, 0);
}

#[test]
fn transfer_moves_sol_after_real_winternitz_mldsa_quorum() {
    let fixture = make_fixture(0, 0);
    let smart_account = deposit_to_smart(&fixture, init_smart_account(&fixture), 150_000);
    let before_smart_lamports = smart_account.lamports;
    let (ix, winternitz_key, winternitz_account, proof_setup, next_root) =
        transfer_winternitz_mldsa_ix(
            &fixture,
            TransferIxInput {
                lamports: 60_000,
                signed_lamports: 60_000,
                quorum_nonce: 0,
                falcon_nonce: 0,
                spend_count: 0,
                destination: fixture.destination,
                signed_destination: fixture.destination,
            },
        );
    let proof_key = proof_setup.proof;
    let signature_key = proof_setup.signature;

    let result = process_transfer_winternitz_mldsa(
        &fixture,
        &ix,
        smart_account,
        system_account(9),
        winternitz_key,
        winternitz_account,
        proof_setup,
    );

    assert!(
        result.program_result.is_ok(),
        "{:?} raw={:?} cu={}",
        result.program_result,
        result.raw_result,
        result.compute_units_consumed
    );
    println!(
        "pq smart transfer Winternitz+ML-DSA CU: {}",
        result.compute_units_consumed
    );
    assert!(result.compute_units_consumed <= SMART_MLDSA_TRANSFER_MAX_CU);
    let smart_account = result_account(&result, fixture.smart_account);
    let destination = result_account(&result, fixture.destination);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(smart_account.lamports, before_smart_lamports - 60_000);
    assert_eq!(destination.lamports, 60_009);
    assert_eq!(spend_count(&smart_account), 1);
    assert_eq!(quorum_next_nonce(&quorum), 1);
    assert_eq!(
        &quorum.data[QUORUM_WINTERNITZ_ROOT_OFFSET..QUORUM_NEXT_NONCE_OFFSET],
        &next_root
    );
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
    assert_eq!(result_account(&result, winternitz_key).lamports, 0);
    assert_eq!(result_account(&result, signature_key).lamports, 0);
    assert_eq!(result_account(&result, proof_key).lamports, 0);
}

#[test]
fn transfer_falcon_mldsa_rejects_tampered_destination() {
    let fixture = make_fixture(0, 0);
    let smart_account = deposit_to_smart(&fixture, init_smart_account(&fixture), 150_000);
    let before_smart_lamports = smart_account.lamports;
    let wrong_destination = Pubkey::new_unique();
    let (ix, proof_setup) = transfer_falcon_mldsa_ix(
        &fixture,
        TransferIxInput {
            lamports: 60_000,
            signed_lamports: 60_000,
            quorum_nonce: 0,
            falcon_nonce: 0,
            spend_count: 0,
            destination: wrong_destination,
            signed_destination: fixture.destination,
        },
    );

    let result =
        process_transfer_falcon_mldsa(&fixture, &ix, smart_account, system_account(9), proof_setup);

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(16))
    );
    let smart_account = result_account(&result, fixture.smart_account);
    let destination = result_account(&result, wrong_destination);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(smart_account.lamports, before_smart_lamports);
    assert_eq!(destination.lamports, 9);
    assert_eq!(spend_count(&smart_account), 0);
    assert_eq!(quorum_next_nonce(&quorum), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn transfer_buffered_falcon_mldsa_rejects_tampered_destination() {
    let fixture = make_fixture(0, 0);
    let smart_account = deposit_to_smart(&fixture, init_smart_account(&fixture), 150_000);
    let before_smart_lamports = smart_account.lamports;
    let wrong_destination = Pubkey::new_unique();
    let (ix, proof_setup, falcon_signature_buffer, falcon_signature_account) =
        transfer_falcon_mldsa_buffered_ix(
            &fixture,
            smart_account.clone(),
            TransferIxInput {
                lamports: 60_000,
                signed_lamports: 60_000,
                quorum_nonce: 0,
                falcon_nonce: 0,
                spend_count: 0,
                destination: wrong_destination,
                signed_destination: fixture.destination,
            },
        );

    let result = process_transfer_falcon_mldsa_buffered(
        &fixture,
        &ix,
        smart_account,
        system_account(9),
        proof_setup,
        falcon_signature_buffer,
        falcon_signature_account,
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(16))
    );
    let smart_account = result_account(&result, fixture.smart_account);
    let destination = result_account(&result, wrong_destination);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    let falcon_signature_buffer_account = result_account(&result, falcon_signature_buffer);
    assert_eq!(smart_account.lamports, before_smart_lamports);
    assert_eq!(destination.lamports, 9);
    assert_eq!(spend_count(&smart_account), 0);
    assert_eq!(quorum_next_nonce(&quorum), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
    assert_ne!(falcon_signature_buffer_account.lamports, 0);
}

#[test]
fn transfer_winternitz_mldsa_rejects_tampered_destination() {
    let fixture = make_fixture(0, 0);
    let smart_account = deposit_to_smart(&fixture, init_smart_account(&fixture), 150_000);
    let before_smart_lamports = smart_account.lamports;
    let wrong_destination = Pubkey::new_unique();
    let (ix, winternitz_key, winternitz_account, proof_setup, _) = transfer_winternitz_mldsa_ix(
        &fixture,
        TransferIxInput {
            lamports: 60_000,
            signed_lamports: 60_000,
            quorum_nonce: 0,
            falcon_nonce: 0,
            spend_count: 0,
            destination: wrong_destination,
            signed_destination: fixture.destination,
        },
    );

    let result = process_transfer_winternitz_mldsa(
        &fixture,
        &ix,
        smart_account,
        system_account(9),
        winternitz_key,
        winternitz_account,
        proof_setup,
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(6))
    );
    let smart_account = result_account(&result, fixture.smart_account);
    let destination = result_account(&result, wrong_destination);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(smart_account.lamports, before_smart_lamports);
    assert_eq!(destination.lamports, 9);
    assert_eq!(spend_count(&smart_account), 0);
    assert_eq!(quorum_next_nonce(&quorum), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn transfer_rejects_tampered_destination() {
    let fixture = make_fixture(0, 0);
    let smart_account = deposit_to_smart(&fixture, init_smart_account(&fixture), 150_000);
    let before_smart_lamports = smart_account.lamports;
    let wrong_destination = Pubkey::new_unique();
    let (ix, winternitz_key, winternitz_account, _) = transfer_ix(
        &fixture,
        TransferIxInput {
            lamports: 60_000,
            signed_lamports: 60_000,
            quorum_nonce: 0,
            falcon_nonce: 0,
            spend_count: 0,
            destination: wrong_destination,
            signed_destination: fixture.destination,
        },
    );

    let result = process_transfer(
        &fixture,
        &ix,
        smart_account,
        system_account(9),
        winternitz_key,
        winternitz_account,
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(6))
    );
    let smart_account = result_account(&result, fixture.smart_account);
    let destination = result_account(&result, wrong_destination);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(smart_account.lamports, before_smart_lamports);
    assert_eq!(destination.lamports, 9);
    assert_eq!(spend_count(&smart_account), 0);
    assert_eq!(quorum_next_nonce(&quorum), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn transfer_rejects_replay_after_quorum_nonce_advances() {
    let fixture = make_fixture(0, 0);
    let smart_account = deposit_to_smart(&fixture, init_smart_account(&fixture), 180_000);
    let (ix, winternitz_key, winternitz_account, _) = transfer_ix(
        &fixture,
        TransferIxInput {
            lamports: 60_000,
            signed_lamports: 60_000,
            quorum_nonce: 0,
            falcon_nonce: 0,
            spend_count: 0,
            destination: fixture.destination,
            signed_destination: fixture.destination,
        },
    );
    let first = process_transfer(
        &fixture,
        &ix,
        smart_account,
        system_account(9),
        winternitz_key,
        winternitz_account.clone(),
    );
    assert!(first.program_result.is_ok(), "{:?}", first.program_result);

    let replay = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, result_account(&first, fixture.authority)),
            (
                fixture.smart_account,
                result_account(&first, fixture.smart_account),
            ),
            (
                fixture.destination,
                result_account(&first, fixture.destination),
            ),
            (
                fixture.quorum_program_id,
                fixture.quorum_program_account.clone(),
            ),
            (fixture.quorum, result_account(&first, fixture.quorum)),
            (
                fixture.falcon_key,
                result_account(&first, fixture.falcon_key),
            ),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            (winternitz_key, winternitz_account),
        ],
    );

    assert_eq!(
        replay.program_result,
        SvmResult::Failure(ProgramError::Custom(7))
    );
    let smart_account = result_account(&replay, fixture.smart_account);
    let destination = result_account(&replay, fixture.destination);
    let quorum = result_account(&replay, fixture.quorum);
    let falcon_key = result_account(&replay, fixture.falcon_key);
    assert_eq!(destination.lamports, 60_009);
    assert_eq!(spend_count(&smart_account), 1);
    assert_eq!(quorum_next_nonce(&quorum), 1);
    assert_eq!(falcon_next_nonce(&falcon_key), 1);
}

#[test]
fn transfer_rejects_rent_unsafe_withdrawal() {
    let fixture = make_fixture(0, 0);
    let smart_account = deposit_to_smart(&fixture, init_smart_account(&fixture), 10_000);
    let before_smart_lamports = smart_account.lamports;
    let (ix, winternitz_key, winternitz_account, _) = transfer_ix(
        &fixture,
        TransferIxInput {
            lamports: before_smart_lamports,
            signed_lamports: before_smart_lamports,
            quorum_nonce: 0,
            falcon_nonce: 0,
            spend_count: 0,
            destination: fixture.destination,
            signed_destination: fixture.destination,
        },
    );

    let result = process_transfer(
        &fixture,
        &ix,
        smart_account,
        system_account(9),
        winternitz_key,
        winternitz_account,
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(7))
    );
    let smart_account = result_account(&result, fixture.smart_account);
    let destination = result_account(&result, fixture.destination);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(smart_account.lamports, before_smart_lamports);
    assert_eq!(destination.lamports, 9);
    assert_eq!(spend_count(&smart_account), 0);
    assert_eq!(quorum_next_nonce(&quorum), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}
