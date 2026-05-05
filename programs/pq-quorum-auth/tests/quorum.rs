use {
    fips204_rs::{KeyGen, MlDsa44, SerDes, Signer},
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
    solana_nostd_keccak::{hash as keccak_hash, hashv as keccak_hashv},
    solana_program::hash::hashv,
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
};

const TAG_REGISTER_QUORUM: u8 = 0;
const TAG_VERIFY_FALCON_WINTERNITZ: u8 = 1;
const TAG_VERIFY_DILITHIUM_UNSUPPORTED: u8 = 2;
const TAG_INIT_WINTERNITZ_SIGNATURE: u8 = 3;
const TAG_WRITE_WINTERNITZ_SIGNATURE_CHUNK: u8 = 4;
const TAG_INIT_MLDSA_PUBLIC_KEY: u8 = 5;
const TAG_WRITE_MLDSA_PUBLIC_KEY_CHUNK: u8 = 6;
const TAG_INIT_MLDSA_SIGNATURE: u8 = 7;
const TAG_WRITE_MLDSA_SIGNATURE_CHUNK: u8 = 8;
const TAG_FINALIZE_MLDSA_PUBLIC_KEY: u8 = 11;
const TAG_INIT_MLDSA_PROOF: u8 = 12;
const TAG_PROVE_MLDSA_COLUMN: u8 = 13;
const TAG_VERIFY_FALCON_MLDSA_PROOF: u8 = 14;
const TAG_VERIFY_WINTERNITZ_MLDSA_PROOF: u8 = 15;
const TAG_PREPARE_MLDSA_PROOF: u8 = 16;
const TAG_FINALIZE_MLDSA_ROW: u8 = 17;
const TAG_PREPARE_MLDSA_Z_COLUMN: u8 = 18;
const FALCON_KEY_SEED: &[u8] = b"falcon-key";
const QUORUM_SEED: &[u8] = b"pq-quorum";
const WINTERNITZ_SIGNATURE_SEED: &[u8] = b"wots-sig";
const MLDSA_PUBLIC_KEY_SEED: &[u8] = b"mldsa-key";
const MLDSA_SIGNATURE_SEED: &[u8] = b"mldsa-sig";
const MLDSA_PROOF_SEED: &[u8] = b"mldsa-proof";
const FALCON_KEY_DISCRIMINATOR: [u8; 8] = *b"FALKYA02";
const QUORUM_DISCRIMINATOR: [u8; 8] = *b"PQQRM001";
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
const SIGBUF_AUTHORITY_OFFSET: usize = 12;
const SIGBUF_QUORUM_OFFSET: usize = 44;
const SIGBUF_NONCE_OFFSET: usize = 76;
const SIGBUF_WRITTEN_OFFSET: usize = 84;
const SIGBUF_DATA_OFFSET: usize = 86;
const WINTERNITZ_SIGNATURE_BUFFER_LEN: usize = SIGBUF_DATA_OFFSET + WINTERNITZ_SIGNATURE_LEN;
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
const FALCON_ACTION_PAYLOAD_LEN: usize = 193;
const QUORUM_ACTION_PAYLOAD_LEN: usize = 225;
const QUORUM_ACTION_V2_PAYLOAD_LEN: usize = 290;
const WOTS16_N: usize = 32;
const WOTS16_W: u8 = 16;
const WOTS16_LEN1: usize = 64;
const WOTS16_LEN2: usize = 3;
const WOTS16_LEN: usize = WOTS16_LEN1 + WOTS16_LEN2;
const WOTS16_MAX_DIGIT: u8 = WOTS16_W - 1;
const WINTERNITZ_SIGNATURE_LEN: usize = WOTS16_LEN * WOTS16_N;
const CLUSTER: u8 = 0;
const VERIFY_FALCON_WINTERNITZ_MAX_CU: u64 = 350_000;
const DEVNET_TX_MAX_CU: u64 = 1_400_000;

struct Fixture {
    mollusk: Mollusk,
    quorum_program_id: Pubkey,
    falcon_auth_program_id: Pubkey,
    authority: Pubkey,
    falcon_key: Pubkey,
    quorum: Pubkey,
    quorum_bump: u8,
    winternitz_signature_account: Pubkey,
    falcon_account: Account,
    falcon_auth_program_account: Account,
    falcon_secret_key: falcon512::SecretKey,
    winternitz_privkey: Wots16Privkey,
}

fn make_fixture(falcon_nonce: u64) -> Fixture {
    let quorum_program_id = Pubkey::new_unique();
    let falcon_auth_program_id = Pubkey::new_unique();
    let mut mollusk = Mollusk::new(&quorum_program_id, "../../target/deploy/pq_quorum_auth");
    mollusk.compute_budget.compute_unit_limit = 20_000_000;
    mollusk.compute_budget.heap_size = 256 * 1024;
    mollusk.add_program(&falcon_auth_program_id, "../../target/deploy/falcon_auth");

    let authority = Pubkey::new_unique();
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
    let (prepared_pubkey, falcon_secret_key) = falcon_keypair();

    Fixture {
        mollusk,
        quorum_program_id,
        falcon_auth_program_id,
        authority,
        falcon_key,
        quorum,
        quorum_bump,
        winternitz_signature_account: Pubkey::new_unique(),
        falcon_account: falcon_account(
            falcon_auth_program_id,
            authority,
            falcon_bump,
            falcon_nonce,
            prepared_pubkey,
        ),
        falcon_auth_program_account: executable_program_account(),
        falcon_secret_key,
        winternitz_privkey: deterministic_winternitz_key(),
    }
}

fn falcon_keypair() -> ([u8; FALCON_512_PREPARED_PUBKEY_LEN], falcon512::SecretKey) {
    let (public_key, secret_key) = falcon512::keypair();
    let mut pk_bytes = [0u8; FALCON_512_PUBKEY_LEN];
    pk_bytes.copy_from_slice(public_key.as_bytes());
    let pubkey = Falcon512Pubkey::from(pk_bytes);
    (*pubkey.try_prepare_pubkey().unwrap().as_bytes(), secret_key)
}

fn deterministic_winternitz_key() -> Wots16Privkey {
    let mut bytes = [0u8; WINTERNITZ_SIGNATURE_LEN];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(17).wrapping_add(11);
    }
    Wots16Privkey::from(bytes)
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

fn wots16_root_step(previous_root: &[u8; 32], chain_index: u8, element: &[u8; 32]) -> [u8; 32] {
    let index_bytes = [chain_index];
    keccak_hashv(&[b"pq-wots16-root-v1", &index_bytes, previous_root, element])
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
    data[11] = 0;
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
    falcon_auth_program_id: Pubkey,
    falcon_key: Pubkey,
    quorum_bump: u8,
    winternitz_root: [u8; 32],
    next_nonce: u64,
) -> Account {
    let mut data = vec![0u8; QUORUM_ACCOUNT_LEN];
    data[..8].copy_from_slice(&QUORUM_DISCRIMINATOR);
    data[8] = 1;
    data[9] = quorum_bump;
    data[QUORUM_CLUSTER_OFFSET] = CLUSTER;
    data[11] = 0;
    data[QUORUM_AUTHORITY_OFFSET..QUORUM_FALCON_AUTH_PROGRAM_OFFSET]
        .copy_from_slice(authority.as_ref());
    data[QUORUM_FALCON_AUTH_PROGRAM_OFFSET..QUORUM_FALCON_KEY_OFFSET]
        .copy_from_slice(falcon_auth_program_id.as_ref());
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

fn register_quorum_ix(fixture: &Fixture) -> Instruction {
    let mut data = Vec::with_capacity(1 + 1 + 1 + 32);
    data.push(TAG_REGISTER_QUORUM);
    data.push(fixture.quorum_bump);
    data.push(CLUSTER);
    data.extend_from_slice(&fixture.winternitz_privkey.public_root());

    Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &data,
        vec![
            AccountMeta::new(fixture.authority, true),
            AccountMeta::new(fixture.quorum, false),
            AccountMeta::new_readonly(fixture.falcon_key, false),
            AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
    )
}

struct VerifyIxInput {
    quorum_nonce: u64,
    falcon_nonce: u64,
    expires_slot: u64,
    target_action_domain: [u8; 32],
    target_action_hash: [u8; 32],
    signed_target_action_hash: [u8; 32],
    next_winternitz_root: [u8; 32],
}

fn verify_ix_and_winternitz_signature(
    fixture: &Fixture,
    input: VerifyIxInput,
) -> (Instruction, [u8; WINTERNITZ_SIGNATURE_LEN]) {
    let quorum_payload = build_quorum_payload(
        fixture.quorum_program_id,
        fixture.authority,
        fixture.quorum,
        input.quorum_nonce,
        input.expires_slot,
        &input.target_action_domain,
        &input.signed_target_action_hash,
        &input.next_winternitz_root,
    );
    let winternitz_sig = fixture.winternitz_privkey.sign(&quorum_payload);

    let falcon_domain = pq_quorum_falcon_domain();
    let falcon_action_hash = pq_quorum_falcon_action_hash(&quorum_payload);
    let falcon_payload = build_falcon_payload(
        fixture.falcon_auth_program_id,
        fixture.authority,
        fixture.falcon_key,
        input.falcon_nonce,
        input.expires_slot,
        &falcon_domain,
        &falcon_action_hash,
    );
    let falcon_signature = falcon_signature_bytes(&falcon_payload, &fixture.falcon_secret_key);

    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 32 + 32 + 32 + FALCON_512_SIGNATURE_LEN);
    data.push(TAG_VERIFY_FALCON_WINTERNITZ);
    data.push(CLUSTER);
    data.extend_from_slice(&input.quorum_nonce.to_le_bytes());
    data.extend_from_slice(&input.falcon_nonce.to_le_bytes());
    data.extend_from_slice(&input.expires_slot.to_le_bytes());
    data.extend_from_slice(&input.target_action_domain);
    data.extend_from_slice(&input.target_action_hash);
    data.extend_from_slice(&input.next_winternitz_root);
    data.extend_from_slice(&falcon_signature);

    let instruction = Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &data,
        vec![
            AccountMeta::new(fixture.authority, false),
            AccountMeta::new(fixture.quorum, false),
            AccountMeta::new(fixture.falcon_key, false),
            AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
            AccountMeta::new(fixture.winternitz_signature_account, false),
        ],
    );

    (instruction, winternitz_sig)
}

fn verify_ix_and_sig_account(fixture: &Fixture, input: VerifyIxInput) -> (Instruction, Account) {
    let (instruction, winternitz_sig) = verify_ix_and_winternitz_signature(fixture, input);
    (instruction, signature_account(winternitz_sig))
}

fn signature_account(signature_bytes: [u8; WINTERNITZ_SIGNATURE_LEN]) -> Account {
    Account {
        lamports: 1_000_000,
        data: signature_bytes.to_vec(),
        owner: solana_sdk_ids::system_program::id(),
        executable: false,
        rent_epoch: 0,
    }
}

fn signature_buffer_address(fixture: &Fixture, quorum_nonce: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            WINTERNITZ_SIGNATURE_SEED,
            fixture.authority.as_ref(),
            fixture.quorum.as_ref(),
            &quorum_nonce.to_le_bytes(),
        ],
        &fixture.quorum_program_id,
    )
}

fn init_signature_buffer_ix(
    fixture: &Fixture,
    signature_buffer: Pubkey,
    bump: u8,
    quorum_nonce: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 1 + 8);
    data.push(TAG_INIT_WINTERNITZ_SIGNATURE);
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

fn write_signature_chunk_ix(
    fixture: &Fixture,
    signature_buffer: Pubkey,
    quorum_nonce: u64,
    offset: usize,
    chunk: &[u8],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 8 + 2 + chunk.len());
    data.push(TAG_WRITE_WINTERNITZ_SIGNATURE_CHUNK);
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

fn initialized_signature_buffer(
    fixture: &Fixture,
    quorum: Account,
    signature_buffer: Pubkey,
    bump: u8,
    quorum_nonce: u64,
) -> Account {
    let result = fixture.mollusk.process_instruction(
        &init_signature_buffer_ix(fixture, signature_buffer, bump, quorum_nonce),
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.quorum, quorum),
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
    result_account(&result, signature_buffer)
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
    let data = vec![TAG_INIT_MLDSA_PUBLIC_KEY, bump];
    Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &data,
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
    assert_eq!(proof_account.data[PROOF_PREPARED_FLAG_OFFSET], 0);

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
    println!(
        "ML-DSA proof prepare CU: {}",
        prepared.compute_units_consumed
    );
    assert!(prepared.compute_units_consumed <= DEVNET_TX_MAX_CU);
    proof_account = result_account(&prepared, proof);
    assert_eq!(proof_account.data[PROOF_PREPARED_FLAG_OFFSET], 1);
    assert_eq!(proof_account.data[PROOF_Z_MASK_OFFSET], 0);

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
        println!(
            "ML-DSA proof prepare z col {} CU: {}",
            col, result.compute_units_consumed
        );
        assert!(result.compute_units_consumed <= DEVNET_TX_MAX_CU);
        proof_account = result_account(&result, proof);
        assert_eq!(
            proof_account.data[PROOF_Z_MASK_OFFSET],
            (1 << (col + 1)) - 1
        );
    }
    assert!(
        proof_account.data[PROOF_PREPARED_SIGNATURE_OFFSET..PROOF_AZ_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
    );

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
            println!(
                "ML-DSA proof row {} col {} CU: {}",
                row, col, result.compute_units_consumed
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
        println!(
            "ML-DSA proof row {} final CU: {}",
            row, result.compute_units_consumed
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
        let row_start = PROOF_W1_OFFSET + row * MLDSA_W1_ROW_LEN;
        let row_end = row_start + MLDSA_W1_ROW_LEN;
        assert!(
            proof_account.data[row_start..row_end]
                .iter()
                .any(|byte| *byte != 0)
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

fn target_domain() -> [u8; 32] {
    hashv(&[b"test-consumer", b"rotate-admin.v1"]).to_bytes()
}

fn target_hash(value: u8) -> [u8; 32] {
    hashv(&[b"test-consumer-action-v1", &[value]]).to_bytes()
}

fn next_winternitz_root(value: u8) -> [u8; 32] {
    let mut bytes = [0u8; WINTERNITZ_SIGNATURE_LEN];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(31).wrapping_add(value);
    }
    Wots16Privkey::from(bytes).public_root()
}

fn quorum_next_nonce(account: &Account) -> u64 {
    u64::from_le_bytes(
        account.data[QUORUM_NEXT_NONCE_OFFSET..QUORUM_NEXT_NONCE_OFFSET + 8]
            .try_into()
            .unwrap(),
    )
}

fn quorum_winternitz_root(account: &Account) -> [u8; 32] {
    account.data[QUORUM_WINTERNITZ_ROOT_OFFSET..QUORUM_NEXT_NONCE_OFFSET]
        .try_into()
        .unwrap()
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

fn registered_quorum(fixture: &Fixture) -> Account {
    let result = fixture.mollusk.process_instruction(
        &register_quorum_ix(fixture),
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.quorum, system_account(0)),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            keyed_account_for_system_program(),
        ],
    );
    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    result_account(&result, fixture.quorum)
}

fn process_verify_ix(
    fixture: &Fixture,
    ix: &Instruction,
    quorum_account: Account,
    falcon_account: Account,
    signature_account: Account,
) -> mollusk_svm::result::InstructionResult {
    let signature_account_key = ix.accounts[4].pubkey;
    fixture.mollusk.process_instruction(
        ix,
        &[
            (fixture.authority, Account::default()),
            (fixture.quorum, quorum_account),
            (fixture.falcon_key, falcon_account),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            (signature_account_key, signature_account),
        ],
    )
}

#[test]
fn register_quorum_creates_program_owned_state() {
    let fixture = make_fixture(0);
    let result = fixture.mollusk.process_instruction(
        &register_quorum_ix(&fixture),
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.quorum, system_account(0)),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            keyed_account_for_system_program(),
        ],
    );

    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    let quorum = result_account(&result, fixture.quorum);
    assert_eq!(quorum.owner, fixture.quorum_program_id);
    assert_eq!(&quorum.data[..8], &QUORUM_DISCRIMINATOR);
    assert_eq!(quorum.data[QUORUM_CLUSTER_OFFSET], CLUSTER);
    assert_eq!(
        &quorum.data[QUORUM_AUTHORITY_OFFSET..QUORUM_FALCON_AUTH_PROGRAM_OFFSET],
        fixture.authority.as_ref()
    );
    assert_eq!(
        &quorum.data[QUORUM_FALCON_KEY_OFFSET..QUORUM_WINTERNITZ_ROOT_OFFSET],
        fixture.falcon_key.as_ref()
    );
    assert_eq!(quorum_next_nonce(&quorum), 0);
}

#[test]
fn register_quorum_rejects_wrong_pda() {
    let fixture = make_fixture(0);
    let wrong_quorum = Pubkey::new_unique();
    let mut ix = register_quorum_ix(&fixture);
    ix.accounts[1].pubkey = wrong_quorum;

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (wrong_quorum, system_account(0)),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            keyed_account_for_system_program(),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(4))
    );
}

#[test]
fn init_signature_buffer_creates_program_owned_buffer() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let (signature_buffer, bump) = signature_buffer_address(&fixture, 0);
    let result = fixture.mollusk.process_instruction(
        &init_signature_buffer_ix(&fixture, signature_buffer, bump, 0),
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.quorum, quorum),
            (signature_buffer, system_account(0)),
            keyed_account_for_system_program(),
        ],
    );

    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    let buffer = result_account(&result, signature_buffer);
    assert_eq!(buffer.owner, fixture.quorum_program_id);
    assert_eq!(buffer.data.len(), WINTERNITZ_SIGNATURE_BUFFER_LEN);
    assert_eq!(&buffer.data[..8], &WINTERNITZ_SIGNATURE_DISCRIMINATOR);
    assert_eq!(
        &buffer.data[SIGBUF_AUTHORITY_OFFSET..SIGBUF_QUORUM_OFFSET],
        fixture.authority.as_ref()
    );
    assert_eq!(
        &buffer.data[SIGBUF_QUORUM_OFFSET..SIGBUF_NONCE_OFFSET],
        fixture.quorum.as_ref()
    );
    assert_eq!(
        u64::from_le_bytes(
            buffer.data[SIGBUF_NONCE_OFFSET..SIGBUF_NONCE_OFFSET + 8]
                .try_into()
                .unwrap()
        ),
        0
    );
    assert_eq!(
        u16::from_le_bytes(
            buffer.data[SIGBUF_WRITTEN_OFFSET..SIGBUF_WRITTEN_OFFSET + 2]
                .try_into()
                .unwrap()
        ),
        0
    );
}

#[test]
fn init_signature_buffer_rejects_wrong_pda() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let wrong_buffer = Pubkey::new_unique();
    let result = fixture.mollusk.process_instruction(
        &init_signature_buffer_ix(&fixture, wrong_buffer, 255, 0),
        &[
            (fixture.authority, system_account(1_000_000_000)),
            (fixture.quorum, quorum),
            (wrong_buffer, system_account(0)),
            keyed_account_for_system_program(),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(4))
    );
}

#[test]
fn write_signature_chunk_appends_into_buffer() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let (signature_buffer, bump) = signature_buffer_address(&fixture, 0);
    let buffer = initialized_signature_buffer(&fixture, quorum.clone(), signature_buffer, bump, 0);
    let chunk = [9u8; 64];
    let result = fixture.mollusk.process_instruction(
        &write_signature_chunk_ix(&fixture, signature_buffer, 0, 0, &chunk),
        &[
            (fixture.authority, Account::default()),
            (fixture.quorum, quorum),
            (signature_buffer, buffer),
        ],
    );

    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    let buffer = result_account(&result, signature_buffer);
    assert_eq!(
        u16::from_le_bytes(
            buffer.data[SIGBUF_WRITTEN_OFFSET..SIGBUF_WRITTEN_OFFSET + 2]
                .try_into()
                .unwrap()
        ),
        chunk.len() as u16
    );
    assert_eq!(
        &buffer.data[SIGBUF_DATA_OFFSET..SIGBUF_DATA_OFFSET + chunk.len()],
        &chunk
    );
}

#[test]
fn write_signature_chunk_rejects_out_of_order_offset() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let (signature_buffer, bump) = signature_buffer_address(&fixture, 0);
    let buffer = initialized_signature_buffer(&fixture, quorum.clone(), signature_buffer, bump, 0);
    let result = fixture.mollusk.process_instruction(
        &write_signature_chunk_ix(&fixture, signature_buffer, 0, 32, &[1u8; 8]),
        &[
            (fixture.authority, Account::default()),
            (fixture.quorum, quorum),
            (signature_buffer, buffer),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(1))
    );
}

#[test]
fn verify_accepts_falcon_and_winternitz_and_increments_nonces() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let (ix, signature_account) = verify_ix_and_sig_account(
        &fixture,
        VerifyIxInput {
            quorum_nonce: 0,
            falcon_nonce: 0,
            expires_slot: 100,
            target_action_domain: target_domain(),
            target_action_hash: target_hash(1),
            signed_target_action_hash: target_hash(1),
            next_winternitz_root: next_winternitz_root(1),
        },
    );

    let result = process_verify_ix(
        &fixture,
        &ix,
        quorum,
        fixture.falcon_account.clone(),
        signature_account,
    );

    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    println!(
        "Falcon + Winternitz quorum CU: {}",
        result.compute_units_consumed
    );
    assert!(result.compute_units_consumed <= VERIFY_FALCON_WINTERNITZ_MAX_CU);
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(quorum_next_nonce(&quorum), 1);
    assert_eq!(quorum_winternitz_root(&quorum), next_winternitz_root(1));
    assert_eq!(falcon_next_nonce(&falcon_key), 1);
}

#[test]
fn verify_accepts_signature_buffer_and_closes_it() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let (signature_buffer, bump) = signature_buffer_address(&fixture, 0);
    let mut buffer =
        initialized_signature_buffer(&fixture, quorum.clone(), signature_buffer, bump, 0);
    let (mut ix, winternitz_sig) = verify_ix_and_winternitz_signature(
        &fixture,
        VerifyIxInput {
            quorum_nonce: 0,
            falcon_nonce: 0,
            expires_slot: 100,
            target_action_domain: target_domain(),
            target_action_hash: target_hash(1),
            signed_target_action_hash: target_hash(1),
            next_winternitz_root: next_winternitz_root(1),
        },
    );
    ix.accounts[4].pubkey = signature_buffer;

    let mut offset = 0;
    while offset < winternitz_sig.len() {
        let end = (offset + 512).min(winternitz_sig.len());
        let result = fixture.mollusk.process_instruction(
            &write_signature_chunk_ix(
                &fixture,
                signature_buffer,
                0,
                offset,
                &winternitz_sig[offset..end],
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

    let result = process_verify_ix(
        &fixture,
        &ix,
        quorum,
        fixture.falcon_account.clone(),
        buffer,
    );

    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    println!(
        "Falcon + Winternitz signature-buffer quorum CU: {}",
        result.compute_units_consumed
    );
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    let buffer = result_account(&result, signature_buffer);
    assert_eq!(quorum_next_nonce(&quorum), 1);
    assert_eq!(quorum_winternitz_root(&quorum), next_winternitz_root(1));
    assert_eq!(falcon_next_nonce(&falcon_key), 1);
    assert_eq!(buffer.lamports, 0);
    assert_eq!(&buffer.data[..8], &[0u8; 8]);
}

#[test]
fn verify_accepts_falcon_and_split_mldsa_proof_and_increments_nonces() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let current_root = fixture.winternitz_privkey.public_root();
    let action_domain = target_domain();
    let action_hash = target_hash(13);
    let proof_setup = initialized_mldsa_proof(
        &fixture,
        quorum.clone(),
        MldsaProofSetupInput {
            mode: QUORUM_MODE_FALCON_MLDSA,
            seed: 52,
            quorum_nonce: 0,
            expires_slot: 100,
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
        0,
        100,
        &falcon_domain,
        &falcon_action_hash,
    );
    let falcon_signature = falcon_signature_bytes(&falcon_payload, &fixture.falcon_secret_key);
    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 32 + 32 + FALCON_512_SIGNATURE_LEN);
    data.push(TAG_VERIFY_FALCON_MLDSA_PROOF);
    data.push(CLUSTER);
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&100u64.to_le_bytes());
    data.extend_from_slice(&action_domain);
    data.extend_from_slice(&action_hash);
    data.extend_from_slice(&falcon_signature);
    let ix = Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &data,
        vec![
            AccountMeta::new(fixture.authority, false),
            AccountMeta::new(fixture.quorum, false),
            AccountMeta::new(fixture.falcon_key, false),
            AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
            AccountMeta::new_readonly(proof_setup.public_key, false),
            AccountMeta::new(proof_setup.signature, false),
            AccountMeta::new(proof_setup.proof, false),
        ],
    );

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, Account::default()),
            (fixture.quorum, quorum),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            (proof_setup.public_key, proof_setup.public_key_account),
            (proof_setup.signature, proof_setup.signature_account),
            (proof_setup.proof, proof_setup.proof_account),
        ],
    );

    assert!(
        result.program_result.is_ok(),
        "{:?} raw={:?} cu={}",
        result.program_result,
        result.raw_result,
        result.compute_units_consumed
    );
    println!(
        "Falcon + split ML-DSA proof final CU: {}",
        result.compute_units_consumed
    );
    assert!(result.compute_units_consumed <= DEVNET_TX_MAX_CU);
    assert_eq!(
        quorum_next_nonce(&result_account(&result, fixture.quorum)),
        1
    );
    assert_eq!(
        falcon_next_nonce(&result_account(&result, fixture.falcon_key)),
        1
    );
    assert_eq!(result_account(&result, proof_setup.signature).lamports, 0);
    assert_eq!(result_account(&result, proof_setup.proof).lamports, 0);
}

#[test]
fn verify_accepts_winternitz_and_split_mldsa_proof_and_rotates_root() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let current_root = fixture.winternitz_privkey.public_root();
    let next_root = next_winternitz_root(17);
    let action_domain = target_domain();
    let action_hash = target_hash(14);
    let proof_setup = initialized_mldsa_proof(
        &fixture,
        quorum.clone(),
        MldsaProofSetupInput {
            mode: QUORUM_MODE_WINTERNITZ_MLDSA,
            seed: 53,
            quorum_nonce: 0,
            expires_slot: 100,
            action_domain,
            action_hash,
            current_winternitz_root: current_root,
            next_winternitz_root: next_root,
        },
    );
    let winternitz_signature = fixture.winternitz_privkey.sign(&proof_setup.payload);
    let (winternitz_signature_buffer, bump) = signature_buffer_address(&fixture, 0);
    let mut winternitz_account = initialized_signature_buffer(
        &fixture,
        quorum.clone(),
        winternitz_signature_buffer,
        bump,
        0,
    );
    let mut offset = 0;
    while offset < winternitz_signature.len() {
        let end = (offset + 512).min(winternitz_signature.len());
        let result = fixture.mollusk.process_instruction(
            &write_signature_chunk_ix(
                &fixture,
                winternitz_signature_buffer,
                0,
                offset,
                &winternitz_signature[offset..end],
            ),
            &[
                (fixture.authority, Account::default()),
                (fixture.quorum, quorum.clone()),
                (winternitz_signature_buffer, winternitz_account),
            ],
        );
        assert!(result.program_result.is_ok(), "{:?}", result.program_result);
        winternitz_account = result_account(&result, winternitz_signature_buffer);
        offset = end;
    }

    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 32 + 32 + 32);
    data.push(TAG_VERIFY_WINTERNITZ_MLDSA_PROOF);
    data.push(CLUSTER);
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&100u64.to_le_bytes());
    data.extend_from_slice(&action_domain);
    data.extend_from_slice(&action_hash);
    data.extend_from_slice(&next_root);
    let ix = Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &data,
        vec![
            AccountMeta::new(fixture.authority, false),
            AccountMeta::new(fixture.quorum, false),
            AccountMeta::new_readonly(fixture.falcon_key, false),
            AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
            AccountMeta::new(winternitz_signature_buffer, false),
            AccountMeta::new_readonly(proof_setup.public_key, false),
            AccountMeta::new(proof_setup.signature, false),
            AccountMeta::new(proof_setup.proof, false),
        ],
    );

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, Account::default()),
            (fixture.quorum, quorum),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            (winternitz_signature_buffer, winternitz_account),
            (proof_setup.public_key, proof_setup.public_key_account),
            (proof_setup.signature, proof_setup.signature_account),
            (proof_setup.proof, proof_setup.proof_account),
        ],
    );

    assert!(
        result.program_result.is_ok(),
        "{:?} raw={:?} cu={}",
        result.program_result,
        result.raw_result,
        result.compute_units_consumed
    );
    println!(
        "Winternitz + split ML-DSA proof final CU: {}",
        result.compute_units_consumed
    );
    assert!(result.compute_units_consumed <= DEVNET_TX_MAX_CU);
    let quorum = result_account(&result, fixture.quorum);
    assert_eq!(quorum_next_nonce(&quorum), 1);
    assert_eq!(quorum_winternitz_root(&quorum), next_root);
    assert_eq!(
        falcon_next_nonce(&result_account(&result, fixture.falcon_key)),
        0
    );
    assert_eq!(
        result_account(&result, winternitz_signature_buffer).lamports,
        0
    );
    assert_eq!(result_account(&result, proof_setup.signature).lamports, 0);
    assert_eq!(result_account(&result, proof_setup.proof).lamports, 0);
}

#[test]
fn verify_rejects_incomplete_split_mldsa_proof() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let current_root = fixture.winternitz_privkey.public_root();
    let action_domain = target_domain();
    let action_hash = target_hash(15);
    let seed = [54u8; 32];
    let (mldsa_pk, mldsa_sk) = MlDsa44::keygen_from_seed(&seed);
    let mldsa_pk_bytes = mldsa_pk.into_bytes();
    let (public_key, public_key_account) =
        initialized_mldsa_public_key_buffer(&fixture, quorum.clone(), &mldsa_pk_bytes);
    let payload = build_quorum_v2_payload(V2PayloadInput {
        mode: QUORUM_MODE_FALCON_MLDSA,
        quorum_program_id: fixture.quorum_program_id,
        authority: fixture.authority,
        quorum: fixture.quorum,
        mldsa_public_key: public_key,
        quorum_nonce: 0,
        expires_slot: 100,
        action_domain: &action_domain,
        action_hash: &action_hash,
        current_winternitz_root: &current_root,
        next_winternitz_root: &current_root,
    });
    let signature_bytes = mldsa_sk.try_sign(&payload, &[]).unwrap();
    let (signature, signature_account) =
        initialized_mldsa_signature_buffer(&fixture, quorum.clone(), 0, &signature_bytes);
    let payload_hash = mldsa_proof_payload_hash(&payload);
    let (proof, bump) = mldsa_proof_address(&fixture, 0);
    let init = fixture.mollusk.process_instruction(
        &init_mldsa_proof_ix(
            &fixture,
            proof,
            bump,
            QUORUM_MODE_FALCON_MLDSA,
            0,
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
    assert!(init.program_result.is_ok(), "{:?}", init.program_result);
    let proof_account = result_account(&init, proof);
    assert_eq!(proof_account.data[PROOF_ROW_MASK_OFFSET], 0);
    let prepared = fixture.mollusk.process_instruction(
        &prepare_mldsa_proof_ix(&fixture, proof, public_key, signature),
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
        "{:?}",
        prepared.program_result
    );
    let proof_account = result_account(&prepared, proof);
    assert_eq!(proof_account.data[PROOF_PREPARED_FLAG_OFFSET], 1);

    let falcon_domain = pq_quorum_falcon_domain_v2();
    let falcon_action_hash = pq_quorum_falcon_action_hash_v2(&payload);
    let falcon_payload = build_falcon_payload(
        fixture.falcon_auth_program_id,
        fixture.authority,
        fixture.falcon_key,
        0,
        100,
        &falcon_domain,
        &falcon_action_hash,
    );
    let falcon_signature = falcon_signature_bytes(&falcon_payload, &fixture.falcon_secret_key);
    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 32 + 32 + FALCON_512_SIGNATURE_LEN);
    data.push(TAG_VERIFY_FALCON_MLDSA_PROOF);
    data.push(CLUSTER);
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&100u64.to_le_bytes());
    data.extend_from_slice(&action_domain);
    data.extend_from_slice(&action_hash);
    data.extend_from_slice(&falcon_signature);
    let ix = Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &data,
        vec![
            AccountMeta::new(fixture.authority, false),
            AccountMeta::new(fixture.quorum, false),
            AccountMeta::new(fixture.falcon_key, false),
            AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
            AccountMeta::new_readonly(public_key, false),
            AccountMeta::new(signature, false),
            AccountMeta::new(proof, false),
        ],
    );
    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, Account::default()),
            (fixture.quorum, quorum),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            (public_key, public_key_account),
            (signature, signature_account),
            (proof, proof_account),
        ],
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(16))
    );
    assert_eq!(
        quorum_next_nonce(&result_account(&result, fixture.quorum)),
        0
    );
    assert_eq!(
        falcon_next_nonce(&result_account(&result, fixture.falcon_key)),
        0
    );
}

#[test]
fn prove_mldsa_column_rejects_duplicate_column() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let current_root = fixture.winternitz_privkey.public_root();
    let action_domain = target_domain();
    let action_hash = target_hash(16);
    let seed = [55u8; 32];
    let (mldsa_pk, mldsa_sk) = MlDsa44::keygen_from_seed(&seed);
    let mldsa_pk_bytes = mldsa_pk.into_bytes();
    let (public_key, public_key_account) =
        initialized_mldsa_public_key_buffer(&fixture, quorum.clone(), &mldsa_pk_bytes);
    let payload = build_quorum_v2_payload(V2PayloadInput {
        mode: QUORUM_MODE_FALCON_MLDSA,
        quorum_program_id: fixture.quorum_program_id,
        authority: fixture.authority,
        quorum: fixture.quorum,
        mldsa_public_key: public_key,
        quorum_nonce: 0,
        expires_slot: 100,
        action_domain: &action_domain,
        action_hash: &action_hash,
        current_winternitz_root: &current_root,
        next_winternitz_root: &current_root,
    });
    let signature_bytes = mldsa_sk.try_sign(&payload, &[]).unwrap();
    let (signature, signature_account) =
        initialized_mldsa_signature_buffer(&fixture, quorum.clone(), 0, &signature_bytes);
    let payload_hash = mldsa_proof_payload_hash(&payload);
    let (proof, bump) = mldsa_proof_address(&fixture, 0);
    let init = fixture.mollusk.process_instruction(
        &init_mldsa_proof_ix(
            &fixture,
            proof,
            bump,
            QUORUM_MODE_FALCON_MLDSA,
            0,
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
    assert!(init.program_result.is_ok(), "{:?}", init.program_result);
    let proof_account = result_account(&init, proof);

    let prepared = fixture.mollusk.process_instruction(
        &prepare_mldsa_proof_ix(&fixture, proof, public_key, signature),
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
        "{:?}",
        prepared.program_result
    );
    let proof_account = result_account(&prepared, proof);

    let z_prepared = fixture.mollusk.process_instruction(
        &prepare_mldsa_z_column_ix(&fixture, proof, 0, public_key, signature),
        &[
            (fixture.authority, Account::default()),
            (fixture.quorum, quorum.clone()),
            (proof, proof_account),
            (public_key, public_key_account.clone()),
            (signature, signature_account.clone()),
        ],
    );
    assert!(
        z_prepared.program_result.is_ok(),
        "{:?}",
        z_prepared.program_result
    );
    let proof_account = result_account(&z_prepared, proof);

    let first = fixture.mollusk.process_instruction(
        &prove_mldsa_column_ix(&fixture, proof, 0, 0, public_key, signature),
        &[
            (fixture.authority, Account::default()),
            (fixture.quorum, quorum.clone()),
            (proof, proof_account),
            (public_key, public_key_account.clone()),
            (signature, signature_account.clone()),
        ],
    );
    assert!(first.program_result.is_ok(), "{:?}", first.program_result);
    let proof_account = result_account(&first, proof);
    assert_eq!(proof_account.data[PROOF_COLUMN_MASK_OFFSET], 1);
    assert_eq!(proof_account.data[PROOF_ROW_MASK_OFFSET], 0);

    let duplicate = fixture.mollusk.process_instruction(
        &prove_mldsa_column_ix(&fixture, proof, 0, 0, public_key, signature),
        &[
            (fixture.authority, Account::default()),
            (fixture.quorum, quorum),
            (proof, proof_account),
            (public_key, public_key_account),
            (signature, signature_account),
        ],
    );
    assert_eq!(
        duplicate.program_result,
        SvmResult::Failure(ProgramError::Custom(16))
    );
    assert_eq!(
        result_account(&duplicate, proof).data[PROOF_COLUMN_MASK_OFFSET],
        1
    );
}

#[test]
fn prove_mldsa_column_rejects_unprepared_proof() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let current_root = fixture.winternitz_privkey.public_root();
    let action_domain = target_domain();
    let action_hash = target_hash(22);
    let seed = [58u8; 32];
    let (mldsa_pk, mldsa_sk) = MlDsa44::keygen_from_seed(&seed);
    let mldsa_pk_bytes = mldsa_pk.into_bytes();
    let (public_key, public_key_account) =
        initialized_mldsa_public_key_buffer(&fixture, quorum.clone(), &mldsa_pk_bytes);
    let payload = build_quorum_v2_payload(V2PayloadInput {
        mode: QUORUM_MODE_FALCON_MLDSA,
        quorum_program_id: fixture.quorum_program_id,
        authority: fixture.authority,
        quorum: fixture.quorum,
        mldsa_public_key: public_key,
        quorum_nonce: 0,
        expires_slot: 100,
        action_domain: &action_domain,
        action_hash: &action_hash,
        current_winternitz_root: &current_root,
        next_winternitz_root: &current_root,
    });
    let signature_bytes = mldsa_sk.try_sign(&payload, &[]).unwrap();
    let (signature, signature_account) =
        initialized_mldsa_signature_buffer(&fixture, quorum.clone(), 0, &signature_bytes);
    let payload_hash = mldsa_proof_payload_hash(&payload);
    let (proof, bump) = mldsa_proof_address(&fixture, 0);
    let init = fixture.mollusk.process_instruction(
        &init_mldsa_proof_ix(
            &fixture,
            proof,
            bump,
            QUORUM_MODE_FALCON_MLDSA,
            0,
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
    assert!(init.program_result.is_ok(), "{:?}", init.program_result);
    let proof_account = result_account(&init, proof);

    let result = fixture.mollusk.process_instruction(
        &prove_mldsa_column_ix(&fixture, proof, 0, 0, public_key, signature),
        &[
            (fixture.authority, Account::default()),
            (fixture.quorum, quorum),
            (proof, proof_account),
            (public_key, public_key_account),
            (signature, signature_account),
        ],
    );
    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(16))
    );
    assert_eq!(
        result_account(&result, proof).data[PROOF_ROW_MASK_OFFSET],
        0
    );
}

#[test]
fn verify_rejects_split_mldsa_payload_hash_mismatch() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let current_root = fixture.winternitz_privkey.public_root();
    let action_domain = target_domain();
    let signed_action_hash = target_hash(17);
    let tampered_action_hash = target_hash(18);
    let proof_setup = initialized_mldsa_proof(
        &fixture,
        quorum.clone(),
        MldsaProofSetupInput {
            mode: QUORUM_MODE_FALCON_MLDSA,
            seed: 56,
            quorum_nonce: 0,
            expires_slot: 100,
            action_domain,
            action_hash: signed_action_hash,
            current_winternitz_root: current_root,
            next_winternitz_root: current_root,
        },
    );

    let tampered_payload = build_quorum_v2_payload(V2PayloadInput {
        mode: QUORUM_MODE_FALCON_MLDSA,
        quorum_program_id: fixture.quorum_program_id,
        authority: fixture.authority,
        quorum: fixture.quorum,
        mldsa_public_key: proof_setup.public_key,
        quorum_nonce: 0,
        expires_slot: 100,
        action_domain: &action_domain,
        action_hash: &tampered_action_hash,
        current_winternitz_root: &current_root,
        next_winternitz_root: &current_root,
    });
    let falcon_domain = pq_quorum_falcon_domain_v2();
    let falcon_action_hash = pq_quorum_falcon_action_hash_v2(&tampered_payload);
    let falcon_payload = build_falcon_payload(
        fixture.falcon_auth_program_id,
        fixture.authority,
        fixture.falcon_key,
        0,
        100,
        &falcon_domain,
        &falcon_action_hash,
    );
    let falcon_signature = falcon_signature_bytes(&falcon_payload, &fixture.falcon_secret_key);
    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 32 + 32 + FALCON_512_SIGNATURE_LEN);
    data.push(TAG_VERIFY_FALCON_MLDSA_PROOF);
    data.push(CLUSTER);
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&100u64.to_le_bytes());
    data.extend_from_slice(&action_domain);
    data.extend_from_slice(&tampered_action_hash);
    data.extend_from_slice(&falcon_signature);
    let ix = Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &data,
        vec![
            AccountMeta::new(fixture.authority, false),
            AccountMeta::new(fixture.quorum, false),
            AccountMeta::new(fixture.falcon_key, false),
            AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
            AccountMeta::new_readonly(proof_setup.public_key, false),
            AccountMeta::new(proof_setup.signature, false),
            AccountMeta::new(proof_setup.proof, false),
        ],
    );

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, Account::default()),
            (fixture.quorum, quorum),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            (proof_setup.public_key, proof_setup.public_key_account),
            (proof_setup.signature, proof_setup.signature_account),
            (proof_setup.proof, proof_setup.proof_account),
        ],
    );
    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(16))
    );
    assert_eq!(
        quorum_next_nonce(&result_account(&result, fixture.quorum)),
        0
    );
    assert_eq!(
        falcon_next_nonce(&result_account(&result, fixture.falcon_key)),
        0
    );
}

#[test]
fn verify_rejects_split_mldsa_proof_mode_mismatch() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let current_root = fixture.winternitz_privkey.public_root();
    let next_root = next_winternitz_root(19);
    let action_domain = target_domain();
    let action_hash = target_hash(19);
    let proof_setup = initialized_mldsa_proof(
        &fixture,
        quorum.clone(),
        MldsaProofSetupInput {
            mode: QUORUM_MODE_WINTERNITZ_MLDSA,
            seed: 57,
            quorum_nonce: 0,
            expires_slot: 100,
            action_domain,
            action_hash,
            current_winternitz_root: current_root,
            next_winternitz_root: next_root,
        },
    );

    let falcon_payload_to_approve = build_quorum_v2_payload(V2PayloadInput {
        mode: QUORUM_MODE_FALCON_MLDSA,
        quorum_program_id: fixture.quorum_program_id,
        authority: fixture.authority,
        quorum: fixture.quorum,
        mldsa_public_key: proof_setup.public_key,
        quorum_nonce: 0,
        expires_slot: 100,
        action_domain: &action_domain,
        action_hash: &action_hash,
        current_winternitz_root: &current_root,
        next_winternitz_root: &current_root,
    });
    let falcon_domain = pq_quorum_falcon_domain_v2();
    let falcon_action_hash = pq_quorum_falcon_action_hash_v2(&falcon_payload_to_approve);
    let falcon_payload = build_falcon_payload(
        fixture.falcon_auth_program_id,
        fixture.authority,
        fixture.falcon_key,
        0,
        100,
        &falcon_domain,
        &falcon_action_hash,
    );
    let falcon_signature = falcon_signature_bytes(&falcon_payload, &fixture.falcon_secret_key);
    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 32 + 32 + FALCON_512_SIGNATURE_LEN);
    data.push(TAG_VERIFY_FALCON_MLDSA_PROOF);
    data.push(CLUSTER);
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&100u64.to_le_bytes());
    data.extend_from_slice(&action_domain);
    data.extend_from_slice(&action_hash);
    data.extend_from_slice(&falcon_signature);
    let ix = Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &data,
        vec![
            AccountMeta::new(fixture.authority, false),
            AccountMeta::new(fixture.quorum, false),
            AccountMeta::new(fixture.falcon_key, false),
            AccountMeta::new_readonly(fixture.falcon_auth_program_id, false),
            AccountMeta::new_readonly(proof_setup.public_key, false),
            AccountMeta::new(proof_setup.signature, false),
            AccountMeta::new(proof_setup.proof, false),
        ],
    );

    let result = fixture.mollusk.process_instruction(
        &ix,
        &[
            (fixture.authority, Account::default()),
            (fixture.quorum, quorum),
            (fixture.falcon_key, fixture.falcon_account.clone()),
            (
                fixture.falcon_auth_program_id,
                fixture.falcon_auth_program_account.clone(),
            ),
            (proof_setup.public_key, proof_setup.public_key_account),
            (proof_setup.signature, proof_setup.signature_account),
            (proof_setup.proof, proof_setup.proof_account),
        ],
    );
    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(16))
    );
    assert_eq!(
        quorum_next_nonce(&result_account(&result, fixture.quorum)),
        0
    );
    assert_eq!(
        falcon_next_nonce(&result_account(&result, fixture.falcon_key)),
        0
    );
}

#[test]
fn verify_rejects_replayed_quorum_nonce() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let (ix, signature_account) = verify_ix_and_sig_account(
        &fixture,
        VerifyIxInput {
            quorum_nonce: 0,
            falcon_nonce: 0,
            expires_slot: 100,
            target_action_domain: target_domain(),
            target_action_hash: target_hash(1),
            signed_target_action_hash: target_hash(1),
            next_winternitz_root: next_winternitz_root(1),
        },
    );
    let first = process_verify_ix(
        &fixture,
        &ix,
        quorum,
        fixture.falcon_account.clone(),
        signature_account.clone(),
    );
    assert!(first.program_result.is_ok(), "{:?}", first.program_result);

    let replay = process_verify_ix(
        &fixture,
        &ix,
        result_account(&first, fixture.quorum),
        result_account(&first, fixture.falcon_key),
        signature_account,
    );

    assert_eq!(
        replay.program_result,
        SvmResult::Failure(ProgramError::Custom(7))
    );
    let quorum = result_account(&replay, fixture.quorum);
    let falcon_key = result_account(&replay, fixture.falcon_key);
    assert_eq!(quorum_next_nonce(&quorum), 1);
    assert_eq!(falcon_next_nonce(&falcon_key), 1);
}

#[test]
fn verify_rejects_bad_winternitz_signature_before_falcon_nonce_moves() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let (ix, mut signature_account) = verify_ix_and_sig_account(
        &fixture,
        VerifyIxInput {
            quorum_nonce: 0,
            falcon_nonce: 0,
            expires_slot: 100,
            target_action_domain: target_domain(),
            target_action_hash: target_hash(1),
            signed_target_action_hash: target_hash(1),
            next_winternitz_root: next_winternitz_root(1),
        },
    );
    signature_account.data[0] ^= 0xff;

    let result = process_verify_ix(
        &fixture,
        &ix,
        quorum,
        fixture.falcon_account.clone(),
        signature_account,
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(6))
    );
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(quorum_next_nonce(&quorum), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn verify_rejects_reusing_current_winternitz_root_as_next_root() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let current_root = fixture.winternitz_privkey.public_root();
    let (ix, signature_account) = verify_ix_and_sig_account(
        &fixture,
        VerifyIxInput {
            quorum_nonce: 0,
            falcon_nonce: 0,
            expires_slot: 100,
            target_action_domain: target_domain(),
            target_action_hash: target_hash(1),
            signed_target_action_hash: target_hash(1),
            next_winternitz_root: current_root,
        },
    );

    let result = process_verify_ix(
        &fixture,
        &ix,
        quorum,
        fixture.falcon_account.clone(),
        signature_account,
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(12))
    );
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(quorum_next_nonce(&quorum), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn verify_rejects_tampered_target_action_hash() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let (ix, signature_account) = verify_ix_and_sig_account(
        &fixture,
        VerifyIxInput {
            quorum_nonce: 0,
            falcon_nonce: 0,
            expires_slot: 100,
            target_action_domain: target_domain(),
            target_action_hash: target_hash(2),
            signed_target_action_hash: target_hash(1),
            next_winternitz_root: next_winternitz_root(1),
        },
    );

    let result = process_verify_ix(
        &fixture,
        &ix,
        quorum,
        fixture.falcon_account.clone(),
        signature_account,
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(6))
    );
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(quorum_next_nonce(&quorum), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn verify_rejects_wrong_falcon_signature_after_winternitz_passes() {
    let fixture = make_fixture(0);
    let quorum = registered_quorum(&fixture);
    let (mut ix, signature_account) = verify_ix_and_sig_account(
        &fixture,
        VerifyIxInput {
            quorum_nonce: 0,
            falcon_nonce: 0,
            expires_slot: 100,
            target_action_domain: target_domain(),
            target_action_hash: target_hash(1),
            signed_target_action_hash: target_hash(1),
            next_winternitz_root: next_winternitz_root(1),
        },
    );
    let last = ix.data.len() - 1;
    ix.data[last] ^= 0xff;

    let result = process_verify_ix(
        &fixture,
        &ix,
        quorum,
        fixture.falcon_account.clone(),
        signature_account,
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(8))
    );
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(quorum_next_nonce(&quorum), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn verify_rejects_expired_action() {
    let mut fixture = make_fixture(0);
    fixture.mollusk.warp_to_slot(10);
    let quorum = registered_quorum(&fixture);
    let (ix, signature_account) = verify_ix_and_sig_account(
        &fixture,
        VerifyIxInput {
            quorum_nonce: 0,
            falcon_nonce: 0,
            expires_slot: 5,
            target_action_domain: target_domain(),
            target_action_hash: target_hash(1),
            signed_target_action_hash: target_hash(1),
            next_winternitz_root: next_winternitz_root(1),
        },
    );

    let result = process_verify_ix(
        &fixture,
        &ix,
        quorum,
        fixture.falcon_account.clone(),
        signature_account,
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(8))
    );
    let quorum = result_account(&result, fixture.quorum);
    let falcon_key = result_account(&result, fixture.falcon_key);
    assert_eq!(quorum_next_nonce(&quorum), 0);
    assert_eq!(falcon_next_nonce(&falcon_key), 0);
}

#[test]
fn verify_dilithium_tag_is_explicitly_unsupported() {
    let fixture = make_fixture(0);
    let ix = Instruction::new_with_bytes(
        fixture.quorum_program_id,
        &[TAG_VERIFY_DILITHIUM_UNSUPPORTED],
        vec![],
    );
    let result = fixture.mollusk.process_instruction(&ix, &[]);

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(10))
    );
}

#[test]
fn verify_validation_rejects_wrong_stored_winternitz_root() {
    let fixture = make_fixture(0);
    let wrong_root = [7u8; 32];
    let quorum = quorum_account(
        fixture.quorum_program_id,
        fixture.authority,
        fixture.falcon_auth_program_id,
        fixture.falcon_key,
        fixture.quorum_bump,
        wrong_root,
        0,
    );
    let (ix, signature_account) = verify_ix_and_sig_account(
        &fixture,
        VerifyIxInput {
            quorum_nonce: 0,
            falcon_nonce: 0,
            expires_slot: 100,
            target_action_domain: target_domain(),
            target_action_hash: target_hash(1),
            signed_target_action_hash: target_hash(1),
            next_winternitz_root: next_winternitz_root(1),
        },
    );

    let result = process_verify_ix(
        &fixture,
        &ix,
        quorum,
        fixture.falcon_account.clone(),
        signature_account,
    );

    assert_eq!(
        result.program_result,
        SvmResult::Failure(ProgramError::Custom(6))
    );
}
