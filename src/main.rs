use std::str::FromStr;

use miniscript::psbt::PsbtExt;
use rand::rngs::OsRng;
use rand::thread_rng;
use secp256k1::{
    hashes::{sha256, Hash},
    scalar::OutOfRangeError,
    schnorr::Signature,
    KeyPair, Message, PublicKey, Scalar, SecretKey, Verification,
};

use bitcoin::{
    blockdata::opcodes,
    key::{self, TapTweak},
    locktime,
    psbt::{self, PartiallySignedTransaction},
    script,
    sighash::{self, TapSighashType},
    taproot::{self, TaprootBuilder, TaprootSpendInfo},
    Address, OutPoint, Script, Sequence, Txid,
};
use bitcoin::{blockdata::script::Builder, ScriptBuf};
use hex;
use secp256k1::Secp256k1;
lazy_static::lazy_static! {
    static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    static ref NETWORK: bitcoin::Network = bitcoin::Network::Regtest;
}

pub fn generate_new_secret_key() -> SecretKey {
    let (secret_key, _) = SECP.generate_keypair(&mut OsRng);
    secret_key
}

pub fn generate_bip340_keypair() -> KeyPair {
    let key_pair = KeyPair::new(&SECP, &mut OsRng);

    key_pair
}

/// Take some byte, dups it and CATs it
/// Then checks if the result
fn create_taproot_script(some_data: [u8; 8]) -> ScriptBuf {
    let mut data_duped: [u8; 16] = [0; 16];

    data_duped[..8].copy_from_slice(&some_data);
    data_duped[8..].copy_from_slice(&some_data);

    let script = Builder::new()
        .push_slice(some_data)
        .push_opcode(opcodes::all::OP_DUP)
        .push_opcode(opcodes::all::OP_CAT)
        .push_slice(data_duped)
        .push_opcode(opcodes::all::OP_EQUAL)
        .into_script();

    script
}

fn generate_taproot_spend_info(
    secp: &Secp256k1<impl Verification>,
    pk: &PublicKey,
    data: [u8; 8],
) -> TaprootSpendInfo {
    let builder = TaprootBuilder::new()
        .add_leaf(0u8, create_taproot_script(data))
        .expect("Couldn't add timelock leaf");

    let finalized_taproot = builder.finalize(&secp, pk.x_only_public_key().0).unwrap();

    finalized_taproot
}

pub fn generate_taproot_address(pk: &PublicKey, data: [u8; 8]) -> Address {
    let taproot_spend_info = generate_taproot_spend_info(&SECP, pk, data);
    let script = ScriptBuf::new_v1_p2tr(
        &SECP,
        pk.x_only_public_key().0,
        taproot_spend_info.merkle_root(),
    );
    let address = Address::from_script(&script, *NETWORK).unwrap();
    address
}

fn main() {
    // let key_pair = generate_bip340_keypair();
    let key_hex = hex::decode("e9e3969ceeb49c13f018acba996c79af35f920d2520bd2a36df03208936cc717")
        .expect("valid hex");
    let keypair = KeyPair::from_seckey_slice(&SECP, &key_hex).expect("valid secret key material");

    let data: [u8; 8] = [0; 8];
    let address = generate_taproot_address(&keypair.public_key(), data);
    println!("Address: {}", address);

    // Modify as needed
    let outpoint = OutPoint::new(
        Txid::from_str("25ab4e7eca285e5b19f6c8eb04ecebfc91d0637d07a59777e757215869d2aa40")
            .expect("valid txid"),
        1,
    );

    // Create a spending tx
    let unsigned_tx = bitcoin::Transaction {
        version: 2,
        lock_time: locktime::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Default::default(),
        }],
        output: vec![bitcoin::TxOut {
            value: 100_000_000,
            script_pubkey: Address::from_str("bcrt1qlkyvulfwzlquwx5v7drkshr4zgq6f33ekunlj5")
                .expect("valid address")
                .assume_checked()
                .script_pubkey(),
        }],
    };
    let mut psbt = PartiallySignedTransaction::from_unsigned_tx(unsigned_tx).expect("valid tx");
    // Add the witness_utxo
    psbt.inputs[0].witness_utxo = Some(bitcoin::TxOut {
        // TODO modify the value as needed
        value: 10_000_000,
        script_pubkey: address.script_pubkey(),
    });

    // Lets create our sighash (to sign payload)
    println!("Unsigned PSBT: {:?}", psbt);
    let mut sighashcache = sighash::SighashCache::new(&psbt.unsigned_tx);
    let prevouts = psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.as_ref().unwrap())
        .collect::<Vec<_>>();
    let sighash = sighashcache
        .taproot_key_spend_signature_hash(
            // Only one input specified in the tx above
            0,
            &psbt::Prevouts::All(&prevouts),
            TapSighashType::All,
        )
        .expect("valid sighash");

    // Need to tweak the key before signing
    let taproot_spend_info = generate_taproot_spend_info(&SECP, &keypair.public_key(), data);
    let tweaked_keypair = keypair.tap_tweak(&SECP, taproot_spend_info.merkle_root());

    // Sign the sighash
    let message = Message::from_slice(&sighash[..]).expect("valid message");
    let signature = SECP.sign_schnorr(&message, &tweaked_keypair.to_inner());
    let taproot_signature = taproot::Signature {
        sig: signature,
        hash_ty: TapSighashType::All,
    };
    psbt.inputs[0].tap_key_sig = Some(taproot_signature);
    psbt.finalize_mut(&SECP).expect("valid psbt");
}
