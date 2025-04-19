use std::fmt;

use bitcoin::consensus::encode;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{Scalar, Secp256k1, SecretKey};
use bitcoin::sighash;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::PrivateKey;
use bitcoin::Witness;
use bitcoin::{bip32, CompressedPublicKey};
use bitcoin::{Amount, Script, Transaction};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::signer;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Event {
    commitment_tx: String,
    sweep_tx: String,
    htlc_tx: Vec<String>,
    commitment_number: u64,
    channel_point: String,
    sweep_tx_add_tweak: String,
    htlc_tx_add_tweak: String,
    serialized_htlc_sweep_tx: Vec<String>,
    funding_private_key_derivation_path: String,
    delayed_payment_base_key_derivation_path: String,
    htlc_base_key_derivation_path: String,
    channel_capacity: u64,
    nonces: Vec<String>,
    counterparty_sweep_tx: Option<String>,
    counterparty_htlc_tx_add_tweak: Option<String>,
    counterparty_serialized_htlc_sweep_tx: Option<Vec<String>>,
    counterparty_nonces: Option<Vec<String>>,
    payment_key_derivation_path: Option<String>,
    counterparty_serialized_commitment_tx: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct StringTuple {
    pub first: String,
    pub second: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Response {
    pub commitment_tx: String,
    pub sweep_tx: String,
    pub htlc_inbound_tx: Vec<StringTuple>,
    pub htlc_outbound_tx: Vec<StringTuple>,
    pub counterparty_sweep_tx: String,
    pub counterparty_htlc_inbound_tx: Vec<String>,
    pub counterparty_htlc_outbound_tx: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum FundsRecoveryKitError {
    Error { message: String },
}

impl std::error::Error for FundsRecoveryKitError {}

impl fmt::Display for FundsRecoveryKitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            Self::Error { message } => message,
        };
        write!(f, "Funds Recovery Kit Error: {}", message)
    }
}

#[derive(Clone, Debug)]
pub struct FundsRecoveryKitInternalError {
    pub error: String,
}

impl fmt::Display for FundsRecoveryKitInternalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Funds Recovery Kit Error")
    }
}

impl std::error::Error for FundsRecoveryKitInternalError {}

impl From<&str> for FundsRecoveryKitInternalError {
    fn from(value: &str) -> Self {
        Self {
            error: value.into(),
        }
    }
}

fn tweak_key(
    secret_key: SecretKey,
    add_tweak: [u8; 32],
) -> Result<SecretKey, FundsRecoveryKitInternalError> {
    let mut res: SecretKey = secret_key;
    let scalar = Scalar::from_be_bytes(add_tweak)
        .map_err(|_| FundsRecoveryKitInternalError::from("Invalid add tweak bytes"))?;
    res = res
        .add_tweak(&scalar)
        .map_err(|_| FundsRecoveryKitInternalError::from("Add tweak operation failed"))?;
    Ok(res)
}

fn derive_private_keys(
    master_seed: String,
    data: &Event,
    network: bitcoin::Network,
) -> Result<
    (
        bip32::Xpriv,
        bip32::Xpriv,
        bip32::Xpriv,
        bip32::Xpriv,
        Option<bip32::Xpriv>,
        Option<bip32::Xpriv>,
    ),
    FundsRecoveryKitInternalError,
> {
    let seed = hex::decode(master_seed).map_err(|_| {
        FundsRecoveryKitInternalError::from("Could not convert master seed hex to byte array")
    })?;
    let bip = bip32::Xpriv::new_master(network, seed.as_slice()).map_err(|_| {
        FundsRecoveryKitInternalError::from("Could not convert master seed to private key")
    })?;
    let secp = Secp256k1::new();

    let funding_private_key_derivation_path =
        bip32::DerivationPath::from_str(&data.funding_private_key_derivation_path).map_err(
            |_| FundsRecoveryKitInternalError::from("Invalid funding_private_key_derivation_path"),
        )?;
    let delayed_payment_base_key_derivation_path = bip32::DerivationPath::from_str(
        &data.delayed_payment_base_key_derivation_path,
    )
    .map_err(|_| {
        FundsRecoveryKitInternalError::from("Invalid delayed_payment_base_key_derivation_path")
    })?;
    let htlc_base_key_derivation_path =
        bip32::DerivationPath::from_str(&data.htlc_base_key_derivation_path).map_err(|_| {
            FundsRecoveryKitInternalError::from("Invalid htlc_base_key_derivation_path")
        })?;
    let preimage_key_derivation_path = bip32::DerivationPath::from_str("m/4h")
        .map_err(|_| FundsRecoveryKitInternalError::from("Invalid preimage_key_derivation_path"))?;

    let funding_private_key = bip
        .derive_priv(&secp, &funding_private_key_derivation_path)
        .map_err(|_| FundsRecoveryKitInternalError::from("Invalid funding_private_key"))?;
    let mut delayed_payment_private_key = bip
        .derive_priv(&secp, &delayed_payment_base_key_derivation_path)
        .map_err(|_| FundsRecoveryKitInternalError::from("Invalid delayed_payment_private_key"))?;
    let mut htlc_private_key = bip
        .derive_priv(&secp, &htlc_base_key_derivation_path)
        .map_err(|_| FundsRecoveryKitInternalError::from("Invalid htlc_private_key"))?;
    let preimage_private_key = bip
        .derive_priv(&secp, &preimage_key_derivation_path)
        .map_err(|_| FundsRecoveryKitInternalError::from("Invalid preimage_key"))?;

    delayed_payment_private_key.private_key = tweak_key(
        delayed_payment_private_key.private_key,
        hex::decode(data.sweep_tx_add_tweak.clone())
            .map_err(|_| FundsRecoveryKitInternalError::from("Invalid sweep_tx_add_tweak"))?
            .try_into()
            .map_err(|_| FundsRecoveryKitInternalError::from("Invalid sweep_tx_add_tweak"))?,
    )
    .map_err(|_| {
        FundsRecoveryKitInternalError::from("Invalid tweaked_delayed_payment_secret_key")
    })?;

    let mut htlc_private_key_clone = htlc_private_key.clone();
    htlc_private_key.private_key = tweak_key(
        htlc_private_key.private_key,
        hex::decode(data.htlc_tx_add_tweak.clone())
            .map_err(|_| FundsRecoveryKitInternalError::from("Invalid htlc_tx_add_tweak"))?
            .try_into()
            .map_err(|_| FundsRecoveryKitInternalError::from("Invalid htlc_tx_add_tweak"))?,
    )
    .map_err(|_| FundsRecoveryKitInternalError::from("Invalid tweaked_htlc_secret_key"))?;

    let mut counterparty_htlc_private_key = None;
    if let Some(counterparty_htlc_tx_add_tweak) = &data.counterparty_htlc_tx_add_tweak {
        htlc_private_key_clone.private_key = tweak_key(
            htlc_private_key_clone.private_key,
            hex::decode(counterparty_htlc_tx_add_tweak.clone())
                .map_err(|_| {
                    FundsRecoveryKitInternalError::from("Invalid counterparty_htlc_tx_add_tweak")
                })?
                .try_into()
                .map_err(|_| {
                    FundsRecoveryKitInternalError::from("Invalid counterparty_htlc_tx_add_tweak")
                })?,
        )
        .map_err(|_| {
            FundsRecoveryKitInternalError::from("Invalid tweaked_counterparty_htlc_secret_key")
        })?;
        counterparty_htlc_private_key = Some(htlc_private_key_clone);
    }

    let mut payment_private_key = None;
    if let Some(payment_key_derivation_path) = &data.payment_key_derivation_path {
        let payment_key_derivation_path =
            bip32::DerivationPath::from_str(payment_key_derivation_path).map_err(|_| {
                FundsRecoveryKitInternalError::from("Invalid payment_key_derivation_path")
            })?;
        payment_private_key = Some(
            bip.derive_priv(&secp, &payment_key_derivation_path)
                .map_err(|_| FundsRecoveryKitInternalError::from("Invalid payment_private_key"))?,
        );
    }

    Ok((
        funding_private_key,
        delayed_payment_private_key,
        htlc_private_key,
        preimage_private_key,
        payment_private_key,
        counterparty_htlc_private_key,
    ))
}

fn deserialize_transaction(raw_tx: &str) -> Result<Transaction, FundsRecoveryKitInternalError> {
    encode::deserialize(
        &<Vec<u8>>::from_hex(raw_tx).map_err(|_| {
            FundsRecoveryKitInternalError::from("Could not convert raw string to hex")
        })?[..],
    )
    .map_err(|_| FundsRecoveryKitInternalError::from("Could not consensus decode raw transaction"))
}

fn derive_preimage(
    nonce: &str,
    preimage_key: &bip32::Xpriv,
) -> Result<Vec<u8>, FundsRecoveryKitInternalError> {
    // let secret_key_bytes = preimage_key.to_bytes();
    let nonce_bytes = hex::decode(nonce).map_err(|_| {
        FundsRecoveryKitInternalError::from("Could not properly decode nonce value")
    })?;

    let mut hmac_engine: HmacEngine<sha512::Hash> =
        HmacEngine::new(&preimage_key.private_key.secret_bytes());
    hmac_engine.input(b"invoice preimage");
    hmac_engine.input(nonce_bytes.as_slice());
    let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
    Ok(hmac_result[..32].into())
}

fn sign_commitment_transaction(
    transaction: &mut Transaction,
    private_key: &PrivateKey,
    amount: u64,
) -> Result<(), FundsRecoveryKitInternalError> {
    let script = Script::from_bytes(
        transaction
            .input
            .first()
            .ok_or(FundsRecoveryKitInternalError::from(
                "Transaction input does not exist",
            ))?
            .witness
            .nth(3)
            .ok_or(FundsRecoveryKitInternalError::from(
                "Transaction witness does not exist in first input",
            ))?,
    );

    let sighash = sighash::SighashCache::new(transaction.clone())
        .p2wsh_signature_hash(0, script, Amount::from_sat(amount), EcdsaSighashType::All)
        .map_err(|_| {
            FundsRecoveryKitInternalError::from(
                "Could not generate sighash for commitment transaction",
            )
        })?;
    let secp = Secp256k1::new();
    let msg = bitcoin::secp256k1::Message::from_digest_slice(sighash.as_byte_array())
        .map_err(|_| FundsRecoveryKitInternalError::from("Could not convert sighash to message"))?;

    let local_sig = secp.sign_ecdsa_low_r(&msg, &private_key.inner);
    let mut sig = local_sig.serialize_der().to_vec();
    sig.push(EcdsaSighashType::All as u8);
    let mut new_witness = transaction
        .input
        .first()
        .ok_or(FundsRecoveryKitInternalError::from(
            "Transaction input does not exist",
        ))?
        .witness
        .to_vec();
    if new_witness
        .get(1)
        .ok_or(FundsRecoveryKitInternalError::from(
            "First element of witness does not exist",
        ))?
        .is_empty()
    {
        new_witness[1] = sig;
    } else {
        new_witness[2] = sig;
    }
    transaction
        .input
        .get_mut(0)
        .ok_or(FundsRecoveryKitInternalError::from(
            "Transaction input does not exist",
        ))?
        .witness = Witness::from_slice(&new_witness);
    Ok(())
}

fn sign_sweep_transaction(
    transaction: &mut Transaction,
    commitment_transaction: &Transaction,
    private_key: &PrivateKey,
) -> Result<(), FundsRecoveryKitInternalError> {
    let amount =
        commitment_transaction.output[transaction.input[0].previous_output.vout as usize].value;

    let script = Script::from_bytes(
        transaction
            .input
            .first()
            .ok_or(FundsRecoveryKitInternalError::from(
                "Transaction input does not exist",
            ))?
            .witness
            .nth(2)
            .ok_or(FundsRecoveryKitInternalError::from(
                "Transaction witness does not exist in first input",
            ))?,
    );

    let sighash = sighash::SighashCache::new(transaction.clone())
        .p2wsh_signature_hash(0, script, amount, EcdsaSighashType::All)
        .map_err(|_| {
            FundsRecoveryKitInternalError::from("Could not generate sighash for sweep transaction")
        })?;
    let secp = Secp256k1::new();
    let msg = bitcoin::secp256k1::Message::from_digest_slice(sighash.as_byte_array())
        .map_err(|_| FundsRecoveryKitInternalError::from("Could not convert sighash to message"))?;

    let local_sig = secp.sign_ecdsa_low_r(&msg, &private_key.inner);
    let mut sig = local_sig.serialize_der().to_vec();
    sig.push(EcdsaSighashType::All as u8);
    let mut new_witness = transaction
        .input
        .first()
        .ok_or(FundsRecoveryKitInternalError::from(
            "Transaction input does not exist",
        ))?
        .witness
        .to_vec();
    new_witness[0] = sig;
    transaction
        .input
        .get_mut(0)
        .ok_or(FundsRecoveryKitInternalError::from(
            "Transaction input does not exist",
        ))?
        .witness = Witness::from_slice(&new_witness);
    Ok(())
}

fn sign_htlc_transaction(
    transaction: &mut Transaction,
    commitment_transaction: &Transaction,
    private_key: &PrivateKey,
    nonce: &str,
    preimage_key: &bip32::Xpriv,
) -> Result<bool, FundsRecoveryKitInternalError> {
    let amount =
        commitment_transaction.output[transaction.input[0].previous_output.vout as usize].value;
    let script = Script::from_bytes(
        transaction
            .input
            .first()
            .ok_or(FundsRecoveryKitInternalError::from(
                "Transaction input does not exist",
            ))?
            .witness
            .nth(4)
            .ok_or(FundsRecoveryKitInternalError::from(
                "Transaction witness does not exist in first input",
            ))?,
    );
    let mut new_witness = transaction
        .input
        .first()
        .ok_or(FundsRecoveryKitInternalError::from(
            "Transaction input does not exist",
        ))?
        .witness
        .to_vec();
    let sighash = sighash::SighashCache::new(transaction.clone())
        .p2wsh_signature_hash(0, script, amount, EcdsaSighashType::All)
        .map_err(|_| {
            FundsRecoveryKitInternalError::from("Could not generate sighash for htlc transaction")
        })?;
    let secp = Secp256k1::new();
    let msg = bitcoin::secp256k1::Message::from_digest_slice(sighash.as_byte_array())
        .map_err(|_| FundsRecoveryKitInternalError::from("Could not convert sighash to message"))?;

    let local_sig = secp.sign_ecdsa_low_r(&msg, &private_key.inner);
    let mut sig = local_sig.serialize_der().to_vec();
    sig.push(EcdsaSighashType::All as u8);
    new_witness[2] = sig;

    if nonce.is_empty() {
        transaction
            .input
            .get_mut(0)
            .ok_or(FundsRecoveryKitInternalError::from(
                "Transaction input does not exist",
            ))?
            .witness = Witness::from_slice(&new_witness);
        return Ok(true);
    }
    let preimage = derive_preimage(nonce, preimage_key)?;
    new_witness[3] = preimage;
    transaction
        .input
        .get_mut(0)
        .ok_or(FundsRecoveryKitInternalError::from(
            "Transaction input does not exist",
        ))?
        .witness = Witness::from_slice(&new_witness);
    Ok(false)
}

fn sign_htlc_sweep_transaction(
    transaction: &mut Transaction,
    htlc_transaction: &Transaction,
    private_key: &PrivateKey,
) -> Result<(), FundsRecoveryKitInternalError> {
    let amount = htlc_transaction.output[transaction.input[0].previous_output.vout as usize].value;
    let script = Script::from_bytes(
        transaction
            .input
            .first()
            .ok_or(FundsRecoveryKitInternalError::from(
                "Transaction input does not exist",
            ))?
            .witness
            .nth(2)
            .ok_or(FundsRecoveryKitInternalError::from(
                "Transaction witness does not exist in first input",
            ))?,
    );
    let mut new_witness = transaction
        .input
        .first()
        .ok_or(FundsRecoveryKitInternalError::from(
            "Transaction input does not exist",
        ))?
        .witness
        .to_vec();
    let sighash = sighash::SighashCache::new(transaction.clone())
        .p2wsh_signature_hash(0, script, amount, EcdsaSighashType::All)
        .map_err(|_| {
            FundsRecoveryKitInternalError::from("Could not generate sighash for sweep transaction")
        })?;
    let secp = Secp256k1::new();
    let msg = bitcoin::secp256k1::Message::from_digest_slice(sighash.as_byte_array())
        .map_err(|_| FundsRecoveryKitInternalError::from("Could not convert sighash to message"))?;
    let local_sig = secp.sign_ecdsa_low_r(&msg, &private_key.inner);
    let mut sig = local_sig.serialize_der().to_vec();
    sig.push(EcdsaSighashType::All as u8);
    new_witness[0] = sig;
    transaction
        .input
        .get_mut(0)
        .ok_or(FundsRecoveryKitInternalError::from(
            "Transaction input does not exist",
        ))?
        .witness = Witness::from_slice(&new_witness);
    Ok(())
}

fn process_htlc_transactions(
    commitment_transaction: &Transaction,
    htlc_transactions: &[String],
    htlc_sweep_transactions: &[String],
    nonces: &[String],
    preimage_key: &bip32::Xpriv,
    htlc_private_key: &PrivateKey,
    sweep_private_key: &PrivateKey,
) -> Result<
    (
        Vec<(Transaction, Transaction)>,
        Vec<(Transaction, Transaction)>,
    ),
    FundsRecoveryKitInternalError,
> {
    let mut all_htlc_inbound_transactions = Vec::new();
    let mut all_htlc_outbound_transactions = Vec::new();

    for i in 0..htlc_transactions.len() {
        let mut htlc_transaction = deserialize_transaction(&htlc_transactions[i])?;
        let mut htlc_sweep_transaction = deserialize_transaction(&htlc_sweep_transactions[i])?;

        let is_outbound = sign_htlc_transaction(
            &mut htlc_transaction,
            commitment_transaction,
            htlc_private_key,
            &nonces[i],
            preimage_key,
        )?;

        sign_htlc_sweep_transaction(
            &mut htlc_sweep_transaction,
            &htlc_transaction,
            sweep_private_key,
        )?;

        if is_outbound {
            all_htlc_outbound_transactions.push((htlc_transaction, htlc_sweep_transaction));
        } else {
            all_htlc_inbound_transactions.push((htlc_transaction, htlc_sweep_transaction));
        }
    }

    Ok((
        all_htlc_inbound_transactions,
        all_htlc_outbound_transactions,
    ))
}

fn sign_counterparty_sweep_transaction(
    transaction: &mut Transaction,
    commitment_transaction: &Transaction,
    private_key: &PrivateKey,
    network: bitcoin::Network,
) -> Result<(), FundsRecoveryKitInternalError> {
    let amount =
        commitment_transaction.output[transaction.input[0].previous_output.vout as usize].value;
    let mut new_witness = transaction
        .input
        .first()
        .ok_or(FundsRecoveryKitInternalError::from(
            "Transaction input does not exist",
        ))?
        .witness
        .to_vec();
    let pubkey = CompressedPublicKey::from_slice(new_witness[1].as_slice()).map_err(|_| {
        FundsRecoveryKitInternalError::from("Could not generate pubkey from witness")
    })?;
    let script = bitcoin::Address::p2wpkh(&pubkey, network).script_pubkey();
    let sighash = sighash::SighashCache::new(transaction.clone())
        .p2wpkh_signature_hash(0, &script, amount, EcdsaSighashType::All)
        .map_err(|e| FundsRecoveryKitInternalError::from(e.to_string().as_str()))?;
    let secp = Secp256k1::new();
    let msg = bitcoin::secp256k1::Message::from_digest_slice(sighash.as_byte_array())
        .map_err(|_| FundsRecoveryKitInternalError::from("Could not convert sighash to message"))?;
    let local_sig = secp.sign_ecdsa_low_r(&msg, &private_key.inner);
    let mut sig = local_sig.serialize_der().to_vec();
    sig.push(EcdsaSighashType::All as u8);
    new_witness[0] = sig;
    transaction
        .input
        .get_mut(0)
        .ok_or(FundsRecoveryKitInternalError::from(
            "Transaction input does not exist",
        ))?
        .witness = Witness::from_slice(&new_witness);
    Ok(())
}

fn sign_counterparty_htlc_transaction(
    transaction: &mut Transaction,
    commitment_transaction: &Transaction,
    private_key: &PrivateKey,
    nonce: &str,
    preimage_key: &bip32::Xpriv,
) -> Result<bool, FundsRecoveryKitInternalError> {
    let amount =
        commitment_transaction.output[transaction.input[0].previous_output.vout as usize].value;
    let script = Script::from_bytes(
        transaction
            .input
            .first()
            .ok_or(FundsRecoveryKitInternalError::from(
                "Transaction input does not exist",
            ))?
            .witness
            .nth(2)
            .ok_or(FundsRecoveryKitInternalError::from(
                "Transaction witness does not exist in first input",
            ))?,
    );
    let mut new_witness = transaction
        .input
        .first()
        .ok_or(FundsRecoveryKitInternalError::from(
            "Transaction input does not exist",
        ))?
        .witness
        .to_vec();
    let sighash = sighash::SighashCache::new(transaction.clone())
        .p2wsh_signature_hash(0, script, amount, EcdsaSighashType::All)
        .map_err(|_| {
            FundsRecoveryKitInternalError::from(
                "Could not generate sighash for counterparty htlc transaction",
            )
        })?;
    let secp = Secp256k1::new();
    let msg = bitcoin::secp256k1::Message::from_digest_slice(sighash.as_byte_array())
        .map_err(|_| FundsRecoveryKitInternalError::from("Could not convert sighash to message"))?;

    let local_sig = secp.sign_ecdsa_low_r(&msg, &private_key.inner);
    let mut sig = local_sig.serialize_der().to_vec();
    sig.push(EcdsaSighashType::All as u8);
    new_witness[0] = sig;
    if nonce.is_empty() {
        transaction
            .input
            .get_mut(0)
            .ok_or(FundsRecoveryKitInternalError::from(
                "Transaction input does not exist",
            ))?
            .witness = Witness::from_slice(&new_witness);
        return Ok(false);
    }
    let preimage = derive_preimage(nonce, preimage_key)?;
    new_witness[1] = preimage;
    transaction
        .input
        .get_mut(0)
        .ok_or(FundsRecoveryKitInternalError::from(
            "Transaction input does not exist",
        ))?
        .witness = Witness::from_slice(&new_witness);
    Ok(true)
}

fn process_counterparty_htlc_transactions(
    commitment_transaction: &Transaction,
    htlc_sweep_transactions: &[String],
    nonces: &[String],
    preimage_key: &bip32::Xpriv,
    htlc_private_key: &PrivateKey,
) -> Result<(Vec<Transaction>, Vec<Transaction>), FundsRecoveryKitInternalError> {
    let mut all_htlc_inbound_transactions = Vec::new();
    let mut all_htlc_outbound_transactions = Vec::new();

    for i in 0..htlc_sweep_transactions.len() {
        let mut htlc_sweep_transaction = deserialize_transaction(&htlc_sweep_transactions[i])?;

        let is_outbound = sign_counterparty_htlc_transaction(
            &mut htlc_sweep_transaction,
            commitment_transaction,
            htlc_private_key,
            &nonces[i],
            preimage_key,
        )?;

        if is_outbound {
            all_htlc_outbound_transactions.push(htlc_sweep_transaction);
        } else {
            all_htlc_inbound_transactions.push(htlc_sweep_transaction);
        }
    }

    Ok((
        all_htlc_inbound_transactions,
        all_htlc_outbound_transactions,
    ))
}

fn sign_transactions_impl(
    master_seed: String,
    data: String,
    network: bitcoin::Network,
) -> Result<Response, FundsRecoveryKitInternalError> {
    let parsed_data = serde_json::from_str::<Event>(&data)
        .map_err(|e| FundsRecoveryKitInternalError::from(e.to_string().as_str()))?;
    let mut commitment_transaction = deserialize_transaction(&parsed_data.commitment_tx)?;
    let (
        funding_private_key,
        delayed_payment_private_key,
        htlc_private_key,
        preimage_key,
        payment_key,
        counterparty_htlc_private_key,
    ) = derive_private_keys(master_seed, &parsed_data, network)?;
    sign_commitment_transaction(
        &mut commitment_transaction,
        &funding_private_key.to_priv(),
        parsed_data.channel_capacity,
    )?;
    let mut sweep_transaction = deserialize_transaction(&parsed_data.sweep_tx)?;
    sign_sweep_transaction(
        &mut sweep_transaction,
        &commitment_transaction,
        &delayed_payment_private_key.to_priv(),
    )?;
    let (all_htlc_inbound_transactions, all_htlc_outbound_transactions) =
        process_htlc_transactions(
            &commitment_transaction,
            &parsed_data.htlc_tx,
            &parsed_data.serialized_htlc_sweep_tx,
            &parsed_data.nonces,
            &preimage_key,
            &htlc_private_key.to_priv(),
            &delayed_payment_private_key.to_priv(),
        )?;
    let mut counterparty_sweep_transaction = None;
    let mut all_counterparty_htlc_inbound_transactions = vec![];
    let mut all_counterparty_htlc_outbound_transactions = vec![];
    if let (
        Some(counterparty_serialized_commitment_tx),
        Some(counterparty_sweep_tx),
        Some(payment_key),
        Some(counterparty_htlc_private_key),
    ) = (
        &parsed_data.counterparty_serialized_commitment_tx,
        &parsed_data.counterparty_sweep_tx,
        payment_key,
        counterparty_htlc_private_key,
    ) {
        let counterparty_commitment_transaction =
            deserialize_transaction(counterparty_serialized_commitment_tx)?;
        let mut counterparty_sweep_tx = deserialize_transaction(counterparty_sweep_tx)?;
        sign_counterparty_sweep_transaction(
            &mut counterparty_sweep_tx,
            &counterparty_commitment_transaction,
            &payment_key.to_priv(),
            network,
        )?;
        counterparty_sweep_transaction = Some(counterparty_sweep_tx);

        if let (Some(counterparty_serialized_htlc_sweep_tx), Some(counterparty_nonces)) = (
            &parsed_data.counterparty_serialized_htlc_sweep_tx,
            &parsed_data.counterparty_nonces,
        ) {
            (
                all_counterparty_htlc_inbound_transactions,
                all_counterparty_htlc_outbound_transactions,
            ) = process_counterparty_htlc_transactions(
                &counterparty_commitment_transaction,
                counterparty_serialized_htlc_sweep_tx,
                counterparty_nonces,
                &preimage_key,
                &counterparty_htlc_private_key.to_priv(),
            )?;
        }
    }
    let counterparty_sweep_tx = if let Some(sweep_tx) = counterparty_sweep_transaction {
        hex::encode(encode::serialize(&sweep_tx))
    } else {
        "".into()
    };
    Ok(Response {
        commitment_tx: hex::encode(encode::serialize(&commitment_transaction)),
        sweep_tx: hex::encode(encode::serialize(&sweep_transaction)),
        htlc_inbound_tx: all_htlc_inbound_transactions
            .iter()
            .map(|(tx, sweep_tx)| StringTuple {
                first: hex::encode(encode::serialize(&tx)),
                second: hex::encode(encode::serialize(&sweep_tx)),
            })
            .collect(),
        htlc_outbound_tx: all_htlc_outbound_transactions
            .iter()
            .map(|(tx, sweep_tx)| StringTuple {
                first: hex::encode(encode::serialize(&tx)),
                second: hex::encode(encode::serialize(&sweep_tx)),
            })
            .collect(),
        counterparty_sweep_tx,
        counterparty_htlc_inbound_tx: all_counterparty_htlc_inbound_transactions
            .iter()
            .map(|tx| hex::encode(encode::serialize(&tx)))
            .collect(),
        counterparty_htlc_outbound_tx: all_counterparty_htlc_outbound_transactions
            .iter()
            .map(|tx| hex::encode(encode::serialize(&tx)))
            .collect(),
    })
}

pub fn sign_transactions(
    master_seed: String,
    data: String,
    network: signer::Network,
) -> Result<Response, FundsRecoveryKitError> {
    let network = match network {
        signer::Network::Bitcoin => bitcoin::Network::Bitcoin,
        signer::Network::Testnet => bitcoin::Network::Testnet,
        signer::Network::Regtest => bitcoin::Network::Regtest,
        signer::Network::Signet => bitcoin::Network::Signet,
    };
    // For now, do not expose implementation errors as the kit should just be serialized and sent. If this fails we will have to look into it further.
    sign_transactions_impl(master_seed, data, network).map_err(|_| FundsRecoveryKitError::Error { message: "Generating the funds recovery kit failed. The kit should only be serialized and sent without modification.".to_string() })
}

// The motivation for these tests will be to match existing ripcord functionality rather than to reprove everything works. They are just unit tests comparing to the python script values as we know that works.
// For all of the tests, we cannot straight copy serialized transactions because different libraries use different nonces for their signatures. Instead we verify the signature against what we know the pubkey will be.
// We will do the same verification tests for both the response in the rust library, and our python responses. The theory is if both pass the same tests, then both ways can be used effectively, and we are proving this code works.
#[cfg(test)]
mod tests {
    use super::*;

    fn verify_signature(tx: &str, index: usize, pubkey_str: &str, msg_str: &str) -> bool {
        let transaction = deserialize_transaction(tx).unwrap();
        let local_sig_slice = transaction
            .input
            .first()
            .unwrap()
            .witness
            .nth(index)
            .ok_or(FundsRecoveryKitInternalError::from(
                "Transaction witness does not exist in first input",
            ))
            .unwrap();
        let local_sig = bitcoin::secp256k1::ecdsa::Signature::from_der(
            &local_sig_slice[..local_sig_slice.len() - 1],
        )
        .unwrap();
        let msg =
            bitcoin::secp256k1::Message::from_digest_slice(&hex::decode(msg_str).unwrap()).unwrap();
        let secp = Secp256k1::new();
        let pubkey = bitcoin::secp256k1::PublicKey::from_str(pubkey_str).unwrap();
        secp.verify_ecdsa(&msg, &local_sig, &pubkey).is_ok()
    }

    #[test]
    fn test_funds_recovery_kit_basic() {
        let data = r#"{"commitment_tx": "0200000000010187748372b3dfb3d47c2bb0a02848a327c77f5c982d036626c6de0a958af56069000000000025cee5800236ad03000000000016001415f586897037ded59858ccb1d24d4fbe7602692e90d00300000000002200204a30a8d4aba2d9d2e245052fc3566e1e18c49c1f364351481bfdd3e4d3a60da00400473044022066dbda605a766bc8143e15825c878b3b9444637b04678da42fe8f0c317c41fc70220482bb1a741497b14650c1e07ec4a00803855ff0f6a1434c88ae068f51567e94201004752210315496a93245ab6a7373b4e7297a30e2a20feefc50c59484dce93b6685e3ec0302103e65fcacf66816c0cb7d85726944463efe1466184a01d99949aed8a8b0676009a52aee1158720", "sweep_tx": "020000000001016d0d0c47799e62541fc4bb51461b4bed8a5ed978ebe4f52d4c168a5b950d6f5401000000009000000001fbb80300000000001600146b0009af85b18052eb83afbdc9c45521c552588f0300004d632102a299258a6ac6b9be6b7ee879a87aca8a30e05d15e915b7af722f09d44c5014a867029000b2752103c74ec665bd1547f4a3dccee02c104677c7e880c6b0bdaec0cea195680d3cb62768ac00000000", "htlc_tx": [], "serialized_htlc_sweep_tx": [], "channel_point": "6960f58a950adec62666032d985c7fc727a34828a0b02b7cd4b3dfb372837487:0", "sweep_tx_add_tweak": "201d490866cdcc50199497d98b699f4ae367b23e801ffe405f3f983deef42f56", "htlc_tx_add_tweak": "146d304968ba398899c7147fb641a6e20d4134b2c78abf4a2eb67e094fd730c1", "funding_private_key_derivation_path": "m/3/599143572/0", "delayed_payment_base_key_derivation_path": "m/3/599143572/3", "htlc_base_key_derivation_path": "m/3/599143572/4", "channel_capacity": 500000, "nonces": [], "commitment_number": 1}"#;
        let master_seed = "f520e5271623fe21c76b0212f855c97a";
        let resp = sign_transactions(master_seed.into(), data.into(), signer::Network::Regtest)
            .expect("Data should be valid");

        // commitment transaction rust
        assert!(verify_signature(
            &resp.commitment_tx,
            1,
            "0315496a93245ab6a7373b4e7297a30e2a20feefc50c59484dce93b6685e3ec030",
            "5c005fea1ea4eea091f10e540c4877cf3223f132fb1b1c75fb14c0823b16cb6f",
        ));
        assert!(verify_signature(
            &resp.commitment_tx,
            2,
            "03e65fcacf66816c0cb7d85726944463efe1466184a01d99949aed8a8b0676009a",
            "5c005fea1ea4eea091f10e540c4877cf3223f132fb1b1c75fb14c0823b16cb6f",
        ));
        // commitment transaction python
        assert!(verify_signature(
            "0200000000010187748372b3dfb3d47c2bb0a02848a327c77f5c982d036626c6de0a958af56069000000000025cee5800236ad03000000000016001415f586897037ded59858ccb1d24d4fbe7602692e90d00300000000002200204a30a8d4aba2d9d2e245052fc3566e1e18c49c1f364351481bfdd3e4d3a60da00400473044022066dbda605a766bc8143e15825c878b3b9444637b04678da42fe8f0c317c41fc70220482bb1a741497b14650c1e07ec4a00803855ff0f6a1434c88ae068f51567e9420147304402205c39cf14c76c1b26518f8f6106d0529e4f8a68661ddedaa1bc81e4a08ba9c95e022043968887f78d52666a49e2805ba7e84fbfa1ad45c1b7eea39a1468961b5fa887014752210315496a93245ab6a7373b4e7297a30e2a20feefc50c59484dce93b6685e3ec0302103e65fcacf66816c0cb7d85726944463efe1466184a01d99949aed8a8b0676009a52aee1158720",
            1,
            "0315496a93245ab6a7373b4e7297a30e2a20feefc50c59484dce93b6685e3ec030",
            "5c005fea1ea4eea091f10e540c4877cf3223f132fb1b1c75fb14c0823b16cb6f",
        ));
        assert!(verify_signature(
            "0200000000010187748372b3dfb3d47c2bb0a02848a327c77f5c982d036626c6de0a958af56069000000000025cee5800236ad03000000000016001415f586897037ded59858ccb1d24d4fbe7602692e90d00300000000002200204a30a8d4aba2d9d2e245052fc3566e1e18c49c1f364351481bfdd3e4d3a60da00400473044022066dbda605a766bc8143e15825c878b3b9444637b04678da42fe8f0c317c41fc70220482bb1a741497b14650c1e07ec4a00803855ff0f6a1434c88ae068f51567e9420147304402205c39cf14c76c1b26518f8f6106d0529e4f8a68661ddedaa1bc81e4a08ba9c95e022043968887f78d52666a49e2805ba7e84fbfa1ad45c1b7eea39a1468961b5fa887014752210315496a93245ab6a7373b4e7297a30e2a20feefc50c59484dce93b6685e3ec0302103e65fcacf66816c0cb7d85726944463efe1466184a01d99949aed8a8b0676009a52aee1158720",
            2,
            "03e65fcacf66816c0cb7d85726944463efe1466184a01d99949aed8a8b0676009a",
            "5c005fea1ea4eea091f10e540c4877cf3223f132fb1b1c75fb14c0823b16cb6f",
        ));

        // sweep transaction rust
        assert!(verify_signature(
            &resp.sweep_tx,
            0,
            "03c74ec665bd1547f4a3dccee02c104677c7e880c6b0bdaec0cea195680d3cb627",
            "8764e497948977b7cd806e652ab7f83c1fb03a4a83e57b208ca6df7af009d471",
        ));
        // sweep transaction python
        assert!(verify_signature(
            "020000000001016d0d0c47799e62541fc4bb51461b4bed8a5ed978ebe4f52d4c168a5b950d6f5401000000009000000001fbb80300000000001600146b0009af85b18052eb83afbdc9c45521c552588f034730440220206ce06d2b56b7fecc82949efdcde2c673fb0e9a11c93b40a36b476f1a0e4d6502200317f278d8f3d1cbb358c30fb50e870dbac1a7be18b2d8aec961be91320f595001004d632102a299258a6ac6b9be6b7ee879a87aca8a30e05d15e915b7af722f09d44c5014a867029000b2752103c74ec665bd1547f4a3dccee02c104677c7e880c6b0bdaec0cea195680d3cb62768ac00000000",
            0,
            "03c74ec665bd1547f4a3dccee02c104677c7e880c6b0bdaec0cea195680d3cb627",
            "8764e497948977b7cd806e652ab7f83c1fb03a4a83e57b208ca6df7af009d471",
        ));
    }

    #[test]
    fn test_funds_recovery_kit_with_counterparty_transactions() {
        let data = r#"{"counterparty_sweep_tx": "020000000001013473c2a4e6c07675f5344f356a94d6e681ea7d98c848f5454de91230e5a82528010000000000000000012dbb0300000000001600146b0009af85b18052eb83afbdc9c45521c552588f0200210371796599c83e9fce1de1877047604d7a6e0b1ca672da7b5290f941b2f2806c5000000000", "counterparty_serialized_htlc_sweep_tx": [], "counterparty_htlc_tx_add_tweak": "cef67a943db83ff419a914492808640ae8894bd87f56efbb4ffa768627086ce0", "counterparty_nonces": [], "payment_key_derivation_path": "m/3/599143572/2", "counterparty_serialized_commitment_tx": "020000000187748372b3dfb3d47c2bb0a02848a327c77f5c982d036626c6de0a958af56069000000000025cee5800236ad030000000000220020c3f5a2a4985affb278fabe1efca88b967f361492c8e2bb178d1acbd90d9fb8dc90d0030000000000160014e7c08ed2ca1a6aad8864f6d3159f8ac9583622ece1158720", "commitment_tx": "0200000000010187748372b3dfb3d47c2bb0a02848a327c77f5c982d036626c6de0a958af56069000000000025cee5800236ad03000000000016001415f586897037ded59858ccb1d24d4fbe7602692e90d00300000000002200204a30a8d4aba2d9d2e245052fc3566e1e18c49c1f364351481bfdd3e4d3a60da00400473044022066dbda605a766bc8143e15825c878b3b9444637b04678da42fe8f0c317c41fc70220482bb1a741497b14650c1e07ec4a00803855ff0f6a1434c88ae068f51567e94201004752210315496a93245ab6a7373b4e7297a30e2a20feefc50c59484dce93b6685e3ec0302103e65fcacf66816c0cb7d85726944463efe1466184a01d99949aed8a8b0676009a52aee1158720", "sweep_tx": "020000000001016d0d0c47799e62541fc4bb51461b4bed8a5ed978ebe4f52d4c168a5b950d6f5401000000009000000001fbb80300000000001600146b0009af85b18052eb83afbdc9c45521c552588f0300004d632102a299258a6ac6b9be6b7ee879a87aca8a30e05d15e915b7af722f09d44c5014a867029000b2752103c74ec665bd1547f4a3dccee02c104677c7e880c6b0bdaec0cea195680d3cb62768ac00000000", "htlc_tx": [], "serialized_htlc_sweep_tx": [], "channel_point": "6960f58a950adec62666032d985c7fc727a34828a0b02b7cd4b3dfb372837487:0", "sweep_tx_add_tweak": "201d490866cdcc50199497d98b699f4ae367b23e801ffe405f3f983deef42f56", "htlc_tx_add_tweak": "146d304968ba398899c7147fb641a6e20d4134b2c78abf4a2eb67e094fd730c1", "funding_private_key_derivation_path": "m/3/599143572/0", "delayed_payment_base_key_derivation_path": "m/3/599143572/3", "htlc_base_key_derivation_path": "m/3/599143572/4", "channel_capacity": 500000, "nonces": [], "commitment_number": 1}"#;
        let master_seed = "f520e5271623fe21c76b0212f855c97a";
        let resp = sign_transactions(master_seed.into(), data.into(), signer::Network::Regtest)
            .expect("Data should be valid");

        // commitment transaction rust
        assert!(verify_signature(
            &resp.commitment_tx,
            1,
            "0315496a93245ab6a7373b4e7297a30e2a20feefc50c59484dce93b6685e3ec030",
            "5c005fea1ea4eea091f10e540c4877cf3223f132fb1b1c75fb14c0823b16cb6f",
        ));
        assert!(verify_signature(
            &resp.commitment_tx,
            2,
            "03e65fcacf66816c0cb7d85726944463efe1466184a01d99949aed8a8b0676009a",
            "5c005fea1ea4eea091f10e540c4877cf3223f132fb1b1c75fb14c0823b16cb6f",
        ));
        // commitment transaction python
        assert!(verify_signature(
            "0200000000010187748372b3dfb3d47c2bb0a02848a327c77f5c982d036626c6de0a958af56069000000000025cee5800236ad03000000000016001415f586897037ded59858ccb1d24d4fbe7602692e90d00300000000002200204a30a8d4aba2d9d2e245052fc3566e1e18c49c1f364351481bfdd3e4d3a60da00400473044022066dbda605a766bc8143e15825c878b3b9444637b04678da42fe8f0c317c41fc70220482bb1a741497b14650c1e07ec4a00803855ff0f6a1434c88ae068f51567e9420147304402205c39cf14c76c1b26518f8f6106d0529e4f8a68661ddedaa1bc81e4a08ba9c95e022043968887f78d52666a49e2805ba7e84fbfa1ad45c1b7eea39a1468961b5fa887014752210315496a93245ab6a7373b4e7297a30e2a20feefc50c59484dce93b6685e3ec0302103e65fcacf66816c0cb7d85726944463efe1466184a01d99949aed8a8b0676009a52aee1158720",
            1,
            "0315496a93245ab6a7373b4e7297a30e2a20feefc50c59484dce93b6685e3ec030",
            "5c005fea1ea4eea091f10e540c4877cf3223f132fb1b1c75fb14c0823b16cb6f",
        ));
        assert!(verify_signature(
            "0200000000010187748372b3dfb3d47c2bb0a02848a327c77f5c982d036626c6de0a958af56069000000000025cee5800236ad03000000000016001415f586897037ded59858ccb1d24d4fbe7602692e90d00300000000002200204a30a8d4aba2d9d2e245052fc3566e1e18c49c1f364351481bfdd3e4d3a60da00400473044022066dbda605a766bc8143e15825c878b3b9444637b04678da42fe8f0c317c41fc70220482bb1a741497b14650c1e07ec4a00803855ff0f6a1434c88ae068f51567e9420147304402205c39cf14c76c1b26518f8f6106d0529e4f8a68661ddedaa1bc81e4a08ba9c95e022043968887f78d52666a49e2805ba7e84fbfa1ad45c1b7eea39a1468961b5fa887014752210315496a93245ab6a7373b4e7297a30e2a20feefc50c59484dce93b6685e3ec0302103e65fcacf66816c0cb7d85726944463efe1466184a01d99949aed8a8b0676009a52aee1158720",
            2,
            "03e65fcacf66816c0cb7d85726944463efe1466184a01d99949aed8a8b0676009a",
            "5c005fea1ea4eea091f10e540c4877cf3223f132fb1b1c75fb14c0823b16cb6f",
        ));

        // sweep transaction rust
        assert!(verify_signature(
            &resp.sweep_tx,
            0,
            "03c74ec665bd1547f4a3dccee02c104677c7e880c6b0bdaec0cea195680d3cb627",
            "8764e497948977b7cd806e652ab7f83c1fb03a4a83e57b208ca6df7af009d471",
        ));
        // sweep transaction python
        assert!(verify_signature(
            "020000000001016d0d0c47799e62541fc4bb51461b4bed8a5ed978ebe4f52d4c168a5b950d6f5401000000009000000001fbb80300000000001600146b0009af85b18052eb83afbdc9c45521c552588f034730440220206ce06d2b56b7fecc82949efdcde2c673fb0e9a11c93b40a36b476f1a0e4d6502200317f278d8f3d1cbb358c30fb50e870dbac1a7be18b2d8aec961be91320f595001004d632102a299258a6ac6b9be6b7ee879a87aca8a30e05d15e915b7af722f09d44c5014a867029000b2752103c74ec665bd1547f4a3dccee02c104677c7e880c6b0bdaec0cea195680d3cb62768ac00000000",
            0,
            "03c74ec665bd1547f4a3dccee02c104677c7e880c6b0bdaec0cea195680d3cb627",
            "8764e497948977b7cd806e652ab7f83c1fb03a4a83e57b208ca6df7af009d471",
        ));

        // counterparty sweep transaction rust
        assert!(verify_signature(
            &resp.counterparty_sweep_tx,
            0,
            "0371796599c83e9fce1de1877047604d7a6e0b1ca672da7b5290f941b2f2806c50",
            "f629079e2da977e598c3587722ea0b20df83fffb921a38765ce96fd755b6a14e",
        ));
        // counterparty sweep transaction python
        assert!(verify_signature(
            "020000000001013473c2a4e6c07675f5344f356a94d6e681ea7d98c848f5454de91230e5a82528010000000000000000012dbb0300000000001600146b0009af85b18052eb83afbdc9c45521c552588f02473044022041c66287ff451d441661b06bd5096129b088e6ce1f5524855c71bb801531915e02201c6fafde655d99683e6dbdeb31a2037de9864c3eccf9b44b4f1e75fa7c94ba7a01210371796599c83e9fce1de1877047604d7a6e0b1ca672da7b5290f941b2f2806c5000000000",
            0,
            "0371796599c83e9fce1de1877047604d7a6e0b1ca672da7b5290f941b2f2806c50",
            "f629079e2da977e598c3587722ea0b20df83fffb921a38765ce96fd755b6a14e",
        ));
    }

    #[test]
    fn test_funds_recovery_kit_with_inbound_htlcs_and_counterparty_outbound_htlcs() {
        let data = r#"{"commitment_tx": "0200000000010105186fe9040861e40860b2e140ff855c7fe83ee1d6820b551d5f3a645590c6d500000000000781c4800350c30000000000002200205819a33452804c9642b389697cedac5f8084d120a103fcdbade9bcceeca02b33301e020000000000160014242e85ae29b8f41d28c7357e6c2efb199cb0fb53e0930400000000002200209590a2001663edd66090460d1f471f9081d152fb9244e71c633463a44c3d3f0d040000483045022100c70ef515822f5c608ec5f656ee9f57f9f964940ee4a524d7b1b3430968e9281f02201910da8a02b7a00723476062fc0b903840850f79325b960c4e4cb9459b015ae301475221020e3b6f63b9f41093fe681ef8f0b40e55ad36499ff5c67c4d28d1d4085f7eb2f121023f693b74c445a2e1e6883579a8aacd1f025e3a146724579a3245da7454fb7cb952aeb014c720", "sweep_tx": "020000000001019297117bf9307b382fe3b828549ff5437fcaa3b26abbcf4601072b2902649dc7020000000090000000014b7c0400000000001600146b0009af85b18052eb83afbdc9c45521c552588f0300004d632103d097f8bde004f9be3166bb61fda07209cfece8af19fd1ca1154ecb74f4e98ffb67029000b275210313c27137b6458fef62f6f8d45145b1d2788381a990607e552013e2555fd8187568ac00000000", "htlc_tx": ["020000000001019297117bf9307b382fe3b828549ff5437fcaa3b26abbcf4601072b2902649dc700000000000000000001fda00000000000002200209590a2001663edd66090460d1f471f9081d152fb9244e71c633463a44c3d3f0d050047304402204467dc7ad1abaf9d00c93255ad0ec2b8293be4d0b9597128d3675f15e1abd25002204fffe0f61d88b882d048132e5eabafe0cd034d73fd257a173f36b0585608beec0100008b76a91467aa35a4cbee56bd2ab29fcdf75d720eb8a02b118763ac67210313932240cb488f8f6dffb5c43bd7e605078212a14439f4bac355cef32522a3257c8201208763a91490b2bd87c689ec31aed86574402095554b19412c88527c21033bd5d1f4d8277b6400e0e32ae8c3b28d7566908bc24420940b32dbf00d6c25b552ae677503ae9300b175ac686800000000"], "serialized_htlc_sweep_tx": ["020000000001012b7ac5288c38f024fc9683f64041f037671b4b552c81fd7e6e01ee46ad185e6b0000000000900000000168890000000000001600146b0009af85b18052eb83afbdc9c45521c552588f0300004d632103d097f8bde004f9be3166bb61fda07209cfece8af19fd1ca1154ecb74f4e98ffb67029000b275210313c27137b6458fef62f6f8d45145b1d2788381a990607e552013e2555fd8187568ac00000000"], "channel_point": "d5c69055643a5f1d550b82d6e13ee87f5c85ff40e1b26008e4610804e96f1805:0", "sweep_tx_add_tweak": "9cd9a5516e1f783e08a92f926a553c04d60b1b28d7c26336105fd2c2a8899d5b", "htlc_tx_add_tweak": "ca0a7f958fd3221def8983eff8f8cd1f0e51b227f1a10bdafbefbb45491cc0cb", "funding_private_key_derivation_path": "m/3/637642393/0", "delayed_payment_base_key_derivation_path": "m/3/637642393/3", "htlc_base_key_derivation_path": "m/3/637642393/4", "channel_capacity": 500000, "nonces": ["18541fe85c5126003c0dedb79e24987a3b36195c13d33ecb77f0728c2f841734"], "counterparty_sweep_tx": "02000000000101a8e7d890e135f4a5066e351b3035c0b11056107967b6e8220a24dbe2cebbe22f020000000000000000017d7e0400000000001600146b0009af85b18052eb83afbdc9c45521c552588f0200210211497bff8343b0566a3bf78d5bf0967a88aa039e9d30a5f9f1eeed38a38e20b800000000", "counterparty_serialized_htlc_sweep_tx": ["02000000000101a8e7d890e135f4a5066e351b3035c0b11056107967b6e8220a24dbe2cebbe22f00000000000000000001f1a20000000000001600146b0009af85b18052eb83afbdc9c45521c552588f0300008576a914c5a930dfd00a9165e9dbbee31326fb8a5d09612f8763ac67210363f80146fd3bdbe88e49a5b5f5a384e873e7423a8a4fb22a912893883795b7d37c820120876475527c2102e59e26ede9c3dd9dd6fa7dbce42467a53b04b86aa7c92fa385c7f9ffcd1bfe5f52ae67a91490b2bd87c689ec31aed86574402095554b19412c88ac686800000000"], "counterparty_htlc_tx_add_tweak": "87c4204be8bc682709f678a8fa4dfc2d672f4d1946ba436a40c6ef4564de97f9", "counterparty_nonces": ["18541fe85c5126003c0dedb79e24987a3b36195c13d33ecb77f0728c2f841734"], "payment_key_derivation_path": "m/3/637642393/2", "counterparty_serialized_commitment_tx": "020000000105186fe9040861e40860b2e140ff855c7fe83ee1d6820b551d5f3a645590c6d500000000000781c4800350c300000000000022002021b1ae8dd7084d0302c4c0b798474e4b1805b98f0fa9d6a17e5da323ba1041c6301e0200000000002200203e7452e0d1c5f0327609a046c1dcc0adfdb5bbd8e13095517c928e6b5ff31378e0930400000000001600146910c10e307c206562bf88ac9dea93d472f90f5ab014c720", "commitment_number": 1}"#;
        let master_seed = "f520e5271623fe21c76b0212f855c97a";
        let resp = sign_transactions(master_seed.into(), data.into(), signer::Network::Regtest)
            .expect("Data should be valid");

        // commitment transaction rust
        assert!(verify_signature(
            &resp.commitment_tx,
            1,
            "020e3b6f63b9f41093fe681ef8f0b40e55ad36499ff5c67c4d28d1d4085f7eb2f1",
            "8cd328fe22d296af5e8926addc9f1bb8a1cce077933b3a95c268c1d79f13f1d8",
        ));
        assert!(verify_signature(
            &resp.commitment_tx,
            2,
            "023f693b74c445a2e1e6883579a8aacd1f025e3a146724579a3245da7454fb7cb9",
            "8cd328fe22d296af5e8926addc9f1bb8a1cce077933b3a95c268c1d79f13f1d8",
        ));
        // commitment transaction python
        assert!(verify_signature(
            "0200000000010105186fe9040861e40860b2e140ff855c7fe83ee1d6820b551d5f3a645590c6d500000000000781c4800350c30000000000002200205819a33452804c9642b389697cedac5f8084d120a103fcdbade9bcceeca02b33301e020000000000160014242e85ae29b8f41d28c7357e6c2efb199cb0fb53e0930400000000002200209590a2001663edd66090460d1f471f9081d152fb9244e71c633463a44c3d3f0d040047304402206a37ccb4dd0163db4b2e4aaa02edad600c4e601aab7a738abe3b874cfea2463202207ebf48599d2e0ffb75e7cae8db04405230bc4d9378020d183bf9d3196f9544da01483045022100c70ef515822f5c608ec5f656ee9f57f9f964940ee4a524d7b1b3430968e9281f02201910da8a02b7a00723476062fc0b903840850f79325b960c4e4cb9459b015ae301475221020e3b6f63b9f41093fe681ef8f0b40e55ad36499ff5c67c4d28d1d4085f7eb2f121023f693b74c445a2e1e6883579a8aacd1f025e3a146724579a3245da7454fb7cb952aeb014c720",
            1,
            "020e3b6f63b9f41093fe681ef8f0b40e55ad36499ff5c67c4d28d1d4085f7eb2f1",
            "8cd328fe22d296af5e8926addc9f1bb8a1cce077933b3a95c268c1d79f13f1d8",
        ));
        assert!(verify_signature(
            "0200000000010105186fe9040861e40860b2e140ff855c7fe83ee1d6820b551d5f3a645590c6d500000000000781c4800350c30000000000002200205819a33452804c9642b389697cedac5f8084d120a103fcdbade9bcceeca02b33301e020000000000160014242e85ae29b8f41d28c7357e6c2efb199cb0fb53e0930400000000002200209590a2001663edd66090460d1f471f9081d152fb9244e71c633463a44c3d3f0d040047304402206a37ccb4dd0163db4b2e4aaa02edad600c4e601aab7a738abe3b874cfea2463202207ebf48599d2e0ffb75e7cae8db04405230bc4d9378020d183bf9d3196f9544da01483045022100c70ef515822f5c608ec5f656ee9f57f9f964940ee4a524d7b1b3430968e9281f02201910da8a02b7a00723476062fc0b903840850f79325b960c4e4cb9459b015ae301475221020e3b6f63b9f41093fe681ef8f0b40e55ad36499ff5c67c4d28d1d4085f7eb2f121023f693b74c445a2e1e6883579a8aacd1f025e3a146724579a3245da7454fb7cb952aeb014c720",
            2,
            "023f693b74c445a2e1e6883579a8aacd1f025e3a146724579a3245da7454fb7cb9",
            "8cd328fe22d296af5e8926addc9f1bb8a1cce077933b3a95c268c1d79f13f1d8",
        ));

        // sweep transaction rust
        assert!(verify_signature(
            &resp.sweep_tx,
            0,
            "0313c27137b6458fef62f6f8d45145b1d2788381a990607e552013e2555fd81875",
            "63594155971bb272c82f827455de2c9ba7c5a2b86598d130364452480f01c14a",
        ));
        // sweep transaction python
        assert!(verify_signature(
            "020000000001019297117bf9307b382fe3b828549ff5437fcaa3b26abbcf4601072b2902649dc7020000000090000000014b7c0400000000001600146b0009af85b18052eb83afbdc9c45521c552588f0347304402205da5fafbaca31ee6b39720851583791ed5bef6f6314a381fd15f388d4da5a1d5022054943923ad11c71d790adf0f12d908f8c7430e4385daea26e9e366e7d89874e101004d632103d097f8bde004f9be3166bb61fda07209cfece8af19fd1ca1154ecb74f4e98ffb67029000b275210313c27137b6458fef62f6f8d45145b1d2788381a990607e552013e2555fd8187568ac00000000",
            0,
            "0313c27137b6458fef62f6f8d45145b1d2788381a990607e552013e2555fd81875",
            "63594155971bb272c82f827455de2c9ba7c5a2b86598d130364452480f01c14a",
        ));

        // counterparty sweep transaction rust
        assert!(verify_signature(
            &resp.counterparty_sweep_tx,
            0,
            "0211497bff8343b0566a3bf78d5bf0967a88aa039e9d30a5f9f1eeed38a38e20b8",
            "650bb8a1c951e7fdb3748f4c393dfce778175f61f518a7258526b9acc5e7c046",
        ));
        // counterparty sweep transaction python
        assert!(verify_signature(
            "02000000000101a8e7d890e135f4a5066e351b3035c0b11056107967b6e8220a24dbe2cebbe22f020000000000000000017d7e0400000000001600146b0009af85b18052eb83afbdc9c45521c552588f02473044022017c948fca2ac8ef5b8587c4e4cbfc7433fa56c1d7d3b14f33aeb79f796924e8b02204c508a11aeb5498ae700b6a32cae499a182165815cfe590e227b67c99a57519101210211497bff8343b0566a3bf78d5bf0967a88aa039e9d30a5f9f1eeed38a38e20b800000000",
            0,
            "0211497bff8343b0566a3bf78d5bf0967a88aa039e9d30a5f9f1eeed38a38e20b8",
            "650bb8a1c951e7fdb3748f4c393dfce778175f61f518a7258526b9acc5e7c046",
        ));

        let (rust_htlc_transaction, rust_htlc_sweep_transaction) = (
            resp.htlc_inbound_tx[0].clone().first,
            resp.htlc_inbound_tx[0].clone().second,
        );
        // inbound htlc transaction rust
        assert!(verify_signature(
            &rust_htlc_transaction,
            1,
            "0313932240cb488f8f6dffb5c43bd7e605078212a14439f4bac355cef32522a325",
            "952e85b50030b682bc144bc8eb5042a3d21fb6e67326ba2ecad4b4a6470ef900",
        ));
        assert!(verify_signature(
            &rust_htlc_transaction,
            2,
            "033bd5d1f4d8277b6400e0e32ae8c3b28d7566908bc24420940b32dbf00d6c25b5",
            "952e85b50030b682bc144bc8eb5042a3d21fb6e67326ba2ecad4b4a6470ef900",
        ));
        // inbound htlc transaction python
        assert!(verify_signature(
            "020000000001019297117bf9307b382fe3b828549ff5437fcaa3b26abbcf4601072b2902649dc700000000000000000001fda00000000000002200209590a2001663edd66090460d1f471f9081d152fb9244e71c633463a44c3d3f0d050047304402204467dc7ad1abaf9d00c93255ad0ec2b8293be4d0b9597128d3675f15e1abd25002204fffe0f61d88b882d048132e5eabafe0cd034d73fd257a173f36b0585608beec014730440220786310375df8258d54200fa79fdca1901af6d4ae9c2801357c7462954bf966720220660d46c0d666d0aeb0c18ad870c8684ea86fec669c45a7d44017c8fdaa77a0b901204a66493b9313b0ce832118dd5ad20b10983af251dc628ea985e9581ed0b064528b76a91467aa35a4cbee56bd2ab29fcdf75d720eb8a02b118763ac67210313932240cb488f8f6dffb5c43bd7e605078212a14439f4bac355cef32522a3257c8201208763a91490b2bd87c689ec31aed86574402095554b19412c88527c21033bd5d1f4d8277b6400e0e32ae8c3b28d7566908bc24420940b32dbf00d6c25b552ae677503ae9300b175ac686800000000",
            1,
            "0313932240cb488f8f6dffb5c43bd7e605078212a14439f4bac355cef32522a325",
            "952e85b50030b682bc144bc8eb5042a3d21fb6e67326ba2ecad4b4a6470ef900",
        ));
        assert!(verify_signature(
            "020000000001019297117bf9307b382fe3b828549ff5437fcaa3b26abbcf4601072b2902649dc700000000000000000001fda00000000000002200209590a2001663edd66090460d1f471f9081d152fb9244e71c633463a44c3d3f0d050047304402204467dc7ad1abaf9d00c93255ad0ec2b8293be4d0b9597128d3675f15e1abd25002204fffe0f61d88b882d048132e5eabafe0cd034d73fd257a173f36b0585608beec014730440220786310375df8258d54200fa79fdca1901af6d4ae9c2801357c7462954bf966720220660d46c0d666d0aeb0c18ad870c8684ea86fec669c45a7d44017c8fdaa77a0b901204a66493b9313b0ce832118dd5ad20b10983af251dc628ea985e9581ed0b064528b76a91467aa35a4cbee56bd2ab29fcdf75d720eb8a02b118763ac67210313932240cb488f8f6dffb5c43bd7e605078212a14439f4bac355cef32522a3257c8201208763a91490b2bd87c689ec31aed86574402095554b19412c88527c21033bd5d1f4d8277b6400e0e32ae8c3b28d7566908bc24420940b32dbf00d6c25b552ae677503ae9300b175ac686800000000",
            2,
            "033bd5d1f4d8277b6400e0e32ae8c3b28d7566908bc24420940b32dbf00d6c25b5",
            "952e85b50030b682bc144bc8eb5042a3d21fb6e67326ba2ecad4b4a6470ef900",
        ));

        // inbound htlc sweep transaction rust
        assert!(verify_signature(
            &rust_htlc_sweep_transaction,
            0,
            "0313c27137b6458fef62f6f8d45145b1d2788381a990607e552013e2555fd81875",
            "716626e2b317fb30d1a351c37e50d3d4edf73a9b6c1a25edd7f7c8bae1eff059",
        ));
        // inbound htlc sweep transaction python
        assert!(verify_signature(
            "020000000001012b7ac5288c38f024fc9683f64041f037671b4b552c81fd7e6e01ee46ad185e6b0000000000900000000168890000000000001600146b0009af85b18052eb83afbdc9c45521c552588f03473044022067d4dcd15733683ca3fec8e84555031dc2ce8d9b4cbf29eea8feb2ee4054587202206791cc000ed2b1789da89f46445e06216d56356efb9048d80001907b55403dbd01004d632103d097f8bde004f9be3166bb61fda07209cfece8af19fd1ca1154ecb74f4e98ffb67029000b275210313c27137b6458fef62f6f8d45145b1d2788381a990607e552013e2555fd8187568ac00000000",
            0,
            "0313c27137b6458fef62f6f8d45145b1d2788381a990607e552013e2555fd81875",
            "716626e2b317fb30d1a351c37e50d3d4edf73a9b6c1a25edd7f7c8bae1eff059",
        ));

        // outbound counterparty htlc transaction rust
        assert!(verify_signature(
            &resp.counterparty_htlc_outbound_tx[0],
            0,
            "0363f80146fd3bdbe88e49a5b5f5a384e873e7423a8a4fb22a912893883795b7d3",
            "762c14864b103172b594863a12dc6ebf8bffbc5dfe355fca9cff48cecd6966d6",
        ));
        // outbound counterparty htlc transaction python
        assert!(verify_signature(
            "02000000000101a8e7d890e135f4a5066e351b3035c0b11056107967b6e8220a24dbe2cebbe22f00000000000000000001f1a20000000000001600146b0009af85b18052eb83afbdc9c45521c552588f03473044022066d8de233b0d7e9aa9dca4bb814cf4b15aa010b468c5520a4d4056bb5bf86ed8022018e5c4fadba222d62f59332fdc09c1e516be6983b6784ca3ce39c8d89b2eddae01204a66493b9313b0ce832118dd5ad20b10983af251dc628ea985e9581ed0b064528576a914c5a930dfd00a9165e9dbbee31326fb8a5d09612f8763ac67210363f80146fd3bdbe88e49a5b5f5a384e873e7423a8a4fb22a912893883795b7d37c820120876475527c2102e59e26ede9c3dd9dd6fa7dbce42467a53b04b86aa7c92fa385c7f9ffcd1bfe5f52ae67a91490b2bd87c689ec31aed86574402095554b19412c88ac686800000000",
            0,
            "0363f80146fd3bdbe88e49a5b5f5a384e873e7423a8a4fb22a912893883795b7d3",
            "762c14864b103172b594863a12dc6ebf8bffbc5dfe355fca9cff48cecd6966d6",
        ));
    }

    #[test]
    fn test_funds_recovery_kit_with_outbound_htlcs_and_counterparty_inbound_htlcs() {
        let data = r#"{"counterparty_sweep_tx": "02000000000101688e5e19da698bc61f8718a44b6e1333246026c7ed6c470faca1a30fd5f320ea00000000000000000001edad0000000000001600146b0009af85b18052eb83afbdc9c45521c552588f02002102ef9180a5eb2e375349e230f2d4db6f2d8640e551cc49268fa13cbc3d1974691d00000000", "counterparty_serialized_htlc_sweep_tx": ["02000000000101688e5e19da698bc61f8718a44b6e1333246026c7ed6c470faca1a30fd5f320ea01000000000000000001fda00000000000001600146b0009af85b18052eb83afbdc9c45521c552588f0300008b76a9146c5ab60ccb89adb2ee50711bbf0276322221a9bf8763ac67210253f0a86f34769a606dba7f8bbe840ed7af058230d0cfa3f19ed9a5c99c9b94ae7c8201208763a914f7b9d68089d95ffcb1aa468f9dfe2ea35efb608488527c21030e12b74fac45f57ea431ddedb26802ea71c7e3caef6bff2c684bc5e5e487824f52ae677503319e00b175ac6868319e0000"], "counterparty_htlc_tx_add_tweak": "7ffdd12ca53fd8ea3d69c4f24a9277b05f62186e8f1e7447845c1717add2ca93", "counterparty_nonces": [""], "payment_key_derivation_path": "m/3/833563776/2", "counterparty_serialized_commitment_tx": "0200000001f09eb2d66530f30845ad2ba16c32cb576b0f5d6aac47822c43f7d7109d753fc60100000000a91c67800350c30000000000001600144001c52674e9382e0a17142bdefbb76edb45e1ac50c30000000000002200207db96038aa3966ba586911dea677743e93a2ad6ef95368911d69ea14e1412629c0ee05000000000022002052f16313b8d8a34517e428cf9225b13d7a8c7325a34aaa2b3e4455e5f1d966b58f447320", "commitment_tx": "02000000000101f09eb2d66530f30845ad2ba16c32cb576b0f5d6aac47822c43f7d7109d753fc60100000000a91c67800350c300000000000022002027e12aecbf0ff9d2de7c0ab0a05f8437baa82e950dd9a3fa94657b46bcc9f23950c3000000000000220020d7c36a365eaaaee3d2ebfcbd24e9932148d5d8b7a21acd934ea2933a06f3fd72c0ee05000000000016001454141bdd6dab56d098d8bceec316330b54374bb00400473044022017f51ba19bcf6910b1b556d9fe6c101fa20734a8b119892914cc1aa55c5b9c2402206837a0acba5a06285ae477e9e815859d0232888d8bb88460fd22418fbc523f2b0100475221021b0861699c0754dc169ea80096e5d66f4ca528d5d7db5dbbd1a33d3f7f5e12ac21032f769f4418aa8b72dee19f0d440dcdc8bd26e5a67fbe0f6e4aa4dbb21586d75e52ae8f447320", "sweep_tx": "020000000001017208c29754db7f75e6b31ef6a986f2593b0f9f6a5592a50f0865bf92ea3d606101000000009000000001bbab0000000000001600146b0009af85b18052eb83afbdc9c45521c552588f0300004d632103efa27702961794d09480b6c9101a67880e45a254f51d139e170008588e7b122367029000b27521027100dc4ee38f2f877ca7c39b7ccba6e1febaf344e8fbd0649fd9200c761ace2768ac00000000", "htlc_tx": ["020000000001017208c29754db7f75e6b31ef6a986f2593b0f9f6a5592a50f0865bf92ea3d606100000000000000000001f1a2000000000000220020d7c36a365eaaaee3d2ebfcbd24e9932148d5d8b7a21acd934ea2933a06f3fd720500483045022100b1e3470ab59ce935aac350474856e831a1a1b21bbf0f80e4b198deb7ed9a97d3022000875eb6e995ecef78170f9afa062e494d16cb594d1835dcee6a9fe410b28a480100008576a914f76a8b93697ebca341901985c6644e5fce6050b38763ac6721026d0b8fc557042d47870c886e16193ec2a15f9bda8be7cbd305d3bacaf4d415e17c820120876475527c2102ee3dd778c31b9a11b11589f2cfbb58ddb4c8d20b386401c64ce1a4e4f9d59c2852ae67a914f7b9d68089d95ffcb1aa468f9dfe2ea35efb608488ac6868319e0000"], "serialized_htlc_sweep_tx": ["02000000000101f747320e858783f6e6a8e05e81c888cfd4defdde6b6560b6ad869a6331347d94000000000090000000015c8b0000000000001600146b0009af85b18052eb83afbdc9c45521c552588f0300004d632103efa27702961794d09480b6c9101a67880e45a254f51d139e170008588e7b122367029000b27521027100dc4ee38f2f877ca7c39b7ccba6e1febaf344e8fbd0649fd9200c761ace2768ac00000000"], "channel_point": "c63f759d10d7f7432c8247ac6a5d0f6b57cb326ca12bad4508f33065d6b29ef0:1", "sweep_tx_add_tweak": "ab823b1e6f52b50b11e69d888941a2a4b88c727e887af8323f2ef7b91d649fe8", "htlc_tx_add_tweak": "e10fe25fae09330c5fd211927fddc3756e9bcad238f3f2c07a8a24b8f7280afb", "funding_private_key_derivation_path": "m/3/833563776/0", "delayed_payment_base_key_derivation_path": "m/3/833563776/3", "htlc_base_key_derivation_path": "m/3/833563776/4", "channel_capacity": 500000, "nonces": [""], "commitment_number": 1}"#;
        let master_seed = "f520e5271623fe21c76b0212f855c97a";
        let resp = sign_transactions(master_seed.into(), data.into(), signer::Network::Regtest)
            .expect("Data should be valid");

        // commitment transaction rust
        assert!(verify_signature(
            &resp.commitment_tx,
            1,
            "021b0861699c0754dc169ea80096e5d66f4ca528d5d7db5dbbd1a33d3f7f5e12ac",
            "f81b02410940d78ec79362b29b57eae209f62c1c4562921a246f8b145db58c6a",
        ));
        assert!(verify_signature(
            &resp.commitment_tx,
            2,
            "032f769f4418aa8b72dee19f0d440dcdc8bd26e5a67fbe0f6e4aa4dbb21586d75e",
            "f81b02410940d78ec79362b29b57eae209f62c1c4562921a246f8b145db58c6a",
        ));
        // commitment transaction python
        assert!(verify_signature(
            "02000000000101f09eb2d66530f30845ad2ba16c32cb576b0f5d6aac47822c43f7d7109d753fc60100000000a91c67800350c300000000000022002027e12aecbf0ff9d2de7c0ab0a05f8437baa82e950dd9a3fa94657b46bcc9f23950c3000000000000220020d7c36a365eaaaee3d2ebfcbd24e9932148d5d8b7a21acd934ea2933a06f3fd72c0ee05000000000016001454141bdd6dab56d098d8bceec316330b54374bb00400473044022017f51ba19bcf6910b1b556d9fe6c101fa20734a8b119892914cc1aa55c5b9c2402206837a0acba5a06285ae477e9e815859d0232888d8bb88460fd22418fbc523f2b01473044022074c31177de217123a83c7ea7c7f6a30ac2da8eeef5d612e86d4ec266998bba5302203e036db6de11017414fb48302aa3be8253f80e5b703f6527a4be5a999e0b314701475221021b0861699c0754dc169ea80096e5d66f4ca528d5d7db5dbbd1a33d3f7f5e12ac21032f769f4418aa8b72dee19f0d440dcdc8bd26e5a67fbe0f6e4aa4dbb21586d75e52ae8f447320",
            1,
            "021b0861699c0754dc169ea80096e5d66f4ca528d5d7db5dbbd1a33d3f7f5e12ac",
            "f81b02410940d78ec79362b29b57eae209f62c1c4562921a246f8b145db58c6a",
        ));
        assert!(verify_signature(
            "02000000000101f09eb2d66530f30845ad2ba16c32cb576b0f5d6aac47822c43f7d7109d753fc60100000000a91c67800350c300000000000022002027e12aecbf0ff9d2de7c0ab0a05f8437baa82e950dd9a3fa94657b46bcc9f23950c3000000000000220020d7c36a365eaaaee3d2ebfcbd24e9932148d5d8b7a21acd934ea2933a06f3fd72c0ee05000000000016001454141bdd6dab56d098d8bceec316330b54374bb00400473044022017f51ba19bcf6910b1b556d9fe6c101fa20734a8b119892914cc1aa55c5b9c2402206837a0acba5a06285ae477e9e815859d0232888d8bb88460fd22418fbc523f2b01473044022074c31177de217123a83c7ea7c7f6a30ac2da8eeef5d612e86d4ec266998bba5302203e036db6de11017414fb48302aa3be8253f80e5b703f6527a4be5a999e0b314701475221021b0861699c0754dc169ea80096e5d66f4ca528d5d7db5dbbd1a33d3f7f5e12ac21032f769f4418aa8b72dee19f0d440dcdc8bd26e5a67fbe0f6e4aa4dbb21586d75e52ae8f447320",
            2,
            "032f769f4418aa8b72dee19f0d440dcdc8bd26e5a67fbe0f6e4aa4dbb21586d75e",
            "f81b02410940d78ec79362b29b57eae209f62c1c4562921a246f8b145db58c6a",
        ));

        // sweep transaction rust
        assert!(verify_signature(
            &resp.sweep_tx,
            0,
            "027100dc4ee38f2f877ca7c39b7ccba6e1febaf344e8fbd0649fd9200c761ace27",
            "14d536abc165eff3963db64f90e0070639f1e9190d3af82126280323a1e9196c",
        ));
        // sweep transaction python
        assert!(verify_signature(
            "020000000001017208c29754db7f75e6b31ef6a986f2593b0f9f6a5592a50f0865bf92ea3d606101000000009000000001bbab0000000000001600146b0009af85b18052eb83afbdc9c45521c552588f03473044022031e283eeb6c5b4621b3f11f1ba69e95f42af07f760d50fc5bfbb49f79885ae2902202521a18692b62e7db0530c738f1c571451be403b23538069f46bda15be7a8a0b01004d632103efa27702961794d09480b6c9101a67880e45a254f51d139e170008588e7b122367029000b27521027100dc4ee38f2f877ca7c39b7ccba6e1febaf344e8fbd0649fd9200c761ace2768ac00000000",
            0,
            "027100dc4ee38f2f877ca7c39b7ccba6e1febaf344e8fbd0649fd9200c761ace27",
            "14d536abc165eff3963db64f90e0070639f1e9190d3af82126280323a1e9196c",
        ));

        // counterparty sweep transaction rust
        assert!(verify_signature(
            &resp.counterparty_sweep_tx,
            0,
            "02ef9180a5eb2e375349e230f2d4db6f2d8640e551cc49268fa13cbc3d1974691d",
            "4a6c8a4c013dcb97d336614f75a7ad14e03593ac61901696102a65eb4e6e3907",
        ));
        // counterparty sweep transaction python
        assert!(verify_signature(
            "02000000000101688e5e19da698bc61f8718a44b6e1333246026c7ed6c470faca1a30fd5f320ea00000000000000000001edad0000000000001600146b0009af85b18052eb83afbdc9c45521c552588f024730440220591ed0f40799c95d24dd2528f8404d4e774d4eae4d9cd525abbc060e9e52e25b02202c14e40632299a36b8cc0e54555eb7c120bcc33e6c3d39f16acb7833e920d26a012102ef9180a5eb2e375349e230f2d4db6f2d8640e551cc49268fa13cbc3d1974691d00000000",
            0,
            "02ef9180a5eb2e375349e230f2d4db6f2d8640e551cc49268fa13cbc3d1974691d",
            "4a6c8a4c013dcb97d336614f75a7ad14e03593ac61901696102a65eb4e6e3907",
        ));

        let (rust_htlc_transaction, rust_htlc_sweep_transaction) = (
            resp.htlc_outbound_tx[0].clone().first,
            resp.htlc_outbound_tx[0].clone().second,
        );
        // outbount htlc transaction rust
        assert!(verify_signature(
            &rust_htlc_transaction,
            1,
            "026d0b8fc557042d47870c886e16193ec2a15f9bda8be7cbd305d3bacaf4d415e1",
            "7353455c82f58e6574974f28ffa9b12b205f86fd91b61409ac25a7b1bd9225a6",
        ));
        assert!(verify_signature(
            &rust_htlc_transaction,
            2,
            "02ee3dd778c31b9a11b11589f2cfbb58ddb4c8d20b386401c64ce1a4e4f9d59c28",
            "7353455c82f58e6574974f28ffa9b12b205f86fd91b61409ac25a7b1bd9225a6",
        ));
        // outbound htlc transaction python
        assert!(verify_signature(
            "020000000001017208c29754db7f75e6b31ef6a986f2593b0f9f6a5592a50f0865bf92ea3d606100000000000000000001f1a2000000000000220020d7c36a365eaaaee3d2ebfcbd24e9932148d5d8b7a21acd934ea2933a06f3fd720500483045022100b1e3470ab59ce935aac350474856e831a1a1b21bbf0f80e4b198deb7ed9a97d3022000875eb6e995ecef78170f9afa062e494d16cb594d1835dcee6a9fe410b28a480147304402200b65d6d5aba6d6cb0e60ef6c29c32afd69c44f2394844540c5697de2809b32ee02201f7a416fe8f89a4e6bf29471e0d090dbb4091caa205511ad96d2c241803e014001008576a914f76a8b93697ebca341901985c6644e5fce6050b38763ac6721026d0b8fc557042d47870c886e16193ec2a15f9bda8be7cbd305d3bacaf4d415e17c820120876475527c2102ee3dd778c31b9a11b11589f2cfbb58ddb4c8d20b386401c64ce1a4e4f9d59c2852ae67a914f7b9d68089d95ffcb1aa468f9dfe2ea35efb608488ac6868319e0000",
            1,
            "026d0b8fc557042d47870c886e16193ec2a15f9bda8be7cbd305d3bacaf4d415e1",
            "7353455c82f58e6574974f28ffa9b12b205f86fd91b61409ac25a7b1bd9225a6",
        ));
        assert!(verify_signature(
            "020000000001017208c29754db7f75e6b31ef6a986f2593b0f9f6a5592a50f0865bf92ea3d606100000000000000000001f1a2000000000000220020d7c36a365eaaaee3d2ebfcbd24e9932148d5d8b7a21acd934ea2933a06f3fd720500483045022100b1e3470ab59ce935aac350474856e831a1a1b21bbf0f80e4b198deb7ed9a97d3022000875eb6e995ecef78170f9afa062e494d16cb594d1835dcee6a9fe410b28a480147304402200b65d6d5aba6d6cb0e60ef6c29c32afd69c44f2394844540c5697de2809b32ee02201f7a416fe8f89a4e6bf29471e0d090dbb4091caa205511ad96d2c241803e014001008576a914f76a8b93697ebca341901985c6644e5fce6050b38763ac6721026d0b8fc557042d47870c886e16193ec2a15f9bda8be7cbd305d3bacaf4d415e17c820120876475527c2102ee3dd778c31b9a11b11589f2cfbb58ddb4c8d20b386401c64ce1a4e4f9d59c2852ae67a914f7b9d68089d95ffcb1aa468f9dfe2ea35efb608488ac6868319e0000",
            2,
            "02ee3dd778c31b9a11b11589f2cfbb58ddb4c8d20b386401c64ce1a4e4f9d59c28",
            "7353455c82f58e6574974f28ffa9b12b205f86fd91b61409ac25a7b1bd9225a6",
        ));

        // outbound htlc sweep transaction rust
        assert!(verify_signature(
            &rust_htlc_sweep_transaction,
            0,
            "027100dc4ee38f2f877ca7c39b7ccba6e1febaf344e8fbd0649fd9200c761ace27",
            "3679c2908c477752ddcbb1618c8f94f9fbace9b78eda50c56c4464cb38ce50bf",
        ));
        // outbound htlc sweep transaction python
        assert!(verify_signature(
            "02000000000101f747320e858783f6e6a8e05e81c888cfd4defdde6b6560b6ad869a6331347d94000000000090000000015c8b0000000000001600146b0009af85b18052eb83afbdc9c45521c552588f03473044022035bd53c89d2fcd43acd624c5203c450fbbb12cccd90c7312b529db1bd78022e402205dadd29dbc3fcc4ccab9015f2137cac870a8c5055f087ea58a0384613d962fc701004d632103efa27702961794d09480b6c9101a67880e45a254f51d139e170008588e7b122367029000b27521027100dc4ee38f2f877ca7c39b7ccba6e1febaf344e8fbd0649fd9200c761ace2768ac00000000",
            0,
            "027100dc4ee38f2f877ca7c39b7ccba6e1febaf344e8fbd0649fd9200c761ace27",
            "3679c2908c477752ddcbb1618c8f94f9fbace9b78eda50c56c4464cb38ce50bf",
        ));

        // inbound counterparty htlc transaction rust
        assert!(verify_signature(
            &resp.counterparty_htlc_inbound_tx[0],
            0,
            "0253f0a86f34769a606dba7f8bbe840ed7af058230d0cfa3f19ed9a5c99c9b94ae",
            "83e04c2be51febc9b117280fe0ce4b5630448c4a53f00ffd2565611ba9f1ade9",
        ));
        // inbound counterparty htlc transaction python
        assert!(verify_signature(
            "02000000000101688e5e19da698bc61f8718a44b6e1333246026c7ed6c470faca1a30fd5f320ea01000000000000000001fda00000000000001600146b0009af85b18052eb83afbdc9c45521c552588f03473044022021815efae8cc0bd1ccaa9bd67381c3397336e53296a0ddad59797a4cc02d9d380220160400adf6c253adb2057a1d77315919ab3476697952959f851836ab1be9d0d601008b76a9146c5ab60ccb89adb2ee50711bbf0276322221a9bf8763ac67210253f0a86f34769a606dba7f8bbe840ed7af058230d0cfa3f19ed9a5c99c9b94ae7c8201208763a914f7b9d68089d95ffcb1aa468f9dfe2ea35efb608488527c21030e12b74fac45f57ea431ddedb26802ea71c7e3caef6bff2c684bc5e5e487824f52ae677503319e00b175ac6868319e0000",
            0,
            "0253f0a86f34769a606dba7f8bbe840ed7af058230d0cfa3f19ed9a5c99c9b94ae",
            "83e04c2be51febc9b117280fe0ce4b5630448c4a53f00ffd2565611ba9f1ade9",
        ));
    }
}
