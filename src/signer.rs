use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use bitcoin::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::hashes::{HmacEngine, sha512, HashEngine, Hmac, Hash};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::hashes::sha256;
use bitcoin::secp256k1::{Message, PublicKey, Scalar, Secp256k1, SecretKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsError, JsValue};

const NODE_KEY_PATH: &str = "m/0";

#[derive(Copy, Clone, Debug)]
pub enum LightsparkSignerError {
    Bip32Error(bip32::Error),
    TweakMustHaveBoth,
    KeyTweakError,
    EntropyLengthError,
}

#[wasm_bindgen]
#[derive(Copy, Clone, Debug)]
pub enum Network {
    Bitcoin,
    Testnet,
    Regtest,
}

impl fmt::Display for LightsparkSignerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Bip32Error(err) => write!(f, "Bip32 error {}", err),
            Self::TweakMustHaveBoth => write!(f, "Both tweaks must be present"),
            Self::KeyTweakError => write!(f, "Key tweak error"),
            Self::EntropyLengthError => write!(f, "Entropy must be 32 bytes"),
        }
    }
}

impl std::error::Error for LightsparkSignerError {}

impl From<LightsparkSignerError> for JsValue {
    fn from(val: LightsparkSignerError) -> Self {
        JsError::from(val).into()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Mnemonic {
    internal: bip32::Mnemonic,
}

#[wasm_bindgen]
impl Mnemonic {
    pub fn new() -> Self {
        let internal = bip32::Mnemonic::random(OsRng, Default::default());
        Self { internal }
    }

    pub fn from_entropy(entropy: Vec<u8>) -> Result<Mnemonic, LightsparkSignerError> {
        let slice = entropy.as_slice();
        let array: [u8; 32] = slice
            .try_into()
            .map_err(|_| LightsparkSignerError::EntropyLengthError)?;
        let internal = bip32::Mnemonic::from_entropy(array, Default::default());
        Ok(Self { internal })
    }

    pub fn from_phrase(phrase: String) -> Result<Mnemonic, LightsparkSignerError> {
        let internal = bip32::Mnemonic::new(phrase, Default::default())
            .map_err(LightsparkSignerError::Bip32Error)?;
        Ok(Self { internal })
    }

    pub fn as_string(&self) -> String {
        self.internal.phrase().to_string()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Seed {
    seed: Vec<u8>,
}

#[wasm_bindgen]
impl Seed {
    pub fn from_mnemonic(mnemonic: &Mnemonic) -> Self {
        let seed = mnemonic.internal.to_seed("").as_bytes().to_vec();
        Self { seed }
    }

    pub fn new(seed: Vec<u8>) -> Self {
        Self { seed }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.seed.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct InvoiceSignature {
    signature: Vec<u8>,
    recovery_id: i32,
}

#[wasm_bindgen]
impl InvoiceSignature {
    pub fn get_signature(&self) -> Vec<u8> {
        self.signature.clone()
    }

    pub fn get_recovery_id(&self) -> i32 {
        self.recovery_id
    }
}

#[wasm_bindgen]
pub struct LightsparkSigner {
    master_private_key: ExtendedPrivKey,
    node_private_key: ExtendedPrivKey,
}

#[wasm_bindgen]
impl LightsparkSigner {
    pub fn new(seed: &Seed, network: Network) -> Self {
        let network: bitcoin::Network = match network {
            Network::Bitcoin => bitcoin::Network::Bitcoin,
            Network::Testnet => bitcoin::Network::Testnet,
            Network::Regtest => bitcoin::Network::Regtest,
        };
        let master_private_key =
            ExtendedPrivKey::new_master(network, seed.as_bytes().as_slice()).unwrap();
        let secp = Secp256k1::new();
        let node_key_path = DerivationPath::from_str(NODE_KEY_PATH).unwrap();
        let node_private_key = master_private_key
            .derive_priv(&secp, &node_key_path)
            .unwrap();
        Self {
            master_private_key,
            node_private_key,
        }
    }

    pub fn from_bytes(seed: Vec<u8>, network: Network) -> Self {
        let seed = Seed::new(seed);
        Self::new(&seed, network)
    }

    pub fn get_master_public_key(&self) -> Result<String, LightsparkSignerError> {
        let secp = Secp256k1::new();
        let pubkey = ExtendedPubKey::from_priv(&secp, &self.master_private_key);
        Ok(pubkey.to_string())
    }

    pub fn derive_public_key(
        &self,
        derivation_path: String,
    ) -> Result<String, LightsparkSignerError> {
        let secp = Secp256k1::new();
        let path = DerivationPath::from_str(&derivation_path).unwrap();
        let private_key = self.master_private_key.derive_priv(&secp, &path).unwrap();
        let pubkey = ExtendedPubKey::from_priv(&secp, &private_key);
        Ok(pubkey.to_string())
    }

    pub fn derive_key_and_sign(
        &self,
        message: Vec<u8>,
        derivation_path: String,
        is_raw: bool,
        add_tweak: Option<Vec<u8>>,
        mul_tweak: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, LightsparkSignerError> {
        let secp = Secp256k1::new();
        let signing_key = self.derive_and_tweak_key(derivation_path, add_tweak, mul_tweak)?;
        let signature: Signature = match is_raw {
            true => {
                let msg = Message::from_slice(message.as_slice()).unwrap();
                secp.sign_ecdsa(&msg, &signing_key)
            }
            false => {
                let msg = Message::from_hashed_data::<sha256::Hash>(message.as_slice());
                secp.sign_ecdsa(&msg, &signing_key)
            }
        };

        Ok(signature.serialize_compact().to_vec())
    }

    pub fn ecdh(&self, public_key: Vec<u8>) -> Result<Vec<u8>, LightsparkSignerError> {
        let pubkey = PublicKey::from_slice(public_key.as_slice()).unwrap();
        let our_key = self.node_private_key.private_key;
        let ss = SharedSecret::new(&pubkey, &our_key);
        Ok(ss.as_ref().to_vec())
    }

    pub fn get_per_commitment_point(
        &self,
        derivation_path: String,
        per_commitment_point_idx: u64,
    ) -> Result<Vec<u8>, LightsparkSignerError> {
        let per_commitment_secret = self
            .release_per_commitment_secret(derivation_path, per_commitment_point_idx)
            .unwrap();
        let secret_key = SecretKey::from_slice(per_commitment_secret.as_slice()).unwrap();
        let public_key = secret_key.public_key(&Secp256k1::new());
        Ok(public_key.serialize().to_vec())
    }

    pub fn release_per_commitment_secret(
        &self,
        derivation_path: String,
        per_commitment_point_idx: u64,
    ) -> Result<Vec<u8>, LightsparkSignerError> {
        let key = self.derive_key(derivation_path).unwrap();
        let channel_seed = Sha256::digest(&key.private_key[..]).to_vec();
        let commitment_seed = self.build_commitment_seed(channel_seed);
        Ok(self.build_commitment_secret(commitment_seed, per_commitment_point_idx))
    }

    pub fn generate_preimage_nonce(&self) -> Vec<u8> {
        let mut rng = OsRng;
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        nonce.to_vec()
    }

    pub fn generate_preimage(&self, nonce: Vec<u8>) -> Result<Vec<u8>, LightsparkSignerError> {
        let key = self.derive_key("m/4h".to_owned())?;
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&key.private_key.secret_bytes());
        hmac_engine.input(b"invoice preimage");
        hmac_engine.input(nonce.as_slice());
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        Ok(hmac_result[..32].into())
    }

    pub fn generate_preimage_hash(&self, nonce: Vec<u8>) -> Result<Vec<u8>, LightsparkSignerError> {
        let preimage = self.generate_preimage(nonce)?;
        Ok(Sha256::digest(preimage).to_vec())
    }

    fn derive_and_tweak_key(
        &self,
        derivation_path: String,
        add_tweak: Option<Vec<u8>>,
        mul_tweak: Option<Vec<u8>>,
    ) -> Result<SecretKey, LightsparkSignerError> {
        let derived_key = self.derive_key(derivation_path).unwrap();
        let add_tweak: Option<[u8; 32]> = add_tweak.map(|tweak| tweak.try_into().unwrap());
        let mul_tweak: Option<[u8; 32]> = mul_tweak.map(|tweak| tweak.try_into().unwrap());
        self.tweak_key(derived_key.private_key, add_tweak, mul_tweak)
    }

    fn derive_key(&self, derivation_path: String) -> Result<ExtendedPrivKey, LightsparkSignerError> {
        let secp = Secp256k1::new();
        let path = DerivationPath::from_str(&derivation_path).unwrap();
        let private_key = self.master_private_key.derive_priv(&secp, &path).unwrap();
        Ok(private_key)
    }

    fn build_commitment_seed(&self, seed: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(b"commitment seed");
        hasher.finalize().to_vec()
    }

    fn build_commitment_secret(&self, seed: Vec<u8>, idx: u64) -> Vec<u8> {
        let mut res = seed;
        for i in 0..48 {
            let bitpos = 47 - i;
            if idx & (1 << bitpos) == (1 << bitpos) {
                res[bitpos / 8] ^= 1 << (bitpos & 7);
                res = Sha256::digest(&res).to_vec();
            }
        }
        res
    }

    fn tweak_key(
        &self,
        secret_key: SecretKey,
        add_tweak: Option<[u8; 32]>,
        mul_tweak: Option<[u8; 32]>,
    ) -> Result<SecretKey, LightsparkSignerError> {
        let mut res: SecretKey = secret_key;
        if let Some(mul_tweak) = mul_tweak {
            let scalar = Scalar::from_be_bytes(mul_tweak).unwrap();
            res = res.mul_tweak(&scalar).unwrap();
        }

        if let Some(add_tweak) = add_tweak {
            let scalar = Scalar::from_be_bytes(add_tweak).unwrap();
            res = res.add_tweak(&scalar).unwrap();
        }

        Ok(res)
    }
}

impl LightsparkSigner {
    pub fn sign_invoice(
        &self,
        unsigned_invoice: String,
    ) -> Result<Arc<InvoiceSignature>, LightsparkSignerError> {
        let signing_key = self.node_private_key.private_key;
        let msg = Message::from_hashed_data::<sha256::Hash>(unsigned_invoice.as_bytes());
        let secp = Secp256k1::new();
        let sig = secp
            .sign_ecdsa_recoverable(&msg, &signing_key)
            .serialize_compact();
        let res = InvoiceSignature {
            signature: sig.1.to_vec(),
            recovery_id: sig.0.to_i32(),
        };
        Ok(res.into())
    }

    pub fn sign_invoice_hash(
        &self,
        invoice_hash: Vec<u8>,
    ) -> Result<Arc<InvoiceSignature>, LightsparkSignerError> {
        let signing_key = self.node_private_key.private_key;
        let msg = Message::from_slice(invoice_hash.as_slice()).unwrap();
        let secp = Secp256k1::new();
        let sig = secp
            .sign_ecdsa_recoverable(&msg, &signing_key)
            .serialize_compact();
        let res = InvoiceSignature {
            signature: sig.1.to_vec(),
            recovery_id: sig.0.to_i32(),
        };
        Ok(res.into())
    }
}

#[wasm_bindgen]
impl LightsparkSigner {
    pub fn sign_invoice_wasm(
        &self,
        unsigned_invoice: String,
    ) -> Result<InvoiceSignature, LightsparkSignerError> {
        let signing_key = self.node_private_key.private_key;
        let msg = Message::from_hashed_data::<sha256::Hash>(unsigned_invoice.as_bytes());
        let secp = Secp256k1::new();
        let sig = secp
            .sign_ecdsa_recoverable(&msg, &signing_key)
            .serialize_compact();
        let res = InvoiceSignature {
            signature: sig.1.to_vec(),
            recovery_id: sig.0.to_i32(),
        };
        Ok(res)
    }

    pub fn sign_invoice_hash_wasm(
        &self,
        invoice_hash: Vec<u8>,
    ) -> Result<InvoiceSignature, LightsparkSignerError> {
        let signing_key = self.node_private_key.private_key;
        let msg = Message::from_slice(invoice_hash.as_slice()).unwrap();
        let secp = Secp256k1::new();
        let sig = secp
            .sign_ecdsa_recoverable(&msg, &signing_key)
            .serialize_compact();
        let res = InvoiceSignature {
            signature: sig.1.to_vec(),
            recovery_id: sig.0.to_i32(),
        };
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_key_derivation() {
        let seed_hex_string = "000102030405060708090a0b0c0d0e0f";
        let seed_bytes = hex::decode(seed_hex_string).unwrap();
        let seed = Seed::new(seed_bytes);

        let signer = LightsparkSigner::new(&seed, Network::Bitcoin);
        let xprv = signer.derive_key("m".to_owned()).unwrap();
        let xprv_string = xprv.to_string();
        let expected_string = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        assert_eq!(xprv_string.as_str(), expected_string);

        let signer = LightsparkSigner::new(&seed, Network::Bitcoin);
        let xprv = signer.derive_key("m/0'".to_owned()).unwrap();
        let xprv_string = xprv.to_string();
        let expected_string = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
        assert_eq!(xprv_string.as_str(), expected_string);
    }

    #[test]
    fn test_public_key() {
        let seed_hex_string = "000102030405060708090a0b0c0d0e0f";
        let seed_bytes = hex::decode(seed_hex_string).unwrap();
        let seed = Seed::new(seed_bytes);

        let signer = LightsparkSigner::new(&seed, Network::Bitcoin);
        let public_key_string = signer.get_master_public_key().unwrap();
        let expected_string = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        assert_eq!(public_key_string, expected_string);

        let signer = LightsparkSigner::new(&seed, Network::Bitcoin);
        let public_key_string = signer.derive_public_key("m/0'".to_owned()).unwrap();
        let expected_string = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";
        assert_eq!(public_key_string, expected_string);
    }

    #[test]
    fn test_sign() {
        let seed_hex_string = "000102030405060708090a0b0c0d0e0f";
        let seed_bytes = hex::decode(seed_hex_string).unwrap();
        let seed = Seed::new(seed_bytes);

        let public_key_string = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

        let signer = LightsparkSigner::new(&seed, Network::Bitcoin);
        let xpub = signer.derive_public_key("m".to_owned()).unwrap();
        assert_eq!(xpub, public_key_string);

        let verification_key = ExtendedPubKey::from_str(public_key_string)
            .unwrap()
            .public_key;

        let message = b"Hello, world!";
        let signature_bytes = signer
            .derive_key_and_sign(message.to_vec(), "m".to_owned(), false, None, None)
            .unwrap();
        let signature = Signature::from_compact(signature_bytes.as_slice()).unwrap();
        let msg = Message::from_hashed_data::<sha256::Hash>(message);
        let secp = Secp256k1::new();
        assert!(secp
            .verify_ecdsa(&msg, &signature, &verification_key)
            .is_ok());
    }

    #[test]
    fn test_ecdh() {
        let seed1_hex_string = "000102030405060708090a0b0c0d0e0f";
        let seed1_bytes = hex::decode(seed1_hex_string).unwrap();
        let seed1 = Seed::new(seed1_bytes);

        let seed2_hex_string = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
        let seed2_bytes = hex::decode(seed2_hex_string).unwrap();
        let seed2 = Seed::new(seed2_bytes);

        let signer1 = LightsparkSigner::new(&seed1, Network::Bitcoin);
        let pub1 = signer1.derive_public_key("m/0".to_owned()).unwrap();
        let xpub1 = ExtendedPubKey::from_str(&pub1).unwrap();
        let pub1_bytes = xpub1.public_key.serialize();

        let signer2 = LightsparkSigner::new(&seed2, Network::Bitcoin);
        let pub2 = signer2.derive_public_key("m/0".to_owned()).unwrap();
        let xpub2 = ExtendedPubKey::from_str(&pub2).unwrap();
        let pub2_bytes = xpub2.public_key.serialize();

        let secret_1 = signer1.ecdh(pub2_bytes.to_vec()).unwrap();
        let secret_2 = signer2.ecdh(pub1_bytes.to_vec()).unwrap();
        assert_eq!(secret_1, secret_2);
    }

    #[test]
    fn test_tweak() {
        let base_hex_string = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let base_bytes = hex::decode(base_hex_string).unwrap();
        let secrect_key = SecretKey::from_slice(base_bytes.as_slice()).unwrap();

        let mul_tweak = "efbf7ba5a074276701798376950a64a90f698997cce0dff4d24a6d2785d20963";
        let mul_tweak_bytes = hex::decode(mul_tweak).unwrap();

        let add_tweak = "8be02a96a97b9a3c1c9f59ebb718401128b72ec009d85ee1656319b52319b8ce";
        let add_tweak_bytes = hex::decode(add_tweak).unwrap();

        let seed_hex_string = "000102030405060708090a0b0c0d0e0f";
        let seed_bytes = hex::decode(seed_hex_string).unwrap();
        let seed = Seed::new(seed_bytes);

        let signer = LightsparkSigner::new(&seed, Network::Bitcoin);
        let key = signer
            .tweak_key(
                secrect_key,
                Some(add_tweak_bytes.try_into().unwrap()),
                Some(mul_tweak_bytes.try_into().unwrap()),
            )
            .unwrap();

        let result_hex = "d09ffff62ddb2297ab000cc85bcb4283fdeb6aa052affbc9dddcf33b61078110";
        assert_eq!(format!("{}", key.display_secret()), result_hex);
    }

    #[test]
    fn test_preimage() {
        let seed_hex_string = "000102030405060708090a0b0c0d0e0f";
        let seed_bytes = hex::decode(seed_hex_string).unwrap();
        let seed = Seed::new(seed_bytes);

        let signer = LightsparkSigner::new(&seed, Network::Bitcoin);
        let nonce = signer.generate_preimage_nonce();
        let preimage = signer.generate_preimage(nonce.clone());
        let preimage_hash = Sha256::digest(preimage.unwrap()).to_vec();
        let preimage_hash2 = signer.generate_preimage_hash(nonce).unwrap();
        assert_eq!(preimage_hash, preimage_hash2);
    }
}
