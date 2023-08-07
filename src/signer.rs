use std::{fmt, str::FromStr};

use bip32::{secp256k1::ecdsa::signature::Signer, secp256k1::ecdsa::Signature, Prefix, XPrv, XPub};
use k256::{
    ecdh,
    elliptic_curve::{generic_array::GenericArray, FieldBytes, PrimeField, Scalar},
    NonZeroScalar, Secp256k1,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsError, JsValue};

#[derive(Copy, Clone, Debug)]
pub enum LightsparkSignerError {
    Bip32Error(bip32::Error),
    TweakMustHaveBoth,
    KeyTweakError,
    EntropyLengthError,
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

impl Into<JsValue> for LightsparkSignerError {
    fn into(self) -> JsValue {
        JsError::from(self).into()
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
        let internal = bip32::Mnemonic::random(&mut OsRng, Default::default());
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
            .map_err(|e| LightsparkSignerError::Bip32Error(e))?;
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
pub struct LightsparkSigner {
    seed: Seed,
    node_private_key: XPrv,
    commitment_seed: Vec<u8>,
}

#[wasm_bindgen]
impl LightsparkSigner {
    pub fn new(seed: &Seed) -> Self {
        let seed = (*seed).clone();
        let node_private_key =
            XPrv::derive_from_path(seed.as_bytes(), &"m/0".parse().unwrap()).unwrap();
        let commitment_seed = Self::build_commitment_seed(&seed);
        Self {
            seed,
            node_private_key,
            commitment_seed,
        }
    }

    pub fn from_bytes(seed: Vec<u8>) -> Self {
        let seed = Seed::new(seed.clone());
        Self::new(&seed)
    }

    fn build_commitment_seed(seed: &Seed) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(b"commitment seed");
        hasher.finalize().to_vec()
    }

    pub fn get_master_public_key(&self) -> Result<String, LightsparkSignerError> {
        self.derive_public_key("m".to_owned())
    }

    pub fn derive_public_key(
        &self,
        derivation_path: String,
    ) -> Result<String, LightsparkSignerError> {
        let xprv = self
            .derive_key(derivation_path)
            .map_err(|e| LightsparkSignerError::Bip32Error(e))?;
        let public_key = xprv.public_key();
        Ok(public_key.to_string(Prefix::XPUB))
    }

    pub fn derive_key_and_sign(
        &self,
        message: Vec<u8>,
        derivation_path: String,
        add_tweak: Option<Vec<u8>>,
        mul_tweak: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, LightsparkSignerError> {
        let signing_key = self.derive_and_tweak_key(derivation_path, add_tweak, mul_tweak)?;
        let signature: Signature = signing_key.sign(&message.as_slice());
        Ok(signature.to_bytes().to_vec())
    }

    pub fn ecdh(&self, public_key: String) -> Result<Vec<u8>, LightsparkSignerError> {
        let secret_key = self.node_private_key.private_key().as_nonzero_scalar();
        let public_key =
            XPub::from_str(&public_key).map_err(|e| LightsparkSignerError::Bip32Error(e))?;
        let shared_secret = ecdh::diffie_hellman(secret_key, public_key.public_key().as_affine());
        Ok(shared_secret.raw_secret_bytes().to_vec())
    }

    pub fn sign_invoice(&self, unsigned_invoice: String) -> Vec<u8> {
        let signing_key = self.node_private_key.private_key();
        let signature: Signature = signing_key.sign(&unsigned_invoice.as_bytes());
        signature.to_bytes().to_vec()
    }

    #[allow(unused_variables)] // TODO: remove after implementation
    pub fn get_per_commitment_point(&self, channel: u64, per_commitment_point_idx: u64) -> Vec<u8> {
        unimplemented!()
    }

    #[allow(unused_variables)] // TODO: remove after implementation
    pub fn build_commitment_secret(&self, channel: u64, per_commitment_point_idx: u64) -> Vec<u8> {
        let mut res = self.commitment_seed.clone();
        for i in 0..48 {
            let bitpos = 47 - i;
            if per_commitment_point_idx & (1 << bitpos) == (1 << bitpos) {
                res[bitpos / 8] ^= 1 << (bitpos & 7);
                res = Sha256::digest(&res).to_vec();
            }
        }
        res
    }

    fn derive_and_tweak_key(
        &self,
        derivation_path: String,
        add_tweak: Option<Vec<u8>>,
        mul_tweak: Option<Vec<u8>>,
    ) -> Result<k256::ecdsa::SigningKey, LightsparkSignerError> {
        let xprv = self
            .derive_key(derivation_path)
            .map_err(|e| LightsparkSignerError::Bip32Error(e))?;
        //unwrap add_tweak and mul_tweak
        if add_tweak.is_some() && mul_tweak.is_some() {
            let private_key_scalar = xprv.private_key().as_nonzero_scalar();
            let tweaked_key =
                self.tweak_key(*private_key_scalar, add_tweak.unwrap(), mul_tweak.unwrap())?;

            let key_bytes = tweaked_key.to_bytes();

            let signing_key = k256::ecdsa::SigningKey::from_bytes(&key_bytes)
                .map_err(|_| LightsparkSignerError::KeyTweakError)?;
            Ok(signing_key)
        } else if add_tweak.is_some() || mul_tweak.is_some() {
            Err(LightsparkSignerError::TweakMustHaveBoth)
        } else {
            Ok(xprv.clone().private_key().to_owned())
        }
    }

    fn derive_key(&self, derivation_path: String) -> Result<XPrv, bip32::Error> {
        let xprv = XPrv::derive_from_path(&self.seed.as_bytes(), &derivation_path.parse()?)?;
        Ok(xprv)
    }

    fn tweak_key(
        &self,
        key_scalar: NonZeroScalar,
        add_tweak: Vec<u8>,
        mul_tweak: Vec<u8>,
    ) -> Result<NonZeroScalar, LightsparkSignerError> {
        let mul_tweak_bytes: [u8; 32] = mul_tweak
            .try_into()
            .map_err(|_| LightsparkSignerError::KeyTweakError)?;
        let mul_scalar = Scalar::<Secp256k1>::from_repr(FieldBytes::<Secp256k1>::from(
            GenericArray::from(mul_tweak_bytes),
        ));

        let add_tweak_bytes: [u8; 32] = add_tweak
            .try_into()
            .map_err(|_| LightsparkSignerError::KeyTweakError)?;
        let add_scalar = Scalar::<Secp256k1>::from_repr(FieldBytes::<Secp256k1>::from(
            GenericArray::from(add_tweak_bytes),
        ));

        if mul_scalar.is_some().into() && add_scalar.is_some().into() {
            let modified_key = key_scalar.mul(&mul_scalar.unwrap());
            let modified_key = modified_key.add(&add_scalar.unwrap());
            let result = NonZeroScalar::new(modified_key);
            if result.is_some().into() {
                return Ok(result.unwrap());
            } else {
                return Err(LightsparkSignerError::KeyTweakError);
            }
        } else {
            return Err(LightsparkSignerError::KeyTweakError);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip32::secp256k1::ecdsa::{signature::Verifier, Signature};
    use hex;

    #[test]
    fn test_key_derivation() {
        let seed_hex_string = "000102030405060708090a0b0c0d0e0f";
        let seed_bytes = hex::decode(seed_hex_string).unwrap();
        let seed = Seed::new(seed_bytes);

        let signer = LightsparkSigner::new(&seed);
        let xprv = signer.derive_key("m".to_owned()).unwrap();
        let xprv_string = xprv.to_string(Prefix::XPRV);
        let expected_string = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        assert_eq!(xprv_string.as_str(), expected_string);

        let signer = LightsparkSigner::new(&seed);
        let xprv = signer.derive_key("m/0'".to_owned()).unwrap();
        let xprv_string = xprv.to_string(Prefix::XPRV);
        let expected_string = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
        assert_eq!(xprv_string.as_str(), expected_string);
    }

    #[test]
    fn test_public_key() {
        let seed_hex_string = "000102030405060708090a0b0c0d0e0f";
        let seed_bytes = hex::decode(seed_hex_string).unwrap();
        let seed = Seed::new(seed_bytes);

        let signer = LightsparkSigner::new(&seed);
        let public_key_string = signer.derive_public_key("m".to_owned()).unwrap();
        let expected_string = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        assert_eq!(public_key_string, expected_string);

        let signer = LightsparkSigner::new(&seed);
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

        let signer = LightsparkSigner::new(&seed);
        let xprv = signer.derive_key("m".to_owned()).unwrap();
        let xpub = xprv.public_key();
        assert_eq!(xpub.to_string(Prefix::XPUB), public_key_string);

        let verification_key = xpub.public_key();

        let message = b"Hello, world!";
        let signature_bytes =
            signer.derive_key_and_sign(message.to_vec(), "m".to_owned(), None, None);

        let signature: Signature = Signature::from_slice(&signature_bytes.unwrap()).unwrap();
        assert!(verification_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_ecdh() {
        let seed1_hex_string = "000102030405060708090a0b0c0d0e0f";
        let seed1_bytes = hex::decode(seed1_hex_string).unwrap();
        let seed1 = Seed::new(seed1_bytes);

        let seed2_hex_string = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
        let seed2_bytes = hex::decode(seed2_hex_string).unwrap();
        let seed2 = Seed::new(seed2_bytes);

        let signer1 = LightsparkSigner::new(&seed1);
        let pub1 = signer1.derive_public_key("m/0".to_owned()).unwrap();

        let signer2 = LightsparkSigner::new(&seed2);
        let pub2 = signer2.derive_public_key("m/0".to_owned()).unwrap();

        let secret_1 = signer1.ecdh(pub2.to_string()).unwrap();
        let secret_2 = signer2.ecdh(pub1.to_string()).unwrap();
        assert_eq!(secret_1, secret_2);
    }

    #[test]
    fn test_tweak() {
        let base_hex_string = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let base_bytes = hex::decode(base_hex_string).unwrap();

        let mul_tweak = "efbf7ba5a074276701798376950a64a90f698997cce0dff4d24a6d2785d20963";
        let mul_tweak_bytes = hex::decode(mul_tweak).unwrap();

        let add_tweak = "8be02a96a97b9a3c1c9f59ebb718401128b72ec009d85ee1656319b52319b8ce";
        let add_tweak_bytes = hex::decode(add_tweak).unwrap();

        let seed_hex_string = "000102030405060708090a0b0c0d0e0f";
        let seed_bytes = hex::decode(seed_hex_string).unwrap();
        let seed = Seed::new(seed_bytes);

        let signer = LightsparkSigner::new(&seed);
        let array = GenericArray::from_slice(&base_bytes);
        let key = signer
            .tweak_key(
                NonZeroScalar::from_repr(FieldBytes::<Secp256k1>::from(*array)).unwrap(),
                add_tweak_bytes,
                mul_tweak_bytes,
            )
            .unwrap();

        let result_hex = "d09ffff62ddb2297ab000cc85bcb4283fdeb6aa052affbc9dddcf33b61078110";
        let result_bytes = hex::decode(result_hex).unwrap();

        assert_eq!(key.to_bytes().to_vec(), result_bytes);
    }
}
