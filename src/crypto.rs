use std::fmt;
use std::str::FromStr as _;
use std::sync::Arc;

use bitcoin::bip32::{DerivationPath, Xpub};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::{
    blockdata::{opcodes::all, script::Builder},
    PublicKey as BitcoinPublicKey,
};
use ecies::decrypt;
use ecies::encrypt;

use crate::signer::Network;

#[derive(Clone, Copy, Debug)]
pub enum CryptoError {
    Secp256k1Error(bitcoin::secp256k1::Error),
    RustSecp256k1Error,
    InvalidPublicKeyScriptError,
    KeyDerivationError,
    KeyTweakError,
}

#[derive(Clone)]
pub struct KeyPair {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl KeyPair {
    pub fn get_public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    pub fn get_private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Secp256k1Error(err) => write!(f, "Secp256k1 error {}", err),
            Self::RustSecp256k1Error => write!(f, "Rust Secp256k1 error"),
            Self::InvalidPublicKeyScriptError => write!(f, "Invalid public key script"),
            Self::KeyDerivationError => write!(f, "Key derivation error"),
            Self::KeyTweakError => write!(f, "Key tweak error"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub fn sign_ecdsa(msg: Vec<u8>, private_key_bytes: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&private_key_bytes).map_err(CryptoError::Secp256k1Error)?;
    let digest = sha256::Hash::hash(&msg);
    let msg = Message::from_digest(digest.to_byte_array());
    let signature = secp.sign_ecdsa(&msg, &sk);
    Ok(signature.serialize_der().to_vec())
}

pub fn verify_ecdsa(
    msg: Vec<u8>,
    signature_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
) -> Result<bool, CryptoError> {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_slice(&public_key_bytes).map_err(CryptoError::Secp256k1Error)?;
    let digest = sha256::Hash::hash(&msg);
    let msg = Message::from_digest(digest.to_byte_array());
    let sig = Signature::from_der(&signature_bytes).map_err(CryptoError::Secp256k1Error)?;
    let result = secp.verify_ecdsa(&msg, &sig, &pk).is_ok();
    Ok(result)
}

pub fn encrypt_ecies(msg: Vec<u8>, public_key_bytes: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    encrypt(&public_key_bytes, &msg).map_err(|_| CryptoError::RustSecp256k1Error)
}

pub fn decrypt_ecies(
    cipher_text: Vec<u8>,
    private_key_bytes: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    decrypt(&private_key_bytes, &cipher_text).map_err(|_| CryptoError::RustSecp256k1Error)
}

pub fn generate_keypair() -> Result<Arc<KeyPair>, CryptoError> {
    let (sk, pk) = ecies::utils::generate_keypair();
    let keypair = KeyPair {
        private_key: sk.serialize().to_vec(),
        public_key: pk.serialize().to_vec(),
    };
    Ok(keypair.into())
}

pub fn derive_and_tweak_pubkey(
    pubkey: String,
    derivation_path: String,
    add_tweak: Option<Vec<u8>>,
    mul_tweak: Option<Vec<u8>>,
) -> Result<Vec<u8>, CryptoError> {
    let secp = Secp256k1::new();
    let path =
        DerivationPath::from_str(&derivation_path).map_err(|_| CryptoError::KeyDerivationError)?;
    let xpub = Xpub::from_str(&pubkey).map_err(|_| CryptoError::KeyDerivationError)?;
    let derived_pubkey = xpub
        .derive_pub(&secp, &path)
        .map_err(|_| CryptoError::KeyDerivationError)?;

    let mut pubkey = derived_pubkey.public_key;
    if let Some(tweak) = mul_tweak {
        let tweak_bytes: [u8; 32] = tweak.try_into().map_err(|_| CryptoError::KeyTweakError)?;
        let tweak_scalar =
            Scalar::from_be_bytes(tweak_bytes).map_err(|_| CryptoError::KeyTweakError)?;
        pubkey = pubkey
            .mul_tweak(&secp, &tweak_scalar)
            .map_err(|_| CryptoError::KeyTweakError)?;
    }

    if let Some(tweak) = add_tweak {
        let tweak_bytes: [u8; 32] = tweak.try_into().map_err(|_| CryptoError::KeyTweakError)?;
        let tweak_scalar =
            Scalar::from_be_bytes(tweak_bytes).map_err(|_| CryptoError::KeyTweakError)?;
        pubkey = pubkey
            .add_exp_tweak(&secp, &tweak_scalar)
            .map_err(|_| CryptoError::KeyTweakError)?;
    }
    Ok(pubkey.serialize().to_vec())
}

pub fn generate_multisig_address(
    network: Network,
    pk1: Vec<u8>,
    pk2: Vec<u8>,
) -> Result<String, CryptoError> {
    let pk1_obj =
        BitcoinPublicKey::new(PublicKey::from_slice(&pk1).map_err(CryptoError::Secp256k1Error)?);
    let pk2_obj =
        BitcoinPublicKey::new(PublicKey::from_slice(&pk2).map_err(CryptoError::Secp256k1Error)?);
    let network = match network {
        Network::Bitcoin => bitcoin_bech32::constants::Network::Bitcoin,
        Network::Testnet => bitcoin_bech32::constants::Network::Testnet,
        Network::Regtest => bitcoin_bech32::constants::Network::Regtest,
    };
    _generate_multisig_address(network, &pk1_obj, &pk2_obj)
}

fn _generate_multisig_address(
    network: bitcoin_bech32::constants::Network,
    pk1: &BitcoinPublicKey,
    pk2: &BitcoinPublicKey,
) -> Result<String, CryptoError> {
    let mut builder = Builder::new();
    builder = builder.push_opcode(all::OP_PUSHNUM_2);

    // The public keys need to be properly ordered in a multisig script.
    if pk1 < pk2 {
        builder = builder.push_key(&pk1);
        builder = builder.push_key(&pk2);
    } else {
        builder = builder.push_key(&pk2);
        builder = builder.push_key(&pk1);
    }

    builder = builder.push_opcode(all::OP_PUSHNUM_2);
    builder = builder.push_opcode(all::OP_CHECKMULTISIG);

    let script = builder.into_script().to_p2wsh();

    Ok(
        bitcoin_bech32::WitnessProgram::from_scriptpubkey(script.as_bytes(), network.into())
            .map_err(|_| CryptoError::InvalidPublicKeyScriptError)?
            .to_address(),
    )
}

#[cfg(test)]
mod tests {
    use ecies::utils::generate_keypair;

    use crate::signer::{LightsparkSigner, Seed};

    use super::*;

    #[test]
    fn test_ecdsa() {
        let (sk, pk) = generate_keypair();
        let msg = b"hello world";
        let signature = sign_ecdsa(msg.to_vec(), sk.serialize().to_vec()).unwrap();
        let result = verify_ecdsa(msg.to_vec(), signature, pk.serialize().to_vec()).unwrap();
        assert_eq!(result, true);
    }

    #[test]
    fn test_ecies() {
        let (sk, pk) = generate_keypair();
        let msg = b"hello world";
        let cipher_text = encrypt_ecies(msg.to_vec(), pk.serialize().to_vec()).unwrap();
        let plain_text = decrypt_ecies(cipher_text, sk.serialize().to_vec()).unwrap();
        assert_eq!(plain_text, msg.to_vec());
    }

    use super::generate_multisig_address;

    #[test]
    fn test_generate_multisig_address() {
        let address = generate_multisig_address(
            Network::Regtest,
            hex::decode("0247997a5c32ccf934257a675c306bf6ec37019358240156628af62baad7066a83")
                .unwrap(),
            hex::decode("03b66b574670a7b6bea89c0548903f70a6f059fd9abe737dc4c5aafe14a127408f")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(
            address,
            "bcrt1qwgpja522vatddf0vfggrej8pcjrzvzcpkl5yvxzzq4djwr0gj9asrk86y9"
        )
    }

    #[test]
    fn test_generate_multisig_address_reversed() {
        let address = generate_multisig_address(
            Network::Regtest,
            hex::decode("03b66b574670a7b6bea89c0548903f70a6f059fd9abe737dc4c5aafe14a127408f")
                .unwrap(),
            hex::decode("0247997a5c32ccf934257a675c306bf6ec37019358240156628af62baad7066a83")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(
            address,
            "bcrt1qwgpja522vatddf0vfggrej8pcjrzvzcpkl5yvxzzq4djwr0gj9asrk86y9"
        )
    }

    #[test]
    fn test_derive_and_tweak_pubkey() {
        let seed_hex_string = "000102030405060708090a0b0c0d0e0f";
        let seed_bytes = hex::decode(seed_hex_string).unwrap();
        let seed = Seed::new(seed_bytes);

        let signer = LightsparkSigner::new(&seed, Network::Bitcoin).unwrap();
        let xpub = signer.derive_public_key("m".to_owned()).unwrap();

        let message =
            hex::decode("9a0c7185121c40850e3e40d3170a5b408374217dc617067f3d7760c522733cef")
                .unwrap();

        let derivation_path = "m/3/1234856/4";
        let add_tweak =
            hex::decode("a66cd04862ae9041906f027db9cd43783dad06615fdf9001c5369b315fbef90a")
                .unwrap();
        let mul_tweak =
            hex::decode("d273f16519917211ffee805216b7cb5ae14600eeca5fbc84cefae62cf6a011a4")
                .unwrap();

        let signature = signer
            .derive_key_and_sign(
                message.clone(),
                derivation_path.to_string(),
                true,
                Some(add_tweak.clone()),
                Some(mul_tweak.clone()),
            )
            .unwrap();

        let pubkey = derive_and_tweak_pubkey(
            xpub,
            derivation_path.to_string(),
            Some(add_tweak.clone()),
            Some(mul_tweak.clone()),
        )
        .unwrap();

        let verify_message = Message::from_digest_slice(message.as_slice()).unwrap();
        let secp = Secp256k1::new();
        let sig = Signature::from_compact(&signature).unwrap();
        let pk = PublicKey::from_slice(&pubkey).unwrap();

        assert!(secp.verify_ecdsa(&verify_message, &sig, &pk).is_ok());
    }
}
