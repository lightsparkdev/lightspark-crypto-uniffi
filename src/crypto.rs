use std::fmt;

use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use ecies::decrypt;
use ecies::encrypt;

#[derive(Clone, Copy, Debug)]
pub enum Error {
    Secp256k1Error(bitcoin::secp256k1::Error),
    RustSecp256k1Error(ecies::SecpError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Secp256k1Error(err) => write!(f, "Secp256k1 error {}", err),
            Self::RustSecp256k1Error(err) => write!(f, "Rust Secp256k1 error {}", err),
        }
    }
}

pub fn sign_ecdsa(msg: Vec<u8>, private_key_bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&private_key_bytes).map_err(Error::Secp256k1Error)?;
    let msg = Message::from_slice(&msg).map_err(Error::Secp256k1Error)?;
    let signature = secp.sign_ecdsa(&msg, &sk);
    Ok(signature.serialize_compact().to_vec())
}

pub fn verify_ecdsa(
    msg: Vec<u8>,
    signature_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
) -> Result<bool, Error> {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_slice(&public_key_bytes).map_err(Error::Secp256k1Error)?;
    let msg = Message::from_slice(&msg).map_err(Error::Secp256k1Error)?;
    let sig = Signature::from_compact(&signature_bytes).map_err(Error::Secp256k1Error)?;
    let result = secp.verify_ecdsa(&msg, &sig, &pk).is_ok();
    Ok(result)
}

pub fn encrypt_ecies(msg: Vec<u8>, public_key_bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
    encrypt(&public_key_bytes, &msg).map_err(Error::RustSecp256k1Error)
}

pub fn decrypt_ecies(cipher_text: Vec<u8>, private_key_bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
    decrypt(&private_key_bytes, &cipher_text).map_err(Error::RustSecp256k1Error)
}
