pub mod crypto;
pub mod remote_signing;
pub mod signer;

use crypto::decrypt_ecies;
use crypto::encrypt_ecies;
use crypto::generate_keypair;
use crypto::sign_ecdsa;
use crypto::verify_ecdsa;
use crypto::CryptoError;
use lightspark_remote_signing::validation::Validation;
use remote_signing::handle_remote_signing_webhook_event;
use remote_signing::RemoteSigningError;
use remote_signing::RemoteSigningResponse;

#[cfg(not(target_arch = "wasm32"))]
use crypto::KeyPair;
#[cfg(not(target_arch = "wasm32"))]
use signer::InvoiceSignature;
#[cfg(not(target_arch = "wasm32"))]
use signer::LightsparkSigner;
#[cfg(not(target_arch = "wasm32"))]
use signer::LightsparkSignerError;
#[cfg(not(target_arch = "wasm32"))]
use signer::Mnemonic;
#[cfg(not(target_arch = "wasm32"))]
use signer::Network;
#[cfg(not(target_arch = "wasm32"))]
use signer::Seed;

#[cfg(not(target_arch = "wasm32"))]
uniffi::include_scaffolding!("lightspark_crypto");
