pub mod crypto;
pub mod funds_recovery_kit;
pub mod remote_signing;
pub mod signer;

#[cfg(not(target_arch = "wasm32"))]
use crate::crypto::generate_multisig_address;
#[cfg(not(target_arch = "wasm32"))]
use crypto::decrypt_ecies;
#[cfg(not(target_arch = "wasm32"))]
use crypto::encrypt_ecies;
#[cfg(not(target_arch = "wasm32"))]
use crypto::generate_keypair;
#[cfg(not(target_arch = "wasm32"))]
use crypto::sign_ecdsa;
#[cfg(not(target_arch = "wasm32"))]
use crypto::verify_ecdsa;
#[cfg(not(target_arch = "wasm32"))]
use crypto::CryptoError;
#[cfg(not(target_arch = "wasm32"))]
use lightspark_remote_signing::validation::Validation;
#[cfg(not(target_arch = "wasm32"))]
use remote_signing::handle_remote_signing_webhook_event;
#[cfg(not(target_arch = "wasm32"))]
use remote_signing::RemoteSigningError;
#[cfg(not(target_arch = "wasm32"))]
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
use crate::funds_recovery_kit::sign_transactions;
#[cfg(not(target_arch = "wasm32"))]
use crate::funds_recovery_kit::FundsRecoveryKitError;
#[cfg(not(target_arch = "wasm32"))]
use funds_recovery_kit::Response;
#[cfg(not(target_arch = "wasm32"))]
use funds_recovery_kit::StringTuple;

#[cfg(not(target_arch = "wasm32"))]
uniffi::include_scaffolding!("lightspark_crypto");
