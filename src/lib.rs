pub mod signer;

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
