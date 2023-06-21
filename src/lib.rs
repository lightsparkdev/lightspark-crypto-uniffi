pub mod signer;

#[cfg(not(target_arch = "wasm32"))]
use signer::LightsparkSigner;
#[cfg(not(target_arch = "wasm32"))]
use signer::LightsparkSignerError;
#[cfg(not(target_arch = "wasm32"))]
use signer::Mnemonic;
#[cfg(not(target_arch = "wasm32"))]
use signer::Seed;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[cfg(not(target_arch = "wasm32"))]
uniffi::include_scaffolding!("lightspark_crypto");
