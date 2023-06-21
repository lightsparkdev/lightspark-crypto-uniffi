pub mod signer;

use signer::LightsparkSigner;
use signer::LightsparkSignerError;
use signer::Mnemonic;
use signer::Seed;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

uniffi::include_scaffolding!("lightspark_crypto");
