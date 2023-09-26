use std::fmt;

use lightspark::{error::Error, webhooks::WebhookEvent};
use lightspark_remote_signing::{
    handler::Handler,
    signer::{LightsparkSigner, Network, Seed},
    validation::Validation,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsError, JsValue};

pub struct RemoteSigningResponse {
    pub query: String,
    pub variables: String,
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct RemoteSigningResponseWasm {
    query: String,
    variables: String,
}

#[wasm_bindgen]
impl RemoteSigningResponseWasm {
    #[wasm_bindgen(getter)]
    pub fn query(&self) -> String {
        self.query.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn variables(&self) -> String {
        self.variables.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_query(&mut self, query: String) {
        self.query = query;
    }

    #[wasm_bindgen(setter)]
    pub fn set_variables(&mut self, variables: String) {
        self.variables = variables;
    }
}

#[wasm_bindgen]
#[derive(Clone, Copy, Debug)]
pub enum RemoteSigningError {
    WebhookParsingError,
    WebhookSignatureError,
    SignerCreationError,
    RemoteSigningHandlerError,
}

impl fmt::Display for RemoteSigningError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::WebhookParsingError => write!(f, "Webhook parsing error"),
            Self::WebhookSignatureError => write!(f, "Webhook signature error"),
            Self::SignerCreationError => write!(f, "Signer creation error"),
            Self::RemoteSigningHandlerError => write!(f, "Remote signing handler error"),
        }
    }
}

impl std::error::Error for RemoteSigningError {}

impl From<RemoteSigningError> for JsValue {
    fn from(val: RemoteSigningError) -> Self {
        JsError::from(val).into()
    }
}

pub fn handle_remote_signing_webhook_event(
    webhook_data: Vec<u8>,
    webhook_signature: String,
    webhook_secret: String,
    master_seed_bytes: Vec<u8>,
    validation: Box<dyn Validation>,
) -> Result<RemoteSigningResponse, RemoteSigningError> {
    let webhook_event =
        WebhookEvent::verify_and_parse(&webhook_data, &webhook_signature, &webhook_secret)
            .map_err(|e| match e {
                Error::WebhookSignatureError => RemoteSigningError::WebhookSignatureError,
                _ => RemoteSigningError::WebhookParsingError,
            })?;

    let seed = Seed::new(master_seed_bytes);
    let data = match webhook_event.data {
        Some(ref data) => data,
        None => return Err(RemoteSigningError::WebhookParsingError),
    };

    let network = match data["bitcoin_network"].as_str() {
        Some("REGTEST") => Network::Regtest,
        Some("MAINNET") => Network::Bitcoin,
        Some("TESTNET") => Network::Testnet,
        _ => return Err(RemoteSigningError::WebhookParsingError),
    };

    let signer = LightsparkSigner::new(&seed, network)
        .map_err(|_| RemoteSigningError::SignerCreationError)?;
    let handler = Handler::new(signer, validation);
    handler
        .handle_remote_signing_webhook_msg(&webhook_event)
        .map_err(|_| RemoteSigningError::RemoteSigningHandlerError)
        .map(|response| RemoteSigningResponse {
            query: response.query,
            variables: serde_json::to_string(&response.variables)
                .expect("serde value to json should not fail"),
        })
}


#[wasm_bindgen]
extern "C" {
    pub type JsValidation;

    #[wasm_bindgen(structural, method)]
    pub fn validate(this: &JsValidation, request: String) -> bool;
}

unsafe impl Send for JsValidation {}
unsafe impl Sync for JsValidation {}

pub struct WasmValidator {
    js_validation: JsValidation,
}

impl WasmValidator {
    pub fn new(js_validation: JsValidation) -> Self {
        Self { js_validation }
    }
}

impl Validation for WasmValidator {
    fn should_sign(&self, webhook: String) -> bool {
        self.js_validation.validate(webhook)
    }
}

#[wasm_bindgen]
pub fn wasm_handle_remote_signing_webhook_event(
    webhook_data: Vec<u8>,
    webhook_signature: String,
    webhook_secret: String,
    master_seed_bytes: Vec<u8>,
    validation: JsValidation,
) -> Result<RemoteSigningResponseWasm, RemoteSigningError> {
    let validator = WasmValidator::new(validation);
    handle_remote_signing_webhook_event(
        webhook_data,
        webhook_signature,
        webhook_secret,
        master_seed_bytes,
        Box::new(validator),
    ).map(|response| RemoteSigningResponseWasm {
        query: response.query,
        variables: response.variables,
    })
}
