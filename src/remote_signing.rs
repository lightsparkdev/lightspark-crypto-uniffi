use std::fmt;

use lightspark_remote_signing::{
    handler::Handler,
    lightspark::{error::Error, webhooks::WebhookEvent},
    signer::{LightsparkSigner, Network, Seed},
    validation::Validation,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsError, JsValue};

#[derive(Debug)]
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
) -> Result<Option<RemoteSigningResponse>, RemoteSigningError> {
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
        Some("SIGNET") => Network::Signet,
        _ => return Err(RemoteSigningError::WebhookParsingError),
    };

    let signer = LightsparkSigner::new(&seed, network)
        .map_err(|_| RemoteSigningError::SignerCreationError)?;
    let handler = Handler::new(signer, validation);
    handler
        .handle_remote_signing_webhook_msg(&webhook_event)
        .map_err(|_| RemoteSigningError::RemoteSigningHandlerError)
        .map(|response| match response {
            None => None,
            Some(response) => Some(RemoteSigningResponse {
                query: response.query,
                variables: serde_json::to_string(&response.variables)
                    .expect("serde value to json should not fail"),
            }),
        })
}

#[wasm_bindgen]
extern "C" {
    pub type WasmValidation;

    #[wasm_bindgen(structural, method)]
    pub fn should_sign(this: &WasmValidation, request: String) -> bool;
}

unsafe impl Send for WasmValidation {}
unsafe impl Sync for WasmValidation {}

pub struct WasmValidator {
    js_validation: WasmValidation,
}

impl WasmValidator {
    pub fn new(js_validation: WasmValidation) -> Self {
        Self { js_validation }
    }
}

impl Validation for WasmValidator {
    fn should_sign(&self, webhook: String) -> bool {
        self.js_validation.should_sign(webhook)
    }
}

#[wasm_bindgen]
pub fn wasm_handle_remote_signing_webhook_event(
    webhook_data: Vec<u8>,
    webhook_signature: String,
    webhook_secret: String,
    master_seed_bytes: Vec<u8>,
    validation: &WasmValidation,
) -> Result<Option<RemoteSigningResponseWasm>, RemoteSigningError> {
    let validation = (*validation).clone();
    let validator = WasmValidator::new(WasmValidation { obj: validation });
    handle_remote_signing_webhook_event(
        webhook_data,
        webhook_signature,
        webhook_secret,
        master_seed_bytes,
        Box::new(validator),
    )
    .map(|response| match response {
        None => None,
        Some(response) => Some(RemoteSigningResponseWasm {
            query: response.query,
            variables: serde_json::to_string(&response.variables)
                .expect("serde value to json should not fail"),
        }),
    })
}

#[cfg(test)]
mod test {
    use lightspark_remote_signing::validation::PositiveValidator;

    use super::handle_remote_signing_webhook_event;

    #[test]
    fn test_handle_remote_signing() {
        let webhook_data_string = r###"
        {
            "event_type": "REMOTE_SIGNING",
            "event_id": "5053dbd8c5b0453494f1c14e01da69cd",
            "timestamp": "2023-09-18T23:50:15.355603+00:00",
            "entity_id": "node_with_server_signing:018a9635-3673-88df-0000-827f23051b19", 
            "data": {
                "sub_event_type": "DERIVE_KEY_AND_SIGN", 
                "bitcoin_network": "SIGNET",
                "signing_jobs": [{"id": "0195813b-ea49-4954-0000-68488c717815", "derivation_path": "m/3/913740152/0", "message": "54ce8d370b5bd43173d19ec535f86b4f7789992c414a549e5055c8ab51210881"}]
            }
        }
        "###;
        let sig = "cedd8170bb431c25cf49de32fedec94bf9051a782c34f02860927e97602dbe99";
        let sec = "39kyJO140v7fYkwHnR7jz8Y3UphqVeNYQk44Xx049ws";
        let seed = "1a6deac8f74fb2e332677e3f4833b5e962f80d153fb368b8ee322a9caca4113d56cccd88f1c6a74e152669d8cd373fee2f27e3645d80de27640177a8c71395f8";
        let master_seed_bytes = hex::decode(seed).unwrap();

        let validator = Box::new(PositiveValidator);
        let response = handle_remote_signing_webhook_event(
            webhook_data_string.as_bytes().to_vec(),
            sig.to_owned(),
            sec.to_owned(),
            master_seed_bytes,
            validator,
        );
        assert!(response.is_ok());
    }
}
