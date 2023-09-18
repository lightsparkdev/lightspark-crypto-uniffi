use std::fmt;

use lightspark::{error::Error, webhooks::WebhookEvent};
use lightspark_remote_signing::{
    handler::Handler,
    signer::{LightsparkSigner, Network, Seed},
    validation::Validation,
};

pub struct RemoteSigningResponse {
    pub query: String,
    pub variables: String,
}

#[derive(Clone, Copy, Debug)]
pub enum RemoteSigningError {
    WebhookParsingError,
    WebhookSignatureError,
    RemoteSigningHandlerError,
}

impl fmt::Display for RemoteSigningError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::WebhookParsingError => write!(f, "Webhook parsing error"),
            Self::WebhookSignatureError => write!(f, "Webhook signature error"),
            Self::RemoteSigningHandlerError => write!(f, "Remote signing handler error"),
        }
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
    let signer = LightsparkSigner::new(&seed, Network::Bitcoin).unwrap();
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
