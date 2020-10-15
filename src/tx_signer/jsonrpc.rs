//! Support for fetching transaction signing requests via a simple JSONRPC
//! protocol.

use super::request::TxSigningRequest;
use crate::{
    error::{Error, ErrorKind},
    prelude::*,
};
use bytes::Buf;
use hyper::http::{header, Uri};
use serde::Deserialize;

/// Transaction builder JSONRPC client.
#[derive(Clone, Debug)]
pub struct Client {
    /// URL to fetch JSON document from
    uri: Uri,
}

impl Client {
    /// Create a new JSONRPC client.
    pub fn new(uri: Uri) -> Self {
        Self { uri }
    }

    /// Get the URI this client is requesting
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Request transactions to be signed from the transaction service
    pub async fn request(&self, _last_tx_ok: bool) -> Result<Vec<TxSigningRequest>, Error> {
        // TODO(tarcieri): incorporate `last_tx_ok` into request
        let mut request = hyper::Request::post(&self.uri).body(hyper::Body::empty())?;

        {
            let headers = request.headers_mut();
            headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
            headers.insert(
                header::USER_AGENT,
                format!("tmkms/{}", env!("CARGO_PKG_VERSION"))
                    .parse()
                    .unwrap(),
            );
        }

        let http_client = hyper::Client::builder().build_http();
        let response = http_client.request(request).await?;
        let response_body = hyper::body::aggregate(response.into_body()).await?;
        let response_json = serde_json::from_slice::<Response>(response_body.bytes())?;

        match response_json.status {
            Status::Ok => Ok(response_json.tx),
            Status::Error => fail!(
                ErrorKind::HttpError,
                "JSONRPC error: {}",
                response_json.msg.unwrap_or_default()
            ),
        }
    }
}

/// JSONRPC responses from the transaction builder service
#[derive(Clone, Debug, Deserialize)]
pub struct Response {
    /// Response status
    pub status: Status,

    /// Optional response message
    pub msg: Option<String>,

    /// Transaction signing requests
    #[serde(default)]
    pub tx: Vec<TxSigningRequest>,
}

/// JSONRPC response status
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq)]
pub enum Status {
    /// Success
    #[serde(rename = "ok")]
    Ok,

    /// Error
    #[serde(rename = "error")]
    Error,
}
