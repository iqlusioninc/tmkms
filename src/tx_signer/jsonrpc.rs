//! Support for fetching transaction signing requests via a simple JSONRPC
//! protocol.

use super::tx_request::TxSigningRequest;
use crate::{
    error::{Error, ErrorKind},
    prelude::*,
};
use bytes::Buf;
use hyper::http::{header, Uri};
use serde::{Deserialize, Serialize};
use tendermint::chain;
use tendermint_rpc::endpoint::{broadcast::tx_commit, status};

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
    pub async fn request(&self, params: Request) -> Result<Option<TxSigningRequest>, Error> {
        let body = hyper::Body::from(params);
        let mut request = hyper::Request::post(&self.uri).body(body)?;

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

/// JSONRPC requests to the transaction builder service
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Request {
    /// Chain ID
    pub network: chain::Id,

    /// Arbitrary context string to pass to transaction source
    #[serde(default)]
    pub context: String,

    /// Network status
    pub status: status::Response,

    /// Response from last signed TX (if available)
    pub last_tx_response: Option<tx_commit::Response>,
}

impl From<Request> for hyper::Body {
    fn from(req: Request) -> hyper::Body {
        hyper::Body::from(serde_json::to_string(&req).expect("JSON serialization error"))
    }
}

/// JSONRPC responses from the transaction builder service
#[derive(Clone, Debug, Deserialize)]
pub struct Response {
    /// Response status
    pub status: Status,

    /// Optional response message
    pub msg: Option<String>,

    /// Transaction signing request
    #[serde(default)]
    pub tx: Option<TxSigningRequest>,
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
