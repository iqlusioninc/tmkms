use serde::{Deserialize, Serialize};
use serde_json::Value;

///Vault message envelop
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root<T> {
    #[serde(rename = "request_id")]
    pub request_id: String,
    #[serde(rename = "lease_id")]
    pub lease_id: String,
    pub renewable: bool,
    #[serde(rename = "lease_duration")]
    pub lease_duration: i64,
    pub data: Option<T>,
    #[serde(rename = "wrap_info")]
    pub wrap_info: Value,
    pub warnings: Value,
    pub auth: Value,
}

///Vault's envelop payload for "data" field
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfLookupData {
    pub accessor: String,
    #[serde(rename = "creation_time")]
    pub creation_time: i64,
    #[serde(rename = "creation_ttl")]
    pub creation_ttl: i64,
    #[serde(rename = "display_name")]
    pub display_name: String,
    #[serde(rename = "entity_id")]
    pub entity_id: String,
    #[serde(rename = "expire_time")]
    pub expire_time: String,
    #[serde(rename = "explicit_max_ttl")]
    pub explicit_max_ttl: i64,
    pub id: String,
    #[serde(rename = "issue_time")]
    pub issue_time: String,
    pub meta: Value,
    #[serde(rename = "num_uses")]
    pub num_uses: i64,
    pub orphan: bool,
    pub path: String,
    pub policies: Vec<String>,
    pub renewable: bool,
    pub ttl: i64,
    #[serde(rename = "type")]
    pub type_field: String,
}
