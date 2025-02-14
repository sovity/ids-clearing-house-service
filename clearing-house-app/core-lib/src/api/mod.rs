use std::string::ToString;
use rocket::serde::json::Value;
use crate::model::document::Document;

pub mod auth;
pub mod claims;
pub mod client;
pub mod crypto;

pub trait ApiClient{
    fn new(url: &str) -> Self;
    fn get_conf_param() -> String;
}

#[derive(Responder, Debug)]
pub enum ApiResponse {
    #[response(status = 200)]
    PreFlight(()),
    #[response(status = 400, content_type = "text/plain")]
    BadRequest(String),
    #[response(status = 201, content_type = "json")]
    SuccessCreate(Value),
    #[response(status = 200, content_type = "json")]
    SuccessOk(Value),
    #[response(status = 204, content_type = "text/plain")]
    SuccessNoContent(String),
    #[response(status = 401, content_type = "text/plain")]
    Unauthorized(String),
    #[response(status = 403, content_type = "text/plain")]
    Forbidden(String),
    #[response(status = 404, content_type = "text/plain")]
    NotFound(String),
    #[response(status = 500, content_type = "text/plain")]
    InternalError(String),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DocumentReceipt{
    pub timestamp: i64,
    pub pid: String,
    pub doc_id: String,
    pub chain_hash: String,
}

impl DocumentReceipt{
    pub fn new(timestamp: i64, pid: &str, doc_id: &str, chain_hash: &str) -> DocumentReceipt{
        DocumentReceipt{
            timestamp,
            pid: pid.to_string(),
            doc_id: doc_id.to_string(),
            chain_hash: chain_hash.to_string(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct QueryResult{
    pub date_from: i64,
    pub date_to: i64,
    pub page: Option<i32>,
    pub size: Option<i32>,
    pub order: String,
    pub documents: Vec<Document>
}

impl QueryResult{
    pub fn new(date_from: i64, date_to: i64, page: Option<i32>, size: Option<i32>, order: String, documents: Vec<Document>) -> QueryResult{
        QueryResult{
            date_from,
            date_to,
            page,
            size,
            order,
            documents
        }
    }
}