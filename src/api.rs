use jsonrpc_http_server::{ServerBuilder};
use jsonrpc_http_server::jsonrpc_core::{IoHandler, Value, Params, Error};
use std::net::SocketAddr;
use crate::store::SharedContentStore;
use futures::StreamExt;

pub fn start_api (rpc_address: &SocketAddr, store: SharedContentStore) {
    let mut io = IoHandler::default();
    io.add_method("list", move |p:Params| {
        let mut cats = Vec::new();
        match p {
            Params::Array(array) => {
                for s in &array {
                    match s {
                        Value::String(s) => cats.push(s.clone()),
                        _ => return Err(Error::invalid_params("expecting strings as categories"))
                    }
                }
            }
            _ => return Err(Error::invalid_params("expecting an array of categories"))
        };
        match store.read().unwrap().list_abstracts(cats) {
            Ok(result) => return Ok(serde_json::to_value(result).unwrap()),
            Err(e) => {
                debug!("failed to retrieve abstracts {:?}", e);
                return Err(Error::internal_error());
            }
        };
    });

    let server = ServerBuilder::new(io)
        .start_http(rpc_address)
        .expect("Unable to start RPC server");

    server.wait();
}