use jsonrpc_http_server::{ServerBuilder};
use jsonrpc_http_server::jsonrpc_core::{IoHandler, Value, Params, Error};
use std::net::SocketAddr;
use crate::store::SharedContentStore;
use futures::StreamExt;

pub fn start_api (rpc_address: &SocketAddr, store: SharedContentStore) {
    let mut io = IoHandler::default();
    io.add_method("list", |p:Params| {
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
        }
        Ok(Value::String(cats.iter().fold(String::new(), |a, s| { a + s.as_str()})))
    });

    let server = ServerBuilder::new(io)
        .start_http(rpc_address)
        .expect("Unable to start RPC server");

    server.wait();
}