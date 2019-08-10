use jsonrpc_http_server::{ServerBuilder};
use jsonrpc_http_server::jsonrpc_core::{IoHandler, Value, Params, Error};
use std::net::SocketAddr;
use crate::store::SharedContentStore;
use futures::StreamExt;

pub fn start_api (rpc_address: &SocketAddr, store: SharedContentStore) {
    let mut io = IoHandler::default();

    // list known categories
    // call with
    // curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "categories", "id":1}' 127.0.0.1:21767
    // answer is:
    // {"jsonrpc":"2.0","result":["category", ...],"id":1}
    let moved_store = store.clone();
    io.add_method("categories", move |_| {
        match moved_store.read().unwrap().list_categories() {
            Ok(result) => return Ok(serde_json::to_value(result).unwrap()),
            Err(e) => {
                debug!("failed to retrieve categories {:?}", e);
                return Err(Error::internal_error());
            }
        };
    });

    // list ids and abstracts for categories
    // params is an array of categories
    // call with
    // curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "list", "params":["misc","other"], "id":1}' 127.0.0.1:21767
    // answer is (ordered by category name and weight descending):
    // {"jsonrpc":"2.0","result":[["id","cat","abstract"]...],"id":1}
    let moved_store = store.clone();
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
        match moved_store.read().unwrap().list_abstracts(cats) {
            Ok(result) => return Ok(serde_json::to_value(result).unwrap()),
            Err(e) => {
                debug!("failed to retrieve abstracts {:?}", e);
                return Err(Error::internal_error());
            }
        };
    });

    // read content
    // params is an array of content ids
    // call with
    // curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "read", "params":["id"...], "id":1}' 127.0.0.1:21767
    // answer is (ordered by category name and weight descending):
    // {"jsonrpc":"2.0","result":[{ content }...],"id":1}
    let moved_store = store.clone();
    io.add_method("read", move |p:Params| {
        let mut ids = Vec::new();
        match p {
            Params::Array(array) => {
                for s in &array {
                    match s {
                        Value::String(s) => ids.push(s.clone()),
                        _ => return Err(Error::invalid_params("expecting string id to read"))
                    }
                }
            }
            _ => return Err(Error::invalid_params("expecting an array of ids"))
        };
        match moved_store.read().unwrap().read_contents(ids) {
            Ok(result) => return Ok(serde_json::to_value(result).unwrap()),
            Err(e) => {
                debug!("failed to retrieve content {:?}", e);
                return Err(Error::internal_error());
            }
        };
    });


    let server = ServerBuilder::new(io)
        .start_http(rpc_address)
        .expect("Unable to start RPC server");

    server.wait();
}