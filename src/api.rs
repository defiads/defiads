use jsonrpc_http_server::{ServerBuilder};
use jsonrpc_http_server::jsonrpc_core::{IoHandler, Value, Params, Error};
use std::net::SocketAddr;
use crate::store::SharedContentStore;

fn parse_arguments (p: Params, api_key: &str) -> Result<Vec<String>, Error> {
    let mut result = Vec::new();
    match p {
        Params::Array(array) => {
            for s in &array {
                match s {
                    Value::String(s) => result.push(s.clone()),
                    _ => return Err(Error::invalid_params("expecting strings"))
                }
            }
        }
        _ => return Err(Error::invalid_params("expecting an array of strings"))
    }
    if result.len() < 1 {
        return Err(Error::invalid_params("missing api key"));
    }
    if result [0].as_str() != api_key {
        return Err(Error::invalid_params("invalid api key"));
    }
    return Ok(result[1..].to_vec());
}

pub fn start_api (rpc_address: &SocketAddr, store: SharedContentStore, apikey: String) {
    let mut io = IoHandler::default();

    // call endpoints with:
    // curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "METHOD", "params": ["apikey", "ARGUMENTS"...] "id":1}' 127.0.0.1:21767
    // see biadnet.cfg for apikey


    // list known categories
    // METHOD: categories
    // ARGUMENTS: none
    // answer is:
    // {"jsonrpc":"2.0","result":["category", ...],"id":1}
    let moved_store = store.clone();
    let moved_apikey = apikey.clone();
    io.add_method("categories", move |p| {
        parse_arguments(p,moved_apikey.as_str())?;
        match moved_store.read().unwrap().list_categories() {
            Ok(result) => return Ok(serde_json::to_value(result).unwrap()),
            Err(e) => {
                debug!("failed to retrieve categories {:?}", e);
                return Err(Error::internal_error());
            }
        };
    });

    // list ids and abstracts for categories
    // METHOD: list
    // ARGUMENTS: "category", ...
    // answer is (ordered by category name and weight descending):
    // {"jsonrpc":"2.0","result":[["id","cat","abstract"]...],"id":1}
    let moved_store = store.clone();
    let moved_apikey = apikey.clone();
    io.add_method("list", move |p:Params| {
        let cats = parse_arguments(p,moved_apikey.as_str())?;
        match moved_store.read().unwrap().list_abstracts(cats) {
            Ok(result) => return Ok(serde_json::to_value(result).unwrap()),
            Err(e) => {
                debug!("failed to retrieve abstracts {:?}", e);
                return Err(Error::internal_error());
            }
        };
    });

    // read content
    // METHOD: read
    // ARGUMENTS: "id", ...
    // answer is (ordered by category name and weight descending):
    // {"jsonrpc":"2.0","result":[{ content }...],"id":1}
    let moved_store = store.clone();
    let moved_apikey = apikey.clone();
    io.add_method("read", move |p:Params| {
        let ids = parse_arguments(p,moved_apikey.as_str())?;
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