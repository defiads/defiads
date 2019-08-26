use jsonrpc_http_server::{ServerBuilder};
use jsonrpc_http_server::jsonrpc_core::{IoHandler, Value, Params, Error};
use std::net::SocketAddr;
use std::str::FromStr;
use crate::store::SharedContentStore;
use bitcoin::{Address};

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

fn parse_wallet_arguments (p: Params, api_key: &str) -> Result<(String, Vec<Value>), Error> {
    let mut result = Vec::new();
    match p {
        Params::Array(array) => {
            for v in &array {
                result.push(v.clone());
            }
        }
        _ => return Err(Error::invalid_params("expecting an array of strings"))
    }
    if result.len() < 2 {
        return Err(Error::invalid_params("missing api key and wallet passphrase"));
    }
    if let Value::String(ref s) = result[0] {
        if *s != api_key {
            return Err(Error::invalid_params("invalid api key"));
        }
    }
    else {
        return Err(Error::invalid_params("invalid api key"));
    }
    if let Value::String(ref s) = result[1] {
        return Ok((s.clone(), result[2..].to_vec()));
    }
    return Err(Error::invalid_params("invalid passpharse"));
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

    // get deposit address
    // METHOD: deposit
    // {"jsonrpc":"2.0","result":"address","id":1}
    let moved_store = store.clone();
    let moved_apikey = apikey.clone();
    io.add_method("deposit", move |p:Params| {
        parse_arguments(p,moved_apikey.as_str())?;
        Ok(serde_json::to_value(moved_store.write().unwrap().deposit_address().to_string()).unwrap())
    });

    // withdraw
    // METHOD: withdraw
    // ARGUMENTS: target_address, fee_per_byte, [amount]
    // if amount is not specified it withdraws all. Amount is in satoshis, fee is in satoshi/vByte
    // answer is (ordered by category name and weight descending):
    // {"jsonrpc":"2.0","result":"txid","id":1}
    let moved_store = store.clone();
    let moved_apikey = apikey.clone();
    io.add_method("withdraw", move |p:Params| {
        let (passpharse, args) = parse_wallet_arguments(p,moved_apikey.as_str())?;
        if args.len () < 2 {
            return Err(Error::invalid_params("missing target address and fee per byte"));
        }
        let address;
        let fee_per_vbyte;
        let mut amount: Option<u64> = None;
        if let Value::String(ref s) = args[0] {
            if let Ok(a) = Address::from_str(s.as_str()) {
                address = a;
            }
            else {
                return Err(Error::invalid_params("malformed address"));
            }
        }
        else {
            return Err(Error::invalid_params("malformed address"));
        }
        if let Value::Number(ref n) = args[1] {
            if let Some(sats) = n.as_u64() {
                fee_per_vbyte = std::cmp::min(sats, 100);
            }
            else {
                debug!("malformed fee");
                return Err(Error::invalid_params("malformed fee"));
            }
        }
        else {
            debug!("malformed fee");
            return Err(Error::invalid_params("malformed fee"));
        }
        if args.len () > 2 {
            if let Value::Number(ref n) = args[2] {
                amount = n.as_u64();
            }
        }
        match moved_store.write().unwrap().withdraw(passpharse, address, fee_per_vbyte, amount) {
            Ok(txid) => Ok(serde_json::to_value(txid).unwrap()),
            Err(e) => Err(Error::invalid_params(e.to_string().as_str()))
        }
    });

    let server = ServerBuilder::new(io)
        .start_http(rpc_address)
        .expect("Unable to start RPC server");

    server.wait();
}