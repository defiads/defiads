[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

# Bitcoin Advertising Network

# Build
[Install Rust](https://www.rust-lang.org/learn/get-started)
```
$ cargo update
$ cargo build --release
```
# Run
```
$ target/release/biadnet
```

Databases and configuration will be stored in $HOME/.biadnet/bitcoin or $HOME/.biadnet/testnet depending on the 
--bitcoin-network option

## Options
```
USAGE:
    biadnet [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --biadnet-connections <n>                  Desired number of connections to the biadnet network [default: 5]
        --biadnet-discovery <biadnet-discovery>
            Enable/Disable biadnet network discovery [default: ON]  [possible values: ON, OFF]

        --biadnet-peers <ADDRESS>...               Biadnet network peers to connect
        --bitcoin-connections <n>                  Desired number of connections to the bitcoin network [default: 5]
        --bitcoin-discovery <bitcoin-discovery>
            Enable/Disable bitcoin network discovery [default: ON]  [possible values: ON, OFF]

        --bitcoin-network <NETWORK>
            Set the used bitcoin network. [default: bitcoin]  [possible values: bitcoin, testnet, regtest]

        --bitcoin-peers <ADDRESS>...               Bitcoin network peers to connect
        --config <FILE>                            Configuration file in .toml format [default: biadnet.cfg]
        --db <FILE>                                Database name [default: biadnet.db]
        --http-rpc <ADDRESS>                       Listen to http-rpc on this address. [default: 127.0.0.1:21767]
        --listen <ADDRESS>...                      Listen to incoming biadnet connections [default: 0.0.0.0:21766]
        --log-file <FILE>                          Log file path. [default: biadnet.log]
        --log-level <LEVEL>
            Set log level. [default: DEBUG]  [possible values: OFF, ERROR, WARN, INFO, DEBUG, TRACE]

        --storage-limit <n>                        Storage limit in GB [default: 1]

```