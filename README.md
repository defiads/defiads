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
        --http-rpc <ADDRESS>                       Listen to http-rpc on this address. [default: 127.0.0.1:21767]
        --listen <ADDRESS>...                      Listen to incoming biadnet connections [default: 0.0.0.0:21766]
        --log-level <LEVEL>
            Set log level. [default: DEBUG]  [possible values: OFF, ERROR, WARN, INFO, DEBUG, TRACE]

        --storage-limit <n>                        Storage limit in GB [default: 1]

```

## First Use
At first use biadnet will generate a key for its bitcoin wallet. The key format follows that of popular wallets and is
compatible with TREZOR, Ledger etc.

The human readable representation of the key are 24 words. You should write them down and keep off-line. The same
words are stored encrypted in the biadnet.cfg file. You set the encryption password at first use. Remember this as 
there is no other way to recover the words from the encrypted storage.

## RPC API
Use JSON RPC 2.0 calls e.g. with curl as follows, assuming the process runs on your local machine. Port is <b>21767</b> for 
the real and <b>21867</b> for the testnet bitcoin network, see option --bitcoin-network. 
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "METHOD", "params": ["ARGUMENTS"...] "id":1}' 127.0.0.1:21767

```
Where the first argument is always an API Key which is unique to this installation. You find the API key in the
biadnet.cfg file.  

The second argument is the encryption key for methods that move bitcoins.

### API Methods
#### categories
Lists the known ad categories. Example call:
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "categories", "params": ["KxNoYPdNXUcN0TvM"], "id":1}' 127.0.0.1:21867

```
Example reply
```
{"jsonrpc":"2.0","result":["misc", "alt"],"id":1}

```
#### list
Lists the ads within a category. Example call:
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "list", "params": ["KxNoYPdNXUcN0TvM", "misc"], "id":1}' 127.0.0.1:21867

```
Example reply
```
{"jsonrpc":"2.0","result":["5bb72726e3df5837f2e3496731b22cda904ce08205c6c153037f7b52ebc3d96a", "misc", "Some abstract"],"id":1}

```
#### read
Read an ad
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "read", "params": ["KxNoYPdNXUcN0TvM", "5bb72726e3df5837f2e3496731b22cda904ce08205c6c153037f7b52ebc3d96a"], "id":1}' 127.0.0.1:21867

```
#### deposit
Get a deposit address of the wallet. Transfer some bitcoins to the deposit address to be able to fund ads.
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "deposit", "params": ["KxNoYPdNXUcN0TvM"], "id":1}' 127.0.0.1:21867

```
Example output
```
{"jsonrpc":"2.0","result":["2N1AvbJPneJmxW4y6dTqEv4z15U7XP7Vz2S"],"id":1}

```
The first number is the confirmed balance the second is the amount available to fund ads. This may be lower than balnce if some funds are already committed to ads.
#### balance
Query wallet balance in satoshis.
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "balance", "params": ["KxNoYPdNXUcN0TvM"], "id":1}' 127.0.0.1:21867

```
Example output
```
{"jsonrpc":"2.0","result":[[5000000000,4000000000]],"id":1}

```
The first number is the confirmed balance the second is the amount available to fund ads. This may be lower than balnce if some funds are already committed to ads.
#### prepare
Prepare an ad for publication
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "prepare", "params": ["KxNoYPdNXUcN0TvM","misc","Some abstract","Some text"], "id":1}' 127.0.0.1:21867

```
Example output
```
{"jsonrpc":"2.0","result":["5bb72726e3df5837f2e3496731b22cda904ce08205c6c153037f7b52ebc3d96a"],"id":1}

```
The returned is the the new ad's unique id. Use it to refer to it while funding it or reading it.
#### list_prepared
List previously prepared publications.
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "list_prepared", "params": ["KxNoYPdNXUcN0TvM"], "id":1}' 127.0.0.1:21867

```
#### read_prepared
Read previously prepared publications.
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "read_prepared", "params": ["KxNoYPdNXUcN0TvM"], "id":1}' 127.0.0.1:21867

```
#### withdraw
Withdraw bitcoins from the wallet. This is how you withdraw 1 bitcoin while paying 10 satoshis/vbyte fees. If amount is omitted the entire available balance will be withdrawn.
Provide the wallet encryption passphrase in the second parameter.
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "withdraw", "params": ["KxNoYPdNXUcN0TvM","horse battery staple correct", 10, 100000000], "id":1}' 127.0.0.1:21867

```
Example output. The returned id is the transaction id that was sent to the network.
```
{"jsonrpc":"2.0","result":["4ce60bb41711b99032e8411d3dc96282a36fad000b0fb0cc43192679d7ab2e0e"],"id":1}

```
#### fund
Fund a previously prepared publication. The parameters after the publication id are the amount in satoshis, term of the ad in number of blocks (7 days here), fees in satoshi/vbyte
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "fund", "params": ["KxNoYPdNXUcN0TvM","horse battery staple correct", "5bb72726e3df5837f2e3496731b22cda904ce08205c6c153037f7b52ebc3d96a", 100000000, 1008, 10], "id":1}' 127.0.0.1:21867

```
Example output. The returned id is the transaction id that was sent to the network.
```
{"jsonrpc":"2.0","result":["4ce60bb41711b99032e8411d3dc96282a36fad000b0fb0cc43192679d7ab2e0e"],"id":1}

```


