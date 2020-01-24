[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

# defiads Network
A defiant ads network to meet the needs of decentralized finance (DeFi).

# Usage
defiads builds a peer-to-peer network to distribute textual ads. It is a [side memory](https://www.mail-archive.com/bitcoin-dev@lists.linuxfoundation.org/msg08301.html) 
to the bitcoin network.

Every defiads node maintains a copy of a network-wide shared 1GB memory pool of current ads.

An ad is replicated to other nodes as long as there is some bitcoin locked to it on the bitcoin network.
Locking means the owner of the bitcoins transferred some sats to an address that is cryptographically associated with the ad
using the [pay-to-contract](https://arxiv.org/pdf/1212.3257.pdf) protocol. The address does not release the bitcoins
until a predefined time span that is the duration of the advertizement, this is accomplished with [OP_CSV](https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki).

defiads nodes rank advertizements by the ratio of length divided by bitcoins locked and will only replicate the top 1GB of this ranked list.

You may read the ads pool by starting a defiads process of your own and the query the content through its JSON-RPC API.

You may place ads by performing the following steps, with the below documented JSON-RPC API
1. deposit some bitcoins into your defiads node's wallet
2. prepare an ad, providing its category, abstract and content
3. fund the ad by locking some of the bitcoins to it for a limited term of the advertizement
4. you may withdraw your coins from the defiads node's wallet after the advertizement expires

## Release notes

0.2.2 do not ban peers that are slow to answer, just disconnect

0.2.0 use published crates and remove local dependencies.

<b>Not backward compatible change to the wallet and header files.</b>
* withdraw your testnet coins from 0.1.0 if you care them
* delete all database files in $HOME/.defiads/testnet 

0.1.0 first publication on the dev list 

## Implementation notes
defiads connects to both the bitcoin and its own peer-to-peer network. You do not need to run a bitcoin node as
defiads does only need a small fraction of the information on the bictoin blockchain and retrieves that on its own,
as an SPV node.

The defiads node's wallet is compatibe with that of TREZOR, Ledger, Greenwallet and many other wallets that support
BIP38, BIP44, BIP48, BIP84 key generation and use standards.

defiads uses [Invertible Bloom Lookup Tables](https://arxiv.org/pdf/1101.2245.pdf) to synchronize the ads pool with its peers.

## Status
It seems to work, but you should not yet use with real bitcoins, therefore by default it connects the bitcoin's test network.

## Future developent
Should the use become popular then 1GB pool might become tight and people start to compete for its use. Some might not have 
enough bitcoin's to lock and might therefore pay others to lock theirs to fund an advertizement. defiads will facilitate this
negotiation and thereby give rise to bitcoin's first truly risk less interest rate market.

# Build
[Install Rust](https://www.rust-lang.org/learn/get-started)
```
$ cargo update
$ cargo build --release
```

# Running On Local Regtest Network (Recommended for developers)
1. Be sure to have a somewhat recent version of bitcoin core installed.
2. Start bitcoin core in regtest mode `$ bitcoind -regtest -daemon`.
3. Your local bitcoin instance will now be listening for connections on (default) port 18444
4. Whenever blocks need to be generated for your testing, you can use the command `$ bitcoin-cli -testnet generatetoaddress <address for mined coins to be sent>`. If you do not know how to use this command, `$ bitcoin-cli help <command>` is your friend. As a reminder, coins mined in block `n` are spendable in block `n+100`.
5. Now you can run your local defiads node and have it connect to your local regtest network:
```
$ target/release/defiads --bitcoin-network regtest --bitcoin-peers 127.0.0.1:18444
```

# Running On Testnet
note: there is no discovery mechanism implemented yet, so the option `defiads-peers <ADDRESS_OF_PEER1>` must be used to connect to some other peers.
```
$ target/release/defiads --defiads-peers <ADDRESS_OF_PEER1>
```

Databases and configuration will be stored in $HOME/.defiads/bitcoin or $HOME/.defiads/testnet depending on the 
--bitcoin-network option

## Options
```
USAGE:
    defiads [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --defiads-connections <n>                  Desired number of connections to the defiads network [default: 5]
        --defiads-discovery <defiads-discovery>
            Enable/Disable defiads network discovery [default: ON]  [possible values: ON, OFF]

        --defiads-peers <ADDRESS>...               defiads network peers to connect
        --bitcoin-connections <n>                  Desired number of connections to the bitcoin network [default: 5]
        --bitcoin-discovery <bitcoin-discovery>
            Enable/Disable bitcoin network discovery [default: ON]  [possible values: ON, OFF]

        --bitcoin-network <NETWORK>
            Set the used bitcoin network. [default: bitcoin]  [possible values: bitcoin, testnet, regtest]

        --bitcoin-peers <ADDRESS>...               Bitcoin network peers to connect
        --datadir <datadir>                        Set the base data directory. defiads.cfg, databases, etc. will be in <bitcoin-netork> [default: ~/.defiads] subdirectories.
        --http-rpc <ADDRESS>                       Listen to http-rpc on this address. [default: 127.0.0.1:21767]
        --listen <ADDRESS>...                      Listen to incoming defiads connections [default: 0.0.0.0:21766]
        --log-level <LEVEL>
            Set log level. [default: DEBUG]  [possible values: OFF, ERROR, WARN, INFO, DEBUG, TRACE]

        --storage-limit <n>                        Storage limit in GB [default: 1]

```

## First Use
At first use defiads will generate a key for its bitcoin wallet. The key format follows that of popular wallets and is
compatible with TREZOR, Ledger etc.

The human readable representation of the key are 24 words. You should write them down and keep off-line. The same
words are stored encrypted in the defiads.cfg file. You set the encryption password at first use. Remember this as 
there is no other way to recover the words from the encrypted storage.

## RPC API
Use JSON RPC 2.0 calls e.g. with curl as follows, assuming the process runs on your local machine. Port is <b>21767</b> for 
the real and <b>21867</b> for the testnet bitcoin network, see option --bitcoin-network. 
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "METHOD", "params": ["ARGUMENTS"...] "id":1}' 127.0.0.1:21767

```
Where the first argument is always an API Key which is unique to this installation. You find the API key in the
defiads.cfg file.  

The second argument is the encryption key for methods that move bitcoins. In the examples on this page, the encryption key is "horse battery staple correct".

It may be helpful to store the API Key in an environmental variable:
```
DEFIADS_APIKEY=$(sed -n '/^apikey = /{s/^apikey = //;p}' ~/.defiads/regtest/defiads.cfg)
```


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
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "list", "params": ['$DEFIADS_APIKEY', "misc"], "id":1}' 127.0.0.1:21867

```
Example reply
```
{"jsonrpc":"2.0","result":["5bb72726e3df5837f2e3496731b22cda904ce08205c6c153037f7b52ebc3d96a", "misc", "Some abstract"],"id":1}

```
#### read
Read an ad
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "read", "params": ['$DEFIADS_APIKEY', "5bb72726e3df5837f2e3496731b22cda904ce08205c6c153037f7b52ebc3d96a"], "id":1}' 127.0.0.1:21867

```
#### deposit
Get a deposit address of the wallet. Transfer some bitcoins to the deposit address to be able to fund ads.
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "deposit", "params": ['$DEFIADS_APIKEY'], "id":1}' 127.0.0.1:21867

```
Example output
```
{"jsonrpc":"2.0","result":["2N1AvbJPneJmxW4y6dTqEv4z15U7XP7Vz2S"],"id":1}

```
The first number is the confirmed balance the second is the amount available to fund ads. This may be lower than balnce if some funds are already committed to ads.
#### balance
Query wallet balance in satoshis.
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "balance", "params": ['$DEFIADS_APIKEY'], "id":1}' 127.0.0.1:21867

```
Example output
```
{"jsonrpc":"2.0","result":[[5000000000,4000000000]],"id":1}

```
The first number is the confirmed balance the second is the amount available to fund ads. This may be lower than balnce if some funds are already committed to ads.
#### prepare
Prepare an ad for publication
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "prepare", "params": ['$DEFIADS_APIKEY',"misc","Some abstract","Some text"], "id":1}' 127.0.0.1:21867

```
Example output
```
{"jsonrpc":"2.0","result":["5bb72726e3df5837f2e3496731b22cda904ce08205c6c153037f7b52ebc3d96a"],"id":1}

```
The returned is the the new ad's unique id. Use it to refer to it while funding it or reading it.
#### list_prepared
List previously prepared publications.
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "list_prepared", "params": ['$DEFIADS_APIKEY'], "id":1}' 127.0.0.1:21867

```
#### read_prepared
Read previously prepared publications.
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "read_prepared", "params": ['$DEFIADS_APIKEY'], "id":1}' 127.0.0.1:21867

```
#### withdraw
Withdraw bitcoins from the wallet. This is how you withdraw 1 bitcoin while paying 10 satoshis/vbyte fees. If amount is omitted the entire available balance will be withdrawn.
Provide the wallet encryption passphrase in the second parameter.
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "withdraw", "params": ['$DEFIADS_APIKEY',"horse battery staple correct", 10, 100000000], "id":1}' 127.0.0.1:21867

```
Example output. The returned id is the transaction id that was sent to the network.
```
{"jsonrpc":"2.0","result":["4ce60bb41711b99032e8411d3dc96282a36fad000b0fb0cc43192679d7ab2e0e"],"id":1}

```
#### fund
Fund a previously prepared publication. The parameters after the publication id are the amount in satoshis, term of the ad in number of blocks (7 days here), fees in satoshi/vbyte
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "fund", "params": ['$DEFIADS_APIKEY',"horse battery staple correct", "5bb72726e3df5837f2e3496731b22cda904ce08205c6c153037f7b52ebc3d96a", 100000000, 1008, 10], "id":1}' 127.0.0.1:21867

```
Example output. The returned id is the transaction id that was sent to the network.
```
{"jsonrpc":"2.0","result":["4ce60bb41711b99032e8411d3dc96282a36fad000b0fb0cc43192679d7ab2e0e"],"id":1}

```


