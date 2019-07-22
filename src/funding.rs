//! Funding related code
use std::error;

use crate::bitcoin::{
    PrivateKey, PublicKey, Script, Transaction,
    blockdata::{
        script::Builder,
        opcodes::all,
        transaction::{TxIn, TxOut, OutPoint, SigHashType}
    },
    util::{
        bip143,
        address::Address
    },
    network::constants::Network
};

use crate::bitcoin_hashes::sha256;

use crate::secp256k1::{Secp256k1, All, Message};

use crate::byteorder::{LittleEndian, ByteOrder};

use crate::rand::{thread_rng, prelude::SliceRandom};

pub fn funding_script (funder: &PublicKey, digest: &sha256::Hash, term: u16, ctx: &Secp256k1<All>) -> Script {
    let mut tweaked = funder.clone();
    tweaked.key.add_exp_assign(ctx, &digest[..]).unwrap();
    let mut buf = [0u8; 4];
    LittleEndian::write_u32(&mut buf, term as u32 | (1 << 22));

    let script = Builder::new()
        .push_slice(tweaked.to_bytes().as_slice())
        .push_opcode(all::OP_CHECKSIGVERIFY)
        .push_slice(&buf[0..3])
        .push_opcode(all::OP_NOP3) // OP_CHECKSEQUENCEVERIFY
        .into_script();

    Address::p2wsh(&script, Network::Bitcoin).script_pubkey()
}

/// spend a previously used funding
pub fn spend_funding (digest: &sha256::Hash, term: u16, funding: &Transaction, secret: &PrivateKey, target: Address, amount: u64, fee: u64, change: Address, ctx: &Secp256k1<All>)
                      -> Result<Transaction, Box<dyn error::Error>> {
    let mut secret = secret.clone();
    secret.key.add_assign(&digest[..])?;

    let funder = PublicKey::from_private_key(ctx, &secret);
    let f_script = funding_script(&funder, &digest, term, ctx);
    let spend = funding.output.iter().enumerate()
        .filter_map(|(vout, o)| if o.script_pubkey == f_script { Some((vout, o.clone()))} else {None})
        .collect::<Vec<(usize, TxOut)>>();
    let input_amount = spend.iter().map(|(_, o)| o.value).sum::<u64>();
    let mut outputs = Vec::new();
    if target == change {
        outputs.push(TxOut{
            value: input_amount - fee,
            script_pubkey: target.script_pubkey()
        });
    }
    else {
        outputs.push(TxOut{
            value: amount,
            script_pubkey: target.script_pubkey()
        });
        outputs.push(TxOut{
            value: input_amount - amount - fee,
            script_pubkey: change.script_pubkey()
        });
        outputs.shuffle(&mut thread_rng());
    }

    let txid = funding.txid();
    let inputs = spend.iter().map(|(vout, _)| TxIn{
        previous_output: OutPoint{txid, vout: *vout as u32},
        script_sig: Builder::new().into_script(),
        sequence: term as u32 | (1 << 22),
        witness: Vec::new()
    }).collect::<Vec<TxIn>>();

    let mut tx = Transaction{
        version: 2,
        lock_time: 0xffffffff,
        input: inputs,
        output: outputs
    };

    let mut sigs = Vec::new();
    for (i, input) in tx.input.iter().enumerate() {
        let hash = bip143::SighashComponents::new(&tx).sighash_all(&input, &f_script, spend[i].1.value);
        let mut sig = ctx.sign(&Message::from_slice(&hash[..]).unwrap(), &secret.key).serialize_der();
        sig.push(SigHashType::All as u8);
        sigs.push(sig);
    }
    for (i, input) in tx.input.iter_mut().enumerate() {
        input.witness.push(sigs[i].clone());
        input.witness.push(f_script.to_bytes());
    }
    Ok(tx)
}

pub struct FundingRequest {
    pub digest: sha256::Hash,
    pub interest_outpoint: OutPoint,
    pub interest_cap: u64,
    pub change: Address
}
