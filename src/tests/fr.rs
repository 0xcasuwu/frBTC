use alkanes::indexer::index_block;
use alkanes::message::AlkaneMessageContext;
use alkanes_support::cellpack::Cellpack;
use alkanes_support::id::AlkaneId;
use anyhow::Result;
use bitcoin::blockdata::transaction::OutPoint;
use bitcoin::{
    Transaction, TxOut, Amount,
    transaction::Version, 
    absolute::LockTime,
    Block, blockdata::block::Header,
    block::Version as BlockVersion,
    BlockHash,
    TxMerkleNode,
    pow::CompactTarget,
    hashes::sha256d,
    Address, Network,
    Script, ScriptBuf,
    Target,
};
use bitcoin::hashes::Hash as HashTrait;
use ordinals::Runestone;
use protorune::protostone::Protostones;
use protorune_support::protostone::Protostone;
use std::str::FromStr;
use protorune::message::MessageContext;
use protorune::tables::RuneTable;
use protorune::balance_sheet::load_sheet;
use metashrew_support::index_pointer::KeyValuePointer;
use metashrew_support::utils::consensus_encode;
use metashrew::stdout;
use std::fmt::Write;
use wasm_bindgen_test::wasm_bindgen_test;

pub const TEST_MINER: &'static str = "bcrt1qzr9vhs60g6qlmk7x3dd7g3ja30wyts48sxuemv";

// Function to create mining reward script
fn create_mining_reward_script(block_height: u32) -> ScriptBuf {
    Script::builder()
        .push_opcode(bitcoin::opcodes::all::OP_RETURN)
        .push_slice(&[0xF2]) // Protocol identifier
        .push_slice(&block_height.to_le_bytes()) // Block height as LE bytes
        .into_script()
}

#[wasm_bindgen_test]
fn test_mining_reward() -> Result<()> {
    let mut block_height: u32 = 850_000;
    let mut output = String::new();
    
    // Create miner address
    let miner_address = Address::from_str(TEST_MINER)?.require_network(Network::Regtest)?;
    
    // Create mining reward script
    let reward_script = create_mining_reward_script(block_height);
    
    // Create initial block
    let compact = CompactTarget::from_consensus(0x207fffff);
    let target = Target::from_compact(compact);
    
    let mut test_block = Block {
        header: Header {
            version: BlockVersion::TWO,
            prev_blockhash: BlockHash::from_raw_hash(sha256d::Hash::all_zeros()),
            merkle_root: TxMerkleNode::from_raw_hash(sha256d::Hash::all_zeros()),
            time: 0,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        },
        txdata: vec![
            Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![],  // Coinbase has no inputs
                output: vec![
                    TxOut {
                        value: Amount::from_sat(5000000000),  // 50 BTC reward
                        script_pubkey: miner_address.script_pubkey(),
                    },
                    TxOut {
                        value: Amount::from_sat(0),
                        script_pubkey: reward_script,
                    }
                ],
            }
        ],
    };

    // Mine the block
    while test_block.header.validate_pow(target).is_err() {
        test_block.header.nonce += 1;
        if test_block.header.nonce % 1000 == 0 {
            println!("Trying nonce: {}", test_block.header.nonce);
        }
    }

    // Verify the mining reward
    let coinbase_tx = &test_block.txdata[0];
    assert_eq!(coinbase_tx.output[0].value, Amount::from_sat(5000000000), "Mining reward amount incorrect");
    assert_eq!(coinbase_tx.output[0].script_pubkey, miner_address.script_pubkey(), "Mining reward recipient incorrect");

    Ok(())
}