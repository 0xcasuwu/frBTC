use alkanes::indexer::index_block;
use alkanes::message::AlkaneMessageContext;
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
    Script,
};
use bitcoin::hashes::Hash as HashTrait;
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
fn create_mining_reward_script(block_height: u32) -> Script {
    let mut script = Script::builder();
    script = script
        .push_opcode(bitcoin::opcodes::all::OP_RETURN)
        .push_slice(&[0xF2]) // Protocol identifier
        .push_slice(&block_height.to_le_bytes()); // Block height as LE bytes
    
    script.into_script()
}

#[wasm_bindgen_test]
fn test_mining_reward() -> Result<()> {
    let mut block_height = 0;
    let mut output = String::new();
    
    // Create miner address
    let miner_address = Address::from_str(TEST_MINER)?.require_network(Network::Regtest)?;
    let miner_script = miner_address.script_pubkey();
    
    // Create initial block with coinbase
    let mut test_block = Block {
        header: Header {
            version: BlockVersion::TWO,
            prev_blockhash: BlockHash::from_raw_hash(sha256d::Hash::all_zeros()),
            merkle_root: TxMerkleNode::from_raw_hash(sha256d::Hash::all_zeros()),
            time: 0,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        },
        txdata: vec![
            // Coinbase transaction
            Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![],  // Empty for coinbase
                output: vec![
                    TxOut {
                        value: Amount::from_sat(50 * 100_000_000),  // 50 BTC reward
                        script_pubkey: miner_script.clone(),
                    },
                    // Add an OP_RETURN output for the mining reward protocol
                    TxOut {
                        value: Amount::from_sat(0),
                        script_pubkey: create_mining_reward_script(block_height),
                    }
                ],
            }
        ],
    };

    // Update merkle root
    test_block.header.merkle_root = test_block.compute_merkle_root().unwrap();
    
    // Index the first block
    index_block(&test_block, block_height)?;

    // Get outpoint from first transaction
    let outpoint = OutPoint {
        txid: test_block.txdata[0].compute_txid(),
        vout: 0,
    };

    // Verify initialization
    let ptr = RuneTable::for_protocol(AlkaneMessageContext::protocol_tag())
        .OUTPOINT_TO_RUNES
        .select(&consensus_encode(&outpoint)?);
    
    let sheet = load_sheet(&ptr);
    write!(output, "Initial state: {:?}\n", sheet)?;
    stdout().write_fmt(format_args!("{}", output))?;

    // Create second block with mining reward
    block_height += 1;
    test_block = Block {
        header: Header {
            version: BlockVersion::TWO,
            prev_blockhash: test_block.block_hash(),
            merkle_root: TxMerkleNode::from_raw_hash(sha256d::Hash::all_zeros()),
            time: 1,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        },
        txdata: vec![
            Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![],
                output: vec![
                    TxOut {
                        value: Amount::from_sat(50 * 100_000_000),
                        script_pubkey: miner_script.clone(),
                    },
                    // Add mining reward protocol output
                    TxOut {
                        value: Amount::from_sat(0),
                        script_pubkey: create_mining_reward_script(block_height),
                    }
                ],
            }
        ],
    };

    // Update merkle root
    test_block.header.merkle_root = test_block.compute_merkle_root().unwrap();
    
    // Index the second block
    index_block(&test_block, block_height)?;

    // Verify mining result
    let mining_result = RuneTable::for_protocol(AlkaneMessageContext::protocol_tag())
        .OUTPOINT_TO_RUNES
        .select(&consensus_encode(&OutPoint {
            txid: test_block.txdata[0].compute_txid(),
            vout: 0
        })?);

    let final_sheet = load_sheet(&mining_result);
    write!(output, "Final state after mining: {:?}\n", final_sheet)?;
    stdout().write_fmt(format_args!("{}", output))?;

    // Verify mining reward was issued
    assert!(!final_sheet.balances.is_empty() && 
            final_sheet.balances.values().any(|&v| v > 0), 
            "No mining reward issued");

    Ok(())
}