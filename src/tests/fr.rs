use alkanes::message::AlkaneMessageContext;
use alkanes_support::id::AlkaneId;
use anyhow::{anyhow, Result};
use bitcoin::blockdata::transaction::OutPoint;
use bitcoin::address::{NetworkChecked};
use bitcoin::{Witness, Sequence,  Amount, ScriptBuf, Script, Address, TxIn, TxOut, Transaction, script::{self, Builder, PushBytes}, absolute::LockTime, transaction::Version, Txid, opcodes::all as opcodes};
use bitcoin_hashes::{Hash, sha256d};

use protorune_support::protostone::Protostone;
use protorune::protostone::Protostones;
#[allow(unused_imports)]
use hex;
use metashrew_support::index_pointer::KeyValuePointer;
#[allow(unused_imports)]
use metashrew_support::{utils::{format_key}};
use protorune::{test_helpers::{get_address}, balance_sheet::load_sheet, message::MessageContext, tables::RuneTable};

use protorune_support::utils::consensus_encode;

use alkanes::indexer::index_block;
use ordinals::{Runestone, Artifact, runestone::tag::Tag};
use alkanes::tests::helpers as alkane_helpers;
use alkanes::precompiled::{alkanes_std_auth_token_build};
use alkanes_support::{cellpack::Cellpack, constants::AUTH_TOKEN_FACTORY_ID};
use crate::tests::std::fr_btc_build;
#[allow(unused_imports)]
use metashrew::{get_cache, index_pointer::IndexPointer, println, stdio::stdout};
use alkane_helpers::{clear};
use std::fmt::Write;
use wasm_bindgen_test::wasm_bindgen_test;

pub const TEST_MULTISIG: &'static str = "bcrt1pys2f8u8yx7nu08txn9kzrstrmlmpvfprdazz9se5qr5rgtuz8htsaz3chd";
pub const ADDRESS1: &'static str = "bcrt1qzr9vhs60g6qlmk7x3dd7g3ja30wyts48sxuemv";

fn pay_to_musig(inputs: Vec<OutPoint>, amount: u64) -> Transaction {
  let protostone: Protostone = Protostone {
    burn: None,
    edicts: vec![],
    pointer: Some(1),
    refund: Some(2),
    from: None,
    protocol_tag: AlkaneMessageContext::protocol_tag(),
    message: (Cellpack {
      target: AlkaneId {
        block: 4,
        tx: 0
      },
      inputs: vec![77]
    }).encipher(),
  };
  let runestone: ScriptBuf = (Runestone {
    etching: None,
    pointer: Some(0), // points to the OP_RETURN, so therefore targets the protoburn
    edicts: Vec::new(),
    mint: None,
    protocol: vec![protostone].encipher().ok(),
  }).encipher();
  let op_return = TxOut {
    value: Amount::from_sat(0),
    script_pubkey: runestone,
  };
  let address: Address<NetworkChecked> = get_address(ADDRESS1);
  let _script_pubkey = address.script_pubkey();
  Transaction {
    version: bitcoin::blockdata::transaction::Version::ONE,
    lock_time: bitcoin::absolute::LockTime::ZERO,
    input: inputs.into_iter().map(|v| TxIn {
      previous_output: v,
      witness: Witness::new(),
      script_sig: ScriptBuf::new(),
      sequence: Sequence::MAX
    }).collect::<Vec<TxIn>>(),
    output: vec![
      TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: get_address(TEST_MULTISIG).script_pubkey()
      },
      TxOut {
        value: Amount::from_sat(546),
        script_pubkey: _script_pubkey.clone()
      },
      op_return
    ]
  }
}

fn set_signer(inputs: Vec<OutPoint>) -> Transaction {
  let protostone: Protostone = Protostone {
    burn: None,
    edicts: vec![],
    pointer: Some(1),
    refund: Some(2),
    from: None,
    protocol_tag: AlkaneMessageContext::protocol_tag(),
    message: (Cellpack {
      target: AlkaneId {
        block: 4,
        tx: 0
      },
      inputs: vec![1, 0]
    }).encipher(),
  };
  let runestone: ScriptBuf = (Runestone {
    etching: None,
    pointer: Some(0), // points to the OP_RETURN, so therefore targets the protoburn
    edicts: Vec::new(),
    mint: None,
    protocol: vec![protostone].encipher().ok(),
  }).encipher();
  let op_return = TxOut {
    value: Amount::from_sat(0),
    script_pubkey: runestone,
  };
  let address: Address<NetworkChecked> = get_address(ADDRESS1);
  let _script_pubkey = address.script_pubkey();
  Transaction {
    version: bitcoin::blockdata::transaction::Version::ONE,
    lock_time: bitcoin::absolute::LockTime::ZERO,
    input: inputs.into_iter().map(|v| TxIn {
      previous_output: v,
      witness: Witness::new(),
      script_sig: ScriptBuf::new(),
      sequence: Sequence::MAX
    }).collect::<Vec<TxIn>>(),
    output: vec![
      TxOut {
        value: Amount::from_sat(546),
        script_pubkey: get_address(TEST_MULTISIG).script_pubkey()
      },
      TxOut {
        value: Amount::from_sat(546),
        script_pubkey: get_address(ADDRESS1).script_pubkey()
      },
      op_return
    ]
  }
}

fn burn(inputs: Vec<OutPoint>) -> Transaction {
  let protostone: Protostone = Protostone {
    burn: None,
    edicts: vec![],
    pointer: Some(0),
    refund: Some(2),
    from: None,
    protocol_tag: AlkaneMessageContext::protocol_tag(),
    message: (Cellpack {
      target: AlkaneId {
        block: 4,
        tx: 0
      },
      inputs: vec![78, 1]
    }).encipher(),
  };
  let runestone: ScriptBuf = (Runestone {
    etching: None,
    pointer: Some(0), // points to the OP_RETURN, so therefore targets the protoburn
    edicts: Vec::new(),
    mint: None,
    protocol: vec![protostone].encipher().ok(),
  }).encipher();
  let op_return = TxOut {
    value: Amount::from_sat(0),
    script_pubkey: runestone,
  };
  let address: Address<NetworkChecked> = get_address(ADDRESS1);
  let _script_pubkey = address.script_pubkey();
  Transaction {
    version: bitcoin::blockdata::transaction::Version::ONE,
    lock_time: bitcoin::absolute::LockTime::ZERO,
    input: inputs.into_iter().map(|v| TxIn {
      previous_output: v,
      witness: Witness::new(),
      script_sig: ScriptBuf::new(),
      sequence: Sequence::MAX
    }).collect::<Vec<TxIn>>(),
    output: vec![
      TxOut {
        value: Amount::from_sat(546),
        script_pubkey: get_address(ADDRESS1).script_pubkey()
      },
      TxOut {
        value: Amount::from_sat(546),
        script_pubkey: get_address(TEST_MULTISIG).script_pubkey()
      },
      op_return
    ]
  }
}

#[wasm_bindgen_test]
fn test_synthetic_init() -> Result<()> {
    clear();
    let mut block_height = 850_000;
    let cellpacks: Vec<Cellpack> = [
        //auth token factory init
        Cellpack {
            target: AlkaneId { block: 3, tx: AUTH_TOKEN_FACTORY_ID },
            inputs: vec![100]
        },
        Cellpack {
            target: AlkaneId { block: 3, tx: 0 },
            inputs: vec![0, 1],
        }
    ]
    .into();
    let mut test_block = alkane_helpers::init_with_multiple_cellpacks_with_tx(
        [alkanes_std_auth_token_build::get_bytes(), fr_btc_build::get_bytes()].into(),
        cellpacks,
    );
    let len = test_block.txdata.len();
    let outpoint = OutPoint {
        txid: test_block.txdata[len - 1].compute_txid(),
        vout: 0
    };
    index_block(&test_block, block_height)?;
    let ptr = RuneTable::for_protocol(AlkaneMessageContext::protocol_tag())
        .OUTPOINT_TO_RUNES
        .select(&consensus_encode(&outpoint)?);
    /*
    get_cache().iter().for_each(|(k, v)| {
      if v.as_ref().len() > 256 {
        ()
      } else {
        println!("{}: {}", format_key(k.as_ref()), hex::encode(v.as_ref()));
        ()
      }
    });
    */
    let sheet = load_sheet(&ptr);
    test_block = alkane_helpers::init_with_multiple_cellpacks_with_tx(vec![], vec![]);
    test_block.txdata.push(set_signer(vec![outpoint.clone()]));
    test_block.txdata.push(pay_to_musig(vec![], 500_000_000));
    block_height = block_height + 1;
    /*
    test_block.txdata.push(pay_to_musig(vec![], 500_000_000));
    */
    let len2 = test_block.txdata.len();
    let outpoint2 = OutPoint {
        txid: test_block.txdata[len2 - 1].compute_txid(),
        vout: 1
    };
    index_block(&test_block, block_height)?;
    let ptr = RuneTable::for_protocol(AlkaneMessageContext::protocol_tag())
        .OUTPOINT_TO_RUNES
        .select(&consensus_encode(&outpoint2)?);
    /*
    get_cache().iter().for_each(|(k, v)| {
      if v.as_ref().len() > 256 {
        ()
      } else {
        println!("{}: {}", format_key(k.as_ref()), hex::encode(v.as_ref()));
        ()
      }
    });
    */
    let sheet2 = load_sheet(&ptr);
    println!("balances at end {:?}", sheet2);
    test_block = alkane_helpers::init_with_multiple_cellpacks_with_tx(vec![], vec![]);
    test_block.txdata.push(burn(vec![outpoint2]));
    block_height = block_height + 1;
    index_block(&test_block, block_height)?;
    println!("{}", hex::encode(IndexPointer::from_keyword("/alkanes/").select(&(AlkaneId {
      block: 4,
      tx: 0
    }).into()).keyword("/storage/").keyword("/payments/byheight/").select_value::<u64>(block_height.into()).get().as_ref().clone()));
    Ok(())
}
#[wasm_bindgen_test]
fn test_burn_basic() -> Result<()> {
    let inputs = vec![OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000000".parse().unwrap(),
        vout: 0
    }];
    let tx = burn(inputs);
    
    assert_eq!(tx.output.len(), 3);
    assert_eq!(tx.output[0].value.to_sat(), 546);
    assert_eq!(tx.output[1].value.to_sat(), 546);
    assert_eq!(tx.output[2].value.to_sat(), 0); // OP_RETURN
    
    // Verify addresses
    assert_eq!(tx.output[0].script_pubkey, get_address(ADDRESS1).script_pubkey());
    assert_eq!(tx.output[1].script_pubkey, get_address(TEST_MULTISIG).script_pubkey());
    
    Ok(())
}

#[wasm_bindgen_test]
fn test_protostone_encoding() -> Result<()> {
    let inputs = vec![OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000000".parse().unwrap(),
        vout: 0
    }];
    
    let tx = pay_to_musig(inputs, 1_000_000);
    
    // Verify the OP_RETURN output contains a valid Protostone
    let artifact = Runestone::decipher(&tx)
        .ok_or_else(|| anyhow!("Failed to decipher runestone"))?;
    
    match artifact {
        Artifact::Runestone(runestone) => {
            assert!(runestone.protocol.is_some());
            assert_eq!(runestone.pointer, Some(0));
            assert!(runestone.edicts.is_empty());
            Ok(())
        },
        Artifact::Cenotaph(_) => {
            Err(anyhow!("Expected Runestone but got Cenotaph"))
        }
    }
}

#[wasm_bindgen_test]
fn test_block_construction_and_deployment() -> Result<()> {
    println!("Starting runestone construction...");
    
    let mut script_builder = Builder::new();
    
    // Add OP_RETURN and magic number
    script_builder = script_builder
        .push_opcode(opcodes::OP_RETURN)
        .push_opcode(Runestone::MAGIC_NUMBER);
    
    // Create tag data
    let mut tag_data = Vec::new();
    
    // Add pointer tag (pointing to output index 1)
    Tag::Pointer.encode([1], &mut tag_data);
    println!("Added pointer to output 1");
    
    // Convert tag data to PushBytes and add to script
    let push_bytes: &PushBytes = tag_data.as_slice().try_into()
        .map_err(|_| anyhow!("Failed to convert tag data to push bytes"))?;
    
    script_builder = script_builder.push_slice(push_bytes);
    
    // Build the final script
    let script_pubkey = script_builder.into_script();
    println!("Created script_pubkey: {:?}", script_pubkey);

    // Create transaction with:
    // - Output 0: Regular output (spendable by synthetic)
    // - Output 1: Target output (pointed to by runestone)
    // - Output 2: OP_RETURN with runestone
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_raw_hash(sha256d::Hash::hash(&[0; 32])),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            // Output 0: Regular output
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            },
            // Output 1: Target output (pointed to by runestone)
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            },
            // Output 2: OP_RETURN with runestone
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey,
            }
        ],
    };

    println!("Created transaction: {:?}", tx);

    // Try to decipher and print the result or detailed error
    match Runestone::decipher(&tx) {
        Some(Artifact::Runestone(runestone)) => {
            println!("Successfully deciphered runestone: {:?}", runestone);
            Ok(())
        },
        Some(Artifact::Cenotaph(cenotaph)) => {
            Err(anyhow!("Got cenotaph (invalid runestone): {:?}", cenotaph))
        },
        None => {
            Err(anyhow!("Failed to decipher runestone - no valid runestone found in transaction"))
        }
    }
}
