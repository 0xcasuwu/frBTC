use alkanes::message::AlkaneMessageContext;
use alkanes_support::id::AlkaneId;
use anyhow::{anyhow, Result};
use bitcoin_hashes::{sha256, Hash};
use std::sync::Arc;
use alkanes_runtime::{runtime::AlkaneResponder, storage::StoragePointer};
use alkanes_support::context::Context;
use alkanes_support::parcel::{AlkaneTransfer, AlkaneTransferParcel};
use alkanes_support::response::CallResponse;
use alkanes_support::utils::shift_or_err;

#[derive(Default)]
pub struct EIP918Token(());

impl EIP918Token {
    // Constants matching the Solidity implementation
    const BASE_MINING_REWARD: u64 = 50;
    const BLOCKS_PER_READJUSTMENT: u64 = 1024;
    const MINIMUM_TARGET: u128 = 2u128.pow(16);
    const MAXIMUM_TARGET: u128 = 2u128.pow(234);
    const MAX_REWARD_ERA: u64 = 39;
    const MINING_RATE_FACTOR: u64 = 60;
    const MAX_ADJUSTMENT_PERCENT: u64 = 100;
    const TARGET_DIVISOR: u64 = 2000;
    const QUOTIENT_LIMIT: u64 = TARGET_DIVISOR / 2;

    // Storage pointers
    fn initialized_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/initialized")
    }

    fn challenge_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/challenge")
    }
    
    fn solution_pointer(&self, challenge: &[u8; 32]) -> StoragePointer {
        StoragePointer::from_keyword("/solutions/").append(&challenge.to_vec())
    }
    
    fn mining_target_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/mining_target")
    }
    
    fn tokens_minted_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/tokens_minted")
    }
    
    fn epoch_count_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/epoch_count") 
    }
    
    fn era_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/era")
    }
    
    fn max_supply_era_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/max_supply_era")
    }
    
    fn total_supply_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/total_supply")
    }

    fn last_difficulty_period_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/last_difficulty_period")
    }

    // Core mining functions
    fn calculate_mining_hash(&self, nonce: u64, challenge_number: &[u8; 32]) -> Result<[u8; 32]> {
        let mut engine = sha256::HashEngine::default();
        engine.input(challenge_number);
        engine.input(&self.context()?.sender.to_vec());
        engine.input(&nonce.to_le_bytes());
        Ok(sha256::Hash::from_engine(engine).into_inner())
    }

    fn verify_mining_solution(&self, context: &Context, nonce: u64) -> Result<()> {
        let challenge_number = self.challenge_pointer().get_value::<[u8; 32]>()?;
        let mining_target = self.mining_target_pointer().get_value::<u128>()?;
        
        // Calculate hash
        let digest = self.calculate_mining_hash(nonce, &challenge_number)?;
        
        // Check solution hasn't been used
        let solution_pointer = self.solution_pointer(&challenge_number);
        if !solution_pointer.get().is_empty() {
            return Err(anyhow!("solution already exists"));
        }
        
        // Verify hash meets difficulty target
        let hash_value = u128::from_be_bytes(digest[0..16].try_into()?);
        if hash_value > mining_target {
            return Err(anyhow!("hash doesn't meet difficulty target"));
        }

        // Store solution
        solution_pointer.set(Arc::new(digest.to_vec()));
        Ok(())
    }

    fn adjust_difficulty(&self) -> Result<()> {
        let current_block = self.context()?.block_height;
        let last_period = self.last_difficulty_period_pointer().get_value::<u64>()?;
        let mining_target = self.mining_target_pointer().get_value::<u128>()?;
        
        let blocks_since_last = current_block.saturating_sub(last_period);
        let target_blocks = self.BLOCKS_PER_READJUSTMENT * self.MINING_RATE_FACTOR;

        let new_target = if blocks_since_last < target_blocks {
            // Make it harder
            let excess_block_pct = (target_blocks * self.MAX_ADJUSTMENT_PERCENT) / blocks_since_last;
            let excess = (excess_block_pct.saturating_sub(100)).min(self.QUOTIENT_LIMIT);
            mining_target.saturating_sub(mining_target / self.TARGET_DIVISOR * excess as u128)
        } else {
            // Make it easier
            let shortage_block_pct = (blocks_since_last * self.MAX_ADJUSTMENT_PERCENT) / target_blocks;
            let shortage = (shortage_block_pct.saturating_sub(100)).min(self.QUOTIENT_LIMIT);
            mining_target.saturating_add(mining_target / self.TARGET_DIVISOR * shortage as u128)
        };

        // Clamp to bounds
        let final_target = new_target.clamp(self.MINIMUM_TARGET, self.MAXIMUM_TARGET);
        
        // Store new values
        self.mining_target_pointer().set(Arc::new(final_target.to_le_bytes().to_vec()));
        self.last_difficulty_period_pointer().set(Arc::new(current_block.to_le_bytes().to_vec()));
        
        Ok(())
    }

    fn start_new_mining_epoch(&self) -> Result<()> {
        let tokens_minted = self.tokens_minted_pointer().get_value::<u128>()?;
        let reward = self.get_mining_reward()?;
        let era = self.era_pointer().get_value::<u64>()?;
        let max_supply_era = self.max_supply_era_pointer().get_value::<u128>()?;
        
        // Check if we need to enter new era
        if tokens_minted.saturating_add(reward) > max_supply_era && era < self.MAX_REWARD_ERA {
            self.era_pointer().set(Arc::new((era + 1).to_le_bytes().to_vec()));
            
            // Update max supply for new era
            let total_supply = self.total_supply_pointer().get_value::<u128>()?;
            let new_max = total_supply - total_supply / (2u128.pow((era + 1) as u32));
            self.max_supply_era_pointer().set(Arc::new(new_max.to_le_bytes().to_vec()));
        }

        // Update epoch count
        let epoch_count = self.epoch_count_pointer().get_value::<u64>()?;
        self.epoch_count_pointer().set(Arc::new((epoch_count + 1).to_le_bytes().to_vec()));

        // Adjust difficulty if needed
        if epoch_count % self.BLOCKS_PER_READJUSTMENT == 0 {
            self.adjust_difficulty()?;
        }

        // Update challenge number
        let context = self.context()?;
        let new_challenge = context.previous_block_hash;
        self.challenge_pointer().set(Arc::new(new_challenge.to_vec()));

        Ok(())
    }

    fn get_mining_reward(&self) -> Result<u128> {
        let era = self.era_pointer().get_value::<u64>()?;
        let base_reward = self.BASE_MINING_REWARD as u128 * 10u128.pow(8); // 8 decimals
        Ok(base_reward / 2u128.pow(era as u32))
    }

    fn initialize(&self, context: &Context) -> Result<()> {
        let mut initialized = self.initialized_pointer().get();
        if !initialized.is_empty() {
            return Err(anyhow!("already initialized"));
        }

        // Set initial values
        self.total_supply_pointer().set(Arc::new((21_000_000u128 * 10u128.pow(8)).to_le_bytes().to_vec()));
        self.mining_target_pointer().set(Arc::new(self.MAXIMUM_TARGET.to_le_bytes().to_vec()));
        self.era_pointer().set(Arc::new(0u64.to_le_bytes().to_vec()));
        self.epoch_count_pointer().set(Arc::new(0u64.to_le_bytes().to_vec()));
        
        // Set max supply for first era
        let total_supply = self.total_supply_pointer().get_value::<u128>()?;
        self.max_supply_era_pointer().set(Arc::new((total_supply / 2).to_le_bytes().to_vec()));
        
        // Set initial challenge
        self.challenge_pointer().set(Arc::new(context.previous_block_hash.to_vec()));
        
        // Mark as initialized
        initialized.set(Arc::new(vec![1]));
        
        Ok(())
    }

    fn mint_tokens(&self, context: &Context, amount: u128) -> Result<()> {
        let tokens_minted = self.tokens_minted_pointer().get_value::<u128>()?;
        self.tokens_minted_pointer().set(Arc::new((tokens_minted + amount).to_le_bytes().to_vec()));
        Ok(())
    }

    fn context(&self) -> Result<Context> {
        Context::current().ok_or_else(|| anyhow!("no context available"))
    }
}

impl AlkaneResponder for EIP918Token {
    fn execute(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut inputs = context.inputs.clone();
        let mut response = CallResponse::default();

        match shift_or_err(&mut inputs)? {
            // Initialize
            0 => {
                self.initialize(&context)?;
                Ok(response)
            },
            // Mine
            1 => {
                let nonce = shift_or_err(&mut inputs)?;
                self.verify_mining_solution(&context, nonce)?;
                
                // Get reward and mint tokens
                let reward = self.get_mining_reward()?;
                self.mint_tokens(&context, reward)?;
                
                // Start new epoch
                self.start_new_mining_epoch()?;
                
                // Create reward transfer
                response.alkanes = AlkaneTransferParcel {
                    transfers: vec![AlkaneTransfer {
                        id: context.myself.clone(),
                        value: reward,
                    }]
                };
                
                Ok(response)
            },
            // Get current mining target
            2 => {
                let target = self.mining_target_pointer().get_value::<u128>()?;
                response.data = target.to_le_bytes().to_vec();
                Ok(response)
            },
            // Get current challenge number
            3 => {
                let challenge = self.challenge_pointer().get_value::<[u8; 32]>()?;
                response.data = challenge.to_vec();
                Ok(response)
            },
            _ => Err(anyhow!("unrecognized opcode"))
        }
    }
}