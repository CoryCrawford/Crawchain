// CrawChain: Modular Blockchain Codebase with Enhanced Security, Sharding, WASM, and ECC Integration

// Main Modules
type Address = String;

mod blockchain {
    use super::*;
    use serde::{Serialize, Deserialize};
    use sha2::{Digest, Sha256};
    use std::collections::{HashMap, HashSet};
    use p256::ecdsa::{SigningKey, VerifyingKey, signature::{Signer, Verifier}};

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct Block {
        pub index: u64,
        pub timestamp: String,
        pub transactions: Vec<Transaction>,
        pub previous_hash: String,
        pub hash: String,
        pub shard_id: Option<u64>,
    }

    impl Block {
        pub fn new(index: u64, transactions: Vec<Transaction>, previous_hash: String, shard_id: Option<u64>) -> Self {
            let timestamp = chrono::Utc::now().to_rfc3339();
            let hash = Self::calculate_hash(index, &timestamp, &transactions, &previous_hash, shard_id);
            Block {
                index,
                timestamp,
                transactions,
                previous_hash,
                hash,
                shard_id,
            }
        }

        fn calculate_hash(
            index: u64,
            timestamp: &str,
            transactions: &Vec<Transaction>,
            previous_hash: &str,
            shard_id: Option<u64>,
        ) -> String {
            let mut hasher = Sha256::new();
            hasher.update(index.to_string());
            hasher.update(timestamp);
            hasher.update(format!("{:?}", transactions));
            hasher.update(previous_hash);
            if let Some(shard) = shard_id {
                hasher.update(shard.to_string());
            }
            format!("{:x}", hasher.finalize())
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct Transaction {
        pub sender: Address,
        pub receiver: Address,
        pub token: Token,
        pub nonce: u64,
        pub contract_code: Option<Vec<u8>>,
        pub gas_limit: u64,
        pub zkp: Option<ZKProof>,
        pub signature: String, // ECC signature for the transaction
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub enum Token {
        CustodyToken(f64),
        EnergyToken(f64),
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct ZKProof {
        pub public_input: Vec<u8>,
        pub proof: Vec<u8>,
    }

    pub struct Blockchain {
        pub lock_shard: Vec<Block>,
        pub vpp_shard: Vec<Block>,
        pub validators: Vec<Address>,
        pub stakes: HashMap<Address, f64>,
        pub used_nonces: HashMap<u64, bool>, // Persistent nonce management
        pub public_keys: HashMap<Address, VerifyingKey>, // Store public keys of users
    }

    impl Blockchain {
        pub fn new() -> Self {
            Blockchain {
                lock_shard: vec![Block::new(0, vec![], "0".to_string(), Some(0))],
                vpp_shard: vec![Block::new(0, vec![], "0".to_string(), Some(1))],
                validators: vec![],
                stakes: HashMap::new(),
                used_nonces: HashMap::new(),
                public_keys: HashMap::new(),
            }
        }

        pub fn assign_shard(&self, sender: &str) -> usize {
            let mut hasher = Sha256::new();
            hasher.update(sender.as_bytes());
            let hash = hasher.finalize();
            (hash[0] as usize) % 2 // Two shards: lock_shard (0) and vpp_shard (1)
        }

        pub fn add_block(&mut self, transactions: Vec<Transaction>, shard_id: usize) {
            if !self.batch_verify_signatures(&transactions) {
                panic!("Batch signature verification failed");
            }

            for tx in &transactions {
                if !self.validate_nonce(tx.nonce) {
                    panic!("Duplicate nonce detected: {}", tx.nonce);
                }
                if !self.validate_transaction(tx) {
                    panic!("Invalid transaction detected");
                }
            }

            let shard = match shard_id {
                0 => &mut self.lock_shard,
                1 => &mut self.vpp_shard,
                _ => panic!("Invalid shard ID"),
            };

            let last_block = shard.last().unwrap();
            let new_block = Block::new(
                last_block.index + 1,
                transactions,
                last_block.hash.clone(),
                Some(shard_id as u64),
            );

            shard.push(new_block);
        }

        fn validate_nonce(&mut self, nonce: u64) -> bool {
            match self.used_nonces.get(&nonce) {
                Some(_) => false,
                None => {
                    self.used_nonces.insert(nonce, true);
                    true
                }
            }
        }

        fn validate_transaction(&self, transaction: &Transaction) -> bool {
            // Example validation: Ensure gas_limit and token values are reasonable
            transaction.gas_limit > 0 && match transaction.token {
                Token::CustodyToken(amount) => amount > 0.0,
                Token::EnergyToken(amount) => amount > 0.0,
            }
        }

        fn batch_verify_signatures(&self, transactions: &Vec<Transaction>) -> bool {
            for transaction in transactions {
                if let Some(public_key) = self.public_keys.get(&transaction.sender) {
                    let message = format!("{}:{}:{}:{}:{}", transaction.sender, transaction.receiver, transaction.token, transaction.nonce, transaction.gas_limit);
                    if public_key.verify(message.as_bytes(), &hex::decode(&transaction.signature).unwrap()).is_err() {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            true
        }
    }
}

mod consensus {
    pub trait Consensus {
        fn validate_block(&self, block: &super::blockchain::Block) -> bool;
    }

    pub struct ProofOfStake;

    impl Consensus for ProofOfStake {
        fn validate_block(&self, block: &super::blockchain::Block) -> bool {
            // Implement Proof of Stake logic, including stake validation and penalties
            // Example placeholder
            block.transactions.iter().all(|tx| tx.gas_limit > 0)
        }
    }
}

mod contracts {
    pub fn execute_wasm_contract(wasm_code: Vec<u8>, gas_limit: u64) -> Result<(), String> {
        use wasmer::{Instance, Module, Store, imports};
        let store = Store::default();
        let module = Module::new(&store, wasm_code).map_err(|e| e.to_string())?;
        let import_object = imports! {};
        let instance = Instance::new(&module, &import_object).map_err(|e| e.to_string())?;

        // Implement gas metering (example placeholder)
        if gas_limit < 500 { // Arbitrary minimum gas
            return Err("Insufficient gas".to_string());
        }

        let main = instance.exports.get_function("main").map_err(|e| e.to_string())?;
        main.call(&[]).map_err(|e| e.to_string())?;

        Ok(())
    }
}

fn main() {
    use p256::ecdsa::{SigningKey, signature::Signer};
    let signing_key = SigningKey::random(rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();

    let mut blockchain = blockchain::Blockchain::new();
    blockchain.public_keys.insert("Alice".to_string(), verifying_key);

    let message = "Alice:Bob:CustodyToken(10.0):1:1000";
    let signature = signing_key.sign(message.as_bytes());

    let tx1 = blockchain::Transaction {
        sender: "Alice".to_string(),
        receiver: "Bob".to_string(),
        token: blockchain::Token::CustodyToken(10.0),
        nonce: 1,
        contract_code: None,
        gas_limit: 1000,
        zkp: None,
        signature: hex::encode(signature.to_der().as_bytes()),
    };

    let shard_id = blockchain.assign_shard(&tx1.sender);
    blockchain.add_block(vec![tx1], shard_id);

    println!("Blockchain initialized and updated with ECC integration, sharding, and batch verification.");
}
