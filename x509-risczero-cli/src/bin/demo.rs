use alloy::{
    dyn_abi::SolType,
    network::EthereumWallet,
    primitives::{Address, Bytes},
    providers::ProviderBuilder,
    rpc::types::TransactionReceipt,
    signers::{k256::ecdsa::SigningKey, local::PrivateKeySigner},
    sol,
    transports::http::reqwest::Url,
};
use anyhow::Result;
use clap::Parser;
use nom::AsBytes;
use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, ProverOpts};
use risc0_ethereum_contracts::groth16;
use std::{env, path::PathBuf, str::FromStr};
use x509_parser::prelude::*;
use x509_risczero_cli::X509_CHAIN_VERIFIER_ELF;

type InputBytesType = sol!(bytes[]);

#[derive(Parser)]
#[command(name = "X509DemoApp")]
#[command(version = "1.0")]
#[command(about = "Performs X509 Chain Verification via Bonsai, then submits proof on-chain", long_about = None)]
struct Cli {
    /// One or more paths to PEM file(s).
    /// If multiple PEM files provided, you must ensure that they are ordered bottom-top
    /// from leaf to root.
    #[arg(short = 'c', long = "cert-chain", value_name = "ONE_OR_MORE_PEM_PATH")]
    cert_chain: Vec<PathBuf>,

    /// Optional: RPC URL
    #[arg(long = "rpc", value_name = "RPC_URL", default_value_t = String::from("https://1rpc.io/ata/testnet"))]
    rpc_url: String,

    /// Optional: X509 Chain Demo Contract Address
    #[arg(long = "contract", value_name = "CONTRACT_ADDRESS", default_value_t = String::from("005537B5cE847Dc3B5C8B9A42B366E7d932431d3"))]
    address: String,

    /// REQUIRED: if the verify option is enabled,
    /// The user must provide an Ethereum Wallet Key
    #[arg(short = 'w', long = "wallet-key")]
    wallet: Option<String>,

    /// Verify the provided cert chain
    /// If not specified, attempts to fetch the Journal on-chain
    #[arg(short = 'v', long = "verify")]
    verify: bool,
}

struct Chain {
    pub rpc_url: Url,
    pub contract_address: Address,
    pub wallet: Option<EthereumWallet>,
}

impl Chain {
    fn new(rpc_url_str: &str, address: &str) -> Self {
        Chain {
            rpc_url: rpc_url_str.parse().unwrap(),
            contract_address: Address::from_str(address).unwrap(),
            wallet: None,
        }
    }

    fn set_wallet(&mut self, wallet_key: &str) {
        let signer_key =
            SigningKey::from_slice(&hex::decode(wallet_key).unwrap()).expect("Invalid key");
        let wallet = EthereumWallet::from(PrivateKeySigner::from_signing_key(signer_key));

        self.wallet = Some(wallet);
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    env_logger::init();

    // Step 1: Read PEM and encode the input
    let mut der_chain: Vec<Vec<u8>> = Vec::with_capacity(cli.cert_chain.len());
    for path in cli.cert_chain.iter() {
        let pem = std::fs::read(path)?;
        let der = pem_to_der(&pem);
        der_chain = [der_chain, der].concat();
    }

    // Step 2: Create a Chain instance
    let mut chain = Chain::new(
        remove_prefix_if_found(&cli.rpc_url),
        remove_prefix_if_found(&cli.address),
    );

    // Step 3
    if cli.verify {
        let input = InputBytesType::abi_encode_params(&der_chain);
        let is_dev_mode = if let Ok(dev_mode) = env::var("RISC0_DEV_MODE") {
            dev_mode == "true" || dev_mode == "1"
        } else {
            false
        };
        let bonsai_configured =
            env::var("BONSAI_API_KEY").is_ok() && env::var("BONSAI_API_URL").is_ok();
        let prover_mode_is_bonsai = if let Ok(prover_mode) = env::var("RISC0_PROVER") {
            bonsai_configured && prover_mode != "local" && prover_mode != "ipc" && !is_dev_mode
        } else {
            bonsai_configured && !is_dev_mode
        };

        if prover_mode_is_bonsai {
            log::info!("Begin proving on Bonsai...");
        } else if is_dev_mode {
            log::info!("Proving in DEV_MODE...");
        } else {
            log::info!("Begin proving locally...");
        }
        let seal = prove(&input, prover_mode_is_bonsai)?;

        // A wallet is required to store the Journal on-chain
        if let Some(wallet_key) = &cli.wallet {
            if prover_mode_is_bonsai {
                log::info!("Submitting SNARK proof on-chain...");
                chain.set_wallet(wallet_key.as_str());
                let rt = tokio::runtime::Runtime::new().unwrap();
                let transaction_receipt =
                    rt.block_on(verify_cert_chain_proof(chain, der_chain, &seal))?;
                println!(
                    "Cert Chain Verified at https://explorer-testnet.ata.network/tx/{}",
                    transaction_receipt.transaction_hash.to_string()
                );
            }
        }
    } else {
        log::info!("Getting journal...");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let journal = rt.block_on(read_journal(chain, der_chain))?;
        println!("{:?}", journal);
    }

    println!("Job completed.");

    Ok(())
}

fn pem_to_der(pem_chain: &[u8]) -> Vec<Vec<u8>> {
    let mut der_chain: Vec<Vec<u8>> = Vec::new();

    for pem in Pem::iter_from_buffer(pem_chain) {
        let current_pem_content = pem.unwrap().contents;
        der_chain.push(current_pem_content);
    }

    der_chain
}

use X509VerifierDemo::Journal;
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    X509VerifierDemo,
    "artifacts/X509VerifierDemo.json"
}

async fn read_journal(chain_config: Chain, der_chain: Vec<Vec<u8>>) -> Result<Journal> {
    let provider = ProviderBuilder::new().on_http(chain_config.rpc_url);
    let contract = X509VerifierDemo::new(chain_config.contract_address, &provider);

    let mut encoded: Vec<Bytes> = Vec::with_capacity(der_chain.len());
    for der in der_chain.iter() {
        encoded.push(Bytes::copy_from_slice(&der));
    }

    let call_builder = contract.getVerifiedX509Journal(encoded);
    let call_return = call_builder.call().await?;

    Ok(call_return.journal)
}

async fn verify_cert_chain_proof(
    chain_config: Chain,
    der_chain: Vec<Vec<u8>>,
    seal: &[u8],
) -> Result<TransactionReceipt> {
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(chain_config.wallet.unwrap())
        .on_http(chain_config.rpc_url);
    let contract = X509VerifierDemo::new(chain_config.contract_address, &provider);

    let mut encoded: Vec<Bytes> = Vec::with_capacity(der_chain.len());
    for der in der_chain.iter() {
        encoded.push(Bytes::copy_from_slice(&der));
    }

    let tx_builder = contract.verifyX509ChainProof(encoded, Bytes::copy_from_slice(seal));
    log::debug!("Calldata: {}", hex::encode(tx_builder.calldata().as_bytes()));
    let receipt = tx_builder.send().await?.get_receipt().await?;

    Ok(receipt)
}

fn remove_prefix_if_found(h: &str) -> &str {
    if h.starts_with("0x") {
        &h[2..]
    } else {
        &h
    }
}

fn prove(input: &[u8], prover_mode_is_bonsai: bool) -> Result<Vec<u8>> {
    let env = ExecutorEnv::builder().write_slice(&input).build()?;

    log::info!("ImageID: {}", compute_image_id(X509_CHAIN_VERIFIER_ELF).unwrap().to_string());

    if prover_mode_is_bonsai {
        let receipt = default_prover()
            .prove_with_opts(env, X509_CHAIN_VERIFIER_ELF, &ProverOpts::groth16())?
            .receipt;

        let snark = receipt.inner.groth16()?.seal.clone();

        let seal = groth16::encode(&snark)?;

        Ok(seal)
    } else {
        // generate STARK proof when run locally
        let receipt = default_prover()
            .prove(env, X509_CHAIN_VERIFIER_ELF)?
            .receipt;
        println!("Receipt: {:?}", receipt);
        Ok(vec![])
    }
}
