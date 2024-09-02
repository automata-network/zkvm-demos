use std::{path::PathBuf, str::FromStr, time::Duration};
use risc0_zkvm::compute_image_id;
use alloy::{
    dyn_abi::SolType, 
    network::EthereumWallet, 
    primitives::{Address, Bytes}, 
    providers::ProviderBuilder, 
    rpc::types::TransactionReceipt, 
    signers::{k256::ecdsa::SigningKey, 
        local::PrivateKeySigner
    }, 
    sol, 
    transports::http::reqwest::Url
};
use anyhow::{Error, Result, Context};
use clap::Parser;
use bonsai_sdk::alpha as bonsai_sdk;
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
    #[arg(long = "rpc", value_name = "RPC_URL", default_value_t = String::from("https://eth-sepolia.public.blastapi.io"))]
    rpc_url: String,

    /// Optional: X509 Chain Demo Contract Address
    #[arg(long = "contract", value_name = "CONTRACT_ADDRESS", default_value_t = String::from("E422F19773Cb4640a1CdAe635E7d74C59CC8Ce10"))]
    address: String,

    /// REQUIRED: if the verify option is enabled,
    /// The user must provide an Ethereum Wallet Key
    #[arg(short = 'w', long = "wallet-key")]
    wallet: Option<String>,

    /// Verify the provided cert chain
    /// If not specified, attempts to fetch the Journal on-chain
    #[arg(short = 'v', long = "verify")]
    verify: bool
}

struct Chain {
    pub rpc_url: Url,
    pub contract_address: Address,
    pub wallet: Option<EthereumWallet>
}

impl Chain {
    fn new(rpc_url_str: &str, address: &str) -> Self {
        Chain {
            rpc_url: rpc_url_str.parse().unwrap(),
            contract_address: Address::from_str(address).unwrap(),
            wallet: None
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
        remove_prefix_if_found(&cli.address)
    );

    // Step 3
    if cli.verify {
        // A wallet is required to store the Journal on-chain
        if let Some(wallet_key) = &cli.wallet {
            chain.set_wallet(wallet_key.as_str());
        } else {
            return Err(Error::msg("Missing wallet key"));
        }

        log::info!("Submitting input to Bonsai...");
        let input = InputBytesType::abi_encode_params(&der_chain);
        let seal = prove(&input)?;
        log::info!("Submitting SNARK proof on-chain...");

        let rt = tokio::runtime::Runtime::new().unwrap();
        let transaction_receipt = rt.block_on(verify_cert_chain_proof(
            chain, 
            der_chain, 
            &seal
        ))?;
        println!("Cert Chain Verified at https://sepolia.etherscan.io/tx/{}", transaction_receipt.transaction_hash.to_string());

    } else {
        log::info!("Getting journal...");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let journal = rt.block_on(read_journal(chain, der_chain))?;
        println!("{:?}", journal);
    }
    
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
    let contract = X509VerifierDemo::new(
        chain_config.contract_address,
        &provider
    );

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
    seal: &[u8]
) -> Result<TransactionReceipt> {
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(chain_config.wallet.unwrap())
        .on_http(chain_config.rpc_url)
    ;
    let contract = X509VerifierDemo::new(
        chain_config.contract_address,
        &provider
    );

    let mut encoded: Vec<Bytes> = Vec::with_capacity(der_chain.len());
    for der in der_chain.iter() {
        encoded.push(Bytes::copy_from_slice(&der));
    }

    let tx_builder = contract.verifyX509ChainProof(
        encoded, 
        Bytes::copy_from_slice(seal)
    );
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

fn prove(input: &[u8]) -> Result<Vec<u8>> {
    let risc_zero_version =
        std::env::var("RISC_ZERO_VERSION").unwrap_or_else(|_| "1.0.1".to_string());
    let client = bonsai_sdk::Client::from_env(&risc_zero_version)?;

    let image_id = compute_image_id(X509_CHAIN_VERIFIER_ELF)?;
    let image_id_hex = image_id.to_string();
    client.upload_img(&image_id_hex, X509_CHAIN_VERIFIER_ELF.to_vec())?;
    log::info!("ImageID: {}", image_id_hex);

    // Prepare input data and upload it.
    let input_id = client.upload_input(input.to_vec())?;

    log::info!("InputID: {}", input_id);

    // Start a session running the prover.
    let session = client.create_session(image_id_hex, input_id, vec![])?;
    log::info!("Prove session created, uuid: {}", session.uuid);
    let _receipt = loop {
        let res = session.status(&client)?;
        if res.status == "RUNNING" {
            std::thread::sleep(Duration::from_secs(15));
            continue;
        }
        if res.status == "SUCCEEDED" {
            log::info!("Prove session is successful!");
            // Download the receipt, containing the output.
            let receipt_url = res
                .receipt_url
                .context("API error, missing receipt on completed session")?;

            log::info!("Receipt URL: {}", &receipt_url);

            // break receipt;
            break;
        }

        panic!(
            "Workflow exited: {} | SessionId: {} | err: {}",
            res.status,
            session.uuid,
            res.error_msg.unwrap_or_default()
        );
    };

    // Fetch the snark.
    let snark_session = client.create_snark(session.uuid)?;
    log::info!(
        "Proof to SNARK session created, uuid: {}",
        snark_session.uuid
    );
    let snark_receipt = loop {
        let res = snark_session.status(&client)?;
        match res.status.as_str() {
            "RUNNING" => {
                std::thread::sleep(Duration::from_secs(15));
                continue;
            }
            "SUCCEEDED" => {
                log::info!("Snark session is successful!");
                break res.output.context("No snark generated :(")?;
            }
            _ => {
                panic!(
                    "Workflow exited: {} | SessionId: {} | err: {}",
                    res.status,
                    snark_session.uuid,
                    res.error_msg.unwrap_or_default()
                );
            }
        }
    };

    let snark = snark_receipt.snark.to_vec();

    let mut seal = Vec::with_capacity(4 + snark.len());
    seal.extend_from_slice(&hex::decode("310fe598")?);
    seal.extend_from_slice(&snark);

    Ok(seal)
}