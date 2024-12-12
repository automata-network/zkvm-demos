# X509 Chain Verifier RiscZero Demo CLI

---

## Summary

Follow these steps to get started with this tool:

0. Install [Rust](https://doc.rust-lang.org/book/ch01-01-installation.html) and [cargo risczero](https://dev.risczero.com/api/zkvm/install)

Make sure you are running `cargo-risczero` at `v1.2.0`. Run the following command to check risczero version:

```bash
cargo risczero --version
```

You shouldn't have issues verifying proofs on-chain as long as you are running `cargo-risczero` at `>=v1.1.0`.

1. Configure the Prover 

### Bonsai Prover

To prove via Bonsai, export the `BONSAI_API_KEY` and `BONSAI_API_URL` envrionmental values into the shell. If you don't have a Bonsai API key, send a [request](https://docs.google.com/forms/d/e/1FAIpQLSf9mu18V65862GS4PLYd7tFTEKrl90J5GTyzw_d14ASxrruFQ/viewform) for one.

```bash
export BONSAI_API_KEY="" # see form linked above
export BONSAI_API_URL="" # provided with your api key
```

### Local Prover

If the `BONSAI_API_KEY` and `BONSAI_API_URL` envrionmental values were not configured, the local prover is set by default. Otherwise, you may also explicitly run the local prover by setting `RISC0_PROVER="local"`.

**Note:** Getting proofs locally will **NOT** send a transaction to the Verifier contract.

2. Build the program.

```bash
cargo build --release
```

---

## CLI Commands

You may run the following command to see available commands.

```bash
./target/release/demo --help
```

Outputs:

```bash
Performs X509 Chain Verification via Bonsai, then submits proof on-chain

Usage: demo [OPTIONS]

Options:
  -c, --cert-chain <ONE_OR_MORE_PEM_PATH>
          One or more paths to PEM file(s). If multiple PEM files provided, you must ensure that they are ordered bottom-top from leaf to root
      --rpc <RPC_URL>
          Optional: RPC URL [default: https://1rpc.io/ata/testnet]
      --contract <CONTRACT_ADDRESS>
          Optional: X509 Chain Demo Contract Address [default: 005537B5cE847Dc3B5C8B9A42B366E7d932431d3]
  -w, --wallet-key <WALLET>
          REQUIRED: if the verify option is enabled, The user must provide an Ethereum Wallet Key
  -v, --verify
          Verify the provided cert chain If not specified, attempts to fetch the Journal on-chain
  -h, --help
          Print help
  -V, --version
          Print version
```

To submit verification of the X509 Certificate Chain, pass one or more `-c` arguments followed by the path to PEM file(s). 

You must pass along the `-v` flag to generate proofs either locally or via Bonsai.

Pass your wallet key to the `-w` flag, if running with Bonsai prover and you intend to verify proofs on-chain. 

Run the following command for an example:

```bash
RUST_LOG="info" ./target/release/demo -c ./samples/attestation.pem -v -w <WALLET_KEY>
```

Upon successful verification, the journal will then be submitted on-chain.

To retrieve an existing journal for a verified X509 Certificate Chain from the verifier contract, you may simply omit the `-v` and `-w` flags.

```bash
./target/release/demo -c ./samples/attestation.pem
```

---

## Automata Testnet Faucet

The demo is currently deployed on our testnet. Feel free to use [L2Faucet](https://www.l2faucet.com/) to get your wallet funded for testing!