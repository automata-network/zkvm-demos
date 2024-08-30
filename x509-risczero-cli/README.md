# X509 Chain Verifier RiscZero Demo CLI

---

## Summary

Follow these steps to get started with this tool:

0. Install [Rust](https://doc.rust-lang.org/book/ch01-01-installation.html)

1. Export `BONSAI_API_KEY` and `BONSAI_API_URL` values into the shell. If you don't have a Bonsai API key, send a [request](https://docs.google.com/forms/d/e/1FAIpQLSf9mu18V65862GS4PLYd7tFTEKrl90J5GTyzw_d14ASxrruFQ/viewform) for one.

```bash
export BONSAI_API_KEY="" # see form linked above
export BONSAI_API_URL="" # provided with your api key
```

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
Performs X509 Chain Verification via Bonsai, then submits proof on-chain

Usage: demo [OPTIONS]

Options:
  -c, --cert-chain <ONE_OR_MORE_PEM_PATH>
          One or more paths to PEM file(s). If multiple PEM files provided, you must ensure that they are ordered bottom-top from leaf to root
      --rpc <RPC_URL>
          Sepolia RPC_URL
      --contract <CONTRACT_ADDRESS>
          Optional: X509 Chain Demo Contract Address [default: E422F19773Cb4640a1CdAe635E7d74C59CC8Ce10]
  -w, --wallet-key <WALLET>
          REQUIRED: if the verify option is enabled, The user must provide an Ethereum Wallet Key
  -v, --verify
          Verify the provided cert chain If not specified, attempts to fetch the Journal on-chain
  -h, --help
          Print help
  -V, --version
          Print version
```

To submit verification of the X509 Certificate Chain, pass one or more `-c` arguments followed by the path to PEM file(s). You must pass along the `-v` flag to enable the verifier and your wallet key to the `-w` flag. Run the following command for an example:

```bash
RUST_LOG="info" ./target/release/demo -c ./samples/attestation.pem -v -w <WALLET_KEY>
```

Upon successful verification, the journal will then be submitted on-chain.

To retrieve an existing journal for a verified X509 Certificate Chain, you may simply omit the `-v` and `-w` flags.

```bash
./target/release/demo -c ./samples/attestation.pem
```

---

## Sepolia Faucet

The demo is currently deployed on Sepolia. Feel free to use our Sepolia [faucet](https://www.sepoliafaucet.io/) to get your wallet funded for testing!