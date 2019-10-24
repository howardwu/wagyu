<h1 align="center">
    <img width="1412" src="https://user-images.githubusercontent.com/9260812/62808478-09eac480-baad-11e9-92c9-f9a6ef4e7bc2.png">
</h1>
<p align="center">
    <a href="https://crates.io/crates/wagyu"><img src="https://img.shields.io/crates/v/wagyu.svg?color=neon"></a>
    <a href="https://travis-ci.com/ArgusHQ/wagyu"><img src="https://img.shields.io/travis/com/ArgusHQ/wagyu/v0.6.1.svg"></a>
    <a href="https://codecov.io/gh/ArgusHQ/wagyu"><img src="https://img.shields.io/codecov/c/github/ArgusHQ/wagyu.svg"></a>
    <a href="./AUTHORS"><img src="https://img.shields.io/badge/authors-Argus-orange.svg"></a>
    <a href="./LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT/Apache--2.0-blue.svg"></a>
</p>

<p align="center">
    <img src="https://user-images.githubusercontent.com/9260812/62804070-05b8aa00-baa1-11e9-905f-faea3d8de13b.gif">
</p>

## <a name='TableofContents'></a>Table of Contents

* [1. Overview](#1-overview)
* [2. Build Guide](#2-build-guide)
    * [2.1 Install from Homebrew](#21-install-from-homebrew)
    * [2.2 Install Rust](#22-install-rust)
    * [2.3a Build from Crates.io](#23a-build-from-cratesio)
    * [2.3b Build from Source Code](#23b-build-from-source-code)
* [3. Usage Guide](#3-usage-guide)
	* [3.1 Generate a cryptocurrency wallet](#31-generate-a-cryptocurrency-wallet)
	* [3.2 Generate an HD cryptocurrency wallet](#32-generate-an-hd-cryptocurrency-wallet)
	* [3.3 Import a cryptocurrency wallet](#33-import-a-cryptocurrency-wallet)
	* [3.4 Import an HD cryptocurrency wallet](#34-import-an-hd-cryptocurrency-wallet)
* [4. License](#4-license)

## 1. Overview

Wagyu is a feature-rich command-line utility to generate a cryptocurrency wallet.

Wagyu enables developers to build their own cryptocurrency application using the following modules.

| Library                                                                                                                                                      | Standard Wallet                                                       | HD Wallet                                                                                    | Mnemonic                        | Network                                                         |
|:------------------------------------------------------------------------------------------------------------------------------------------------------------:|-----------------------------------------------------------------------|----------------------------------------------------------------------------------------------|---------------------------------|-----------------------------------------------------------------|
| [**wagyu-bitcoin**](./bitcoin)   <br/> [![Crates.io](https://img.shields.io/crates/v/wagyu-bitcoin.svg?color=neon)](https://crates.io/crates/wagyu-bitcoin)  | <br/><ul><li>P2PKH</li><li>P2SH-P2WPKH</li><li>Bech32</li></ul>       | <br/><ul><li>BIP-32</li><li>BIP-44</li><li>BIP-49</li><li>Custom</li></ul>                   | <br/><ul><li>BIP-39</li></ul>   | <br/><ul><li>Mainnet</li><li>Testnet</li></ul>                  |
| [**wagyu-ethereum**](./ethereum) <br/> [![Crates.io](https://img.shields.io/crates/v/wagyu-ethereum.svg?color=neon)](https://crates.io/crates/wagyu-ethereum)| <br/><ul><li>Standard</li></ul>                                       | <br/><ul><li>Ethereum</li><li>Ledger</li><li>Trezor</li><li>Keepkey</li><li>Custom</li></ul> | <br/><ul><li>BIP-39</li></ul>   | <br/><ul><li>All</li></ul>                                      |
| [**wagyu-monero**](./monero)     <br/> [![Crates.io](https://img.shields.io/crates/v/wagyu-monero.svg?color=neon)](https://crates.io/crates/wagyu-monero)    | <br/><ul><li>Standard</li><li>Integrated</li><li>Subaddress</li></ul> | <br/><ul><li>N/A</ul>                                                                        | <br/><ul><li>Electrum</li></ul> | <br/><ul><li>Mainnet</li><li>Testnet</li><li>Stagenet</li></ul> |
| [**wagyu-zcash**](./zcash)       <br/> [![Crates.io](https://img.shields.io/crates/v/wagyu-zcash.svg?color=neon)](https://crates.io/crates/wagyu-zcash)      | <br/><ul><li>P2PKH</li><li>Sprout</li><li>Sapling</li></ul>                          | <br/><ul><li>ZIP-32</li></ul>                                                 | <br/><ul><li>N/A</li></ul>      | <br/><ul><li>Mainnet</li><li>Testnet</li></ul>                  |

Wagyu can support new cryptocurrencies by implementing the model as outlined in this module.

| Library                                                                                                                                           | Standard Wallet                                                                                                                                                | HD Wallet                                                                                                                                                                                                       | Mnemonic                                                                                                       | Network                                                   |
|:-------------------------------------------------------------------------------------------------------------------------------------------------:|----------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| [**wagyu_model**](./model) <br/> [![Crates.io](https://img.shields.io/crates/v/wagyu-model.svg?color=neon)](https://crates.io/crates/wagyu-model) | <br/><ul><li>[Address](./model/src/address.rs)</li><li>[Public Key](./model/src/public_key.rs)</li><li>[Private Key](./model/src/private_key.rs)</li></ul>     | <br/><ul><li>[Derivation Path](./model/src/derivation_path.rs)</li><li>[Extended Public Key](./model/src/extended_public_key.rs)</li><li>[Extended Private Key](./model/src/extended_private_key.rs)</li></ul>  | <br/><ul><li>[Mnemonic](./model/src/mnemonic.rs)</li><li>[Wordlist](model/src/wordlist/wordlist.rs)</li></ul>  |<br/><ul><li>[Network](./model/src/network.rs)</li></ul>   |


## 2. Build Guide

### 2.1 Install from Homebrew

The simplest way to install `wagyu` is via Homebrew as follows:

```bash
brew install wagyu
```

### 2.2 Install Rust

We recommend installing Rust using [rustup](https://www.rustup.rs/). You can install `rustup` as follows:

- macOS or Linux:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- Windows (64-bit):  
  
  Download the [Windows 64-bit executable](https://win.rustup.rs/x86_64) and follow the on-screen instructions.

- Windows (32-bit):  
  
  Download the [Windows 32-bit executable](https://win.rustup.rs/i686) and follow the on-screen instructions.

### 2.3a Build from Crates.io

We recommend installing `wagyu` this way. In your terminal, run:

```bash
cargo install wagyu
```

Now to use `wagyu`, in your terminal, run:
```bash
wagyu
```
 
### 2.3b Build from Source Code

Alternatively, you can install `wagyu` by building from the source code as follows:

```bash
# Download the source code
git clone https://github.com/ArgusHQ/wagyu
cd wagyu

# Build in release mode
$ cargo build --release
```

This will generate an executable under the `./target/release` directory. To use wagyu, run the following command:
```bash
./target/release/wagyu
```

## 3. Usage Guide

### 3.1 Generate a cryptocurrency wallet

To generate a cryptocurrency wallet, run:
```
wagyu [CRYPTOCURRENCY] [FLAGS] [OPTIONS]
```

#### 3.1.1 Bitcoin

To generate a Bitcoin wallet, run:
```
wagyu bitcoin [FLAGS] [OPTIONS]
```

The command can be run with the following optional parameters:
```
FLAGS:
    -h, --help    Prints help information
    -j, --json    Prints the generated wallet(s) in JSON format

OPTIONS:
    -c, --count <count>        Generates a specified number of wallets
    -f, --format <format>      Generates a wallet with a specified format [possible values: bech32, legacy, segwit]
    -n, --network <network>    Generates a wallet for a specified network [possible values: mainnet, testnet]
```

#### 3.1.2 Ethereum

To generate an Ethereum wallet, run:
```
wagyu ethereum [FLAGS] [OPTIONS]
```

The command can be run with the following optional parameters:
```
FLAGS:
    -h, --help    Prints help information
    -j, --json    Prints the generated wallet(s) in JSON format

OPTIONS:
    -c, --count <count>    Generates a specified number of wallets
```


#### 3.1.3 Monero

To generate a Monero wallet, run:
```
wagyu monero [FLAGS] [OPTIONS]
```

The command can be run with the following parameters: 

```
FLAGS:
    -h, --help    Prints help information
    -j, --json    Prints the generated wallet(s) in JSON format

OPTIONS:
    -c, --count <count>                             Generates a specified number of wallets
    -i, --integrated <PaymentID>                    Generates a wallet with a specified payment ID
    -l, --language <language>                       Generates a wallet with a specified language [possible values: chinese_simplified, dutch, english, esperanto, french, german, italian, japanese, lojban, portuguese, russian, spanish]
    -n, --network <network>                         Generates a wallet for a specified network [possible values: mainnet, stagenet, testnet]
    -s, --subaddress <Major Index> <Minor Index>    Generates a wallet with a specified major and minor index
```

#### 3.1.4 Zcash

To generate a Zcash wallet, run:
```
wagyu zcash [FLAGS] [OPTIONS]
```

The command can be run with the following parameters: 

```
FLAGS:
    -h, --help    Prints help information
    -j, --json    Prints the generated wallet(s) in JSON format

OPTIONS:
    -c, --count <count>                Generates a specified number of wallets
        --diversifier <diversifier>    Generates a wallet with a specified Sapling address diversifier
    -f, --format <format>              Generates a wallet with a specified format [possible values: sapling, sprout, transparent]
    -n, --network <network>            Generates a wallet for a specified network [possible values: mainnet, testnet]
```

### 3.2 Generate an HD cryptocurrency wallet

To generate an HD cryptocurrency wallet, run:
```
wagyu [CRYPTOCURRENCY] hd [FLAGS] [OPTIONS]
```

#### 3.2.1 Bitcoin

To generate a Bitcoin HD wallet, run:
```
wagyu bitcoin hd [FLAGS] [OPTIONS]
```

This command can be run with the following parameters:
```
FLAGS:
    -h, --help    Prints help information
    -j, --json    Prints the generated wallet(s) in JSON format

OPTIONS:
    -c, --count <count>              Generates a specified number of wallets
    -d, --derivation <"path">        Generates an HD wallet for a specified derivation path (in quotes) [possible values: bip32, bip44, bip49, "<custom path>"]
    -l, --language <language>        Generates an HD wallet with a specified language [possible values: chinese_simplified, chinese_traditional, english, french, italian, japanese, korean, spanish]
    -n, --network <network>          Generates an HD wallet for a specified network [possible values: mainnet, testnet]
    -p, --password <password>        Generates an HD wallet with a specified password
    -w, --word-count <word count>    Generates an HD wallet with a specified word count [possible values: 12, 15, 18, 21, 24]
```

#### 3.2.2 Ethereum

To generate an Ethereum HD wallet, run:
```
wagyu ethereum hd [FLAGS] [OPTIONS]
```

The command can be run with the following parameters: 
```
FLAGS:
    -h, --help    Prints help information
    -j, --json    Prints the generated wallet(s) in JSON format

OPTIONS:
    -c, --count <count>              Generates a specified number of wallets
    -d, --derivation <"path">        Generates an HD wallet for a specified derivation path (in quotes) [possible values: ethereum, keepkey, ledger-legacy, ledger-live, trezor, "<custom path>"]
    -l, --language <language>        Generates an HD wallet with a specified language [possible values: chinese_simplified, chinese_traditional, english, french, italian, japanese, korean, spanish]
    -p, --password <password>        Generates an HD wallet with a specified password
    -w, --word-count <word count>    Generates an HD wallet with a specified word count [possible values: 12, 15, 18, 21, 24]
```

#### 3.2.3 Zcash

To generate a Zcash HD wallet, run:
```
wagyu zcash hd [FLAGS] [OPTIONS]
```

The command can be run with the following parameters: 
```
FLAGS:
    -h, --help    Prints help information
    -j, --json    Prints the generated wallet(s) in JSON format

OPTIONS:
    -c, --count <count>                Generates a specified number of wallets
    -d, --derivation <"path">          Generates an HD wallet for a specified derivation path (in quotes) [possible values: zip32, "<custom path>"]
        --diversifier <diversifier>    Imports a wallet with a specified Sapling address diversifier
    -n, --network <network>            Generates an HD wallet for a specified network [possible values: mainnet, testnet]
```

### 3.3 Import a cryptocurrency wallet

To import a cryptocurrency wallet, run:
```
wagyu [CRYPTOCURRENCY] import [FLAGS] [OPTIONS]
```

#### 3.3.1 Bitcoin

To import a Bitcoin wallet, run:
```
wagyu bitcoin import [FLAGS] [OPTIONS]
```

This command can be run with the following parameters:
```
FLAGS:
    -h, --help    Prints help information
    -j, --json    Prints the generated wallet(s) in JSON format

OPTIONS:
        --address <address>        Imports a partial wallet for a specified address
    -f, --format <format>          Imports a wallet with a specified format [possible values: bech32, legacy, segwit]
    -n, --network <network>        Imports a wallet for a specified network [possible values: mainnet, testnet]
        --private <private key>    Imports a wallet for a specified private key
        --public <public key>      Imports a partial wallet for a specified public key
```

#### 3.3.2 Ethereum

To import an Etheruem wallet, run:
```
wagyu ethereum import [FLAGS] [OPTIONS]
```

This command can be run with the following parameters:

```
FLAGS:
    -h, --help    Prints help information
    -j, --json    Prints the generated wallet(s) in JSON format

OPTIONS:
        --address <address>        Imports a partial wallet for a specified address
        --private <private key>    Imports a wallet for a specified private key
        --public <public key>      Imports a partial wallet for a specified public key
```

#### 3.3.3 Monero

To import a Monero wallet, run:
```
wagyu monero import [FLAGS] [OPTIONS]
```

This command can be run with the following parameters:
```
FLAGS:
    -h, --help    Prints help information
    -j, --json    Prints the generated wallet(s) in JSON format

OPTIONS:
        --address <address>                         Imports a partial wallet for a specified address
    -i, --integrated <PaymentID>                    Imports a wallet with a specified payment ID
    -l, --language <language>                       Imports a wallet with a specified mnemonic language (requires private spend key) [possible values: chinese_simplified, dutch, english, esperanto, french, german, italian, japanese, lojban, portuguese, russian, spanish]
    -m, --mnemonic <"mnemonic">                     Imports a wallet for a specified mnemonic (in quotes)
    -n, --network <network>                         Imports a wallet for a specified network [possible values: mainnet, stagenet, testnet]
        --private-spend <private spend key>         Imports a wallet for a specified private spend key
        --private-view <private view key>           Imports a partial wallet for a specified private view key
        --public-spend <public spend key>           Imports a partial wallet for a specified public spend key
        --public-view <public view key>             Imports a partial wallet for a specified public view key
    -s, --subaddress <Major Index> <Minor Index>    Imports a wallet with a specified major and minor index
```

#### 3.3.4 Zcash

To import a Zcash wallet, run:
```
wagyu zcash import [FLAGS] [OPTIONS]
```

This command can be run with the following parameters:

```
FLAGS:
    -h, --help    Prints help information
    -j, --json    Prints the generated wallet(s) in JSON format

OPTIONS:
        --address <address>            Imports a partial wallet for a specified address
        --diversifier <diversifier>    Imports a wallet with a specified Sapling address diversifier
        --private <private key>        Imports a wallet for a specified private key
        --public <public key>          Imports a partial wallet for a specified public key
```

### 3.4 Import an HD cryptocurrency wallet

To import an HD cryptocurrency wallet, run:
```
wagyu [CRYPTOCURRENCY] import-hd [FLAGS] [OPTIONS]
```

#### 3.4.1 Bitcoin

To import an Bitcoin HD wallet, run:
```
wagyu bitcoin hd [FLAGS] [OPTIONS]
```

This command can be run with the following parameters:
```
FLAGS:
    -h, --help    Prints help information
    -j, --json    Prints the generated wallet(s) in JSON format

OPTIONS:
    -a, --account <account>                      Imports an HD wallet for a specified account number for bip44 and bip49 derivations
    -c, --chain <chain>                          Imports an HD wallet for a specified (external/internal) chain for bip44 and bip49 derivations [possible values: 0, 1]
    -d, --derivation <"path">                    Imports an HD wallet for a specified derivation path (in quotes) [possible values: bip32, bip44, bip49, "<custom path>"]
        --extended-private <extended private>    Imports a partial HD wallet for a specified extended private key
        --extended-public <extended public>      Imports a partial HD wallet for a specified extended public key
    -i, --index <index>                          Imports an HD wallet for a specified index
    -m, --mnemonic <"mnemonic">                  Imports an HD wallet for a specified mnemonic (in quotes)
    -n, --network <network>                      Imports an HD wallet for a specified network [possible values: mainnet, testnet]
    -p, --password <password>                    Imports an HD wallet with a specified password
```

#### 3.4.2 Ethereum

To import an Ethereum HD wallet, run:
```
wagyu ethereum hd [FLAGS] [OPTIONS]
```

This command can be run with the following parameters:

```
FLAGS:
    -h, --help    Prints help information
    -j, --json    Prints the generated wallet(s) in JSON format

OPTIONS:
    -d, --derivation <"path">                    Imports an HD wallet for a specified derivation path (in quotes) [possible values: ethereum, keepkey, ledger-legacy, ledger-live, trezor, "<custom path>"]
        --extended-private <extended private>    Imports a partial HD wallet for a specified extended private key
        --extended-public <extended public>      Imports a partial HD wallet for a specified extended public key
    -i, --index <index>                          Imports an HD wallet for a specified index
    -m, --mnemonic <"mnemonic">                  Imports an HD wallet for a specified mnemonic (in quotes)
    -p, --password <password>                    Imports an HD wallet with a specified password
```

#### 3.4.3 Zcash

To import an Zcash HD wallet, run:
```
wagyu zcash hd [FLAGS] [OPTIONS]
```

This command can be run with the following parameters:

```
FLAGS:
    -h, --help    Prints help information
    -j, --json    Prints the generated wallet(s) in JSON format

OPTIONS:
    -a, --account <account>                      Imports an HD wallet for a specified account number for bip44 and bip49 derivations
    -d, --derivation <"path">                    Imports an HD wallet for a specified derivation path (in quotes) [possible values: zip32, "<custom path>"]
        --diversifier <diversifier>              Imports an HD wallet with a specified Sapling address diversifier
        --extended-private <extended private>    Imports a partial HD wallet for a specified extended private key
        --extended-public <extended public>      Imports a partial HD wallet for a specified extended public key
    -i, --index <index>                          Imports an HD wallet for a specified index
```

## 4. License

This work is licensed under either of the following licenses, at your discretion.

- Apache License Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
