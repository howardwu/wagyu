<h1 align="center"><img width="1346" alt="Screen Shot 2019-07-28 at 9 54 51 PM" src="https://user-images.githubusercontent.com/9260812/62022781-b01bfd80-b182-11e9-98d1-909ab0b9ce14.png"></h1>

<p align="center">
    <a href="https://crates.io/crates/wagyu"><img src="https://img.shields.io/crates/v/wagyu.svg?color=neon"></a>
    <a href="https://travis-ci.com/ArgusHQ/wagu"><img src="https://img.shields.io/travis/com/ArgusHQ/wagyu/v0.6.0.svg"></a>
    <a href="https://coveralls.io/github/ArgusHQ/wagyu?branch=v0.6.0"><img src="https://coveralls.io/repos/github/ArgusHQ/wagyu/badge.svg?branch=v0.6.0"></a>
    <a href="./AUTHORS"><img src="https://img.shields.io/badge/authors-Argus-orange.svg"></a>
    <a href="./LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT/Apache--2.0-blue.svg"></a>
</p>

<p align="center">
    <img src="https://i.gyazo.com/134f7a29c4accef35ff730430cd87b52.gif">
</p>

## <a name='TableofContents'></a>Table of Contents

* [1. Overview](#1-overview)
* [2. Build Guide](#2-build-guide)
    * [2.1 Install Rust](#21-install-rust)
    * [2.2a Build from Crates.io](#22a-build-from-cratesio)
    * [2.2b Build from Source Code](#22b-build-from-source-code)
* [3. Features](#3-features)
	* [3.1 Generate a wallet with default options](#31-generate-a-wallet-with-default-options)
	* [3.2 Generate a mainnet or testnet wallet](#32-generate-a-mainnet-and-testnet-wallet)
	* [3.3 Generate a wallet as a JSON object](#33-generate-a-wallet-as-a-json-object)
	* [3.4 Generate multiple wallets of the same type](#34-generate-multiple-wallets-of-the-same-type)
	* [3.5 Generate a P2SH_P2WPKH SegWit wallet](#35-generate-a-p2sh_p2wpkh-segwit-wallet)
* [4. License](#4-license)

## 1. Overview

Wagu is a lightweight command-line utility to generate a cryptocurrency wallet.


Wagu enables developers to build their own cryptocurrency application using the following modules.

| Library                                                                                                                                       | Doc                       | Standard Wallet                                                       | HD Wallet                     | Mnemonic                        | Network                                                         |
|:---------------------------------------------------------------------------------------------------------------------------------------------:|---------------------------|-----------------------------------------------------------------------|-------------------------------|---------------------------------|-----------------------------------------------------------------|
| [**wagyu-bitcoin**](./bitcoin)   <br/> [![Crates.io](https://img.shields.io/crates/v/wagyu.svg?color=neon)](https://crates.io/crates/wagyu)      | [View](docs/bitcoin.md)   | <br/><ul><li>P2PKH</li><li>P2SH-P2WPKH</li><li>Bech32</li></ul>       | <br/><ul><li>BIP-32</li></ul> | <br/><ul><li>BIP-39</li></ul>   | <br/><ul><li>Mainnet</li><li>Testnet</li></ul>                  |
| [**wagyu-ethereum**](./ethereum) <br/> [![Crates.io](https://img.shields.io/crates/v/wagyu.svg?color=neon)](https://crates.io/crates/wagyu)      | [View](docs/ethereum.md)  | <br/><ul><li>Standard</li></ul>                                       | <br/><ul><li>BIP-32</li></ul> | <br/><ul><li>BIP-39</li></ul>   | <br/><ul><li>All</li></ul>                                      |
| [**wagyu-monero**](./monero)     <br/> [![Crates.io](https://img.shields.io/crates/v/wagyu.svg?color=neon)](https://crates.io/crates/wagyu)      | [View](docs/monero.md)    | <br/><ul><li>Standard</li><li>Integrated</li><li>Subaddress</li></ul> | <br/><ul><li>N/A</ul>         | <br/><ul><li>Electrum</li></ul> | <br/><ul><li>Mainnet</li><li>Testnet</li><li>Stagenet</li></ul> |
| [**wagyu-zcash**](./zcash)       <br/> [![Crates.io](https://img.shields.io/crates/v/wagyu.svg?color=neon)](https://crates.io/crates/wagyu)      | [View](docs/zcash.md)     | <br/><ul><li>P2PKH</li><li>Sapling</li></ul>                          | <br/><ul><li>ZIP-32</li></ul> | <br/><ul><li>N/A</li></ul>      | <br/><ul><li>Mainnet</li><li>Testnet</li></ul>                  |

Wagu can support new cryptocurrencies by implementing the model as outlined in this module.

| Library                                                                                                                            | Standard Wallet                                                                                                                                                | HD Wallet                                                                                                                                             | Mnemonic                                                  | Network                                                   |
|:----------------------------------------------------------------------------------------------------------------------------------:|----------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|-----------------------------------------------------------|
| [**wagyu_model**](./model) <br/> [![Crates.io](https://img.shields.io/crates/v/wagyu.svg?color=neon)](https://crates.io/crates/wagyu) | <br/><ul><li>[Address](./model/src/address.rs)</li><li>[Public Key](./model/src/public_key.rs)</li><li>[Private Key](./model/src/private_key.rs)</li></ul>     | <br/><ul><li>[Derivation Path](./model/src/derivation_path.rs)</li><li>[Extended Public Key](./model/src/extended_public_key.rs)</li><li>[Extended Private Key](./model/src/extended_private_key.rs)</li></ul>  | <br/><ul><li>[Mnemonic](./model/src/mnemonic.rs)</li><li>[Wordlist](model/src/wordlist/wordlist.rs)</li></ul>  |<br/><ul><li>[Network](./model/src/network.rs)</li></ul>   |


## 2. Build Guide

### 2.1 Install Rust

We recommend installing Rust using [rustup](https://www.rustup.rs/). You can install `rustup` as follows:

- macOS or Linux:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- Windows (64-bit):  
  
  Download the [Windows 64-bit executable](https://win.rustup.rs/x86_64) and follow the on-screen instructions.

- Windows (32-bit):  
  
  Download the [Windows 32-bit executable](https://win.rustup.rs/i686) and follow the on-screen instructions.

### 2.2a Build from Crates.io

We recommend installing `wagyu` this way. In your terminal, run:

```bash
cargo install wagyu
```

Now to use `wagyu`, in your terminal, run:
```bash
wagyu
```
 
### 2.2b Build from Source Code

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

## 3. Features

The following demonstrates the functionality of `wagyu`. All examples are for the Bitcoin blockchain and more specific exampls can be found in the `/docs` folder.

### 3.1 Generate a wallet with default options

Generate a compressed mainnet private key and address with the following command:

`wagyu bitcoin`

```bash
╰─ wagyu bitcoin

        Private Key:    L5hax5dZaByC3kJ4aLrZgnMXGSQReqRDYNqM1VAeXpqDRkRjX42H
        Address:        1uNM6oivjCJU2RcsNbfooVwcPjDRhjW7U
        Network:        mainnet
        Compressed:     true
```

### 3.2 Generate a mainnet and testnet wallet

Generate a testnet private key and address with the following command:

`wagyu bitcoin --network testnet`

```bash
╰─ wagyu bitcoin --network testnet

        Private Key:    cSCkpm1oSHTUtX5CHdQ4FzTv9qxLQWKx2SXMg22hbGSTNVcsUcCX,
        Address:        mwCDgjeRgGpfTMY1waYAJF2dGz4Q5XAx6w
        Network:        testnet
        Compressed:     true
```

### 3.3 Generate a wallet as a JSON object

Generate a compressed mainnet private key and address with the following command:

`wagyu bitcoin -j` OR `wagyu bitcoin --json`

```bash
╰─ wagyu -j
[
  {
    "privateKey": {
      "wif": "L5hax5dZaByC3kJ4aLrZgnMXGSQReqRDYNqM1VAeXpqDRkRjX42H",
      "network": "mainnet",
      "compressed": true
    },
    "address": {
      "address": "1uNM6oivjCJU2RcsNbfooVwcPjDRhjW7U",
      "network": "mainnet",
      "address_type": "P2PKH"
    }
  }
]
```

### 3.4 Generate multiple wallets of the same type

Generates multiple wallets with the following command:

`wagyu bitcoin --count 3` OR `wagyu bitcoin -n 3`

```bash
╰─ wagyu bitcoin -n 3

        Private Key:    L5hax5dZaByC3kJ4aLrZgnMXGSQReqRDYNqM1VAeXpqDRkRjX42H
        Address:        1uNM6oivjCJU2RcsNbfooVwcPjDRhjW7U
        Network:        mainnet
        Compressed:     true


        Private Key:    L4uNhZS86VLiKKGZZGNxwP7s67EfYfQ7S9bNnVfVbU9GBVVo2xoD
        Address:        16sz5SMFeRfwaqY6wKzkiufwPmF1J7RhAx
        Network:        mainnet
        Compressed:     true


        Private Key:    KyH2BrThuUnzSXxDrDxQbpK277HxZfwPxVaCs5cwbzDEVNno2nts
        Address:        17QAwDwsLpehmCqSQXdHZb8vpsYVDnX7ic
        Network:        mainnet
        Compressed:     true
```

### 3.5 Generate a P2SH_P2WPKH SegWit wallet

Generate a SegWit mainnet private key and address with the following command:

`wagyu bitcoin --segwit`

```bash
╰─ wagyu --segwit

        Private Key:    L13EzQBa7izHyXHdhAwBzApAPL1Q8rdVRpY7CASWXyFPyHTuPJxs
        Address:        3Qz5gtJ4GKoeSHHErF8Nvs9bDp5TQDw89o
        Network:        mainnet
        Compressed:     true
```

## 4. License

This work is licensed under either of the following licenses, at your discretion.

- Apache License Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
