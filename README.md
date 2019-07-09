<h1 align="center">wagu</h1>

<p align="center">
    <a href="https://travis-ci.com/ArgusDeveloper/wagu"><img src="https://travis-ci.com/ArgusDeveloper/wagu.svg"></a>
    <a href="https://github.com/ArgusDeveloper/wagu/blob/master/AUTHORS"><img src="https://img.shields.io/badge/authors-Argus-orange.svg"></a>
    <a href="https://github.com/ArgusDeveloper/wagu/blob/master/LICENSE-APACHE"><img src="https://img.shields.io/badge/license-APACHE-blue.svg"></a>
   <a href="https://github.com/ArgusDeveloper/wagu/blob/master/LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

Pronounced like [wagyu](https://en.wikipedia.org/wiki/Wagyu). Wagu is the **wa**llet **g**eneration **u**tility.

Wagu allows users to generate cryptocurrency wallets for the following cryptocurrencies:

- Bitcoin
- Ethereum
- Monero
- Zcash (Transparent Addresses)

## <a name='Install'></a>Install

To install `wagu`, please first install [Rust](https://www.rust-lang.org/en-US/). Then run the following command in your terminal of choice:

```cargo install wagu```

## <a name='QuickUsage'></a>Quick Usage

Create a wallet for any currency like so:

[![Wagu Bitcoin Demo](https://i.gyazo.com/134f7a29c4accef35ff730430cd87b52.gif)](https://gyazo.com/134f7a29c4accef35ff730430cd87b52)

The supported currencies are listed above. Detailed examples are found below and in the `docs` folder.

## <a name='TableofContents'></a>Table of Contents

* [Table of Contents](#TableofContents)
* [Documentation](#documentation)
* [Features](#Features)
	* [Generate a wallet with default options](#Generateawalletwithdefaultoptions)
	* [Generate testnet and mainnet wallets](#Generatetestnetandmainnetwallets)
	* [Generate wallets as JSON object](#GeneratewalletsasJSONobject)
	* [Generate multiple wallets of the same kind](#Generatemultiplewalletsofthesamekind)
	* [Generate a P2WPKH_P2SH (SegWit) Wallet](#GenerateaP2WPKHSegWitWallet)
	* [Generate compressed and uncompressed (default) wallets](#Generatecompressedanduncompresseddefaultwallets)
* [Help](#Help)

## Documentation

* [Bitcoin](./docs/bitcoin.md)
* [Ethereum](./docs/ethereum.md)
* [Monero](./docs/monero.md)
* [Zcash](./docs/zcash.md)

##  <a name='Features'></a>Features

The following demonstrates the functionality of `wagu`. All examples are for the Bitcoin blockchain and more specific exampls can be found in the `/docs` folder.

#### <a name='Generateawalletwithdefaultoptions'></a>Generate a wallet with default options

Generate an uncompressed mainnet private key and address with the following command:

`wagu bitcoin`

```bash
╰─ wagu bitcoin

        Private Key:    5JHwLmRafAxdtRddv3o2urYo2bfFUT2V29LSoDM3QFJPzoUoBJT
        Address:        1GMmaXUixBA2ZMqw9U1zX4cTCmhWtNhgTB
        Network:        Mainnet
        Compressed:     false
```

#### <a name='Generatetestnetandmainnetwallets'></a>Generate testnet and mainnet wallets

Generate a testnet private key and address with the following command:

`wagu bitcoin --network testnet`

```bash
╰─ wagu bitcoin --network testnet

        Private Key:    92Rk56bU8atxbM9mUyNJtijc8XFyw7UHrDaasyTzcn9iLn4M9Le
        Address:        myPXYe7NrVpq8oYBugTFtHwamejxB6wNC8
        Network:        Testnet
        Compressed:     false
```

#### <a name='GeneratewalletsasJSONobject'></a>Generate wallets as JSON object

Generate an uncompressed mainnet private key and address with the following command:

`wagu bitcoin -j` OR `wagu bitcoin --json`

```bash
╰─ wagu -j
[
  {
    "privateKey": {
      "wif": "5JZPS2WbS8A5jkZYtSvHibvNQMN6vU2Btht5YqAZze7zEiFtNDd",
      "network": "Mainnet",
      "compressed": false
    },
    "address": {
      "wif": "1NuPmGDSsCFcSZCuAccq6zJTvXi2vNzRwg",
      "network": "Mainnet",
      "address_type": "P2PKH"
    }
  }
]
```

#### <a name='Generatemultiplewalletsofthesamekind'></a>Generate multiple wallets of the same kind

Generate a multiple wallets with the following command:

`wagu bitcoin --count 3` OR `wagu bitcoin -n 3`

```bash
╰─ wagu bitcoin -n 3

        Private Key:    5JsktgmsNQh3MbHMcwNWG3gd5awH59dnUa64Uih6rAssCsdjjU9
        Address:        1N4Ezyuo4K4FFvBnbeyPv5qPA93mBVi5P9
        Network:        Mainnet
        Compressed:     false


        Private Key:    5JzxKHZNEqN9zNgxkjJQASnpCYvBj5NQMs6HfEgMRsQ84VXJpyU
        Address:        1AzoF4Cw8fS7JdFocmsVoKJdv1j4a81Tf9
        Network:        Mainnet
        Compressed:     false


        Private Key:    5JxRr7Evz4YSKRWvMLzAtg7WZHg7uEfpM6D6TK4w3HUE3aSQbF7
        Address:        19uxwixdfxdYVJ4HjrLKT31EakWCqrhb1r
        Network:        Mainnet
        Compressed:     false
```

#### <a name='GenerateaP2WPKHSegWitWallet'></a>Generate a P2WPKH_P2SH (SegWit) Wallet

Generate a SegWit mainnet private key and address with the following command:

`wagu bitcoin --segwit`

```bash
╰─ wagu --segwit

        Private Key:    L13EzQBa7izHyXHdhAwBzApAPL1Q8rdVRpY7CASWXyFPyHTuPJxs
        Address:        3Qz5gtJ4GKoeSHHErF8Nvs9bDp5TQDw89o
        Network:        Mainnet
        Compressed:     true
```

#### <a name='Generatecompressedanduncompresseddefaultwallets'></a>Generate compressed and uncompressed (default) wallets 

Generate a compressed mainnet private key and address with the following command:

`wagu bitcoin --compressed` OR `wagu bitcoin -c`

```bash
╰─ wagu bitcoin -c

        Private Key:    KzpvjTPuU7p2GZFki2FRnnTceDn5jdVAYZkVvDBptWrHMcLeGWFn
        Address:        1G75ZLkSbTr6wBzr4pthM7eV9NzenMyZPC
        Network:        Mainnet
        Compressed:     true
```

## <a name='Help'></a>Help

The cli contains useful help text, displayed below.

```
wagu v0.6.0
Argus Developer <team@argus.dev>
Generate a wallet for any cryptocurrency

Supported Currencies: Bitcoin, Ethereum, Monero, Zcash (t-address)

USAGE:
    wagu [FLAGS] [OPTIONS] <currency>

FLAGS:
    -c, --compressed    Enabling this flag generates a wallet which corresponds to a compressed public key
    -h, --help          Prints help information
    -j, --json          Enabling this flag prints the wallet in JSON format
        --segwit        Enabling this flag generates a wallet with a SegWit address
    -V, --version       Prints version information

OPTIONS:
    -n, --count <count>        Number of wallets to generate
    -N, --network <network>    Network of wallet(s) to generate (e.g. mainnet, testnet) [values: mainnet, testnet]

ARGS:
    <currency>    Name of the currency to generate a wallet for (e.g. bitcoin, ethereum, monero, zcash)
```

## License

This work is licensed under either of the following licenses, at your discretion.

- Apache License Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.