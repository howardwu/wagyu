# wagu

Pronounced like [wagyu](https://en.wikipedia.org/wiki/Wagyu). Wagu is the **wa**llet **g**eneration **u**tility.

Wagu allows users to generate wallets for the following cryptocurrencies:

- Bitcoin

## <a name='TableofContents'></a>Table of Contents

<!-- vscode-markdown-toc -->
* [Table of Contents](#TableofContents)
* [Features](#Features)
		* [Generate a wallet with default options](#Generateawalletwithdefaultoptions)
		* [Generate wallets as JSON object](#GeneratewalletsasJSONobject)
		* [Generate a P2WPKH (SegWit) Wallet](#GenerateaP2WPKHSegWitWallet)
		* [Generate testnet and mainnet wallets](#Generatetestnetandmainnetwallets)
		* [Generate compressed and uncompressed (default) wallets](#Generatecompressedanduncompresseddefaultwallets)
		* [Generate multiple wallets of the same kind](#Generatemultiplewalletsofthesamekind)
* [Help](#Help)

<!-- vscode-markdown-toc-config
	numbering=false
	autoSave=true
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->

## <a name='Features'></a>Features

#### <a name='Generateawalletwithdefaultoptions'></a>Generate a wallet with default options

![alt text](examples/simple.png "simple")

#### <a name='GeneratewalletsasJSONobject'></a>Generate wallets as JSON object

![alt text](examples/json.png "network")

#### <a name='GenerateaP2WPKHSegWitWallet'></a>Generate a P2WPKH (SegWit) Wallet

![alt text](examples/segwit.png "segwit")

#### <a name='Generatetestnetandmainnetwallets'></a>Generate testnet and mainnet wallets

![alt text](examples/network.png "network")

#### <a name='Generatecompressedanduncompresseddefaultwallets'></a>Generate compressed and uncompressed (default) wallets 

![alt text](examples/compressed.png "compressed")

#### <a name='Generatemultiplewalletsofthesamekind'></a>Generate multiple wallets of the same kind

![alt text](examples/multiple.png "multiple")


## <a name='Help'></a>Help

The cli contains useful help text, displayed below.

```
wagu v0.2.0
Argus Observer <ali@argus.observer>
Generate a wallet for any cryptocurrency

Supported Currencies: Bitcoin

USAGE:
    wagu [FLAGS] [OPTIONS] <currency>

FLAGS:
    -c, --compressed    Enabling this flag generates a wallet which corresponds to a compressed public key
    -h, --help          Prints help information
    -j, --json          Enabling this flag prints the wallet in JSON format
    -V, --version       Prints version information

OPTIONS:
    -n, --count <count>        Number of wallets to generate
    -N, --network <network>    Network of wallet(s) to generate (e.g. mainnet, testnet)

ARGS:
    <currency>    Name of the currency to generate a wallet for (e.g. bitcoin)
```