# wagu

Pronounced like [wagyu](https://en.wikipedia.org/wiki/Wagyu). Wagu is the **wa**llet **g**eneration **u**tility.

Wagu allows users to generate wallets for the following cryptocurrencies:

- Bitcoin
- Zcash (Transparent Addresses)

## Table of Contents

<!-- vscode-markdown-toc -->
1. [Features](#Features)
    * 1.1. [Generate a wallet with default options](#Generateawalletwithdefaultoptions)
    * 1.2. [Generate wallets as JSON object](#GeneratewalletsasJSONobject)
    * 1.3. [Generate testnet and mainnet wallets](#Generatetestnetandmainnetwallets)
    * 1.4. [Generate compressed and uncompressed (default) wallets](#Generatecompressedanduncompresseddefaultwallets)
    * 1.5. [Generate multiple wallets of the same kind](#Generatemultiplewalletsofthesamekind)
2. [Help](#Help)

<!-- vscode-markdown-toc-config
	numbering=true
	autoSave=true
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->

##  1. <a name='Features'></a>Features

####  1.1. <a name='Generateawalletwithdefaultoptions'></a>Generate a wallet with default options

![alt text](examples/simple.png "simple")

####  1.2. <a name='GeneratewalletsasJSONobject'></a>Generate wallets as JSON object

![alt text](examples/json.png "network")

####  1.3. <a name='Generatetestnetandmainnetwallets'></a>Generate testnet and mainnet wallets

![alt text](examples/network.png "network")

####  1.4. <a name='Generatecompressedanduncompresseddefaultwallets'></a>Generate compressed and uncompressed (default) wallets 

![alt text](examples/compressed.png "compressed")

####  1.5. <a name='Generatemultiplewalletsofthesamekind'></a>Generate multiple wallets of the same kind

![alt text](examples/multiple.png "multiple")


##  2. <a name='Help'></a>Help

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