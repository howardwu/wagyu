# `wagyu bitcoin`

## <a name='TableofContents'></a>Table of Contents

* [Features](#Features)
	* [Generate a wallet with default options](#Generateawalletwithdefaultoptions)
	* [Generate testnet and mainnet wallets](#Generatetestnetandmainnetwallets)
	* [Generate wallets as JSON object](#GeneratewalletsasJSONobject)
	* [Generate multiple wallets of the same kind](#Generatemultiplewalletsofthesamekind)
	* [Generate a P2WPKH_P2SH (SegWit) Wallet](#GenerateaP2WPKHSegWitWallet)
	* [Generate compressed and uncompressed (default) wallets](#Generatecompressedanduncompresseddefaultwallets)

##  <a name='Features'></a>Features

#### <a name='Generateawalletwithdefaultoptions'></a>Generate a wallet with default options

Generate an uncompressed mainnet private key and address with the following command:

`wagyu bitcoin`

```bash
╰─ wagyu bitcoin

        Private Key:    5JHwLmRafAxdtRddv3o2urYo2bfFUT2V29LSoDM3QFJPzoUoBJT
        Address:        1GMmaXUixBA2ZMqw9U1zX4cTCmhWtNhgTB
        Network:        mainnet
        Compressed:     false
```

#### <a name='Generatetestnetandmainnetwallets'></a>Generate testnet and mainnet wallets

Generate a testnet private key and address with the following command:

`wagyu bitcoin --network testnet`

```bash
╰─ wagyu bitcoin --network testnet

        Private Key:    92Rk56bU8atxbM9mUyNJtijc8XFyw7UHrDaasyTzcn9iLn4M9Le
        Address:        myPXYe7NrVpq8oYBugTFtHwamejxB6wNC8
        Network:        testnet
        Compressed:     false
```

#### <a name='GeneratewalletsasJSONobject'></a>Generate wallets as JSON object

Generate an uncompressed mainnet private key and address with the following command:

`wagyu bitcoin -j` OR `wagyu bitcoin --json`

```bash
╰─ wagyu -j
[
  {
    "privateKey": {
      "wif": "5JZPS2WbS8A5jkZYtSvHibvNQMN6vU2Btht5YqAZze7zEiFtNDd",
      "network": "mainnet",
      "compressed": false
    },
    "address": {
      "wif": "1NuPmGDSsCFcSZCuAccq6zJTvXi2vNzRwg",
      "network": "mainnet",
      "address_type": "P2PKH"
    }
  }
]
```

#### <a name='Generatemultiplewalletsofthesamekind'></a>Generate multiple wallets of the same kind

Generate a multiple wallets with the following command:

`wagyu bitcoin --count 3` OR `wagyu bitcoin -n 3`

```bash
╰─ wagyu bitcoin -n 3

        Private Key:    5JsktgmsNQh3MbHMcwNWG3gd5awH59dnUa64Uih6rAssCsdjjU9
        Address:        1N4Ezyuo4K4FFvBnbeyPv5qPA93mBVi5P9
        Network:        mainnet
        Compressed:     false


        Private Key:    5JzxKHZNEqN9zNgxkjJQASnpCYvBj5NQMs6HfEgMRsQ84VXJpyU
        Address:        1AzoF4Cw8fS7JdFocmsVoKJdv1j4a81Tf9
        Network:        mainnet
        Compressed:     false


        Private Key:    5JxRr7Evz4YSKRWvMLzAtg7WZHg7uEfpM6D6TK4w3HUE3aSQbF7
        Address:        19uxwixdfxdYVJ4HjrLKT31EakWCqrhb1r
        Network:        mainnet
        Compressed:     false
```

#### <a name='GenerateaP2WPKHSegWitWallet'></a>Generate a P2WPKH_P2SH (SegWit) Wallet

Generate a SegWit mainnet private key and address with the following command:

`wagyu bitcoin --segwit`

```bash
╰─ wagyu --segwit

        Private Key:    L13EzQBa7izHyXHdhAwBzApAPL1Q8rdVRpY7CASWXyFPyHTuPJxs
        Address:        3Qz5gtJ4GKoeSHHErF8Nvs9bDp5TQDw89o
        Network:        mainnet
        Compressed:     true
```

#### <a name='Generatecompressedanduncompresseddefaultwallets'></a>Generate compressed and uncompressed (default) wallets 

Generate a compressed mainnet private key and address with the following command:

`wagyu bitcoin --compressed` OR `wagyu bitcoin -c`

```bash
╰─ wagyu bitcoin -c

        Private Key:    KzpvjTPuU7p2GZFki2FRnnTceDn5jdVAYZkVvDBptWrHMcLeGWFn
        Address:        1G75ZLkSbTr6wBzr4pthM7eV9NzenMyZPC
        Network:        mainnet
        Compressed:     true
```
