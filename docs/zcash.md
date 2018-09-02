# `wagu zcash`

## <a name='TableofContents'></a>Table of Contents

* [Features](#Features)
	* [Generate a wallet with default options](#Generateawalletwithdefaultoptions)
	* [Generate testnet and mainnet wallets](#Generatetestnetandmainnetwallets)
	* [Generate wallets as JSON object](#GeneratewalletsasJSONobject)
	* [Generate multiple wallets of the same kind](#Generatemultiplewalletsofthesamekind)
	* [Generate compressed and uncompressed (default) wallets](#Generatecompressedanduncompresseddefaultwallets)

##  <a name='Features'></a>Features

#### <a name='Generateawalletwithdefaultoptions'></a>Generate a wallet with default options

Generate an uncompressed mainnet private key and address with the following command:

`wagu zcash`

```bash
╰─ wagu zcash

        Private Key:    5KPcKEuisYjGqqSfZyArrDFjR6xuNRSRotLTu6h4ciu9Qk15bSf
        Address:        t1gNVAzETZA6ygaiDPRrSrz2tqGMPxVCGUN
        Network:        Mainnet
        Compressed:     false
```

#### <a name='Generatetestnetandmainnetwallets'></a>Generate testnet and mainnet wallets

Generate a testnet private key and address with the following command:

`wagu zcash --network testnet`

```bash
╰─ wagu zcash --network testnet

        Private Key:    92YaFzZkMKFBkndQGsct96CQcLrcMgvsopv7hzHYvJ3HHVSk2Xu
        Address:        tmAMCGitxDgDTDFf6bwhqxAsmk8qGiXHYZv
        Network:        Testnet
        Compressed:     false
```

#### <a name='GeneratewalletsasJSONobject'></a>Generate wallets as JSON object

Generate an uncompressed mainnet private key and address with the following command:

`wagu zcash -j` OR `wagu zcash --json`

```bash
╰─ wagu -j
[
  {
    "privateKey": {
      "wif": "5JPkNynw2LPvfheom94SG7C4wwcoX9b54qvVFa4AJ1579goKxGP",
      "network": "Mainnet",
      "compressed": false
    },
    "address": {
      "wif": "t1aevKxZCLGqe1G4gLc6s7QB3vjcCrJ3hN9",
      "network": "Mainnet"
    }
  }
]
```

#### <a name='Generatemultiplewalletsofthesamekind'></a>Generate multiple wallets of the same kind

Generate a multiple wallets with the following command:

`wagu zcash --count 3` OR `wagu zcash -n 3`

```bash
╰─ wagu zcash -n 3

        Private Key:    5K6unwsCYTnqbk2uyqNMJGRoHR3kGeBVKmHtTKPQpg6xTSz69Jw
        Address:        t1NNXgRsca1jT7WUEXV97dDn9pz7KNFPrLs
        Network:        Mainnet
        Compressed:     false


        Private Key:    5JuCtommZKUyPv2nAL4c4jWJ3ShqMNAFpmv983JnMW6wQcFyxS6
        Address:        t1WhNEp8K9imhjrmbuxP33Q7rxZAgY3m697
        Network:        Mainnet
        Compressed:     false


        Private Key:    5Jix5DemZhkZb65943jJkkXMM4K15C8L9REEdphmqiRicccQttj
        Address:        t1YRNCuv9QnwZNVGvfY688MNjNWvm8po3ye
        Network:        Mainnet
        Compressed:     false
```

#### <a name='Generatecompressedanduncompresseddefaultwallets'></a>Generate compressed and uncompressed (default) wallets 

Generate a compressed mainnet private key and address with the following command:

`wagu zcash --compressed` OR `wagu zcash -c`

```bash
╰─ wagu zcash -c

        Private Key:    L4LwPgRwru6evQWqQZbqyW5JKePSF4rUBpF5nNaNDozxs2Z8PNpx
        Address:        t1h46b74XVAggQL6kcngVHaD7JxvebW7hP2
        Network:        Mainnet
        Compressed:     true
```
