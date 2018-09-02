# `wagu ethereum`

## <a name='TableofContents'></a>Table of Contents

* [Features](#Features)
	* [Generate a wallet with default options](#Generateawalletwithdefaultoptions)
	* [Generate wallets as JSON object](#GeneratewalletsasJSONobject)
	* [Generate multiple wallets of the same kind](#Generatemultiplewalletsofthesamekind)

##  <a name='Features'></a>Features

#### <a name='Generateawalletwithdefaultoptions'></a>Generate a wallet with default options

Generate a mainnet spend key, viewing key, and address with the following command:

`wagu ethereum`

```bash
╰─ wagu ethereum

        Private Key:    1feff6005396b01f57a18df8bed2151b0f5f1dc409624773a910daf67121b300
        Address:        0x288786a40e8fc5E990C85bf7A029E4A34E633527

```

#### <a name='GeneratewalletsasJSONobject'></a>Generate wallets as JSON object

Generate a spend key, viewing key, and address as a json object with the following command:

`wagu ethereum -j` OR `wagu ethereum --json`

```bash
╰─ wagu -j
[
  {
    "private_key": "e9569857471d6463e8b46642c57373d047211aac472a4c5e564b090ddd173ed2",
    "address": "0x7f1E2ed1129258695f579cC535bE68B908BC7D6c"
  }
]
```

#### <a name='Generatemultiplewalletsofthesamekind'></a>Generate multiple wallets of the same kind

Generate multiple wallets with the following command:

`wagu ethereum --count 3` OR `wagu ethereum -n 3`

```bash
╰─ wagu ethereum -n 3

        Private Key:    726c79c575d7d966af657cbe56ab23890d833b16f0cdb03bdc5526760f25d61a
        Address:        0xab0C8e649f19abb789A0ddBe74c2bef462Ebf937


        Private Key:    beb9fb7c9c3a1e0a4df23a6cfb86d59f22e3aab0d0e91aee3ec5c94ac9f34d32
        Address:        0x950d1D425b5b8F88ACA4354348Ac2a174a318148


        Private Key:    b3dfb88c7d720de77178e36e107e399a9f205482486523f598e089ff512f11d0
        Address:        0x80367300a0B0838f3A1aaC79854A5Ad9BB68c7fD

```