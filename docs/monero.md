# `wagyu monero`

## <a name='TableofContents'></a>Table of Contents

* [Features](#Features)
	* [Generate a wallet with default options](#Generateawalletwithdefaultoptions)
	* [Generate testnet and mainnet wallets](#Generatetestnetandmainnetwallets)
	* [Generate wallets as JSON object](#GeneratewalletsasJSONobject)
	* [Generate multiple wallets of the same kind](#Generatemultiplewalletsofthesamekind)

##  <a name='Features'></a>Features

#### <a name='Generateawalletwithdefaultoptions'></a>Generate a wallet with default options

Generate a mainnet spend key, viewing key, and address with the following command:

`wagyu monero`

```bash
╰─ wagyu monero

        Address:              47tePDVnheTZMKKAwsQb24XwN1ZtxW82VSpWu8y1RjLmjESinEb4L5d6WhQkPqracg3P5ZA9TMTpFaviU5ZEAVNBSm57jjr
        Private Spend Key:    e67bec328c3584d0bd55a880fea4a3c8024dd4420369ed7ed9af26e05466210b
        Private View Key:     6e8386018159df0bd60310501d4b71b1f00daffd83ea211207484ed09921ef03

```

#### <a name='Generatetestnetandmainnetwallets'></a>Generate testnet and mainnet wallets

Generate a testnet spend key, viewing key, and address with the following command:

`wagyu monero --network testnet`

```bash
╰─ wagyu monero --network testnet

        Address:              9tujjZKVyu5d9D2kqEDTLfUipPmtrd21A2RxMXhiwmUBgtySLfyF8wUbrh4ohjQ5KKPPnrQPxepYREuWmoM9kEnfBJX64W3
        Private Spend Key:    b0fceaf37b84d9f201d48c6f5a4e9a5eef536ba0d576955a74c6f8b0eb8ad805
        Private View Key:     91d8f5fa5f48cea2a71fa274f6650f4b6bc26018b142575944d82ffd91260b02

```

#### <a name='GeneratewalletsasJSONobject'></a>Generate wallets as JSON object

Generate a spend key, viewing key, and address as a json object with the following command:

`wagyu monero -j` OR `wagyu monero --json`

```bash
╰─ wagyu -j
[
  {
    "address": "42TPgwJZxhkF2BNPeZvv3ZYk1P3jjyZPb7F4qA1rdpnQjTezTRSpFJDW13nvckjXauJFET5mjNwZAPjh6JYzjXJHSu6J62p",
    "spend_key": "337a46c0af371e3412c69fc1b61c219e6a0d42438ece92d19f0a9d16476d9a09",
    "view_key": "95bf578a1bd03c40a744de85c3e747605b58ec9a23cb6ba7e520443ed2bcae0b"
  }
]
```

#### <a name='Generatemultiplewalletsofthesamekind'></a>Generate multiple wallets of the same kind

Generate multiple wallets with the following command:

`wagyu monero --count 3` OR `wagyu monero -n 3`

```bash
╰─ wagyu monero -n 3

        Address:              4ABpi3Xij4NjfEU8gTH62ncM16b45x1QedJaC6LoksDC2Ge33ws1ecEaZ3nVigJP6sAKnuZWXTmAihhKyivmf1aaRqfxm4h
        Private Spend Key:    4ddc66f907d6d7b52374bcb29038b634cd55a0e8bee0a7113539bf7dbc6d950a
        Private View Key:     1fa8c7d46d272a051a75043e26ce10f376542e86ff0401db0d1dbcbe4e47a304


        Address:              42gshFDxUQTe9M3nqd9U7gjddrx6ApZcfgdMRmezrzbbaUeTpQputmb4baH1cNfxy8RpYzfK8NboBgoEs98tSmgK6wgzU82
        Private Spend Key:    f3b3da88008fc78d8c7e03574b4ff2cade3ae928839f5c33585a36e22936290d
        Private View Key:     b4cb89e82cc11d87ac5ceefcc47a5369848c4c3a9db11fb60132a8923b60c501


        Address:              49sqUHKJWHjDQEWpwX2wUpdKWcZW8Pas79rTJNiHedWmXR48iMpCHRwAitGEhF115fifR8k8GSa95MAsbUaY3qYhAHB9fgB
        Private Spend Key:    2cd7fa88c54d573abe952b967457fb396e6acf2f5dd2259ca4fd7df9b613940f
        Private View Key:     f9b6098cf884d18f1fa5c84d33e0dfebc973b89eb0ba539cb16c105990bd6b04
```
