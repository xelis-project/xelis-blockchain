# API

## Daemon

### JSON-RPC methods

#### Get Version
Retrieve current daemon version

##### Method `get_version`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_version",
	"id": 1
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": "1.2.0"
}
```

#### Get Info
Retrieve current info from chain

##### Method `get_info`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_info",
	"id": 1
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "average_block_time": 16494,
        "block_reward": 145979248,
        "block_time_target": 15000,
        "circulating_supply": 3155962164200,
        "difficulty": "62283705000",
        "height": 21510,
        "maximum_supply": 1840000000000000,
        "mempool_size": 0,
        "network": "Testnet",
        "pruned_topoheight": null,
        "stableheight": 21502,
        "top_block_hash": "000000000b47de796f1c033a23ddeacd2321606b8f0b3e5b5e11ba23b1d59dbb",
        "topoheight": 21809,
        "version": "1.8.0-70169a8"
    }
}
```

#### Get Dev Fee Thresholds
Retrieve configured dev fees thresholds

##### Method `get_dev_fee_thresholds`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_dev_fee_thresholds",
	"id": 1
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": [
		{
			"fee_percentage": 15,
			"height": 0
		},
		{
			"fee_percentage": 10,
			"height": 1250000
		},
		{
			"fee_percentage": 5,
			"height": 3000000
		}
	]
}
```

#### Get Size On Disk
Retrieve blockchain size on disk

##### Method `get_size_on_disk`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_size_on_disk",
	"id": 1
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"size_bytes": 94896128,
		"size_formatted": "90.5 MiB"
	}
}
```

#### Get Height
Retrieve current height of the chain

##### Method `get_height`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_height",
	"id": 1
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": 23
}
```

#### Get Topo Height
Retrieve current topological height of the chain

##### Method `get_topoheight`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_topoheight",
	"id": 1
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": 23
}
```

#### Get Stable Height
Retrieve current stable height of the chain.

##### Method `get_stableheight`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_stableheight",
	"id": 1
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": 15
}
```

#### Get Block Template
Retrieve the block template for PoW work

##### Method `get_block_template`

##### Parameters
|   Name  |   Type  | Required |            Note           |
|:-------:|:-------:|:--------:|:-------------------------:|
| address | Address | Required | Miner address for rewards |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_block_template",
    "id": 1,
    "params": {
        "address": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk"
    }
}
```

#### Submit Block
Submit a block header in hexadecimal format to the daemon.

##### Method `submit_block`

##### Parameters
|      Name      |  Type  | Required |         Note        |
|:--------------:|:------:|:--------:|:-------------------:|
| block_template | String | Required | Block in hex format |

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 0,
	"method": "submit_block",
	"params": {
		"block_template": "0000000000000be0000000000000000000000186c0d2dac5000000000003e33798b264214181b57720a6e6cdf87cd9bcd80391dde6780223f87176aff03b45080100000040453896c70b2be2d7088860f179a9e9fc3d03941170d6bf8c2dc6d3e60000d549622a55c88b5c14c263ec0db5f5ffae249c7288f68b0c1333cb105df89450"
	}
}
```

##### Response
```json
{
	"id": 0,
	"jsonrpc": "2.0",
	"result": true
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "difficulty": "92606820000",
        "height": 21863,
        "template": "0000000000000055670000018e8715a7e30000000000000000c0e5e874714934c447db03757ac0666bbb1712f61da2c9d9aa548741240ccac10100000000098c66fcb4a8d5c1eeb5acdde7a31e9bc912120c61e41826328e6dee0000d67ad13934337b85c34985491c437386c95de0d97017131088724cfbedebdc55"
    }
}
```

#### Get Block At Topo Height
Retrieve a block at a specific topo height

##### Method `get_block_at_topoheight`

##### Parameters
|     Name    |   Type  | Required |                           Note                           |
|:-----------:|:-------:|:--------:|:--------------------------------------------------------:|
|  topoheight | Integer | Required | Topoheight must be equal or less than current topoheight |
| include_txs | Boolean | Optional |                  Include txs serialized                  |

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_block_at_topoheight",
	"id": 1,
	"params": {
		"topoheight": 10
	}
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "block_type": "Sync",
        "cumulative_difficulty": "192780001",
        "difficulty": "27915000",
        "extra_nonce": "0a560da5a79ee20c286be60563ec56aa8ca3d4a0a08fb8c253d90523ec231d00",
        "hash": "0000000b308634e9a34256c90df9023d979e3f7e7290c4d8e479424ba6c06871",
        "height": 10,
        "miner": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
        "nonce": 432581,
        "reward": 146229945,
        "supply": 1608530035,
        "timestamp": 1711135323375,
        "tips": [
            "000000263fc1172a2fdbbcf34334fd1853cc72618233be2b3bf247436f92ebea"
        ],
        "topoheight": 10,
        "total_fees": null,
        "total_size_in_bytes": 124,
        "txs_hashes": [],
        "version": 0
    }
}
```
NOTE: `total_fees` field is not `null` when TXs are fetched (`include_txs` is at `true`).

#### Get Blocks At Height
Retrieve all blocks at a specific height

##### Method `get_blocks_at_height`

##### Parameters
|     Name    |   Type  | Required |                       Note                       |
|:-----------:|:-------:|:--------:|:------------------------------------------------:|
|    height   | Integer | Required | Height must be equal or less than current height |
| include_txs | Boolean | Optional |              Include txs serialized              |

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_blocks_at_height",
	"id": 1,
	"params": {
		"height": 23
	}
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": [
        {
            "block_type": "Sync",
            "cumulative_difficulty": "971580001",
            "difficulty": "68940000",
            "extra_nonce": "4633b3dfdb9e99a607835f1e4d05cb0338c7d9e938a4e58659601b45b2704d00",
            "hash": "0000001e7c2427f078f49d70002a568d050c2726a959b23b6c500307183cc943",
            "height": 23,
            "miner": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
            "nonce": 13171398,
            "reward": 146229794,
            "supply": 3509518265,
            "timestamp": 1711135431639,
            "tips": [
                "00000024f5688723a4afb000f49ed23b2a00bb25744b822700b82655c0df80b8"
            ],
            "topoheight": 23,
            "total_fees": null,
            "total_size_in_bytes": 124,
            "txs_hashes": [],
            "version": 0
        }
    ]
}
```
NOTE: `total_fees` field is not `null` when TXs are fetched (`include_txs` is at `true`).

#### Get Block By Hash
Retrieve a block by its hash

##### Method `get_block_by_hash`

##### Parameters
|     Name    |   Type  | Required |                  Note                 |
|:-----------:|:-------:|:--------:|:-------------------------------------:|
|     hash    |   Hash  | Required | Valid block Hash present in the chain |
| include_txs | Boolean | Optional |         Include txs serialized        |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_block_by_hash",
    "id": 1,
    "params": {
        "hash": "0000000242978129bc2f36b732afe2dca0da717c43efa2442eb76bb765ddbccd",
        "include_txs": false
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "block_type": "Sync",
        "cumulative_difficulty": "13952430001",
        "difficulty": "1100460000",
        "extra_nonce": "21436825cfa7f4acb5be459e52fedd23523783f241f9744a3013b8fd178bf80a",
        "hash": "0000000242978129bc2f36b732afe2dca0da717c43efa2442eb76bb765ddbccd",
        "height": 69,
        "miner": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
        "nonce": 133614499,
        "reward": 146229256,
        "supply": 10279945002,
        "timestamp": 1711310140627,
        "tips": [
            "00000003ca482c0b91e103c180f3ac675b4f4a1e061086d382ec8879b19f8d16"
        ],
        "topoheight": 70,
        "total_fees": null,
        "total_size_in_bytes": 124,
        "txs_hashes": [],
        "version": 0
    }
}
```
NOTE: `total_fees` field is not `null` when TXs are fetched (`include_txs` is at `true`).

#### Get Top Block
Retrieve the highest block based on the topological height

##### Method `get_top_block`

##### Parameters
|     Name    |   Type  | Required |          Note          |
|:-----------:|:-------:|:--------:|:----------------------:|
| include_txs | Boolean | Optional | Include txs serialized |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_top_block",
    "id": 1,
    "params": {
        "include_txs": false
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "block_type": "Normal",
        "cumulative_difficulty": "871369752120001",
        "difficulty": "55459980000",
        "extra_nonce": "7951ff513c29bbb55b305592b10bbe274627573d42fe08a7c3223c82b0f73323",
        "hash": "0000000001e99d90bea903ba618bb4f4d4a408a70ac4874bfcd1cb3a281199e9",
        "height": 21875,
        "miner": "xet:sj7cfaalq5l5qlvtwlf4zmgrzv3jje08dc6dpgc5zjk6djqqvyrsqly8rex",
        "nonce": 35440241,
        "reward": 145975015,
        "supply": 3209375196561,
        "timestamp": 1711663576873,
        "tips": [
            "0000000001ef6ad0bcc58afd8ffdd458ce262132b88211dcc0b6fd0f8505b858"
        ],
        "topoheight": 22177,
        "total_fees": null,
        "total_size_in_bytes": 124,
        "txs_hashes": [],
        "version": 0
    }
}
```
NOTE: `total_fees` field is not `null` when TXs are fetched (`include_txs` is at `true`).

#### Get Nonce
Retrieve the nonce for address in request params.

If no nonce is found for this address and its a valid one, it is safe to assume its nonce start at 0.
Each nonce represents how many TX has been made by this address and prevent replay attacks.

##### Method `get_nonce`

##### Parameters
|    Name    |   Type  | Required |                    Note                    |
|:----------:|:-------:|:--------:|:------------------------------------------:|
|   address  | Address | Required |      Valid address registered on chain     |
| topoheight | Integer | Optional |        nonce at specified topoheight       |

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "get_nonce",
    "params": {
        "address": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk"
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "nonce": 1459,
        "previous_topoheight": 11269,
        "topoheight": 11982
    }
}
```

NOTE: `topoheight` is the last nonce topoheight (the last time account sent a transaction)

#### Has Nonce
Verify if address has a nonce on-chain registered.

##### Method `has_nonce`

##### Parameters
|    Name    |   Type  | Required |                    Note                    |
|:----------:|:-------:|:--------:|:------------------------------------------:|
|   address  | Address | Required |      Valid address registered on chain     |
| topoheight | Integer | Optional |        nonce at specified topoheight       |

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "has_nonce",
	"params": {
		"address": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk"
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"exist": true
	}
}
```

#### Get Nonce At TopoHeight
Get nonce from address at exact topoheight

##### Method `get_nonce_at_topoheight`

##### Parameters
|    Name    |   Type  | Required |                           Note                          |
|:----------:|:-------:|:--------:|:-------------------------------------------------------:|
|   address  | Address | Required |            Valid address registered on chain            |
| topoheight | Integer | Required | Topoheight to retrieve a version (if exists) of balance |

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "get_nonce_at_topoheight",
    "params": {
        "address": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
        "topoheight": 11269
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "nonce": 1458,
        "previous_topoheight": 11266
    }
}
```
NOTE: `topoheight` field isn't returned because you're requesting an exact topoheight already, so you know it.

#### Get Balance
Get up-to-date asset's balance for a specific address

NOTE: Balance is returned in atomic units

##### Method `get_balance`

##### Parameters
|   Name  |   Type  | Required |                Note               |
|:-------:|:-------:|:--------:|:---------------------------------:|
| address | Address | Required | Valid address registered on chain |
|  asset  |   Hash  | Required |    Asset ID registered on chain   |

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "get_balance",
    "params": {
        "address": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
        "asset": "0000000000000000000000000000000000000000000000000000000000000000"
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "topoheight": 21337,
        "version": {
            "balance_type": "input",
            "final_balance": {
                "commitment": [
                    22,
                    183,
                    144,
                    165,
                    136,
                    210,
                    70,
                    241,
                    198,
                    222,
                    153,
                    185,
                    106,
                    129,
                    206,
                    59,
                    87,
                    170,
                    84,
                    46,
                    92,
                    255,
                    123,
                    37,
                    13,
                    46,
                    151,
                    145,
                    178,
                    174,
                    229,
                    112
                ],
                "handle": [
                    178,
                    229,
                    67,
                    191,
                    17,
                    36,
                    76,
                    48,
                    173,
                    11,
                    225,
                    181,
                    151,
                    61,
                    47,
                    241,
                    96,
                    181,
                    250,
                    151,
                    110,
                    224,
                    65,
                    49,
                    211,
                    10,
                    25,
                    33,
                    120,
                    110,
                    103,
                    10
                ]
            },
            "output_balance": null,
            "previous_topoheight": 11982
        }
    }
}
```
NOTE: `balance_type` values are: `input`, `output` or `both`.
This determine what changes happened on the encrypted balance.

#### Has Balance
Verify if address has a balance on-chain registered for requested asset.

##### Method `has_balance`

##### Parameters
|    Name    |   Type  | Required |                    Note                    |
|:----------:|:-------:|:--------:|:------------------------------------------:|
|   address  | Address | Required |      Valid address registered on chain     |
|    asset   |   Hash  | Required |        Asset ID registered on chain        |
| topoheight | Integer | Optional |        nonce at specified topoheight       |

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "has_balance",
    "params": {
        "address": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
        "asset": "0000000000000000000000000000000000000000000000000000000000000000"
    }
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"exist": true
	}
}
```
NOTE: If you don't precise the `topoheight` parameter, this will search if this account had already a balance at any moment of this asset.

#### Get Balance At TopoHeight
Get encrypted asset's balance from address at exact topoheight.

An error his returned if account has no asset's balance at requested topoheight.

##### Method `get_balance_at_topoheight`

##### Parameters
|    Name    |   Type  | Required |                           Note                          |
|:----------:|:-------:|:--------:|:-------------------------------------------------------:|
|   address  | Address | Required |            Valid address registered on chain            |
|    asset   |   Hash  | Required |               Asset ID registered on chain              |
| topoheight | Integer | Required | Topoheight to retrieve a version (if exists) of balance |

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "get_balance_at_topoheight",
    "params": {
        "address": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
        "asset": "0000000000000000000000000000000000000000000000000000000000000000",
        "topoheight": 60
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "balance_type": "input",
        "final_balance": {
            "commitment": [
                132,
                139,
                164,
                225,
                126,
                144,
                203,
                234,
                48,
                123,
                134,
                144,
                2,
                62,
                233,
                158,
                144,
                125,
                19,
                220,
                11,
                117,
                49,
                144,
                80,
                31,
                29,
                189,
                25,
                252,
                197,
                71
            ],
            "handle": [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ]
        },
        "output_balance": null,
        "previous_topoheight": 59
    }
}
```

#### Get Assets
Get all assets available on network with its registered topoheight and necessary decimals for a full coin.

##### Method `get_assets`

##### Parameters
|   Name  |   Type  | Required |                   Note                   |
|:-------:|:-------:|:--------:|:----------------------------------------:|
|   skip  | Integer | Optional |          How many assets to skip         |
| maximum | Integer | Optional | Maximum assets to fetch (limited to 100) |

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "get_assets",
	"params": {}
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": [
        {
            "asset": "0000000000000000000000000000000000000000000000000000000000000000",
            "decimals": 8,
            "topoheight": 0
        }
    ]
}
```

#### Get Asset
Get registered topoheight and decimals data from a specific asset.

##### Method `get_asset`

##### Parameters
|  Name | Type | Required |        Note        |
|:-----:|:----:|:--------:|:------------------:|
| asset | Hash | Required | Asset ID requested |

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_asset",
	"id": 1,
	"params": {
		"asset": "0000000000000000000000000000000000000000000000000000000000000000"
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"decimals": 8,
		"topoheight": 0
	}
}
```

#### Count Assets
Counts the number of assets saved on disk

##### Method `count_assets`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "count_assets"
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": 1
}
```

#### Count Accounts
Counts the number of accounts saved on disk

##### Method `count_accounts`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "count_accounts"
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": 1271
}
```

#### Count Transactions
Counts the number of transactions saved on disk

##### Method `count_transactions`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "count_transactions"
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": 44
}
```

#### Get Tips
Retrieve Tips (highest blocks from blockDAG) from chain.
This is the available blocks hashes to mine on to continue the chain and merge DAG branches in one chain.

##### Method `get_tips`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "get_tips"
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": [
		"0000073b071e04ce4e79b095f3c44f4aefb65f4e70f8a5591c986cb4b688d692"
	]
}
```

#### P2p Status
Retrieve some informations about P2p

##### Method `p2p_status`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "p2p_status"
}
```

##### Response
```json
{	
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"best_topoheight": 23,
		"median_topoheight": 23,
		"max_peers": 32,
		"our_topoheight": 23,
		"peer_count": 1,
		"peer_id": 17384099500704996810,
		"tag": null
	}
}
```

#### Get Peers
Retrieve all peers connected

##### Method `get_peers`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "get_peers"
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "hidden_peers": 0,
        "peers": [
            {
                "addr": "162.19.249.100:2125",
                "connected_on": 1711663198,
                "cumulative_difficulty": "874788276435001",
                "height": 21939,
                "id": 7089875151156203202,
                "last_ping": 1711664680,
                "local_port": 2125,
                "peers": {
                    "255.255.255.255:2125": "In",
                    "74.208.251.149:2125": "Both"
                },
                "pruned_topoheight": null,
                "tag": null,
                "top_block_hash": "0000000007eeed3fecdaedff82ad867a224826230c12465cf39186471e2e360e",
                "topoheight": 22241,
                "version": "1.8.0-58bb439"
            },
			{
                "addr": "74.208.251.149:2125",
                "connected_on": 1711663199,
                "cumulative_difficulty": "874788276435001",
                "height": 21939,
                "id": 2448648666414530279,
                "last_ping": 1711664682,
                "local_port": 2125,
                "peers": {
                    "127.0.0.1:2125": "In",
                    "127.0.0.1:2126": "Both"
                },
                "pruned_topoheight": null,
                "tag": null,
                "top_block_hash": "0000000007eeed3fecdaedff82ad867a224826230c12465cf39186471e2e360e",
                "topoheight": 22241,
                "version": "1.8.0-58bb439"
            },
        ],
        "total_peers": 4
    }
}
```
NOTE: Addresses displayed in this example are not real one and were replaced for privacy reasons.

#### Get DAG Order
Retrieve the whole DAG order (all blocks hash ordered by topoheight).
If no parameters are set, it will retrieve the last 64 blocks hash ordered descending.
Maximum of 64 blocks hashes only per request.

##### Method `get_dag_order`

##### Parameters
|       Name       |   Type  | Required |                      Note                     |
|:----------------:|:-------:|:--------:|:---------------------------------------------:|
| start_topoheight | Integer | Optional | If not set, will retrieve last 64 blocks hash |
|  end_topoheight  | Integer | Optional |        Must be under current topoheight       |

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "get_dag_order",
	"params": {
		"start_topoheight": 0,
		"end_topoheight": 5
	}
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": [
        "b715cb0229d13f5f540ae48adf03bc31b094b040b0756a2454631b2ddd899c3a",
        "00000079f04345ac9e14116385dc845a77ad1d4f9f83d8b2b7a84ce3beaa4522",
        "000000c09b5ccd8749feb3d27fe72203ddca2f6f44998ab9db977d2724eaf032",
        "000000fca9a3e66a8f0cfba1138a740ed7ca74ee1b6c915c35717756baa80386",
        "0000007c0d5744a003f0dbc09c08429297f677e7ed49d02bc4455f0ecaf315a4",
        "00000063204b910d1cb486f1705efdaea8a42fbcaef8d3c308c1f3bd296601e9"
    ]
}
```

#### Submit Transaction
Submit a transaction in hex format to daemon mempool.

##### Method `submit_transaction`

##### Parameters
| Name |  Type  | Required |            Note           |
|:----:|:------:|:--------:|:-------------------------:|
|  hex | String | Required | Transaction in HEX format |

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 0,
	"method": "submit_transaction",
	"params": {
		"data": "a15637c25cefd438998a2a043867ef8df905542078a8724ada1aabce003df3cc010100000000000000000000000000000000000000000000000000000000000000000000000000003a986c24cdc1c8ee8f028b8cafe7b79a66a0902f26d89dd54eeff80abcf251a9a3bd0000000000000003e80000000000000002d297ef720d388ff2aaedf6755a1f93b4ac1b55c987da5dc53c19350d8a779d970c7f4cfcc25d2f4ce3f4ef3a77d0f31d15635d221d5a72ef6651dbb7f1810301"
	}
}
```

##### Response
```json
{
	"id": 0,
	"jsonrpc": "2.0",
	"result": true
}
```

#### Get Transaction
Fetch a transaction on disk and in mempool by its hash from daemon.

NOTE: result returned in `data` field can changes based on the Transaction Type (transfers, burn, Smart Contract call, Deploy Code..)

##### Method `get_transaction`

##### Parameters
| Name | Type | Required |            Note           |
|:----:|:----:|:--------:|:-------------------------:|
| hash | Hash | Required | Transaction hash to fetch |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_transaction",
    "id": 1,
    "params": {
        "hash": "dd693bad09cb03ba0bf9a6fa7b787f918748db869c1463b7fa16e20b498dea88"
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "blocks": [
            "000000000e4547de9f088734d54d0199605338896a58b7d2d7dea06c1ef35cfc"
        ],
        "data": {
            "transfers": [
                {
                    "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                    "commitment": [
                        170,
                        159,
                        5,
                        118,
                        31,
                        241,
                        255,
                        72,
                        38,
                        232,
                        229,
                        153,
                        126,
                        13,
                        245,
                        123,
                        146,
                        109,
                        138,
                        145,
                        248,
                        11,
                        54,
                        88,
                        225,
                        178,
                        100,
                        101,
                        115,
                        10,
                        81,
                        51
                    ],
                    "ct_validity_proof": {
                        "Y_0": [
                            188,
                            32,
                            23,
                            134,
                            208,
                            143,
                            254,
                            203,
                            250,
                            2,
                            57,
                            204,
                            45,
                            3,
                            219,
                            73,
                            231,
                            214,
                            36,
                            205,
                            20,
                            130,
                            237,
                            50,
                            16,
                            76,
                            190,
                            34,
                            157,
                            8,
                            65,
                            69
                        ],
                        "Y_1": [
                            140,
                            127,
                            88,
                            17,
                            119,
                            167,
                            148,
                            202,
                            69,
                            228,
                            234,
                            13,
                            228,
                            238,
                            35,
                            212,
                            128,
                            141,
                            160,
                            29,
                            38,
                            150,
                            111,
                            219,
                            255,
                            33,
                            211,
                            53,
                            124,
                            255,
                            165,
                            56
                        ],
                        "z_r": [
                            157,
                            140,
                            192,
                            88,
                            119,
                            197,
                            248,
                            220,
                            52,
                            244,
                            129,
                            66,
                            134,
                            77,
                            236,
                            207,
                            52,
                            52,
                            226,
                            162,
                            80,
                            185,
                            162,
                            57,
                            132,
                            105,
                            108,
                            138,
                            19,
                            44,
                            250,
                            10
                        ],
                        "z_x": [
                            140,
                            171,
                            28,
                            227,
                            183,
                            24,
                            176,
                            106,
                            228,
                            113,
                            201,
                            42,
                            9,
                            198,
                            218,
                            81,
                            59,
                            89,
                            8,
                            87,
                            61,
                            32,
                            183,
                            2,
                            20,
                            179,
                            74,
                            105,
                            27,
                            79,
                            200,
                            0
                        ]
                    },
                    "destination": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
                    "extra_data": null,
                    "receiver_handle": [
                        240,
                        59,
                        85,
                        197,
                        199,
                        134,
                        254,
                        182,
                        158,
                        3,
                        72,
                        190,
                        67,
                        39,
                        171,
                        83,
                        31,
                        168,
                        245,
                        91,
                        153,
                        226,
                        30,
                        160,
                        7,
                        202,
                        250,
                        207,
                        28,
                        68,
                        138,
                        41
                    ],
                    "sender_handle": [
                        190,
                        164,
                        128,
                        240,
                        94,
                        148,
                        3,
                        60,
                        124,
                        89,
                        177,
                        56,
                        246,
                        74,
                        127,
                        81,
                        14,
                        34,
                        54,
                        234,
                        67,
                        159,
                        133,
                        136,
                        81,
                        195,
                        9,
                        165,
                        238,
                        33,
                        148,
                        65
                    ]
                }
            ]
        },
        "executed_in_block": "000000000e4547de9f088734d54d0199605338896a58b7d2d7dea06c1ef35cfc",
        "fee": 25000,
        "hash": "dd693bad09cb03ba0bf9a6fa7b787f918748db869c1463b7fa16e20b498dea88",
        "in_mempool": false,
        "nonce": 4,
        "range_proof": [
            116,
            190,
            32,
            232,
            184,
            86,
            88,
            122,
            104,
            176,
            166,
            69,
            222,
            113,
            92,
            36,
            17,
            39,
            222,
            107,
            75,
            70,
            199,
            251,
            63,
            222,
            60,
            10,
            117,
            208,
            43,
            46,
            242,
            181,
            3,
            198,
            212,
            73,
            98,
            104,
            88,
            193,
            76,
            54,
            73,
            234,
            75,
            250,
            63,
            69,
            137,
            223,
            74,
            193,
            216,
            68,
            59,
            138,
            245,
            171,
            64,
            82,
            213,
            50,
            60,
            164,
            89,
            210,
            181,
            24,
            81,
            116,
            34,
            22,
            255,
            130,
            132,
            202,
            178,
            157,
            227,
            99,
            120,
            83,
            27,
            51,
            196,
            174,
            127,
            63,
            249,
            163,
            57,
            67,
            233,
            61,
            160,
            123,
            222,
            109,
            22,
            137,
            252,
            147,
            34,
            139,
            111,
            189,
            169,
            10,
            223,
            226,
            186,
            206,
            146,
            52,
            154,
            21,
            139,
            65,
            119,
            88,
            246,
            116,
            95,
            73,
            204,
            82,
            92,
            179,
            234,
            8,
            84,
            249,
            47,
            226,
            202,
            245,
            225,
            96,
            200,
            51,
            87,
            152,
            213,
            193,
            136,
            175,
            69,
            102,
            177,
            237,
            176,
            92,
            94,
            234,
            173,
            212,
            216,
            2,
            247,
            30,
            156,
            73,
            36,
            136,
            15,
            147,
            240,
            131,
            83,
            59,
            97,
            120,
            222,
            253,
            152,
            120,
            211,
            199,
            82,
            152,
            228,
            248,
            156,
            72,
            244,
            69,
            225,
            57,
            203,
            2,
            234,
            66,
            38,
            107,
            50,
            144,
            54,
            185,
            91,
            189,
            95,
            160,
            120,
            33,
            126,
            52,
            202,
            18,
            138,
            102,
            56,
            227,
            131,
            117,
            88,
            218,
            16,
            205,
            69,
            184,
            14,
            3,
            56,
            174,
            167,
            122,
            192,
            53,
            149,
            177,
            201,
            54,
            98,
            154,
            6,
            206,
            19,
            105,
            172,
            152,
            138,
            176,
            80,
            202,
            228,
            175,
            182,
            63,
            237,
            239,
            47,
            121,
            235,
            41,
            32,
            212,
            38,
            246,
            73,
            3,
            255,
            231,
            140,
            92,
            11,
            179,
            97,
            68,
            89,
            213,
            61,
            105,
            219,
            77,
            210,
            141,
            213,
            241,
            89,
            150,
            234,
            98,
            121,
            74,
            154,
            48,
            186,
            69,
            141,
            240,
            158,
            65,
            120,
            104,
            51,
            115,
            25,
            92,
            187,
            215,
            88,
            128,
            211,
            87,
            46,
            30,
            162,
            82,
            48,
            155,
            32,
            219,
            3,
            238,
            202,
            22,
            49,
            69,
            110,
            168,
            60,
            252,
            14,
            209,
            180,
            247,
            86,
            145,
            59,
            51,
            174,
            220,
            183,
            192,
            99,
            33,
            8,
            132,
            56,
            204,
            15,
            78,
            120,
            24,
            32,
            71,
            63,
            149,
            10,
            81,
            2,
            43,
            83,
            146,
            134,
            108,
            161,
            129,
            170,
            174,
            175,
            41,
            63,
            17,
            137,
            69,
            50,
            90,
            143,
            151,
            178,
            27,
            182,
            201,
            23,
            214,
            161,
            139,
            16,
            249,
            123,
            101,
            216,
            70,
            77,
            92,
            247,
            130,
            114,
            115,
            23,
            10,
            88,
            244,
            139,
            18,
            57,
            73,
            2,
            169,
            167,
            59,
            201,
            200,
            245,
            156,
            13,
            209,
            167,
            189,
            252,
            188,
            135,
            104,
            108,
            226,
            156,
            15,
            182,
            193,
            83,
            184,
            214,
            73,
            110,
            84,
            130,
            167,
            46,
            153,
            233,
            25,
            8,
            44,
            32,
            26,
            141,
            238,
            91,
            128,
            45,
            52,
            79,
            187,
            13,
            73,
            172,
            232,
            133,
            91,
            143,
            188,
            54,
            185,
            118,
            66,
            255,
            138,
            89,
            62,
            2,
            252,
            90,
            121,
            244,
            212,
            117,
            88,
            254,
            230,
            57,
            115,
            67,
            203,
            78,
            173,
            204,
            48,
            124,
            207,
            185,
            233,
            80,
            25,
            155,
            116,
            46,
            96,
            115,
            204,
            128,
            58,
            206,
            71,
            141,
            40,
            209,
            19,
            129,
            212,
            200,
            13,
            158,
            127,
            181,
            45,
            177,
            238,
            22,
            48,
            36,
            56,
            117,
            40,
            32,
            42,
            102,
            75,
            49,
            85,
            250,
            30,
            93,
            89,
            229,
            240,
            156,
            76,
            117,
            6,
            150,
            172,
            68,
            94,
            50,
            75,
            8,
            233,
            1,
            17,
            186,
            124,
            152,
            31,
            102,
            91,
            65,
            41,
            114,
            182,
            175,
            173,
            219,
            84,
            181,
            128,
            235,
            231,
            125,
            62,
            40,
            224,
            17,
            152,
            107,
            222,
            209,
            24,
            213,
            216,
            19,
            113,
            178,
            111,
            202,
            58,
            68,
            63,
            169,
            134,
            145,
            86,
            125,
            149,
            172,
            9,
            79,
            50,
            7,
            102,
            135,
            147,
            20,
            130,
            98,
            202,
            135,
            164,
            160,
            142,
            89,
            50,
            111,
            17,
            154,
            19,
            174,
            107,
            57,
            10,
            114,
            48,
            26,
            90,
            245,
            33,
            173,
            124,
            178,
            76,
            18,
            142,
            240,
            199,
            10,
            163,
            202,
            63,
            159,
            249,
            150,
            132,
            51,
            88,
            207,
            135,
            85,
            100,
            62,
            217,
            208,
            33,
            173,
            172,
            147,
            217,
            103,
            89,
            210,
            55,
            1,
            25,
            211,
            71,
            221,
            96,
            61,
            43,
            70,
            128,
            49,
            11,
            181,
            79,
            15,
            131,
            28,
            61,
            134,
            58,
            17,
            226,
            159,
            154,
            234,
            106,
            125,
            150,
            231,
            121,
            224,
            106,
            137,
            65,
            246,
            127,
            124,
            22,
            206,
            187,
            215,
            113,
            139,
            148,
            32,
            131,
            211,
            241,
            207,
            238,
            193,
            8,
            221,
            105,
            181,
            204,
            152,
            69,
            88,
            135,
            114,
            244,
            159,
            241,
            212,
            15,
            247,
            20,
            114,
            163,
            24,
            159,
            163,
            219,
            107,
            65,
            169,
            1,
            207,
            9,
            162,
            214,
            217,
            11
        ],
        "reference": {
            "hash": "0000000007068e3656a526e04280b0f975bf9d9d1e156ea0677970abe6cceafa",
            "topoheight": 10656
        },
        "signature": "37a6b9bf89e524a7481b6427c2d5d026a212b230410cedbe46fedb615edbb107288663e24567485d4802659f0f03ca5e6b27e7ea35541d07b2c71ed2ad94f300",
        "source": "xet:dn3x9yspqtuzhm874m267a3g9fkdztr3uztyx534wdx3p9rkdspqqhpss5d",
        "source_commitments": [
            {
                "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                "commitment": [
                    32,
                    109,
                    176,
                    123,
                    209,
                    112,
                    50,
                    37,
                    54,
                    231,
                    73,
                    185,
                    229,
                    180,
                    53,
                    229,
                    150,
                    126,
                    250,
                    20,
                    24,
                    94,
                    33,
                    230,
                    149,
                    123,
                    201,
                    88,
                    219,
                    90,
                    20,
                    12
                ],
                "proof": {
                    "Y_0": [
                        170,
                        157,
                        102,
                        164,
                        247,
                        173,
                        19,
                        222,
                        8,
                        109,
                        125,
                        56,
                        113,
                        126,
                        64,
                        207,
                        105,
                        130,
                        12,
                        248,
                        127,
                        25,
                        194,
                        177,
                        17,
                        194,
                        17,
                        233,
                        182,
                        14,
                        40,
                        92
                    ],
                    "Y_1": [
                        230,
                        231,
                        231,
                        223,
                        246,
                        98,
                        206,
                        132,
                        38,
                        229,
                        234,
                        106,
                        195,
                        90,
                        241,
                        137,
                        88,
                        247,
                        94,
                        169,
                        200,
                        5,
                        218,
                        188,
                        86,
                        25,
                        201,
                        131,
                        57,
                        11,
                        25,
                        44
                    ],
                    "Y_2": [
                        8,
                        203,
                        46,
                        47,
                        49,
                        145,
                        71,
                        80,
                        194,
                        92,
                        219,
                        53,
                        204,
                        170,
                        65,
                        243,
                        245,
                        153,
                        182,
                        185,
                        176,
                        150,
                        134,
                        13,
                        174,
                        42,
                        206,
                        226,
                        223,
                        179,
                        144,
                        69
                    ],
                    "z_r": [
                        60,
                        198,
                        164,
                        99,
                        178,
                        110,
                        162,
                        185,
                        107,
                        151,
                        88,
                        185,
                        133,
                        2,
                        217,
                        227,
                        222,
                        4,
                        85,
                        159,
                        125,
                        137,
                        116,
                        155,
                        128,
                        166,
                        164,
                        246,
                        83,
                        186,
                        195,
                        10
                    ],
                    "z_s": [
                        147,
                        206,
                        92,
                        159,
                        213,
                        8,
                        102,
                        210,
                        199,
                        36,
                        106,
                        215,
                        62,
                        11,
                        223,
                        238,
                        87,
                        39,
                        146,
                        230,
                        211,
                        70,
                        96,
                        225,
                        189,
                        190,
                        65,
                        182,
                        17,
                        94,
                        173,
                        14
                    ],
                    "z_x": [
                        210,
                        220,
                        75,
                        86,
                        34,
                        137,
                        110,
                        182,
                        151,
                        92,
                        28,
                        207,
                        216,
                        31,
                        165,
                        215,
                        2,
                        65,
                        23,
                        238,
                        189,
                        178,
                        237,
                        156,
                        112,
                        109,
                        28,
                        94,
                        213,
                        181,
                        20,
                        8
                    ]
                }
            }
        ],
        "version": 0
    }
}
```

#### Get Mempool
Fetch all transactions presents in the mempool

##### Method `get_mempool`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "get_mempool"
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": [
        {
            "blocks": null,
            "data": {
                "transfers": [
                    {
                        "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                        "commitment": [
                            218,
                            137,
                            118,
                            13,
                            16,
                            98,
                            204,
                            27,
                            215,
                            144,
                            246,
                            211,
                            178,
                            168,
                            50,
                            50,
                            214,
                            47,
                            38,
                            213,
                            149,
                            49,
                            46,
                            101,
                            251,
                            35,
                            2,
                            84,
                            54,
                            7,
                            68,
                            94
                        ],
                        "ct_validity_proof": {
                            "Y_0": [
                                158,
                                231,
                                220,
                                17,
                                123,
                                132,
                                51,
                                28,
                                233,
                                0,
                                168,
                                98,
                                126,
                                7,
                                204,
                                191,
                                246,
                                187,
                                147,
                                221,
                                210,
                                166,
                                249,
                                38,
                                76,
                                110,
                                12,
                                160,
                                87,
                                190,
                                73,
                                66
                            ],
                            "Y_1": [
                                224,
                                7,
                                55,
                                141,
                                143,
                                193,
                                193,
                                116,
                                14,
                                21,
                                254,
                                72,
                                202,
                                135,
                                223,
                                232,
                                143,
                                29,
                                173,
                                215,
                                27,
                                13,
                                142,
                                70,
                                128,
                                77,
                                157,
                                173,
                                219,
                                40,
                                107,
                                14
                            ],
                            "z_r": [
                                101,
                                195,
                                217,
                                89,
                                4,
                                15,
                                150,
                                77,
                                34,
                                185,
                                137,
                                33,
                                255,
                                103,
                                191,
                                44,
                                99,
                                34,
                                54,
                                217,
                                235,
                                49,
                                172,
                                242,
                                45,
                                152,
                                6,
                                198,
                                185,
                                36,
                                221,
                                9
                            ],
                            "z_x": [
                                0,
                                38,
                                78,
                                61,
                                66,
                                242,
                                187,
                                16,
                                155,
                                139,
                                250,
                                140,
                                3,
                                85,
                                253,
                                202,
                                190,
                                26,
                                183,
                                196,
                                8,
                                239,
                                141,
                                147,
                                57,
                                19,
                                21,
                                37,
                                84,
                                70,
                                27,
                                10
                            ]
                        },
                        "destination": "xet:q622pz5exf5hmw98d73dlqhwjvfwd5g9k0tpuay90ga634c64cgsqczfmvx",
                        "extra_data": null,
                        "receiver_handle": [
                            24,
                            152,
                            119,
                            104,
                            18,
                            50,
                            26,
                            255,
                            8,
                            247,
                            126,
                            14,
                            156,
                            62,
                            135,
                            55,
                            131,
                            133,
                            33,
                            233,
                            248,
                            202,
                            145,
                            75,
                            233,
                            224,
                            102,
                            163,
                            0,
                            64,
                            196,
                            63
                        ],
                        "sender_handle": [
                            20,
                            59,
                            247,
                            220,
                            127,
                            42,
                            78,
                            103,
                            239,
                            17,
                            131,
                            30,
                            126,
                            110,
                            74,
                            163,
                            142,
                            85,
                            90,
                            52,
                            154,
                            129,
                            10,
                            49,
                            21,
                            74,
                            104,
                            98,
                            237,
                            16,
                            156,
                            1
                        ]
                    }
                ]
            },
            "executed_in_block": null,
            "fee": 25000,
            "first_seen": 1711665284,
            "hash": "5c0c4a0d58cf678015af2e10f79119ed6d969dd3d1e98ca4ffefbb4439765658",
            "in_mempool": true,
            "nonce": 1461,
            "range_proof": [
                152,
                151,
                60,
                45,
                85,
                18,
                16,
                164,
                118,
                234,
                156,
                125,
                246,
                97,
                104,
                9,
                127,
                48,
                209,
                201,
                216,
                221,
                90,
                165,
                40,
                92,
                168,
                17,
                141,
                27,
                234,
                66,
                16,
                112,
                30,
                126,
                229,
                71,
                182,
                165,
                209,
                223,
                33,
                13,
                46,
                79,
                39,
                85,
                24,
                124,
                214,
                238,
                32,
                211,
                121,
                62,
                17,
                183,
                134,
                67,
                200,
                13,
                34,
                90,
                48,
                159,
                174,
                238,
                16,
                134,
                120,
                177,
                210,
                122,
                246,
                203,
                179,
                74,
                1,
                176,
                225,
                122,
                230,
                124,
                194,
                82,
                37,
                137,
                116,
                137,
                64,
                167,
                149,
                54,
                188,
                36,
                6,
                24,
                206,
                54,
                245,
                111,
                185,
                21,
                79,
                168,
                207,
                10,
                60,
                190,
                15,
                103,
                130,
                136,
                86,
                46,
                156,
                145,
                143,
                114,
                96,
                121,
                190,
                193,
                188,
                193,
                13,
                46,
                68,
                220,
                94,
                70,
                90,
                47,
                99,
                254,
                33,
                158,
                147,
                100,
                83,
                172,
                24,
                18,
                160,
                67,
                122,
                31,
                26,
                226,
                79,
                251,
                169,
                119,
                50,
                116,
                179,
                223,
                137,
                3,
                157,
                237,
                40,
                81,
                53,
                44,
                177,
                21,
                244,
                147,
                135,
                5,
                67,
                59,
                48,
                254,
                204,
                147,
                8,
                104,
                192,
                166,
                48,
                39,
                43,
                228,
                118,
                108,
                190,
                129,
                209,
                12,
                47,
                118,
                41,
                173,
                134,
                102,
                169,
                27,
                246,
                45,
                215,
                3,
                148,
                97,
                240,
                111,
                171,
                131,
                134,
                170,
                27,
                160,
                45,
                189,
                121,
                2,
                54,
                53,
                130,
                76,
                42,
                1,
                144,
                146,
                190,
                213,
                109,
                239,
                10,
                58,
                82,
                65,
                186,
                40,
                32,
                69,
                185,
                127,
                115,
                236,
                5,
                151,
                36,
                47,
                152,
                155,
                18,
                95,
                56,
                69,
                75,
                184,
                94,
                68,
                14,
                237,
                228,
                245,
                111,
                203,
                206,
                42,
                52,
                59,
                180,
                8,
                45,
                206,
                9,
                129,
                52,
                93,
                231,
                152,
                128,
                177,
                153,
                44,
                73,
                162,
                86,
                15,
                44,
                234,
                130,
                40,
                60,
                81,
                238,
                36,
                11,
                41,
                213,
                158,
                231,
                130,
                236,
                185,
                60,
                172,
                84,
                221,
                219,
                78,
                97,
                61,
                56,
                39,
                198,
                126,
                28,
                62,
                169,
                52,
                44,
                122,
                230,
                101,
                204,
                247,
                17,
                247,
                42,
                238,
                121,
                167,
                126,
                206,
                156,
                195,
                185,
                18,
                81,
                163,
                211,
                1,
                239,
                10,
                215,
                0,
                219,
                242,
                191,
                197,
                142,
                118,
                248,
                77,
                86,
                57,
                2,
                40,
                161,
                195,
                165,
                31,
                232,
                92,
                228,
                26,
                147,
                77,
                148,
                40,
                109,
                44,
                116,
                128,
                149,
                144,
                218,
                136,
                204,
                233,
                208,
                160,
                172,
                179,
                207,
                218,
                174,
                16,
                242,
                28,
                90,
                132,
                88,
                42,
                112,
                131,
                154,
                2,
                63,
                160,
                210,
                57,
                79,
                27,
                11,
                132,
                86,
                81,
                110,
                154,
                243,
                47,
                94,
                29,
                241,
                252,
                11,
                31,
                103,
                4,
                118,
                170,
                187,
                179,
                237,
                160,
                37,
                35,
                75,
                120,
                186,
                151,
                164,
                83,
                55,
                139,
                147,
                4,
                89,
                231,
                226,
                21,
                182,
                189,
                59,
                61,
                120,
                120,
                231,
                40,
                109,
                60,
                26,
                156,
                77,
                240,
                152,
                136,
                139,
                199,
                168,
                33,
                156,
                245,
                218,
                0,
                226,
                64,
                149,
                97,
                97,
                25,
                212,
                197,
                148,
                231,
                215,
                75,
                79,
                216,
                154,
                84,
                72,
                66,
                214,
                62,
                190,
                169,
                22,
                150,
                40,
                53,
                2,
                96,
                102,
                44,
                67,
                90,
                56,
                147,
                69,
                131,
                186,
                223,
                24,
                181,
                53,
                97,
                60,
                102,
                68,
                12,
                26,
                27,
                208,
                106,
                186,
                32,
                220,
                18,
                199,
                120,
                108,
                230,
                245,
                58,
                77,
                239,
                179,
                172,
                103,
                169,
                152,
                201,
                204,
                105,
                189,
                69,
                9,
                180,
                251,
                17,
                233,
                118,
                67,
                150,
                201,
                14,
                58,
                138,
                121,
                104,
                30,
                158,
                46,
                137,
                12,
                63,
                5,
                86,
                58,
                207,
                50,
                240,
                226,
                94,
                105,
                110,
                37,
                181,
                108,
                84,
                196,
                222,
                195,
                156,
                207,
                146,
                168,
                1,
                180,
                138,
                113,
                24,
                210,
                252,
                109,
                207,
                139,
                27,
                42,
                47,
                71,
                113,
                208,
                210,
                189,
                168,
                219,
                200,
                216,
                174,
                135,
                217,
                90,
                126,
                173,
                108,
                231,
                80,
                100,
                69,
                196,
                50,
                69,
                252,
                145,
                163,
                211,
                201,
                217,
                141,
                89,
                184,
                171,
                31,
                88,
                113,
                226,
                130,
                195,
                2,
                44,
                71,
                213,
                60,
                16,
                169,
                255,
                136,
                118,
                82,
                181,
                117,
                172,
                115,
                7,
                172,
                53,
                76,
                22,
                38,
                53,
                116,
                174,
                217,
                175,
                91,
                33,
                159,
                255,
                195,
                84,
                112,
                54,
                141,
                165,
                186,
                148,
                240,
                207,
                2,
                22,
                97,
                48,
                74,
                85,
                182,
                5,
                71,
                153,
                249,
                41,
                165,
                215,
                18,
                185,
                143,
                101,
                205,
                74,
                210,
                120,
                51,
                17,
                212,
                193,
                63,
                196,
                16,
                170,
                2,
                225,
                230,
                243,
                87,
                168,
                14,
                3,
                152,
                101,
                127,
                84,
                120,
                135,
                132,
                126,
                80,
                136,
                124,
                133,
                106,
                66,
                182,
                185,
                56,
                31,
                202,
                237,
                60,
                7,
                244,
                89,
                180,
                151,
                138,
                231,
                25,
                20,
                3
            ],
            "reference": {
                "hash": "000000000bc1070fda6b86eb31fbf3f15e89be9c10928415b2254fcab96088a8",
                "topoheight": 22285
            },
            "signature": "b3362192f0ae054964279fc67e55f3dc2cde9c6d6d0c98b00a1c31672d6a330aa1cdad4929662d68fa0a830349da429eef342fef43125b97fea87c16fa2f6607",
            "source": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
            "source_commitments": [
                {
                    "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                    "commitment": [
                        162,
                        234,
                        124,
                        8,
                        122,
                        42,
                        11,
                        22,
                        134,
                        13,
                        71,
                        91,
                        26,
                        80,
                        192,
                        4,
                        149,
                        92,
                        35,
                        2,
                        69,
                        33,
                        94,
                        84,
                        83,
                        83,
                        50,
                        84,
                        209,
                        203,
                        45,
                        40
                    ],
                    "proof": {
                        "Y_0": [
                            116,
                            218,
                            91,
                            32,
                            206,
                            34,
                            61,
                            109,
                            135,
                            5,
                            174,
                            150,
                            213,
                            28,
                            15,
                            5,
                            79,
                            168,
                            84,
                            64,
                            199,
                            155,
                            22,
                            248,
                            76,
                            5,
                            201,
                            196,
                            66,
                            69,
                            228,
                            32
                        ],
                        "Y_1": [
                            232,
                            30,
                            221,
                            209,
                            235,
                            222,
                            168,
                            0,
                            204,
                            1,
                            10,
                            186,
                            182,
                            228,
                            205,
                            104,
                            242,
                            219,
                            123,
                            147,
                            135,
                            35,
                            12,
                            202,
                            232,
                            1,
                            102,
                            134,
                            41,
                            158,
                            212,
                            29
                        ],
                        "Y_2": [
                            14,
                            184,
                            127,
                            213,
                            147,
                            230,
                            161,
                            52,
                            135,
                            223,
                            62,
                            143,
                            110,
                            219,
                            156,
                            170,
                            241,
                            152,
                            8,
                            241,
                            89,
                            249,
                            46,
                            183,
                            17,
                            173,
                            129,
                            172,
                            150,
                            45,
                            215,
                            105
                        ],
                        "z_r": [
                            33,
                            238,
                            204,
                            122,
                            192,
                            122,
                            31,
                            198,
                            135,
                            69,
                            31,
                            98,
                            72,
                            90,
                            41,
                            244,
                            184,
                            159,
                            106,
                            125,
                            17,
                            248,
                            30,
                            170,
                            73,
                            107,
                            91,
                            124,
                            15,
                            60,
                            98,
                            1
                        ],
                        "z_s": [
                            176,
                            230,
                            7,
                            8,
                            210,
                            21,
                            88,
                            239,
                            54,
                            119,
                            207,
                            5,
                            27,
                            137,
                            141,
                            68,
                            142,
                            55,
                            5,
                            0,
                            97,
                            67,
                            90,
                            223,
                            150,
                            126,
                            112,
                            219,
                            243,
                            131,
                            171,
                            14
                        ],
                        "z_x": [
                            226,
                            223,
                            152,
                            216,
                            17,
                            235,
                            42,
                            50,
                            243,
                            244,
                            232,
                            177,
                            183,
                            178,
                            27,
                            46,
                            203,
                            154,
                            18,
                            177,
                            82,
                            53,
                            203,
                            213,
                            178,
                            112,
                            156,
                            49,
                            21,
                            191,
                            125,
                            8
                        ]
                    }
                }
            ],
            "version": 0
        }
    ]
}
```

#### Get Transactions
Fetch transactions by theirs hashes from database and mempool of daemon and keep the same order in response

##### Method `get_transactions`

##### Parameters
| Name | Type | Required |            Note           |
|:----:|:----:|:--------:|:-------------------------:|
| hash | Hash | Required | Transaction hash to fetch |

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "get_transactions",
	"params": {
		"tx_hashes": [
			"5c0c4a0d58cf678015af2e10f79119ed6d969dd3d1e98ca4ffefbb4439765658"
		]
	}
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": [
        {
            "blocks": [
                "000000000bc1070fda6b86eb31fbf3f15e89be9c10928415b2254fcab96088a8"
            ],
            "data": {
                "transfers": [
                    {
                        "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                        "commitment": [
                            250,
                            223,
                            149,
                            61,
                            162,
                            95,
                            167,
                            123,
                            147,
                            48,
                            229,
                            121,
                            70,
                            107,
                            159,
                            33,
                            93,
                            138,
                            52,
                            125,
                            112,
                            67,
                            196,
                            92,
                            229,
                            122,
                            189,
                            104,
                            59,
                            206,
                            43,
                            3
                        ],
                        "ct_validity_proof": {
                            "Y_0": [
                                240,
                                56,
                                135,
                                79,
                                159,
                                131,
                                179,
                                215,
                                10,
                                173,
                                199,
                                218,
                                211,
                                152,
                                3,
                                119,
                                177,
                                130,
                                82,
                                11,
                                186,
                                45,
                                189,
                                4,
                                177,
                                242,
                                57,
                                215,
                                208,
                                18,
                                156,
                                38
                            ],
                            "Y_1": [
                                96,
                                109,
                                73,
                                111,
                                203,
                                185,
                                150,
                                92,
                                241,
                                162,
                                66,
                                103,
                                119,
                                135,
                                244,
                                47,
                                3,
                                4,
                                209,
                                167,
                                173,
                                37,
                                0,
                                236,
                                45,
                                151,
                                150,
                                224,
                                127,
                                169,
                                46,
                                98
                            ],
                            "z_r": [
                                247,
                                33,
                                119,
                                43,
                                63,
                                160,
                                69,
                                28,
                                100,
                                125,
                                103,
                                81,
                                79,
                                249,
                                247,
                                99,
                                157,
                                207,
                                253,
                                92,
                                251,
                                107,
                                237,
                                126,
                                108,
                                197,
                                226,
                                7,
                                133,
                                176,
                                88,
                                6
                            ],
                            "z_x": [
                                14,
                                152,
                                174,
                                185,
                                108,
                                19,
                                100,
                                100,
                                12,
                                48,
                                46,
                                93,
                                174,
                                151,
                                157,
                                155,
                                162,
                                90,
                                148,
                                78,
                                33,
                                36,
                                50,
                                119,
                                249,
                                77,
                                198,
                                234,
                                175,
                                143,
                                198,
                                12
                            ]
                        },
                        "destination": "xet:q622pz5exf5hmw98d73dlqhwjvfwd5g9k0tpuay90ga634c64cgsqczfmvx",
                        "extra_data": null,
                        "receiver_handle": [
                            52,
                            82,
                            52,
                            83,
                            129,
                            131,
                            58,
                            205,
                            187,
                            254,
                            112,
                            59,
                            69,
                            128,
                            62,
                            11,
                            42,
                            203,
                            113,
                            2,
                            123,
                            33,
                            239,
                            179,
                            17,
                            203,
                            49,
                            51,
                            16,
                            145,
                            7,
                            106
                        ],
                        "sender_handle": [
                            188,
                            54,
                            8,
                            9,
                            247,
                            56,
                            242,
                            39,
                            232,
                            99,
                            0,
                            158,
                            33,
                            27,
                            235,
                            151,
                            179,
                            101,
                            72,
                            71,
                            175,
                            255,
                            7,
                            240,
                            45,
                            159,
                            243,
                            241,
                            91,
                            139,
                            140,
                            6
                        ]
                    }
                ]
            },
            "executed_in_block": "000000000bc1070fda6b86eb31fbf3f15e89be9c10928415b2254fcab96088a8",
            "fee": 25000,
            "hash": "cb26c0a203cd75206ebd122213e442ffabf5dc21286fbe92e46c864ba723dcdd",
            "in_mempool": false,
            "nonce": 1460,
            "range_proof": [
                124,
                241,
                170,
                167,
                140,
                68,
                24,
                166,
                41,
                145,
                191,
                69,
                234,
                201,
                234,
                239,
                61,
                60,
                99,
                63,
                200,
                141,
                100,
                229,
                15,
                102,
                94,
                188,
                248,
                30,
                4,
                48,
                42,
                120,
                154,
                41,
                222,
                76,
                118,
                151,
                244,
                51,
                113,
                250,
                217,
                83,
                96,
                203,
                197,
                148,
                184,
                74,
                60,
                166,
                241,
                160,
                143,
                102,
                62,
                155,
                215,
                38,
                37,
                122,
                42,
                248,
                247,
                186,
                179,
                253,
                194,
                35,
                207,
                139,
                39,
                187,
                239,
                147,
                82,
                62,
                108,
                59,
                155,
                205,
                191,
                135,
                218,
                57,
                36,
                189,
                189,
                84,
                151,
                1,
                39,
                107,
                208,
                196,
                174,
                14,
                189,
                108,
                152,
                135,
                212,
                165,
                216,
                216,
                5,
                92,
                113,
                45,
                238,
                54,
                128,
                107,
                187,
                198,
                112,
                167,
                232,
                179,
                104,
                254,
                250,
                231,
                189,
                87,
                82,
                52,
                38,
                254,
                193,
                108,
                172,
                216,
                158,
                181,
                100,
                119,
                124,
                16,
                138,
                131,
                228,
                171,
                63,
                181,
                25,
                3,
                110,
                91,
                165,
                101,
                94,
                170,
                238,
                103,
                98,
                3,
                174,
                73,
                71,
                183,
                231,
                165,
                105,
                188,
                78,
                62,
                176,
                243,
                8,
                136,
                227,
                139,
                43,
                32,
                142,
                224,
                69,
                103,
                152,
                64,
                121,
                148,
                80,
                249,
                71,
                245,
                153,
                9,
                64,
                81,
                107,
                254,
                25,
                185,
                43,
                46,
                168,
                157,
                255,
                232,
                217,
                255,
                98,
                1,
                206,
                13,
                161,
                124,
                126,
                241,
                83,
                166,
                157,
                151,
                195,
                71,
                84,
                244,
                83,
                3,
                240,
                39,
                164,
                253,
                188,
                212,
                254,
                252,
                17,
                100,
                140,
                197,
                27,
                29,
                30,
                222,
                188,
                172,
                39,
                143,
                135,
                203,
                210,
                18,
                203,
                59,
                67,
                207,
                192,
                90,
                152,
                78,
                144,
                105,
                115,
                204,
                215,
                73,
                135,
                212,
                0,
                102,
                83,
                236,
                36,
                167,
                123,
                128,
                246,
                39,
                64,
                76,
                38,
                214,
                230,
                158,
                211,
                115,
                69,
                55,
                26,
                124,
                130,
                127,
                88,
                49,
                80,
                53,
                74,
                123,
                64,
                176,
                12,
                181,
                200,
                168,
                101,
                218,
                106,
                7,
                2,
                82,
                77,
                24,
                152,
                118,
                19,
                230,
                145,
                194,
                226,
                230,
                4,
                106,
                233,
                1,
                18,
                49,
                98,
                210,
                85,
                137,
                0,
                175,
                91,
                101,
                139,
                123,
                205,
                99,
                221,
                6,
                250,
                28,
                16,
                139,
                248,
                161,
                202,
                43,
                143,
                57,
                24,
                103,
                74,
                77,
                56,
                77,
                160,
                128,
                80,
                105,
                27,
                166,
                46,
                236,
                142,
                138,
                52,
                118,
                129,
                246,
                186,
                14,
                159,
                85,
                134,
                22,
                22,
                125,
                144,
                1,
                248,
                84,
                165,
                160,
                71,
                108,
                116,
                103,
                162,
                198,
                160,
                167,
                110,
                45,
                106,
                26,
                193,
                118,
                110,
                104,
                165,
                91,
                81,
                98,
                236,
                144,
                142,
                109,
                13,
                83,
                10,
                14,
                56,
                117,
                231,
                93,
                105,
                76,
                186,
                89,
                178,
                230,
                151,
                186,
                254,
                145,
                134,
                135,
                112,
                48,
                213,
                215,
                243,
                237,
                174,
                89,
                170,
                71,
                151,
                125,
                185,
                140,
                234,
                66,
                44,
                184,
                130,
                122,
                187,
                103,
                22,
                13,
                138,
                180,
                224,
                115,
                92,
                221,
                6,
                143,
                62,
                9,
                188,
                39,
                190,
                20,
                69,
                173,
                44,
                5,
                57,
                147,
                130,
                83,
                45,
                22,
                34,
                159,
                159,
                192,
                123,
                212,
                189,
                97,
                56,
                198,
                4,
                239,
                167,
                31,
                177,
                203,
                2,
                171,
                170,
                121,
                160,
                46,
                185,
                104,
                60,
                24,
                175,
                236,
                123,
                238,
                149,
                49,
                233,
                88,
                127,
                119,
                221,
                221,
                159,
                10,
                234,
                223,
                4,
                56,
                108,
                153,
                103,
                252,
                91,
                128,
                224,
                22,
                240,
                98,
                250,
                111,
                204,
                177,
                49,
                20,
                63,
                229,
                58,
                255,
                177,
                22,
                127,
                15,
                54,
                124,
                38,
                5,
                104,
                241,
                71,
                23,
                110,
                150,
                13,
                123,
                92,
                186,
                79,
                55,
                192,
                15,
                225,
                113,
                95,
                233,
                82,
                69,
                123,
                67,
                239,
                27,
                57,
                149,
                28,
                157,
                121,
                12,
                132,
                26,
                48,
                74,
                31,
                202,
                234,
                140,
                29,
                237,
                180,
                5,
                73,
                171,
                248,
                103,
                27,
                98,
                114,
                222,
                91,
                236,
                211,
                54,
                115,
                32,
                150,
                172,
                148,
                224,
                214,
                174,
                231,
                7,
                232,
                102,
                236,
                255,
                130,
                169,
                169,
                36,
                229,
                25,
                75,
                43,
                80,
                97,
                189,
                23,
                189,
                177,
                215,
                118,
                139,
                164,
                7,
                249,
                193,
                221,
                163,
                78,
                162,
                216,
                149,
                27,
                88,
                168,
                250,
                34,
                158,
                65,
                24,
                219,
                150,
                110,
                41,
                200,
                20,
                40,
                216,
                180,
                150,
                151,
                24,
                81,
                49,
                73,
                179,
                204,
                238,
                34,
                140,
                243,
                130,
                51,
                226,
                56,
                251,
                158,
                86,
                132,
                170,
                107,
                160,
                7,
                88,
                111,
                129,
                136,
                218,
                41,
                43,
                251,
                102,
                232,
                204,
                38,
                228,
                223,
                139,
                49,
                60,
                170,
                245,
                210,
                135,
                41,
                32,
                10,
                27,
                151,
                62,
                177,
                224,
                107,
                94,
                138,
                21,
                49,
                42,
                87,
                3,
                37,
                218,
                213,
                6,
                162,
                121,
                20,
                132,
                241,
                191,
                213,
                46,
                96,
                142,
                169,
                44,
                57,
                44,
                12
            ],
            "reference": {
                "hash": "00000000040f90c8bcbb33bc832c1cd9f0683204af1c099a0af52c7a247840f5",
                "topoheight": 22284
            },
            "signature": "afe694d96aa7a4ea44e57e7f7090a19a84105fc49df40c35cb5c1bfe4a949303d8b918e2ccbc38c8058449edcb334883471265743c99be39180a574d2adbfd05",
            "source": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
            "source_commitments": [
                {
                    "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                    "commitment": [
                        30,
                        9,
                        94,
                        111,
                        239,
                        211,
                        250,
                        72,
                        102,
                        174,
                        187,
                        72,
                        167,
                        33,
                        129,
                        6,
                        73,
                        190,
                        134,
                        190,
                        64,
                        225,
                        59,
                        197,
                        136,
                        241,
                        222,
                        65,
                        35,
                        83,
                        225,
                        102
                    ],
                    "proof": {
                        "Y_0": [
                            132,
                            37,
                            94,
                            173,
                            246,
                            110,
                            115,
                            155,
                            19,
                            237,
                            96,
                            209,
                            166,
                            69,
                            71,
                            48,
                            84,
                            116,
                            64,
                            118,
                            81,
                            92,
                            49,
                            175,
                            166,
                            52,
                            213,
                            167,
                            139,
                            99,
                            75,
                            38
                        ],
                        "Y_1": [
                            102,
                            101,
                            95,
                            195,
                            49,
                            88,
                            151,
                            204,
                            18,
                            197,
                            170,
                            13,
                            70,
                            148,
                            228,
                            161,
                            246,
                            36,
                            215,
                            153,
                            249,
                            144,
                            136,
                            193,
                            100,
                            236,
                            238,
                            129,
                            206,
                            102,
                            140,
                            27
                        ],
                        "Y_2": [
                            234,
                            117,
                            216,
                            69,
                            16,
                            98,
                            103,
                            162,
                            226,
                            39,
                            135,
                            167,
                            169,
                            215,
                            205,
                            93,
                            1,
                            40,
                            42,
                            42,
                            60,
                            88,
                            141,
                            35,
                            184,
                            20,
                            218,
                            7,
                            0,
                            100,
                            157,
                            73
                        ],
                        "z_r": [
                            122,
                            202,
                            29,
                            135,
                            106,
                            190,
                            110,
                            76,
                            17,
                            36,
                            196,
                            111,
                            108,
                            216,
                            183,
                            199,
                            156,
                            138,
                            71,
                            134,
                            212,
                            70,
                            62,
                            172,
                            134,
                            206,
                            177,
                            180,
                            146,
                            172,
                            189,
                            15
                        ],
                        "z_s": [
                            208,
                            43,
                            20,
                            1,
                            26,
                            162,
                            40,
                            9,
                            66,
                            134,
                            126,
                            104,
                            102,
                            12,
                            50,
                            240,
                            94,
                            101,
                            51,
                            44,
                            124,
                            226,
                            219,
                            41,
                            167,
                            143,
                            62,
                            77,
                            157,
                            35,
                            190,
                            8
                        ],
                        "z_x": [
                            22,
                            249,
                            106,
                            65,
                            177,
                            124,
                            195,
                            165,
                            212,
                            66,
                            207,
                            4,
                            169,
                            121,
                            83,
                            133,
                            125,
                            240,
                            201,
                            94,
                            62,
                            73,
                            202,
                            42,
                            185,
                            86,
                            23,
                            215,
                            117,
                            198,
                            206,
                            15
                        ]
                    }
                }
            ],
            "version": 0
        }
    ]
}
```

#### Get Account History
Fetch up to 20 history events for an account on a specific asset.

NOTE: If no asset is provided, default is set to XELIS.

##### Method `get_account_history`

##### Parameters
|        Name        |   Type  | Required |                Note               |
|:------------------:|:-------:|:--------:|:---------------------------------:|
|       address      | Address | Required | Valid address registered on chain |
|        asset       |   Hash  | Optional |           Asset to track          |
| minimum_topoheight | Integer | Optional |   minimum topoheight for history  |
| maximum_topoheight | Integer | Optional | Maximum topoheight for history    |

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "get_account_history",
    "params": {
        "address": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
        "asset": "0000000000000000000000000000000000000000000000000000000000000000"
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": [
        {
            "block_timestamp": 1711665303229,
            "hash": "5c0c4a0d58cf678015af2e10f79119ed6d969dd3d1e98ca4ffefbb4439765658",
            "outgoing": {
                "to": "xet:q622pz5exf5hmw98d73dlqhwjvfwd5g9k0tpuay90ga634c64cgsqczfmvx"
            },
            "topoheight": 22286
        },
        {
            "block_timestamp": 1711487499112,
            "hash": "0000000001088c329a08fce87b8ce49734d1508d91708aa4234ba1548190c75b",
            "mining": {
                "reward": 131491368
            },
            "topoheight": 11203
        },
        {
            "block_timestamp": 1711478790950,
            "hash": "1a16381b252405636b72756a5b4c664a043a8a7ed659f5724085286250fd1f07",
            "outgoing": {
                "to": "xet:t23w8pp90zsj04sp5r3r9sjpz3vq7rxcwhydf5ztlk6efhnusersqvf8sny"
            },
            "topoheight": 10659
        },
    ]
}
```

#### Get Account Assets
Retrieve all assets for an account

##### Method `get_account_assets`

##### Parameters
|   Name  |   Type  | Required |                Note               |
|:-------:|:-------:|:--------:|:---------------------------------:|
| address | Address | Required | Valid address registered on chain |

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "get_account_assets",
    "params": {
        "address": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk"
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": [
        "0000000000000000000000000000000000000000000000000000000000000000"
    ]
}
```

#### Get Accounts
Retrieve a list of available accounts (each account returned had at least one interaction on-chain)
The topoheight range in parameters search for all accounts having a on-chain interaction in this inclusive range.

##### Method `get_accounts`

##### Parameters
|        Name        |   Type  | Required |                        Note                       |
|:------------------:|:-------:|:--------:|:-------------------------------------------------:|
|        skip        | Integer | Optional |             How many accounts to skip             |
|       maximum      | Integer | Optional |     Maximum accounts to fetch (limited to 100)    |
| minimum_topoheight | Integer | Optional | Minimum topoheight for first on-chain interaction |
| maximum_topoheight | Integer | Optional | Maximum topoheight for first on-chain interaction |

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "get_accounts",
	"params": {}
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": [
        "xet:qze954a6tjc2d36zdjuapgu75hpckvtlmfxsymevmqn9ewvpkfasqkrzdql",
        "xet:qf5u2p46jpgqmypqc2xwtq25yek2t7qhnqtdhw5kpfwcrlavs5asq0r83r7",
        "xet:qn7qwdmweculrklzh94p6wvss2yj46vrgmlh8y6fh7rue2fmn9usqr3dq78",
        "xet:q622pz5exf5hmw98d73dlqhwjvfwd5g9k0tpuay90ga634c64cgsqczfmvx",
        "xet:pquh4gagcfmjg42jvx0ywc6a3ph03n6zxynaak9gdv5eh0zdysrqq5mrlz3",
        "xet:pg6nn3q3fqqaw0h7p689ul4a0tz9z76kkj6ys2umexs08flsrvmsqg4eea0",
        "xet:zpt4h6tcqhrdatkyvwmcffmjrqwq00ryy62tzgu7ra5uvhqx0ckqq537j52",
        "xet:z63vuknmvtq2yqj320dgc3vzsvszyxmd2w5j06k539snv9pxlcsqqkkusu9",
        "xet:rqp2gplxyy9duud0jh7kz7kamcujfrcdmqtpgu2tx46fk7yzwa4qqdrgpmn",
        "xet:rr3s2erc8ta6qg29m8ujksxdw26053wev8ja8kaxc62yc0yuceqqqqedmvd",
        "xet:rt7260ltjnnqw9qfpgcackrhwkaeyc8hhtp8vls6ws99g5lq44xsqrjs9r9",
        "xet:rjq4yt20zwcq3tyc7z4kjdp9e2h7q5f29wjht7vht575jtlkkq6qqhlx97s",
        "xet:r6zyz66ppefhxy3mmhvlyeplmp734zpltl270egxd04u02pe2fdsqzmts74",
        "xet:ypyeqzf6wyedmjeqrkplpwqkz0yp3rj4nnepmpvqvjj7gv4ae54qqzfaw3n",
        "xet:yp8rlns8ufqd2ktfs86e0h93e92vy5u8pd9m8652n4fppdtjwsaqquzug5z",
        "xet:xc73lapnp2qar6u804f5px756k9xayfssvrr24k9g7d9vxhx650qqg0euc0",
        "xet:xc7ux9465mxjffuafv2t9lpt5nhquvfsqk7fmaa983vppz3dygmsqql9pts",
        "xet:8jj5v2xqje9r4lmn0xjak7khfx0qr6x5fp629mqszre609m2r9fsqzxm6kq",
        "xet:gpxqv0gs89tmdz8ggv6anhlx94ed6lwmwedl0j4ukepxpwu7sgjqqmvvyn9",
        "xet:g6520vnznu6t6zt8fu85srm7upnlp7tpd5u5tu0urdptmldnwvcqqd539vl"
    ]
}
```

#### Get Blocks Range By TopoHeight
Retrieve a specific range of blocks (up to 20 maximum) based on topoheight.

NOTE: Bounds are inclusive.

##### Method `get_blocks_range_by_topoheight`

##### Parameters
|       Name       |   Type  | Required |                   Note                   |
|:----------------:|:-------:|:--------:|:----------------------------------------:|
| start_topoheight | Integer | Optional | If not set, will retrieve last 20 blocks |
|  end_topoheight  | Integer | Optional |      Must be under current topoheight    |

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "get_blocks_range_by_topoheight",
	"params": {
		"start_topoheight": 0,
		"end_topoheight": 2
	}
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": [
        {
            "block_type": "Sync",
            "cumulative_difficulty": "1",
            "difficulty": "1",
            "extra_nonce": "0000000000000000000000000000000000000000000000000000000000000000",
            "hash": "b715cb0229d13f5f540ae48adf03bc31b094b040b0756a2454631b2ddd899c3a",
            "height": 0,
            "miner": "xet:3tr88r8vvx3qxvgr7gdja5kae784v8htc7ayaj4nxlzgflhchlmqqdmycjf",
            "nonce": 0,
            "reward": 146230061,
            "supply": 146230061,
            "timestamp": 1708339574098,
            "tips": [],
            "topoheight": 0,
            "total_fees": null,
            "total_size_in_bytes": 92,
            "txs_hashes": [],
            "version": 0
        },
        {
            "block_type": "Sync",
            "cumulative_difficulty": "15000001",
            "difficulty": "15000000",
            "extra_nonce": "fa001f6340fbe79e4263ef60610d4f4ce82e69771805772e69735ea9c1df2300",
            "hash": "00000079f04345ac9e14116385dc845a77ad1d4f9f83d8b2b7a84ce3beaa4522",
            "height": 1,
            "miner": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
            "nonce": 2969302,
            "reward": 146230050,
            "supply": 292460111,
            "timestamp": 1711135309926,
            "tips": [
                "b715cb0229d13f5f540ae48adf03bc31b094b040b0756a2454631b2ddd899c3a"
            ],
            "topoheight": 1,
            "total_fees": null,
            "total_size_in_bytes": 124,
            "txs_hashes": [],
            "version": 0
        },
        {
            "block_type": "Sync",
            "cumulative_difficulty": "30000001",
            "difficulty": "15000000",
            "extra_nonce": "aa5c6ccea415e2c39704dedc582ac6ca6a1701a549f5199dffd37e30f93d5900",
            "hash": "000000c09b5ccd8749feb3d27fe72203ddca2f6f44998ab9db977d2724eaf032",
            "height": 2,
            "miner": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
            "nonce": 12047121,
            "reward": 146230038,
            "supply": 438690149,
            "timestamp": 1711135311567,
            "tips": [
                "00000079f04345ac9e14116385dc845a77ad1d4f9f83d8b2b7a84ce3beaa4522"
            ],
            "topoheight": 2,
            "total_fees": null,
            "total_size_in_bytes": 124,
            "txs_hashes": [],
            "version": 0
        }
    ]
}
```

#### Get Blocks Range By Height
Retrieve a specific range of blocks (up to 20 maximum) based on height.

NOTE: Bounds are inclusive.

##### Method `get_blocks_range_by_height`

##### Parameters
|     Name     |   Type  | Required |                   Note                   |
|:------------:|:-------:|:--------:|:----------------------------------------:|
| start_height | Integer | Optional | If not set, will retrieve last 20 blocks |
|  end_height  | Integer | Optional |       Must be under current height       |

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "get_blocks_range_by_height",
	"params": {
		"start_height": 0,
		"end_height": 2
	}
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": [
        {
            "block_type": "Sync",
            "cumulative_difficulty": "1",
            "difficulty": "1",
            "extra_nonce": "0000000000000000000000000000000000000000000000000000000000000000",
            "hash": "b715cb0229d13f5f540ae48adf03bc31b094b040b0756a2454631b2ddd899c3a",
            "height": 0,
            "miner": "xet:3tr88r8vvx3qxvgr7gdja5kae784v8htc7ayaj4nxlzgflhchlmqqdmycjf",
            "nonce": 0,
            "reward": 146230061,
            "supply": 146230061,
            "timestamp": 1708339574098,
            "tips": [],
            "topoheight": 0,
            "total_fees": null,
            "total_size_in_bytes": 92,
            "txs_hashes": [],
            "version": 0
        },
        {
            "block_type": "Sync",
            "cumulative_difficulty": "15000001",
            "difficulty": "15000000",
            "extra_nonce": "fa001f6340fbe79e4263ef60610d4f4ce82e69771805772e69735ea9c1df2300",
            "hash": "00000079f04345ac9e14116385dc845a77ad1d4f9f83d8b2b7a84ce3beaa4522",
            "height": 1,
            "miner": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
            "nonce": 2969302,
            "reward": 146230050,
            "supply": 292460111,
            "timestamp": 1711135309926,
            "tips": [
                "b715cb0229d13f5f540ae48adf03bc31b094b040b0756a2454631b2ddd899c3a"
            ],
            "topoheight": 1,
            "total_fees": null,
            "total_size_in_bytes": 124,
            "txs_hashes": [],
            "version": 0
        },
        {
            "block_type": "Sync",
            "cumulative_difficulty": "30000001",
            "difficulty": "15000000",
            "extra_nonce": "aa5c6ccea415e2c39704dedc582ac6ca6a1701a549f5199dffd37e30f93d5900",
            "hash": "000000c09b5ccd8749feb3d27fe72203ddca2f6f44998ab9db977d2724eaf032",
            "height": 2,
            "miner": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
            "nonce": 12047121,
            "reward": 146230038,
            "supply": 438690149,
            "timestamp": 1711135311567,
            "tips": [
                "00000079f04345ac9e14116385dc845a77ad1d4f9f83d8b2b7a84ce3beaa4522"
            ],
            "topoheight": 2,
            "total_fees": null,
            "total_size_in_bytes": 124,
            "txs_hashes": [],
            "version": 0
        }
    ]
}
```

#### Is TX executed in Block
Verify if a transaction hash is executed in requested block hash.

##### Method `is_tx_executed_in_block`

##### Parameters
|     Name    |   Type  | Required |                  Note                 |
|:-----------:|:-------:|:--------:|:-------------------------------------:|
|   tx_hash   |   Hash  | Required |      Transaction hash to verify       |
|  block_hash |   Hash  | Required |          Expected Block hash          |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "is_tx_executed_in_block",
    "id": 1,
    "params": {
        "tx_hash": "dd693bad09cb03ba0bf9a6fa7b787f918748db869c1463b7fa16e20b498dea88",
		"block_hash": "000000000e4547de9f088734d54d0199605338896a58b7d2d7dea06c1ef35cfc"
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": true
}
```

## Wallet

### JSON-RPC methods

#### Get Version
Retrieve current daemon version

##### Method `get_version`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_version",
	"id": 1
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": "1.7.0"
}
```


#### Get Network
Retrieve network used by the wallet

##### Method `get_network`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_network",
	"id": 1
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": "Testnet"
}
```

#### Get Nonce
Retrieve account nonce saved in wallet

##### Method `get_nonce`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_nonce",
	"id": 1
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": 1
}
```

#### Get TopoHeight
Retrieve daemon topoheight until which the wallet scanned transactions/balances.

##### Method `get_topoheight`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_topoheight",
	"id": 1
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": 69817
}
```

#### Get Address
Retrieve wallet address with or without integrated data in it.
Without parameters set, it returns the normal wallet address.

##### Method `get_address`

##### Parameters
TODO integrated_data

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_address",
	"id": 1,
	"params": {
		"integrated_data": {
			"hello": "world"
		}
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": "xet1qqqsyqgpq45x2mrvduqqzqg9wahhymrysrd48fdl3js2ss2hsu7d6w8rnuymz33fkyc5eth20dxv67g2a66s832qvr"
}
```

#### Split Address
Split address and integrated data in two differents fields.

##### Method `split_address`

##### Parameters
TODO

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "split_address",
	"id": 1,
	"params": {
		"address": "xet1qqqsyqgpq45x2mrvduqqzqg9wahhymrysrd48fdl3js2ss2hsu7d6w8rnuymz33fkyc5eth20dxv67g2a66s832qvr"
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"address": "xet1qqqgpk6n5klceg9gg9tcw0xa8r3e7zd3gc5mzv2v4m48knxd0y9wadg3mdp9t",
		"integrated_data": {
			"hello": "world"
		}
	}
}
```

#### Rescan
Request the wallet to rescan balances and transactions history until the specified topoheight.
When no topoheight is set, it rescan until 0.

**WARNING**: All balances and transactions will be deleted from wallet storage to be up-to-date with the chain of the node connected to.

##### Method `rescan`

##### Parameters
TODO

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "rescan",
	"id": 1,
	"params": {
		"topoheight": 1337
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": true
}
```

#### Get Balance
Get asset balance from wallet.
When no parameter is set, default asset is XELIS.

NOTE: By default, if no balance for the requested asset is found, it will returns 0.
Use `has_balance` to determine if the wallet as an asset balance or not.

##### Method `get_balance`

##### Parameters
TODO

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_balance",
	"id": 1,
	"params": {}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": 8660741
}
```

#### Has Balance
Verify if wallet has the requested asset balance.
When no parameter is set, default asset is XELIS.

##### Method `has_balance`

##### Parameters
TODO

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "has_balance",
	"id": 1,
	"params": {}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": true
}
```

#### Get Tracked Assets
Retrieve all assets that are tracked by the wallet.

##### Method `get_tracked_assets`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_tracked_assets",
	"id": 1
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": [
		"0000000000000000000000000000000000000000000000000000000000000000"
	]
}
```

#### Get Asset Precision
Retrieve the decimals precision for the selected asset.

##### Method `get_asset_precision`

##### Parameters
TODO

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_asset_precision",
	"id": 1,
	"params": {
		"asset": "0000000000000000000000000000000000000000000000000000000000000000"
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": 8
}
```

#### Get Transaction
Get transaction by hash from wallet.

##### Method `get_transaction`

##### Parameters
TODO

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_transaction",
	"id": 1,
	"params": {
		"hash": "c3ea4ce5c78d9c4f00c10cd43ce1f9886e28d23839a356c0f98a6bf107a4c040"
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"fee": 1000,
		"hash": "c3ea4ce5c78d9c4f00c10cd43ce1f9886e28d23839a356c0f98a6bf107a4c040",
		"nonce": 0,
		"outgoing": [
			{
				"amount": 100000,
				"asset": "0000000000000000000000000000000000000000000000000000000000000000",
				"extra_data": null,
				"key": "xet1qqq8ar5gagvjhznhj59l3r4lqhe7edutendy6vd4y7jd59exl6u7xschfuhym"
			}
		],
		"topoheight": 69752
	}
}
```

#### Build Transaction
Build a transaction to be send by the wallet.
It can be broadcasted or not to the network.

**NOTE**: Amount set are in atomic units, for XELIS it would `100000` to represents 1 XELIS because of 5 decimals precision.

##### Method `build_transaction`

##### Parameters
TODO

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "build_transaction",
	"id": 1,
	"params": {
		"transfers": [
			{
				"amount": 1000,
				"asset": "0000000000000000000000000000000000000000000000000000000000000000",
				"to": "xet1qqq8ar5gagvjhznhj59l3r4lqhe7edutendy6vd4y7jd59exl6u7xschfuhym"
			}
		],
		"broadcast": false
	}
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "data": {
            "transfers": [
                {
                    "amount": 1000,
                    "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                    "extra_data": null,
                    "to": "xet1qqq8ar5gagvjhznhj59l3r4lqhe7edutendy6vd4y7jd59exl6u7xschfuhym"
                }
            ]
        },
        "fee": 1000,
        "hash": "6872c06e853fe35a3d936fc7281abc51018706ed36a54135e0dbbbb79a07fc25",
        "nonce": 1,
        "owner": "xet1qqqgpk6n5klceg9gg9tcw0xa8r3e7zd3gc5mzv2v4m48knxd0y9wadg3mdp9t",
        "signature": "3c05e13f43283b75bb2ebae4d513d1a36bb1d86083164a50b03422ce2e8ed6c8446c34f12868df61335fb76e136be9068cb1940abf92690d513553079e6f770d",
        "version": 0
    }
}
```

#### List Transactions
Search transactions based on various parameters.
By default it accepts every TXs.

##### Method `list_transactions`

##### Parameters
|       Name      |   Type  | Required |           Note           |
|:---------------:|:-------:|:--------:|:------------------------:|
|  min_topoheight | Integer | Optional | Start from specific topo |
|  max_topoheight | Integer | Optional |   End at specific topo   |
|     address     |  String | Optional |    Filter with address   |
| accept_incoming | Boolean | Optional |      Filter incoming     |
| accept_outgoing | Boolean | Optional |      Filter outgoing     |
| accept_coinbase | Boolean | Optional |      Filter coinbase     |
|   accept_burn   | Boolean | Optional |        Filter burn       |

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "list_transactions",
	"id": 1,
	"params": {
		"accept_coinbase": true,
		"accept_outgoing": true,
		"accept_incoming": false
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": [
		{
			"coinbase": 146175,
			"hash": "000000077f636b4fc259c41b9ab04a52ceb4b6b0acfb7f5aaf7c6184f2144fcd",
			"topoheight": 4741
		},
		{
			"fee": 1000,
			"hash": "c3ea4ce5c78d9c4f00c10cd43ce1f9886e28d23839a356c0f98a6bf107a4c040",
			"nonce": 0,
			"outgoing": [
				{
					"amount": 100000,
					"asset": "0000000000000000000000000000000000000000000000000000000000000000",
					"extra_data": null,
					"key": "xet1qqq8ar5gagvjhznhj59l3r4lqhe7edutendy6vd4y7jd59exl6u7xschfuhym"
				}
			],
			"topoheight": 69752
		}
	]
}
```

#### Sign Data
Generate a signature for the input data using your wallet key pair.

##### Method `sign_data`

##### Parameters
Parameter value can be anything (object, value, array...)

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "estimate_fees",
	"id": 1,
	"params": {
		"hello": "world"
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": "5bb7a1f33c3c89e968be9f1c343aa15393ec98905976e38087d53595a3411bd0130f9414b7e5fe4e3bcdcad03e0c6d2cbee01c10514289ad3b2b5e3b2fe8fd03"
}
```

#### Estimate Fees
Estimate the minimum required fees for a future transaction.
Returned fees are in atomic units.

##### Method `estimate_fees`

##### Parameters
Paramater value can be anything (object, value, array...)

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "build_transaction",
	"id": 1,
	"params": {
		"transfers": [
			{
				"amount": 1000,
				"asset": "0000000000000000000000000000000000000000000000000000000000000000",
				"to": "xet1qqq8ar5gagvjhznhj59l3r4lqhe7edutendy6vd4y7jd59exl6u7xschfuhym"
			}
		]
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": 10000
}
```