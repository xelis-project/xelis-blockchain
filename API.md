# API

## Daemon

### Events

This require to use the WebSocket connection.

All events sent by the daemon to be notified in real-time through the WebSocket.

Every events are registered using the following RPC request (example for `new_block` event)

```json
{
	"jsonrpc": "2.0",
	"method": "subscribe",
	"id": 1,
	"params": {
		"notify": "new_block"
	}
}
```

This returns the following response:

```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": true
}
```

If its true, that means the daemon accepted the subscription to the requested event.
If its returning false, that may means you are already subscribed to this event.

To unsubscribe from an event, replace the method name `subscribe` by `unsubscribe`.

**NOTE**: The field `id` used during the subscription of the event is reused for each event fired by the daemon.
This is useful to determine which kind of event it is. You must set a unique `id` value to each event.

#### New Block

When a new block has been accepted and included in the chain by the daemon.

##### Name `new_block`

##### On Event
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "block_type": "Normal",
        "cumulative_difficulty": "9909351292695001",
        "difficulty": "85713090000",
        "event": "new_block",
        "extra_nonce": "cb4a04b8cd2913f0947c323c8a2fe4d3623047f1e8a9f4e5f717aaf6ec5da70e",
        "hash": "0000000008ef82aeb890b919803e19985c430311ddd34aa9b0cb2d40a6dffb87",
        "height": 106173,
        "miner": "xet:4fcjmjxs6dyq7d3xl95m26wzfwrluz2tcqdtfp6fpc7rah2kmqusqdr3c66",
        "nonce": 121282154,
        "reward": 144997766,
        "supply": 15506012755620,
        "timestamp": 1713028338116,
        "tips": [
            "0000000000beaccfbb05ffc3b33536daffa85a90cbbf4761287376a65dcac859"
        ],
        "topoheight": 107219,
        "total_fees": 0,
        "total_size_in_bytes": 124,
        "txs_hashes": [],
        "version": 0
    }
}
```

#### Block Ordered

When a block has been ordered and executed by the DAG order.

##### Name `block_ordered`

##### On Event
```json

```

#### Block Orphaned

When a block was previously executed in the DAG but due to DAG reorg, got rewinded.

##### Name `block_orphaned`

##### On Event
```json

```

#### Stable Height Changed

When the DAG found a new stable height.
This means no new blocks can be added at this height or below.

##### Name `stable_height_changed`

##### On Event
```json

```

#### Transaction Orphaned

When a transaction that was previously executed in the DAG but due to DAG reorg, got rewinded.
If transaction couldn't be added back to the mempool, it is orphaned.

##### Name `transaction_orphaned`

##### On Event
```json

```

#### Transaction Added In Mempool

When a valid transaction is added in the daemon mempool.

##### Name `transaction_added_in_mempool`

##### On Event
```json

```

#### Transaction Executed

When a transaction has been executed by the DAG order.

##### Name `transaction_executed`

##### On Event
```json

```

#### Peer Connected

When a new peer is connected to our daemon and allows to be shared through API.

##### Name `peer_connected`

##### On Event
```json

```

#### Peer Disconnected

When a peer previously connected disconnect from us.

##### Name `peer_disconnected`

##### On Event
```json

```

#### Peer PeerList Updated

When a peer peerlist has been updated.

##### Name `peer_peer_list_updated`

##### On Event
```json

```

#### Peer State Updated

When a peer state has been updated due to a ping packet.

##### Name `peer_state_updated`

##### On Event
```json

```

#### Peer Peer Disconnected

When a peer's peer has disconnected from him and notified us.

##### Name `peer_peer_disconnected`

##### On Event
```json

```

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


#### Is Account Registered
Verify if the account on chain is registered.
This is useful to determine if we should pay additionnal fee or not.

For transactions, it is recommended to verify that the account is already registered in stable height.

##### Method `is_account_registered`

##### Parameters
|       Name       |   Type  | Required |                            Note                           |
|:----------------:|:-------:|:--------:|:---------------------------------------------------------:|
|      address     | Address | Required |               Account address to search for               |
| in_stable_height | Boolean | Required | If registration must be done only in stable height or not |

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "is_account_registered",
	"id": 1,
	"params": {
		"address": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
		"in_stable_height": true
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

#### Get Account Registration TopoHeight
Retrieve the account registration topoheight.

This is like its "first time" doing an action on the chain.

##### Method `get_account_registration_topoheight`

##### Parameters
|   Name  |   Type  | Required |              Note             |
|:-------:|:-------:|:--------:|:-----------------------------:|
| address | Address | Required | Account address to search for |

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_account_registration_topoheight",
	"id": 1,
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
	"result": 57
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

#### Get Mempool Cache
Retrieve the stored mempool cache for a requested address.

This includes nonce range (min/max) used, final output balances expected per asset used, and all transactions hashes related to this account.

##### Method `get_mempool_cache`

##### Parameters
|        Name        |   Type  | Required |                Note               |
|:------------------:|:-------:|:--------:|:---------------------------------:|
|       address      | Address | Required | Valid address registered on chain |

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "get_mempool_cache",
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
        "balances": {
            "0000000000000000000000000000000000000000000000000000000000000000": {
                "commitment": [
                    244,
                    202,
                    158,
                    128,
                    207,
                    119,
                    30,
                    237,
                    144,
                    243,
                    146,
                    197,
                    136,
                    223,
                    240,
                    34,
                    50,
                    232,
                    217,
                    160,
                    125,
                    120,
                    125,
                    135,
                    65,
                    192,
                    213,
                    220,
                    116,
                    235,
                    120,
                    122
                ],
                "handle": [
                    122,
                    13,
                    209,
                    236,
                    109,
                    230,
                    21,
                    124,
                    148,
                    244,
                    88,
                    0,
                    117,
                    99,
                    188,
                    49,
                    90,
                    214,
                    225,
                    239,
                    229,
                    183,
                    230,
                    142,
                    10,
                    56,
                    82,
                    96,
                    70,
                    232,
                    110,
                    104
                ]
            }
        },
        "max": 2829,
        "min": 2825,
        "txs": [
            "78148376846b2a8ce1f3b248a65bd5ed4e22ebb6ac98514377a4ea47d08cb2a8",
            "d8b1d090eea0812e99c1384137240773079dcd79a4fbfe4d78d395288ff1823a",
            "c82cba8d5472dc2c1d6d38dd30ee3726d32638001e0c54903905c4f0c814ae6a",
            "2f4bf1ea35fc8ef33961a465ac0cf0dc2c6010daaee423ed06ffdcdf2b9c0d6d",
            "f1c8425a7f3bea049dbdcaf905ef447d43ca41763740b54d2958baac15d0d3ae"
        ]
    }
}
```

## Wallet

### Events

This require to use the WebSocket connection.

All events sent by the wallet to be notified in real-time through the WebSocket.

Every events are registered using the following RPC request (example for `new_topo_height` event)

```json
{
	"jsonrpc": "2.0",
	"method": "subscribe",
	"id": 1,
	"params": {
		"notify": "new_topo_height"
	}
}
```

This returns the following response:

```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": true
}
```

If its true, that means the daemon accepted the subscription to the requested event.
If its returning false, that may means you are already subscribed to this event.

To unsubscribe from an event, replace the method name `subscribe` by `unsubscribe`.

**NOTE**: The field `id` used during the request `subscribe` of the event is reused for each event fired by the wallet.
This is useful to determine which kind of event it is. You must set a unique `id` value to each event.

#### New TopoHeight

When a new topoheight is detected by the wallet.
It may be lower than the previous one, based on how the DAG reacts

##### Name `new_topo_height`

##### On Event
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"event": "new_topo_height",
		"topoheight": 57
	}
}
```

#### New Asset

When a new asset is detected by the wallet.

##### Name `new_asset`

##### On Event
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"event": "new_asset",
		"asset": "0000000000000000000000000000000000000000000000000000000000000000",
		"topoheight": 57,
		"decimals": 8
	}
}
```

#### New Transaction

When a new transaction is detected by the wallet.

##### Name `new_transaction`

##### On Event
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "event": "new_transaction",
        "hash": "b84adead7fe1c0499f92826c08f4f67f8e5133981465b7b9cf0b34649e11f1e0",
        "outgoing": {
            "fee": 125000,
            "nonce": 3530,
            "transfers": [
                {
                    "amount": 100000000,
                    "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                    "destination": "xet:6elhr5zvx5wl2ljjl82l6yxxxqkxjvcr38kcq9qef3nurm2r2arsq89z4ll",
                    "extra_data": null
                }
            ]
        },
        "topoheight": 107853
    }
}
```

#### Balance Changed

When an asset balance has been updated.

**NOTE**: Balance is in atomic units.

##### Name `balance_changed`

##### On Event
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"event": "balance_changed",
		"asset": "0000000000000000000000000000000000000000000000000000000000000000",
		"balance": 178800000000
	}
}
```

#### Rescan

When a rescan has been triggered by the wallet.
The event response contains the topoheight until which the wallet rescanned and deleted the transactions.

##### Name `rescan`

##### On Event
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"event": "rescan",
		"start_topoheight": 50
	}
}
```

#### Online

When the wallet is in online mode (connected to a daemon).

##### Name `online`

##### On Event
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "event": "online"
    }
}
```

#### Offline

When the wallet is in offline mode (not connected to any daemon).

##### Name `offline`

##### On Event
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "event": "offline"
    }
}
```

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
	"result": 1462
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

NOTE: Integrated data can be useful for services like Exchanges to identify a user transaction
by integrating an ID (or anything else) in the address (like PaymentID for Monero).

It is not mandatory and support any data formatted in JSON up to 1 KB in serialized format.

##### Method `get_address`

##### Parameters
|       Name      | Type | Required |                       Note                       |
|:---------------:|:----:|:--------:|:------------------------------------------------:|
| integrated_data | JSON | Optional | Add data that will be integrated in the transfer |

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_address",
	"id": 1,
	"params": {
		"integrated_data": {
			"hello": "world",
			"words": [
				"Hello",
				"World",
				"from",
				"XELIS"
			],
			"items": {
				"sword": 5
			}
		}
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32szqsrqyzkjar9d4esyqgpq4ehwmmjvsqqypgpq45x2mrvduqqzpthdaexceqpq4mk7unywvqsgqqpq4yx2mrvduqqzp2hdaexceqqqyzxvun0d5qqzp2cg4xyj5ct5udlg"
}
```

#### Split Address
Split address and integrated data in two differents fields.

##### Method `split_address`

##### Parameters
|   Name  |   Type  | Required |                                 Note                                 |
|:-------:|:-------:|:--------:|:--------------------------------------------------------------------:|
| address | Address | Required | Address to split in two parts: original address, and integrated data |

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "split_address",
	"id": 1,
	"params": {
		"address": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32szqsrqyzkjar9d4esyqgpq4ehwmmjvsqqypgpq45x2mrvduqqzpthdaexceqpq4mk7unywvqsgqqpq4yx2mrvduqqzp2hdaexceqqqyzxvun0d5qqzp2cg4xyj5ct5udlg"
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"address": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
		"integrated_data": {
			"hello": "world",
			"items": {
				"sword": 5
			},
			"words": [
				"Hello",
				"World",
				"from",
				"XELIS"
			]
		}
	}
}
```

#### Rescan
Request the wallet to rescan balances and transactions history until the specified topoheight.
When no topoheight is set, it rescan until topoheight 0.

**WARNING**: All balances and transactions will be deleted from wallet storage to be up-to-date with the chain of the node connected to.

##### Method `rescan`

##### Parameters
|       Name       |   Type  | Required |                     Note                     |
|:----------------:|:-------:|:--------:|:--------------------------------------------:|
| until_topoheight | Integer | Optional | Until which topoheight wallet have to rescan |

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

Balance is returned in atomic units.

##### Method `get_balance`

##### Parameters
|  Name | Type | Required |                 Note                 |
|:-----:|:----:|:--------:|:------------------------------------:|
| asset | Hash | Optional | Asset to use to retrieve the balance |


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
|  Name | Type | Required |     Note     |
|:-----:|:----:|:--------:|:------------:|
| asset | Hash | Optional | Asset to use |

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

This is useful to format correctly the atomic units coins to human readable.

##### Method `get_asset_precision`

##### Parameters
|  Name | Type | Required |     Note     |
|:-----:|:----:|:--------:|:------------:|
| asset | Hash | Required | Asset to use |

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
| Name | Type | Required |                   Note                   |
|:----:|:----:|:--------:|:----------------------------------------:|
| hash | Hash | Required | Transaction hash to retrieve from wallet |


##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_transaction",
	"id": 1,
	"params": {
		"hash": "6e4bbd77b305fb68e2cc7576b4846d2db3617e3cbc2eb851cb2ae69b879e9d0f"
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"hash": "6e4bbd77b305fb68e2cc7576b4846d2db3617e3cbc2eb851cb2ae69b879e9d0f",
		"outgoing": {
			"fee": 25000,
			"nonce": 1458,
			"transfers": [
				{
					"amount": 1,
					"asset": "0000000000000000000000000000000000000000000000000000000000000000",
					"destination": "xet:t23w8pp90zsj04sp5r3r9sjpz3vq7rxcwhydf5ztlk6efhnusersqvf8sny",
					"extra_data": null
				}
			]
		},
		"topoheight": 11982
	}
}
```

#### Build Transaction
Build a transaction to be send by the wallet.
It can be broadcasted or not to the network.

**NOTE**: Amount set are in atomic units, for XELIS it would be `100000000` to represents 1 XELIS because of 8 decimals precision.

##### Method `build_transaction`

##### Parameters
|        Name       |       Type      | Required |                         Note                         |
|:-----------------:|:---------------:|:--------:|:----------------------------------------------------:|
|        fee        |    FeeBuilder   | Optional |        Set an exact fee value or a multiplier        |
|     broadcast     |     Boolean     | Optional |    Broadcast TX to daemon. By default set to true    |
|     tx_as_hex     |     Boolean     | Optional | Serialize TX to hexadecimal. By default set to false |
| transfers OR burn | TransactionType | Required |              Transaction Type parameter              |

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
				"destination": "xet:t23w8pp90zsj04sp5r3r9sjpz3vq7rxcwhydf5ztlk6efhnusersqvf8sny"
			}
		],
		"broadcast": true,
		"tx_as_hex": false,
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
					"asset": "0000000000000000000000000000000000000000000000000000000000000000",
					"commitment": [
						238,
						30,
						130,
						122,
						67,
						194,
						32,
						246,
						200,
						80,
						46,
						141,
						222,
						187,
						208,
						43,
						46,
						241,
						237,
						203,
						213,
						205,
						144,
						205,
						106,
						244,
						151,
						18,
						159,
						206,
						225,
						27
					],
					"ct_validity_proof": {
						"Y_0": [
							34,
							161,
							9,
							177,
							40,
							33,
							77,
							242,
							77,
							112,
							209,
							50,
							59,
							17,
							40,
							73,
							99,
							137,
							151,
							99,
							21,
							36,
							139,
							98,
							139,
							33,
							36,
							78,
							13,
							17,
							86,
							4
						],
						"Y_1": [
							246,
							227,
							225,
							213,
							98,
							38,
							179,
							199,
							194,
							26,
							105,
							255,
							182,
							252,
							126,
							214,
							206,
							82,
							121,
							33,
							249,
							175,
							95,
							155,
							97,
							173,
							192,
							26,
							58,
							124,
							129,
							123
						],
						"z_r": [
							132,
							174,
							99,
							68,
							255,
							98,
							219,
							211,
							53,
							25,
							171,
							58,
							186,
							21,
							19,
							48,
							70,
							10,
							247,
							124,
							34,
							175,
							32,
							199,
							39,
							33,
							244,
							190,
							111,
							50,
							226,
							12
						],
						"z_x": [
							149,
							199,
							235,
							9,
							160,
							202,
							252,
							137,
							113,
							231,
							100,
							13,
							164,
							127,
							101,
							153,
							198,
							0,
							234,
							125,
							20,
							245,
							19,
							156,
							107,
							152,
							222,
							25,
							129,
							123,
							129,
							1
						]
					},
					"destination": [
						90,
						162,
						227,
						132,
						37,
						120,
						161,
						39,
						214,
						1,
						160,
						226,
						50,
						194,
						65,
						20,
						88,
						15,
						12,
						216,
						117,
						200,
						212,
						208,
						75,
						253,
						181,
						148,
						222,
						124,
						134,
						71
					],
					"extra_data": null,
					"receiver_handle": [
						70,
						92,
						163,
						71,
						45,
						166,
						111,
						10,
						214,
						112,
						178,
						2,
						248,
						12,
						74,
						222,
						198,
						149,
						232,
						169,
						122,
						187,
						32,
						80,
						209,
						254,
						33,
						215,
						53,
						36,
						64,
						49
					],
					"sender_handle": [
						16,
						154,
						78,
						139,
						148,
						124,
						170,
						82,
						177,
						145,
						156,
						250,
						214,
						21,
						224,
						39,
						168,
						154,
						248,
						173,
						246,
						203,
						66,
						233,
						71,
						177,
						41,
						217,
						173,
						119,
						160,
						15
					]
				}
			]
		},
		"fee": 25000,
		"hash": "f8bd7c15e3a94085f8130cc67e1fefd89192cdd208b68b10e1cc6e1a83afe5d6",
		"nonce": 1463,
		"range_proof": [
			22,
			154,
			245,
			17,
			22,
			208,
			99,
			27,
			169,
			112,
			109,
			130,
			77,
			251,
			72,
			194,
			68,
			177,
			205,
			118,
			202,
			20,
			66,
			168,
			230,
			82,
			224,
			178,
			133,
			230,
			73,
			42,
			162,
			133,
			127,
			92,
			247,
			143,
			146,
			34,
			19,
			71,
			117,
			36,
			166,
			127,
			179,
			225,
			192,
			214,
			141,
			98,
			248,
			164,
			177,
			235,
			43,
			182,
			149,
			226,
			248,
			228,
			208,
			53,
			166,
			208,
			75,
			155,
			20,
			215,
			12,
			110,
			142,
			132,
			104,
			74,
			219,
			10,
			217,
			184,
			194,
			132,
			22,
			219,
			40,
			38,
			169,
			88,
			59,
			88,
			44,
			63,
			129,
			207,
			123,
			34,
			66,
			118,
			176,
			170,
			41,
			117,
			86,
			129,
			107,
			27,
			73,
			84,
			226,
			206,
			244,
			220,
			108,
			180,
			247,
			202,
			149,
			134,
			5,
			69,
			178,
			101,
			96,
			71,
			101,
			198,
			77,
			106,
			236,
			217,
			137,
			137,
			104,
			1,
			224,
			19,
			235,
			233,
			44,
			87,
			228,
			163,
			138,
			206,
			92,
			134,
			236,
			65,
			165,
			12,
			111,
			110,
			215,
			80,
			21,
			240,
			3,
			59,
			85,
			4,
			36,
			103,
			129,
			196,
			218,
			71,
			143,
			227,
			201,
			249,
			69,
			165,
			110,
			219,
			41,
			137,
			155,
			229,
			133,
			186,
			64,
			150,
			196,
			33,
			43,
			146,
			66,
			95,
			228,
			204,
			89,
			5,
			207,
			65,
			4,
			86,
			219,
			33,
			223,
			8,
			126,
			235,
			206,
			190,
			49,
			211,
			124,
			28,
			81,
			75,
			115,
			205,
			86,
			31,
			99,
			50,
			20,
			146,
			27,
			237,
			57,
			63,
			206,
			4,
			252,
			238,
			201,
			65,
			147,
			132,
			12,
			172,
			249,
			11,
			55,
			92,
			65,
			35,
			92,
			171,
			252,
			86,
			99,
			95,
			65,
			100,
			246,
			247,
			23,
			219,
			83,
			140,
			60,
			194,
			142,
			86,
			226,
			32,
			66,
			234,
			17,
			118,
			206,
			20,
			65,
			169,
			213,
			119,
			150,
			203,
			74,
			39,
			132,
			154,
			113,
			163,
			11,
			122,
			174,
			233,
			128,
			2,
			176,
			214,
			59,
			185,
			128,
			36,
			218,
			59,
			36,
			169,
			84,
			240,
			142,
			21,
			46,
			184,
			255,
			132,
			51,
			79,
			255,
			11,
			130,
			113,
			228,
			211,
			181,
			154,
			206,
			48,
			174,
			178,
			27,
			127,
			210,
			107,
			121,
			56,
			46,
			6,
			72,
			33,
			26,
			74,
			236,
			120,
			234,
			152,
			68,
			230,
			11,
			246,
			167,
			48,
			183,
			145,
			132,
			172,
			55,
			44,
			184,
			213,
			215,
			239,
			200,
			195,
			180,
			71,
			172,
			60,
			28,
			96,
			156,
			78,
			71,
			138,
			187,
			236,
			245,
			159,
			221,
			219,
			180,
			102,
			81,
			1,
			115,
			167,
			1,
			221,
			224,
			80,
			149,
			56,
			19,
			242,
			85,
			141,
			61,
			28,
			72,
			92,
			138,
			116,
			194,
			31,
			252,
			122,
			107,
			212,
			54,
			19,
			60,
			82,
			25,
			202,
			246,
			75,
			211,
			146,
			92,
			71,
			254,
			159,
			129,
			165,
			54,
			210,
			116,
			94,
			209,
			240,
			112,
			19,
			28,
			208,
			80,
			141,
			56,
			122,
			138,
			152,
			204,
			230,
			27,
			171,
			155,
			180,
			112,
			142,
			164,
			144,
			228,
			131,
			190,
			96,
			234,
			195,
			98,
			119,
			69,
			142,
			209,
			214,
			186,
			119,
			108,
			13,
			167,
			66,
			79,
			194,
			200,
			136,
			241,
			38,
			66,
			73,
			243,
			24,
			86,
			84,
			70,
			141,
			31,
			52,
			68,
			112,
			207,
			243,
			119,
			108,
			15,
			80,
			113,
			245,
			0,
			101,
			202,
			56,
			58,
			11,
			104,
			86,
			29,
			29,
			159,
			187,
			75,
			98,
			192,
			82,
			231,
			19,
			145,
			81,
			18,
			44,
			18,
			27,
			208,
			230,
			103,
			164,
			50,
			12,
			115,
			114,
			53,
			109,
			210,
			5,
			158,
			77,
			255,
			79,
			249,
			131,
			193,
			122,
			85,
			209,
			198,
			69,
			168,
			185,
			132,
			18,
			115,
			249,
			182,
			151,
			14,
			90,
			118,
			174,
			16,
			205,
			203,
			44,
			123,
			44,
			140,
			191,
			1,
			52,
			243,
			154,
			17,
			186,
			167,
			8,
			226,
			162,
			215,
			97,
			215,
			33,
			80,
			103,
			205,
			97,
			187,
			40,
			46,
			237,
			166,
			81,
			21,
			154,
			60,
			24,
			37,
			10,
			42,
			153,
			62,
			249,
			156,
			196,
			80,
			197,
			10,
			29,
			191,
			7,
			15,
			136,
			38,
			25,
			171,
			130,
			46,
			53,
			6,
			179,
			3,
			145,
			40,
			222,
			163,
			182,
			33,
			6,
			38,
			61,
			34,
			23,
			83,
			209,
			148,
			107,
			120,
			108,
			73,
			214,
			224,
			166,
			119,
			189,
			213,
			18,
			215,
			197,
			2,
			166,
			71,
			167,
			242,
			199,
			28,
			3,
			115,
			210,
			37,
			89,
			62,
			46,
			18,
			174,
			181,
			14,
			90,
			74,
			152,
			73,
			102,
			45,
			155,
			9,
			143,
			134,
			20,
			90,
			167,
			66,
			182,
			1,
			175,
			164,
			133,
			148,
			94,
			107,
			15,
			243,
			77,
			113,
			163,
			95,
			48,
			57,
			129,
			209,
			29,
			122,
			222,
			5,
			2,
			32,
			206,
			75,
			228,
			144,
			68,
			232,
			121,
			51,
			121,
			195,
			143,
			18,
			10,
			145,
			54,
			245,
			214,
			77,
			166,
			27,
			44,
			2,
			243,
			13,
			48,
			110,
			17,
			195,
			80,
			81,
			244,
			71,
			64,
			99,
			173,
			26,
			170,
			44,
			209,
			181,
			153,
			209,
			172,
			62,
			214,
			12,
			134,
			184,
			174,
			183,
			175,
			1,
			70,
			4
		],
		"reference": {
			"hash": "000000000c1845717b0820bd32b57d1928af1b4ae80bdec71b73ab8d60f9eb74",
			"topoheight": 25770
		},
		"signature": "6731b973cb5c06c7e4e6fa9135acf4ea7c1b2e2bd0a63e41110aad3b39174204067bf7de87f3c3e2042cbcf6899a307e480d80e7c7f96638eabbf1fe6cfded09",
		"source": [
			214,
			122,
			209,
			57,
			52,
			51,
			123,
			133,
			195,
			73,
			133,
			73,
			28,
			67,
			115,
			134,
			201,
			93,
			224,
			217,
			112,
			23,
			19,
			16,
			136,
			114,
			76,
			251,
			237,
			235,
			220,
			85
		],
		"source_commitments": [
			{
				"asset": "0000000000000000000000000000000000000000000000000000000000000000",
				"commitment": [
					52,
					95,
					172,
					42,
					119,
					170,
					29,
					153,
					85,
					23,
					13,
					26,
					36,
					222,
					194,
					109,
					96,
					244,
					155,
					201,
					205,
					213,
					116,
					191,
					230,
					215,
					173,
					208,
					191,
					1,
					106,
					68
				],
				"proof": {
					"Y_0": [
						28,
						207,
						136,
						127,
						215,
						121,
						118,
						217,
						44,
						139,
						232,
						122,
						84,
						126,
						16,
						61,
						165,
						22,
						126,
						190,
						74,
						156,
						153,
						231,
						65,
						146,
						81,
						115,
						141,
						195,
						182,
						67
					],
					"Y_1": [
						254,
						133,
						105,
						79,
						0,
						96,
						176,
						204,
						205,
						119,
						165,
						52,
						240,
						129,
						8,
						193,
						54,
						137,
						213,
						145,
						25,
						113,
						100,
						80,
						249,
						35,
						79,
						206,
						228,
						248,
						221,
						47
					],
					"Y_2": [
						232,
						233,
						143,
						111,
						74,
						214,
						200,
						95,
						19,
						223,
						120,
						103,
						12,
						146,
						107,
						226,
						4,
						59,
						183,
						93,
						210,
						97,
						4,
						129,
						108,
						10,
						50,
						181,
						79,
						0,
						247,
						21
					],
					"z_r": [
						137,
						168,
						98,
						243,
						57,
						141,
						18,
						165,
						185,
						78,
						29,
						176,
						134,
						205,
						226,
						140,
						144,
						60,
						242,
						58,
						241,
						53,
						23,
						137,
						118,
						236,
						221,
						220,
						237,
						97,
						115,
						6
					],
					"z_s": [
						240,
						97,
						50,
						134,
						174,
						27,
						207,
						100,
						147,
						139,
						180,
						62,
						221,
						59,
						227,
						43,
						246,
						94,
						88,
						22,
						235,
						132,
						68,
						161,
						36,
						64,
						19,
						236,
						28,
						211,
						62,
						3
					],
					"z_x": [
						193,
						64,
						130,
						188,
						169,
						56,
						213,
						79,
						187,
						77,
						229,
						110,
						54,
						171,
						40,
						6,
						217,
						124,
						86,
						255,
						39,
						147,
						70,
						35,
						13,
						44,
						107,
						19,
						12,
						11,
						203,
						12
					]
				}
			}
		],
		"tx_as_hex": "00d67ad13934337b85c34985491c437386c95de0d97017131088724cfbedebdc55010100000000000000000000000000000000000000000000000000000000000000005aa2e3842578a127d601a0e232c24114580f0cd875c8d4d04bfdb594de7c864700ee1e827a43c220f6c8502e8ddebbd02b2ef1edcbd5cd90cd6af497129fcee11b109a4e8b947caa52b1919cfad615e027a89af8adf6cb42e947b129d9ad77a00f465ca3472da66f0ad670b202f80c4adec695e8a97abb2050d1fe21d73524403122a109b128214df24d70d1323b1128496389976315248b628b21244e0d115604f6e3e1d56226b3c7c21a69ffb6fc7ed6ce527921f9af5f9b61adc01a3a7c817b84ae6344ff62dbd33519ab3aba151330460af77c22af20c72721f4be6f32e20c95c7eb09a0cafc8971e7640da47f6599c600ea7d14f5139c6b98de19817b810100000000000061a800000000000005b701345fac2a77aa1d9955170d1a24dec26d60f49bc9cdd574bfe6d7add0bf016a441ccf887fd77976d92c8be87a547e103da5167ebe4a9c99e7419251738dc3b643fe85694f0060b0cccd77a534f08108c13689d59119716450f9234fcee4f8dd2fe8e98f6f4ad6c85f13df78670c926be2043bb75dd26104816c0a32b54f00f715f0613286ae1bcf64938bb43edd3be32bf65e5816eb8444a1244013ec1cd33e03c14082bca938d54fbb4de56e36ab2806d97c56ff279346230d2c6b130c0bcb0c89a862f3398d12a5b94e1db086cde28c903cf23af135178976ecdddced617306000000000000000000000000000000000000000000000000000000000000000002e0169af51116d0631ba9706d824dfb48c244b1cd76ca1442a8e652e0b285e6492aa2857f5cf78f922213477524a67fb3e1c0d68d62f8a4b1eb2bb695e2f8e4d035a6d04b9b14d70c6e8e84684adb0ad9b8c28416db2826a9583b582c3f81cf7b224276b0aa297556816b1b4954e2cef4dc6cb4f7ca95860545b265604765c64d6aecd989896801e013ebe92c57e4a38ace5c86ec41a50c6f6ed75015f0033b5504246781c4da478fe3c9f945a56edb29899be585ba4096c4212b92425fe4cc5905cf410456db21df087eebcebe31d37c1c514b73cd561f633214921bed393fce04fceec94193840cacf90b375c41235cabfc56635f4164f6f717db538c3cc28e56e22042ea1176ce1441a9d57796cb4a27849a71a30b7aaee98002b0d63bb98024da3b24a954f08e152eb8ff84334fff0b8271e4d3b59ace30aeb21b7fd26b79382e0648211a4aec78ea9844e60bf6a730b79184ac372cb8d5d7efc8c3b447ac3c1c609c4e478abbecf59fdddbb466510173a701dde050953813f2558d3d1c485c8a74c21ffc7a6bd436133c5219caf64bd3925c47fe9f81a536d2745ed1f070131cd0508d387a8a98cce61bab9bb4708ea490e483be60eac36277458ed1d6ba776c0da7424fc2c888f1264249f3185654468d1f344470cff3776c0f5071f50065ca383a0b68561d1d9fbb4b62c052e7139151122c121bd0e667a4320c7372356dd2059e4dff4ff983c17a55d1c645a8b9841273f9b6970e5a76ae10cdcb2c7b2c8cbf0134f39a11baa708e2a2d761d7215067cd61bb282eeda651159a3c18250a2a993ef99cc450c50a1dbf070f882619ab822e3506b3039128dea3b62106263d221753d1946b786c49d6e0a677bdd512d7c502a647a7f2c71c0373d225593e2e12aeb50e5a4a9849662d9b098f86145aa742b601afa485945e6b0ff34d71a35f303981d11d7ade050220ce4be49044e8793379c38f120a9136f5d64da61b2c02f30d306e11c35051f4474063ad1aaa2cd1b599d1ac3ed60c86b8aeb7af014604000000000c1845717b0820bd32b57d1928af1b4ae80bdec71b73ab8d60f9eb7400000000000064aa6731b973cb5c06c7e4e6fa9135acf4ea7c1b2e2bd0a63e41110aad3b39174204067bf7de87f3c3e2042cbcf6899a307e480d80e7c7f96638eabbf1fe6cfded09",
		"version": 0
	}
}
```

#### List Transactions
Search transactions based on various parameters.
By default it accepts every TXs.

For `address` param, it is compared to the sender if it's an incoming TX, and to destination address for outgoing TX.

##### Method `list_transactions`

##### Parameters
|       Name      |   Type  | Required |              Note             |
|:---------------:|:-------:|:--------:|:-----------------------------:|
|  min_topoheight | Integer | Optional |    Start from specific topo   |
|  max_topoheight | Integer | Optional |      End at specific topo     |
|     address     |  String | Optional |      Filter with address      |
| accept_incoming | Boolean | Optional |        Filter incoming        |
| accept_outgoing | Boolean | Optional |        Filter outgoing        |
| accept_coinbase | Boolean | Optional |        Filter coinbase        |
|   accept_burn   | Boolean | Optional |          Filter burn          |
|      query      |  Query  | Optional | Allow to filter on extra data |

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "list_transactions",
	"id": 1,
	"params": {
		"accept_coinbase": false,
		"accept_outgoing": false,
		"accept_incoming": true
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
			"hash": "dd693bad09cb03ba0bf9a6fa7b787f918748db869c1463b7fa16e20b498dea88",
			"incoming": {
				"from": "xet:dn3x9yspqtuzhm874m267a3g9fkdztr3uztyx534wdx3p9rkdspqqhpss5d",
				"transfers": [
					{
						"amount": 100000000,
						"asset": "0000000000000000000000000000000000000000000000000000000000000000",
						"extra_data": null
					}
				]
			},
			"topoheight": 10657
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
|        Name       |       Type      | Required |             Note             |
|:-----------------:|:---------------:|:--------:|:----------------------------:|
| transfers OR burn | TransactionType | Required |  Transaction Type parameter  |


##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "estimate_fees",
	"id": 1,
	"params": {
		"transfers": [
			{
				"amount": 1000,
				"asset": "0000000000000000000000000000000000000000000000000000000000000000",
				"destination": "xet:t23w8pp90zsj04sp5r3r9sjpz3vq7rxcwhydf5ztlk6efhnusersqvf8sny"
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
	"result": 25000
}
```