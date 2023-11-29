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
		"average_block_time": 11812,
		"block_reward": 865869,
		"block_time_target": 15000,
		"difficulty": 35533666,
		"height": 27552,
		"mempool_size": 0,
		"circulating_supply": 24141030101,
		"maximum_supply": 18400000000000,
		"network": "Testnet",
		"pruned_topoheight": null,
		"stableheight": 27544,
		"top_block_hash": "00000014adb905b46053363e264975dd32cd0020eaf474fe08c5f492110aa95c",
		"topoheight": 28032,
		"version": "1.4.0"
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
		"address": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5"
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"difficulty": 1699032,
		"height": 113,
		"template": "00000000000000180000000000000000000001845c7a6e000000000000000000eed448813c9c2028d21e029ada21b5a82840b195e70fff8ce7be256afe35d2dc010000073b071e04ce4e79b095f3c44f4aefb65f4e70f8a5591c986cb4b688d69200006c24cdc1c8ee8f028b8cafe7b79a66a0902f26d89dd54eeff80abcf251a9a3bd02"
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
		"topoheight": 23
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
		"cumulative_difficulty": 76173573,
		"difficulty": 7902701,
		"extra_nonce": "cac46116afea8a00d2d9f9ea10d20a3a5bc9c2ae7f47201f24450e3e3fe5ec09",
		"hash": "0000019fab49717777dba2ee23f46f9f27706a9c5103a5550cf429f9c786b1e4",
		"height": 23,
		"miner": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5",
		"nonce": 183776,
		"reward": 877360,
		"supply": 42113762,
		"timestamp": 1674226439134,
		"tips": [
			"000001aa69c15167a192de809eeed112f50ec91e513cfbf7b1674523583acbf9"
		],
		"topoheight": 23,
		"total_fees": null,
		"total_size_in_bytes": 131,
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
			"block_type": "Normal",
			"cumulative_difficulty": 76173573,
			"difficulty": 7902701,
			"extra_nonce": "cac46116afea8a00d2d9f9ea10d20a3a5bc9c2ae7f47201f24450e3e3fe5ec09",
			"hash": "0000019fab49717777dba2ee23f46f9f27706a9c5103a5550cf429f9c786b1e4",
			"height": 23,
			"miner": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5",
			"nonce": 183776,
			"reward": 877360,
			"supply": 42113762,
			"timestamp": 1674226439134,
			"tips": [
				"000001aa69c15167a192de809eeed112f50ec91e513cfbf7b1674523583acbf9"
			],
			"topoheight": 23,
			"total_fees": null,
			"total_size_in_bytes": 131,
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
		"hash": "000002144bb86d9fcbe223aff1f6c2526d0c47eef0b8f7433b3abec22685fb31"
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
		"cumulative_difficulty": 76173573,
		"difficulty": 7902701,
		"extra_nonce": "cac46116afea8a00d2d9f9ea10d20a3a5bc9c2ae7f47201f24450e3e3fe5ec09",
		"hash": "0000019fab49717777dba2ee23f46f9f27706a9c5103a5550cf429f9c786b1e4",
		"height": 23,
		"miner": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5",
		"nonce": 183776,
		"reward": 877360,
		"supply": 42113762,
		"timestamp": 1674226439134,
		"tips": [
			"000001aa69c15167a192de809eeed112f50ec91e513cfbf7b1674523583acbf9"
		],
		"topoheight": 23,
		"total_fees": null,
		"total_size_in_bytes": 131,
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
	"params": {}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"block_type": "Normal",
		"cumulative_difficulty": 76173573,
		"difficulty": 7902701,
		"extra_nonce": "cac46116afea8a00d2d9f9ea10d20a3a5bc9c2ae7f47201f24450e3e3fe5ec09",
		"hash": "0000019fab49717777dba2ee23f46f9f27706a9c5103a5550cf429f9c786b1e4",
		"height": 23,
		"miner": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5",
		"nonce": 183776,
		"reward": 877360,
		"supply": 42113762,
		"timestamp": 1674226439134,
		"tips": [
			"000001aa69c15167a192de809eeed112f50ec91e513cfbf7b1674523583acbf9"
		],
		"topoheight": 23,
		"total_fees": null,
		"total_size_in_bytes": 131,
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
		"address": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5"
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"nonce": 6216,
		"previous_topoheight": 454254,
		"topoheight": 454352
	}
}
```

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
		"address": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5"
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

#### Get Last Balance
Get up-to-date asset's balance for a specific address

NOTE: Balance is returned in atomic units

##### Method `get_last_balance`

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
	"result": {
		"address": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5",
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
		"balance": {
			"balance": 37726957,
			"previous_topoheight": 41
		},
		"topoheight": 42
	}
}
```

#### Get Balance At TopoHeight
Get asset's balance from address at exact topoheight

NOTE: Balance is returned in atomic units

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
		"address": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5",
		"asset": "0000000000000000000000000000000000000000000000000000000000000000",
		"topoheight": 30
	}
}
```

##### Response
```json
{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"balance": 27198582,
		"previous_topoheight": 29
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
			"decimals": 5,
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
		"decimals": 5,
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
Retrieve Tips (highest blocks from blockDAG) from chain 

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
	"result": [
		{
			"addr": "255.255.255.255:2125",
			"cumulative_difficulty": 15429361306853,
			"height": 488400,
			"id": 8185485348476293826,
			"last_ping": 1697559833,
			"pruned_topoheight": 488000,
			"tag": null,
			"top_block_hash": "0000006a04cccb82b11e68468be07e4a1da46de8b47dc41d66b2300ff494f80e",
			"topoheight": 489291,
			"version": "1.5.0"
		},
		{
			"addr": "192.168.55.43:2125",
			"cumulative_difficulty": 15429361306853,
			"height": 488400,
			"id": 2491091954271682078,
			"last_ping": 1697559834,
			"pruned_topoheight": 489200,
			"tag": null,
			"top_block_hash": "0000006a04cccb82b11e68468be07e4a1da46de8b47dc41d66b2300ff494f80e",
			"topoheight": 489291,
			"version": "1.5.0"
		}
	]
}
```
NOTE: Addresses displayed in this example are not real one and were replaced for privacy reasons.

#### Get DAG Order
Retrieve the whole DAG order (all blocks hash ordered by topoheight).
If no parameters are set, it will retrieve the last 64 blocks hash ordered descending.
Maximum of 64 blocks hash only per request.

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
		"83f6a544d69ca4852e8e2b6bc98b3a1602509e8feea7d744f6a60deeef51c663",
		"00005c58f5c2a506b2a24e79967db009d3b2be13f15e657d6352b1aa59cdfedc",
		"00002d138fbab2bc14958061edbc4a0c272d1ac27d60ef4a72e2f5ac9d1a2b0a",
		...
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

NOTE: result returned in `data` field can changes based on the TransactionType (transfer, burn, Smart Contract call, Deploy Code..)

##### Method `get_transaction`

##### Parameters
| Name | Type | Required |            Note           |
|:----:|:----:|:--------:|:-------------------------:|
| hash | Hash | Required | Transaction hash to fetch |

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 0,
	"method": "get_transaction",
	"params": {
		"hash": "136e9c19f8e9afd814e1e5f819914dca8fc0df01b68c5744bcfba0ab224dc0c2"
	}
}
```

##### Response
```json
{
	"id": 0,
	"jsonrpc": "2.0",
	"result": {
		"hash": "136e9c19f8e9afd814e1e5f819914dca8fc0df01b68c5744bcfba0ab224dc0c2",
		"blocks": [
			"0000073b071e04ce4e79b095f3c44f4aefb65f4e70f8a5591c986cb4b688d692"
		],
		"executed_in_block": "0000073b071e04ce4e79b095f3c44f4aefb65f4e70f8a5591c986cb4b688d692",
		"data": {
			"transfers": [
				{
					"amount": 15000,
					"asset": "0000000000000000000000000000000000000000000000000000000000000000",
					"extra_data": null,
					"to": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5"
				}
			]
		},
		"version": 0,
		"fee": 1000,
		"in_mempool": false,
		"nonce": 2,
		"owner": "xel1qyq2z43hcfwwl4pcnx9z5ppcvlhcm7g92ss832rjftdp427wqq7l8nqp5khq3",
		"signature": "d297ef720d388ff2aaedf6755a1f93b4ac1b55c987da5dc53c19350d8a779d970c7f4cfcc25d2f4ce3f4ef3a77d0f31d15635d221d5a72ef6651dbb7f1810301"
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
	"id": 0,
	"method": "get_mempool"
}
```

##### Response
```json
{
	"id": 0,
	"jsonrpc": "2.0",
	"result": [
		{
			"hash": "136e9c19f8e9afd814e1e5f819914dca8fc0df01b68c5744bcfba0ab224dc0c2",
			"blocks": null,
			"executed_in_block": null,
			"data": {
				"transfers": [
					{
						"amount": 1500,
						"asset": "0000000000000000000000000000000000000000000000000000000000000000",
						"extra_data": null,
						"to": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5"
					}
				]
			},
			"version": 0,
			"fee": 1000,
			"in_mempool": true,
			"nonce": 3,
			"owner": "xel1qyq2z43hcfwwl4pcnx9z5ppcvlhcm7g92ss832rjftdp427wqq7l8nqp5khq3",
			"signature": "9e9fcd6be9b2e968b7d44ae15909e406b827b87f3108e08646b1d5e45754ffe3e166c4eaf26a63b8ddc0ac0668a893c339ed313fb522b46a4e95b8706a2ba005"
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
	"id": 0,
	"method": "get_transactions",
	"params": {
		"tx_hashes": [
			"136e9c19f8e9afd814e1e5f819914dca8fc0df01b68c5744bcfba0ab224dc0c2",
			"136e9c19f8e9afd814e1e5f819914dca8fc0df01b68c5744bcfba0ab224dc0c3"
		]
	}
}
```

##### Response
```json
{
	"id": 0,
	"jsonrpc": "2.0",
	"result": [
		{
			"hash": "136e9c19f8e9afd814e1e5f819914dca8fc0df01b68c5744bcfba0ab224dc0c2",
			"blocks": [
				"0000073b071e04ce4e79b095f3c44f4aefb65f4e70f8a5591c986cb4b688d692"
			],
			"executed_in_block": "0000073b071e04ce4e79b095f3c44f4aefb65f4e70f8a5591c986cb4b688d692",
			"data": {
				"transfers": [
					{
						"amount": 15000,
						"asset": "0000000000000000000000000000000000000000000000000000000000000000",
						"extra_data": null,
						"to": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5"
					}
				]
			},
			"version": 0,
			"fee": 1000,
			"in_mempool": false,
			"nonce": 2,
			"owner": "xel1qyq2z43hcfwwl4pcnx9z5ppcvlhcm7g92ss832rjftdp427wqq7l8nqp5khq3",
			"signature": "d297ef720d388ff2aaedf6755a1f93b4ac1b55c987da5dc53c19350d8a779d970c7f4cfcc25d2f4ce3f4ef3a77d0f31d15635d221d5a72ef6651dbb7f1810301"
		},
		null
	]
}
```

#### Get Account History
Fetch up to 20 history events for an account on a specific asset

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
		"address": "xet1qqqyvh9vgkcurtj2la0e4jspnfsq7vkaqm863zcfdnej92xg4mpzz3suf96k4"
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
			"block_timestamp": 1697492997128,
			"hash": "0000006f160df7d7aaa5d519f341136ae95fce1324280546070fecd8efe93751",
			"mining": {
				"reward": 117059
			},
			"topoheight": 485818
		},
		{
			"block_timestamp": 1697492967931,
			"hash": "0000001f62cc170349de2475a7f2338513f5340481c73af9e94c35aa2805d9cf",
			"mining": {
				"reward": 117059
			},
			"topoheight": 485817
		}
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
	"id": 1,
	"jsonrpc": "2.0",
	"result": [
		"0000000000000000000000000000000000000000000000000000000000000000"
	]
}
```

##### Response
```json

```

#### Submit Block
Submit a block to the daemon

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

#### Get Blocks Range By TopoHeight
Retrieve a specific range of blocks (up to 20 maximum) based on topoheight

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
			"cumulative_difficulty": 1,
			"difficulty": 1,
			"extra_nonce": "0000000000000000000000000000000000000000000000000000000000000000",
			"hash": "55a162b8e0e137bb6a8de9f4c4b214fb60bcd2df15ec32fdd8f06759b863f06e",
			"height": 0,
			"miner": "xel1qqqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680gtl9ky3",
			"nonce": 0,
			"reward": 877380,
			"supply": 877380,
			"timestamp": 1678215431432,
			"tips": [],
			"topoheight": 0,
			"total_fees": null,
			"total_size_in_bytes": 99,
			"txs_hashes": [],
			"version": 0
		},
		{
			"block_type": "Sync",
			"cumulative_difficulty": 150001,
			"difficulty": 150000,
			"extra_nonce": "e9a96f6130943e4ce3cbd6d4999efa1ca28020be6119f3da77dbcc837731600e",
			"hash": "000011152d66bfe7a2b1d2e18a09a94c1d1593ae8ddeafcfc8f1b8c2b03b7995",
			"height": 1,
			"miner": "xel1qqqd2jtz9f2u3z6uznpx8mqdkh6llt3yn3eg3a5tpsfn8jcsthufg5q08670u",
			"nonce": 3837,
			"reward": 877379,
			"supply": 1754759,
			"timestamp": 1678215668838,
			"tips": [
				"55a162b8e0e137bb6a8de9f4c4b214fb60bcd2df15ec32fdd8f06759b863f06e"
			],
			"topoheight": 1,
			"total_fees": null,
			"total_size_in_bytes": 131,
			"txs_hashes": [],
			"version": 0
		},
		{
			"block_type": "Sync",
			"cumulative_difficulty": 300001,
			"difficulty": 150000,
			"extra_nonce": "f7c22d4f517c384493fa271304b885d1f092ab969a87e901fe9245ad0ca4490d",
			"hash": "0000631d920e582069e47149adc53dfe8bb009163c94715d33e81e71b7a8dca3",
			"height": 2,
			"miner": "xel1qqqd2jtz9f2u3z6uznpx8mqdkh6llt3yn3eg3a5tpsfn8jcsthufg5q08670u",
			"nonce": 1113,
			"reward": 877379,
			"supply": 2632138,
			"timestamp": 1678215668843,
			"tips": [
				"000011152d66bfe7a2b1d2e18a09a94c1d1593ae8ddeafcfc8f1b8c2b03b7995"
			],
			"topoheight": 2,
			"total_fees": null,
			"total_size_in_bytes": 131,
			"txs_hashes": [],
			"version": 0
		}
	]
}
```

#### Get Blocks Range By Height
Retrieve a specific range of blocks (up to 20 maximum) based on height

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
			"cumulative_difficulty": 1,
			"difficulty": 1,
			"extra_nonce": "0000000000000000000000000000000000000000000000000000000000000000",
			"hash": "55a162b8e0e137bb6a8de9f4c4b214fb60bcd2df15ec32fdd8f06759b863f06e",
			"height": 0,
			"miner": "xel1qqqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680gtl9ky3",
			"nonce": 0,
			"reward": 877380,
			"supply": 877380,
			"timestamp": 1678215431432,
			"tips": [],
			"topoheight": 0,
			"total_fees": null,
			"total_size_in_bytes": 99,
			"txs_hashes": [],
			"version": 0
		},
		{
			"block_type": "Sync",
			"cumulative_difficulty": 150001,
			"difficulty": 150000,
			"extra_nonce": "e9a96f6130943e4ce3cbd6d4999efa1ca28020be6119f3da77dbcc837731600e",
			"hash": "000011152d66bfe7a2b1d2e18a09a94c1d1593ae8ddeafcfc8f1b8c2b03b7995",
			"height": 1,
			"miner": "xel1qqqd2jtz9f2u3z6uznpx8mqdkh6llt3yn3eg3a5tpsfn8jcsthufg5q08670u",
			"nonce": 3837,
			"reward": 877379,
			"supply": 1754759,
			"timestamp": 1678215668838,
			"tips": [
				"55a162b8e0e137bb6a8de9f4c4b214fb60bcd2df15ec32fdd8f06759b863f06e"
			],
			"topoheight": 1,
			"total_fees": null,
			"total_size_in_bytes": 131,
			"txs_hashes": [],
			"version": 0
		},
		{
			"block_type": "Sync",
			"cumulative_difficulty": 300001,
			"difficulty": 150000,
			"extra_nonce": "f7c22d4f517c384493fa271304b885d1f092ab969a87e901fe9245ad0ca4490d",
			"hash": "0000631d920e582069e47149adc53dfe8bb009163c94715d33e81e71b7a8dca3",
			"height": 2,
			"miner": "xel1qqqd2jtz9f2u3z6uznpx8mqdkh6llt3yn3eg3a5tpsfn8jcsthufg5q08670u",
			"nonce": 1113,
			"reward": 877379,
			"supply": 2632138,
			"timestamp": 1678215668843,
			"tips": [
				"000011152d66bfe7a2b1d2e18a09a94c1d1593ae8ddeafcfc8f1b8c2b03b7995"
			],
			"topoheight": 2,
			"total_fees": null,
			"total_size_in_bytes": 131,
			"txs_hashes": [],
			"version": 0
		}
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
		"xet1qqq9rrdy6s2zy4yavp59094jzlm66n33vy0datvv900yls8pugvyvmqn46pvl",
		"xet1qqqgpk6n5klceg9gg9tcw0xa8r3e7zd3gc5mzv2v4m48knxd0y9wadg3mdp9t",
		"xet1qqqvpwf9qprl6hzysg0zycm3y56ygys32wukxnl7yezqc7ydudy3azcxq6nwv",
		"xet1qqqvltq9dsmvdsvapr6y0742sv477766g9vpvp2expe5v7x7fadvftc9h2vyw",
		"xet1qqqd9ur03xahtts6q00t8z8ya2gxm39qx43ljz32vmv8p7j9ccxn6zccrfnxp",
		"xet1qqqd2jtz9f2u3z6uznpx8mqdkh6llt3yn3eg3a5tpsfn8jcsthufg5qmwwl2j"
	]
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

#### Get Balance
Get asset balance from wallet.
When no parameter is set, default asset is XELIS.

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

##### Method `get_version`

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