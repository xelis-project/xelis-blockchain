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
        "native_supply": 24141030101,
        "network": "Testnet",
        "pruned_topoheight": null,
        "stableheight": 27544,
        "top_hash": "00000014adb905b46053363e264975dd32cd0020eaf474fe08c5f492110aa95c",
        "topoheight": 28032,
        "version": "1.4.0"
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

NOTE: `total_fees` field is not `null` when TXs are fetched (`include_txs` is at `true`).

```

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

If no nonce is found for this address and its valid, value start at 0.
Each nonce represents how many TX has been made by this address.

##### Method `get_nonce`

##### Parameters
|   Name  |   Type  | Required |                Note               |
|:-------:|:-------:|:--------:|:---------------------------------:|
| address | Address | Required | Valid address registered on chain |

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
	"result": 17
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
Get all assets available on network

##### Method `get_assets`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "get_assets"
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
		"max_peers": 32,
		"our_topoheight": 23,
		"peer_count": 1,
		"peer_id": 17384099500704996810,
		"tag": null
	}
}
```

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
Fetch a transaction by its hash from daemon

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
			"Transfer": [
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
				"Transfer": [
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
			"nonce": 3,
			"owner": "xel1qyq2z43hcfwwl4pcnx9z5ppcvlhcm7g92ss832rjftdp427wqq7l8nqp5khq3",
			"signature": "9e9fcd6be9b2e968b7d44ae15909e406b827b87f3108e08646b1d5e45754ffe3e166c4eaf26a63b8ddc0ac0668a893c339ed313fb522b46a4e95b8706a2ba005"
		}
	]
}
```

#### Get Transactions
Fetch transactions by theirs hashes from daemon and keep the same order in response

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
				"Transfer": [
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
			"nonce": 2,
			"owner": "xel1qyq2z43hcfwwl4pcnx9z5ppcvlhcm7g92ss832rjftdp427wqq7l8nqp5khq3",
			"signature": "d297ef720d388ff2aaedf6755a1f93b4ac1b55c987da5dc53c19350d8a779d970c7f4cfcc25d2f4ce3f4ef3a77d0f31d15635d221d5a72ef6651dbb7f1810301"
		},
		null
	]
}
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