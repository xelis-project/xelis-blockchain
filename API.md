# API

## Daemon

### JSON-RPC methods

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
        "block_time_target": 15000,
        "difficulty": 310532,
        "height": 9,
        "mempool_size": 0,
        "native_supply": 8773780,
        "stableheight": 1,
        "top_hash": "00000d5f00dc3cf5873f9bd09963a011a2c007b4d1a987b93f5d3bed3d050ef0",
        "topoheight": 9,
        "version": "alpha-0.0.1"
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
		"template": "00000000000000180000000000000000000001845c7a6e000000000000000000eed448813c9c2028d21e029ada21b5a82840b195e70fff8ce7be256afe35d2dc010000073b071e04ce4e79b095f3c44f4aefb65f4e70f8a5591c986cb4b688d69200006c24cdc1c8ee8f028b8cafe7b79a66a0902f26d89dd54eeff80abcf251a9a3bd02"
	}
}
```

#### Get Block At Topo Height
Retrieve a block at a specific topo height

##### Method `get_block_at_topoheight`

##### Parameters
|    Name    |   Type  | Required |                           Note                           |
|:----------:|:-------:|:--------:|:--------------------------------------------------------:|
| topoheight | Integer | Required | Topoheight must be equal or less than current topoheight |

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
		"tips": [
			"000001aa69c15167a192de809eeed112f50ec91e513cfbf7b1674523583acbf9"
		],
		"topoheight": 23,
		"txs_hashes": []
	}
}
```

#### Get Blocks At Height
Retrieve all blocks at a specific height

##### Method `get_blocks_at_height`

##### Parameters
|  Name  |   Type  | Required |                       Note                       |
|:------:|:-------:|:--------:|:------------------------------------------------:|
| height | Integer | Required | Height must be equal or less than current height |

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
			"tips": [
				"000001aa69c15167a192de809eeed112f50ec91e513cfbf7b1674523583acbf9"
			],
			"topoheight": 23,
			"txs_hashes": []
		}
	]
}
```

#### Get Block By Hash
Retrieve a block by its hash

##### Method `get_block_by_hash`

##### Parameters
| Name | Type | Required |                  Note                 |
|:----:|:----:|:--------:|:-------------------------------------:|
| hash | Hash | Required | Valid block Hash present in the chain |

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
		"tips": [
			"000001aa69c15167a192de809eeed112f50ec91e513cfbf7b1674523583acbf9"
		],
		"topoheight": 23,
		"txs_hashes": []
	}
}
```

#### Get Top Block
Retrieve the highest block based on the topological height

##### Method `get_top_block`

##### Parameters
No parameters

##### Request
```json
{
	"jsonrpc": "2.0",
	"method": "get_top_block",
	"id": 1
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
		"tips": [
			"000001aa69c15167a192de809eeed112f50ec91e513cfbf7b1674523583acbf9"
		],
		"topoheight": 23,
		"txs_hashes": []
	}
}
```

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
|   Name  |   Type  | Required |                Note               |
|:-------:|:-------:|:--------:|:---------------------------------:|
| address | Address | Required | Valid address registered on chain |
|  asset  |   Hash  | Required |    Asset ID registered on chain   |

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
		"best_height": 23,
		"max_peers": 32,
		"our_height": 23,
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

TODO:
- `submit_block`

- `submit_transaction`

- `get_transaction`

- `get_mempool`