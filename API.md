# API

## Daemon

### JSON-RPC methods

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
		"cumulative_difficulty": 16050593,
		"hash": "0000073b071e04ce4e79b095f3c44f4aefb65f4e70f8a5591c986cb4b688d692",
		"height": 23,
		"miner_tx": {
			"owner": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5",
			"signature": null,
			"variant": "Coinbase"
		},
		"nonce": 1370526,
		"tips": [
			"000002144bb86d9fcbe223aff1f6c2526d0c47eef0b8f7433b3abec22685fb31"
		],
		"topoheight": 23,
		"transactions": [],
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
			"cumulative_difficulty": 16050593,
			"hash": "0000073b071e04ce4e79b095f3c44f4aefb65f4e70f8a5591c986cb4b688d692",
			"height": 23,
			"miner_tx": {
				"owner": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5",
				"signature": null,
				"variant": "Coinbase"
			},
			"nonce": 1370526,
			"tips": [
				"000002144bb86d9fcbe223aff1f6c2526d0c47eef0b8f7433b3abec22685fb31"
			],
			"topoheight": 23,
			"transactions": [],
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
		"cumulative_difficulty": 14125125,
		"hash": "000002144bb86d9fcbe223aff1f6c2526d0c47eef0b8f7433b3abec22685fb31",
		"height": 22,
		"miner_tx": {
			"owner": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5",
			"signature": null,
			"variant": "Coinbase"
		},
		"nonce": 1940650,
		"tips": [
			"000007691f86da1d48f67d56c5a8ea4410ba37628702c629618e2ac7f5234cba"
		],
		"topoheight": 22,
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
		"cumulative_difficulty": 16050593,
		"hash": "0000073b071e04ce4e79b095f3c44f4aefb65f4e70f8a5591c986cb4b688d692",
		"height": 23,
		"miner_tx": {
			"owner": "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5",
			"signature": null,
			"variant": "Coinbase"
		},
		"nonce": 1370526,
		"tips": [
			"000002144bb86d9fcbe223aff1f6c2526d0c47eef0b8f7433b3abec22685fb31"
		],
		"topoheight": 23,
		"transactions": [],
		"txs_hashes": []
	}
}
```

#### Get Account
Retrieve the account based on its address

##### Method `get_account`

##### Parameters
|   Name  |   Type  | Required |                Note               |
|:-------:|:-------:|:--------:|:---------------------------------:|
| address | Address | Required | Valid address registered on chain |

##### Request
```json
{
	"jsonrpc": "2.0",
	"id": 1,
	"method": "get_account",
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
		"balance": 21057003,
		"nonce": 0
	}
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
	"result": 17
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
-  `submit_block`

-  `submit_transaction`

- `get_transaction`

-  `get_mempool`