# API

## Daemon

### JSON-RPC methods

#### Get Height
Retrieve current height of the chain
##### Method `get_height`
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

TODO:
-  `submit_block`

-  `submit_transaction`

-  `p2p_status`

-  `get_mempool`

-  `get_tips`

-  `is_chain_valid`

-  `get_dag_order`
