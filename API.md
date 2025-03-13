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
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "block_hash": "e42555732f8ca3a55bf97cbb8d63c73c0e8db8b376f60f4794871d468ffe83fc",
        "block_type": "Normal",
        "event": "block_ordered",
        "topoheight": 641917
    }
}
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
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "event": "stable_height_changed",
        "new_stable_height": 611815,
        "previous_stable_height": 611814
    }
}
```

#### Transaction Orphaned

When a transaction that was previously executed in the DAG but due to DAG reorg, got rewinded.
If transaction couldn't be added back to the mempool, it is orphaned.

##### Name `transaction_orphaned`

##### On Event
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "blocks": null,
        "data": {
            "transfers": [
                {
                    "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                    "commitment": [...],
                    "ct_validity_proof": {
                        "Y_0": [...],
                        "Y_1": [...],
                        "z_r": [...],
                        "z_x": [...]
                    },
                    "destination": "xel:qcd39a5u8cscztamjuyr7hdj6hh2wh9nrmhp86ljx2sz6t99ndjqqm7wxj8",
                    "extra_data": [...],
                    "receiver_handle": [...],
                    "sender_handle": [...]
                }
            ]
        },
        "event": "transaction_orphaned",
        "executed_in_block": null,
        "fee": 25000,
        "first_seen": 1723502900,
        "hash": "4951a4d10b8921c8e08d3c380993305a1e4706cbba606e2e79ffdfc06c54eb5f",
        "in_mempool": false,
        "nonce": 46056,
        "range_proof": [...],
        "reference": {
            "hash": "547ef0b63e8b6b26b299e8764614e439a4106a22418ade7f8b0280da405ca5b2",
            "topoheight": 641930
        },
        "signature": "9c0b4d7db7221e5866ad11ee495113b56b77360a5782b53ba189afb120b2a004678facbdb167cd9db0dd7d376caed2f24af781f2bae247b43779e54107e5f500",
        "size": 1517,
        "source": "xel:ntpjg269f0efkvft8rckyqd0dwq480jphngy0fujxal7ng6qmfxqqnp3r5l",
        "source_commitments": [
            {
                "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                "commitment": [...],
                "proof": {
                    "Y_0": [...],
                    "Y_1": [...],
                    "Y_2": [...],
                    "z_r": [...],
                    "z_s": [...],
                    "z_x": [...]
                }
            }
        ],
        "version": 0
    }
}
```

#### Transaction Added In Mempool

When a valid transaction is added in the daemon mempool.

##### Name `transaction_added_in_mempool`

##### On Event
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "blocks": null,
        "data": {
            "transfers": [
                {
                    "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                    "commitment": [...],
                    "ct_validity_proof": {
                        "Y_0": [...],
                        "Y_1": [...],
                        "z_r": [...],
                        "z_x": [...]
                    },
                    "destination": "xel:qcd39a5u8cscztamjuyr7hdj6hh2wh9nrmhp86ljx2sz6t99ndjqqm7wxj8",
                    "extra_data": [...],
                    "receiver_handle": [...],
                    "sender_handle": [...]
                }
            ]
        },
        "event": "transaction_added_in_mempool",
        "executed_in_block": null,
        "fee": 25000,
        "first_seen": 1723502900,
        "hash": "4951a4d10b8921c8e08d3c380993305a1e4706cbba606e2e79ffdfc06c54eb5f",
        "in_mempool": true,
        "nonce": 46056,
        "range_proof": [...],
        "reference": {
            "hash": "547ef0b63e8b6b26b299e8764614e439a4106a22418ade7f8b0280da405ca5b2",
            "topoheight": 641930
        },
        "signature": "9c0b4d7db7221e5866ad11ee495113b56b77360a5782b53ba189afb120b2a004678facbdb167cd9db0dd7d376caed2f24af781f2bae247b43779e54107e5f500",
        "size": 1517,
        "source": "xel:ntpjg269f0efkvft8rckyqd0dwq480jphngy0fujxal7ng6qmfxqqnp3r5l",
        "source_commitments": [
            {
                "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                "commitment": [...],
                "proof": {
                    "Y_0": [...],
                    "Y_1": [...],
                    "Y_2": [...],
                    "z_r": [...],
                    "z_s": [...],
                    "z_x": [...]
                }
            }
        ],
        "version": 0
    }
}
```

#### Transaction Executed

When a transaction has been executed by the DAG order.

##### Name `transaction_executed`

##### On Event
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "block_hash": "f51d9df594e8222a51d060469478bd8f0c73cf67dde47d8f22eb215f633692a6",
        "event": "transaction_executed",
        "topoheight": 641928,
        "tx_hash": "591e28f8e03e234804fe51f6beef3553698f31015288f93a088f42430bbc0130"
    }
}
```

#### Peer Connected

When a new peer is connected to our daemon and allows to be shared through API.

##### Name `peer_connected`

##### On Event
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "addr": "127.0.0.1:9999",
        "bytes_recv": 224,
        "bytes_sent": 200,
        "connected_on": 1723503355,
        "cumulative_difficulty": "195612980025169136041",
        "event": "peer_connected",
        "height": 583755,
        "id": 19831114311557978,
        "last_ping": 0,
        "local_port": 2125,
        "peers": {},
        "pruned_topoheight": null,
        "tag": null,
        "top_block_hash": "14e037f9bcf2ef932b51fffdacdb0e40f5c13cbc8c213fad108f6f1c7508be6e",
        "topoheight": 612269,
        "version": "1.13.3-55810cc"
    }
}
```

#### Peer Disconnected

When a peer previously connected disconnect from us.

##### Name `peer_disconnected`

##### On Event
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "addr": "127.0.0.1:9999",
        "bytes_recv": 224,
        "bytes_sent": 200,
        "connected_on": 1723503355,
        "cumulative_difficulty": "195612980025169136041",
        "event": "peer_disconnected",
        "height": 583755,
        "id": 19831114311557978,
        "last_ping": 0,
        "local_port": 2125,
        "peers": {},
        "pruned_topoheight": null,
        "tag": null,
        "top_block_hash": "14e037f9bcf2ef932b51fffdacdb0e40f5c13cbc8c213fad108f6f1c7508be6e",
        "topoheight": 612269,
        "version": "1.13.3-55810cc"
    }
}
```

#### Peer PeerList Updated

When a peer peerlist has been updated.

##### Name `peer_peer_list_updated`

##### On Event
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "event": "peer_peer_list_updated",
        "peer_id": 7542674138406502028,
        "peerlist": [
            "1.1.1.1:2125"
        ]
    }
}
```

#### Peer State Updated

When a peer state has been updated due to a ping packet.

##### Name `peer_state_updated`

##### On Event
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "addr": "0.0.0.0:35202",
        "bytes_recv": 20227736,
        "bytes_sent": 23927245,
        "connected_on": 1722433223,
        "cumulative_difficulty": "195614728296525524836",
        "event": "peer_state_updated",
        "height": 611867,
        "id": 7542674138406502028,
        "last_ping": 1723503479,
        "local_port": 2125,
        "peers": {
            "0.0.0.0:2125": "Out",
        },
        "pruned_topoheight": 449592,
        "tag": null,
        "top_block_hash": "284dc3a7be770bf7b630df83d614aebbddb6a6e69b4a6c33b8cd42860aa13d7d",
        "topoheight": 641967,
        "version": "1.13.2-0027ba5"
    }
}
```

#### Peer Peer Disconnected

When a peer's peer has disconnected from him and notified us.

##### Name `peer_peer_disconnected`

##### On Event
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "event": "peer_peer_disconnected",
        "peer_addr": "1.1.1.1:2125",
        "peer_id": 7542674138406502028
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
        "miner_reward": 1313813232,
        "dev_reward": 14597924,
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

#### Get Pruned Topo Height
Retrieve the pruned topoheight if the node has a pruned chain.
Otherwise, returns `null` as value.

##### Method `get_pruned_topoheight`

##### Parameters
No parameters

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_pruned_topoheight",
    "id": 1
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": null
}
```

#### Get Stable Height
Retrieve current stable height of the chain.

##### Method `get_stable_height`

##### Parameters
No parameters

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_stable_height",
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

#### Get Stable TopoHeight
Retrieve current stable topoheight of the chain.

##### Method `get_stable_topoheight`

##### Parameters
No parameters

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_stable_topoheight",
    "id": 1
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": 18
}
```

#### Get Difficulty
Retrieve current difficulty and associated network hashrate.

##### Method `get_difficulty`

##### Parameters
No parameters

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_difficulty",
    "id": 1
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "difficulty": "79746345000",
        "hashrate": "5316423000",
        "hashrate_formatted": "5.32 GH/s"
    }
}
```

#### Validate Address
Validate a wallet address by accepting or not integrated address.

##### Method `validate_address`

##### Parameters
|       Name       |   Type  | Required |                         Note                        |
|:----------------:|:-------:|:--------:|:---------------------------------------------------:|
|      address     | Address | Required |               wallet address to verify              |
| allow_integrated | Boolean | Optional | Allow integrated addresses. By default set to false |

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "validate_address",
    "params": {
        "address": "xel:vs3mfyywt0fjys0rgslue7mm4wr23xdgejsjk0ld7f2kxng4d4nqqnkdufz",
        "allow_integrated": false
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "is_integrated": false,
        "is_valid": true
    }
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

#### Extract Key From Address
Extract public key from a wallet address

##### Method `extract_key_from_address`

##### Parameters
|    Name   |   Type  | Required |                                         Note                                         |
|:---------:|:-------:|:--------:|:------------------------------------------------------------------------------------:|
|  address  | Address | Required |                               wallet address to verify                               |
|  as_hex   | Boolean | Optional | Returns Public Key as hexadecimal. By default set to false and returns a byte array. |

NOTE: If `as_hex` is `false`, the response result will contains a field named `bytes` instead of `hex`.

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "extract_key_from_address",
    "params": {
        "address": "xel:vs3mfyywt0fjys0rgslue7mm4wr23xdgejsjk0ld7f2kxng4d4nqqnkdufz",
        "as_hex": true
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "hex": "6423b4908e5bd32241e3443fccfb7bab86a899a8cca12b3fedf255634d156d66"
    }
}
```

#### Make Integrated Address
Create an integrated address using a wallet address and data to include.

NOTE: Integrated data can be useful for services like Exchanges to identify a user transaction
by integrating an ID (or anything else) in the address (like PaymentID for Monero).

It is not mandatory and support any data formatted in JSON up to 1 KB in serialized format.

##### Method `make_integrated_address`

##### Parameters
|       Name      |   Type  | Required |                       Note                       |
|:---------------:|:-------:|:--------:|:------------------------------------------------:|
|     address     | Address | Required | Wallet address to use for the integrated address |
| integrated_data |   JSON  | Required |           Any data type in JSON format           |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "make_integrated_address",
    "id": 1,
    "params": {
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

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": "xel:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32szqsrqyzkjar9d4esyqgpq4ehwmmjvsqqypgpq45x2mrvduqqzpthdaexceqpq4mk7unywvqsgqqpq4yx2mrvduqqzp2hdaexceqqqyzxvun0d5qqzp2cg4xyj5ct5udlg"
}
```

#### Get Block Template
Retrieve the block template (Block Header) for PoW work.

Block Header can be serialized/deserialized using following order on byte array:
- 1 byte for version
- 8 bytes for height (u64) big endian format
- 8 bytes for timestamp (u64) big endian format
- 8 bytes for nonce (u64) big endian format
- 32 bytes for extra nonce (this space is free and can be used to spread more the work or write anything)
- 1 byte for tips count
- 32 bytes per hash (count of elements is based on previous byte)
- 2 bytes for txs hashes count (u16) big endian format
- 32 bytes per hash (count of elements is based on previous value)
- 32 bytes for miner public key

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

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "difficulty": "15000",
        "height": 45,
        "template": "00000000000000002d0000018f1cbd697000000000000000000eded85557e887b45989a727b6786e1bd250de65042d9381822fa73d01d2c4ff01d3a0154853dbb01dc28c9102e9d94bea355b8ee0d82c3e078ac80841445e86520000d67ad13934337b85c34985491c437386c95de0d97017131088724cfbedebdc55",
        "topoheight": 44,
        "algorithm": "xel/v1"
    }
}
```

#### Get Miner Work
Get a miner work based on a block template set in parameter.
It is working the same as GetWork Server

A `MinerWork` struct is created from the block header work hash which represent the immutable part.

For the mutable part that can be updated by the miner we have the following field:
- timestamp (u64) big endian format
- nonce (u64) big endian format
- miner key (32 bytes)
- extra nonce (32 bytes)

NOTE: `topoheight` field is only the current node topoheight, it is included for visual only.

Due to DAG, you are not mining on a topoheight (which is set later dynamically by DAG order) but on a height.

##### Method `get_miner_work`

##### Parameters
|   Name   |      Type     | Required |                               Note                              |
|:--------:|:-------------:|:--------:|:---------------------------------------------------------------:|
| template | BlockTemplate | Required |     Block Template from which the MinerWork will be created     |
|  address |    Address    | Optional | Miner address for rewards. By default use address from template |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_miner_work",
    "id": 1,
    "params": {
        "template": "010000000000000054000001903764c5a70000000000000000f9ad5aa02ac0f78cad0f7c7f45c0af76c7908c2af490f4c23a32c96b8a336cc1019a687b66ed4e0bde3aea9f0d621a0df6cd751275748dccdd3c61578964ee602c00007e97ae5c4541acf3a43bd5789beda45586e28c427333373f96c2dc23fca46753",
        "address": "xet:06t6uhz9gxk08fpm64ufhmdy2krw9rzzwvenw0ukctwz8l9yvafsqdltctp"
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "algorithm": "xel/v2",
        "difficulty": "107445",
        "height": 84,
        "miner_work": "e306a56d779b2cc9dc3b117eda5e02804c49a7ca3f2075b1c2a4ea870c92c0df000001903764c5a70000000000000000f9ad5aa02ac0f78cad0f7c7f45c0af76c7908c2af490f4c23a32c96b8a336cc17e97ae5c4541acf3a43bd5789beda45586e28c427333373f96c2dc23fca46753",
        "topoheight": 83
    }
}
```

#### Submit Block
Submit a block header in hexadecimal format to the daemon.

**NOTE**: Parameter `miner_work` is optional has it is also supported to be directly applied on `block_template`.

##### Method `submit_block`

##### Parameters
|      Name      |  Type  | Required |            Note          |
|:--------------:|:------:|:--------:|:------------------------:|
| block_template | String | Required |   Block in hex format    |
|   miner_work   | String | Optional | Miner work in hex format |

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 0,
    "method": "submit_block",
    "params": {
        "block_template": "00000000000000002d0000018f1cbd697000000000000000000eded85557e887b45989a727b6786e1bd250de65042d9381822fa73d01d2c4ff01d3a0154853dbb01dc28c9102e9d94bea355b8ee0d82c3e078ac80841445e86520000d67ad13934337b85c34985491c437386c95de0d97017131088724cfbedebdc55"
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
        "reward": 146229454,
        "miner_reward": 131606509,
        "dev_reward": 14622945,
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
            "reward": 146229454,
            "miner_reward": 131606509,
            "dev_reward": 14622945,
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
        "reward": 146229454,
        "miner_reward": 131606509,
        "dev_reward": 14622945,
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
        "reward": 146229454,
        "miner_reward": 131606509,
        "dev_reward": 14622945,
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
                "commitment": [...],
                "handle": [...]
            },
            "output_balance": null,
            "previous_topoheight": 11982
        }
    }
}
```
NOTE: `balance_type` values are: `input`, `output` or `both`.
This determine what changes happened on the encrypted balance.

#### Get Stable Balance
Same as `get_balance`, Get up-to-date asset's balance for a specific address.

The only difference is its searching first for:
- the latest balance with a output included (even in in unstable height)
- If not found, the latest available balance in stable height.

This difference is made so that ZK Proofs are less likely to be invalidated.
The reference (block hash, topoheight) is also included in the response.

##### Method `get_stable_balance`

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
    "method": "get_stable_balance",
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
        "stable_topoheight": 21337,
        "stable_block_hash": "3a4584239039a9024e205c18a2f81b9f5d1eaa8a8e22a3e384aeada1124590f3",
        "version": {
            "balance_type": "input",
            "final_balance": {
                "commitment": [...],
                "handle": [...]
            },
            "output_balance": null,
            "previous_topoheight": 11982
        }
    }
}
```

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
            "commitment": [...],
            "handle": [...]
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
    "result": {
        "0000000000000000000000000000000000000000000000000000000000000000": {
            "contract": null,
            "decimals": 8,
            "max_supply": 1840000000000000,
            "name": "XELIS"
        }
    }
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

#### Count Contracts
Counts the number of contracts saved on disk

##### Method `count_contracts`

##### Parameters
No parameters

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "count_contracts"
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
|  data | String | Required | Transaction in HEX format |

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
                    "commitment": [...],
                    "ct_validity_proof": {
                        "Y_0": [...],
                        "Y_1": [...],
                        "z_r": [...],
                        "z_x": [...]
                    },
                    "destination": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
                    "extra_data": null,
                    "receiver_handle": [...],
                    "sender_handle": [...]
                }
            ]
        },
        "executed_in_block": "000000000e4547de9f088734d54d0199605338896a58b7d2d7dea06c1ef35cfc",
        "fee": 25000,
        "hash": "dd693bad09cb03ba0bf9a6fa7b787f918748db869c1463b7fa16e20b498dea88",
        "in_mempool": false,
        "nonce": 4,
        "range_proof": [...],
        "reference": {
            "hash": "0000000007068e3656a526e04280b0f975bf9d9d1e156ea0677970abe6cceafa",
            "topoheight": 10656
        },
        "signature": "37a6b9bf89e524a7481b6427c2d5d026a212b230410cedbe46fedb615edbb107288663e24567485d4802659f0f03ca5e6b27e7ea35541d07b2c71ed2ad94f300",
        "source": "xet:dn3x9yspqtuzhm874m267a3g9fkdztr3uztyx534wdx3p9rkdspqqhpss5d",
        "source_commitments": [
            {
                "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                "commitment": [...],
                "proof": {
                    "Y_0": [...],
                    "Y_1": [...],
                    "Y_2": [...],
                    "z_r": [...],
                    "z_s": [...],
                    "z_x": [...]
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
                        "commitment": [...],
                        "ct_validity_proof": {
                            "Y_0": [...],
                            "Y_1": [...],
                            "z_r": [...],
                            "z_x": [...]
                        },
                        "destination": "xet:q622pz5exf5hmw98d73dlqhwjvfwd5g9k0tpuay90ga634c64cgsqczfmvx",
                        "extra_data": null,
                        "receiver_handle": [...],
                        "sender_handle": [...]
                    }
                ]
            },
            "executed_in_block": null,
            "fee": 25000,
            "first_seen": 1711665284,
            "hash": "5c0c4a0d58cf678015af2e10f79119ed6d969dd3d1e98ca4ffefbb4439765658",
            "in_mempool": true,
            "nonce": 1461,
            "range_proof": [...],
            "reference": {
                "hash": "000000000bc1070fda6b86eb31fbf3f15e89be9c10928415b2254fcab96088a8",
                "topoheight": 22285
            },
            "signature": "b3362192f0ae054964279fc67e55f3dc2cde9c6d6d0c98b00a1c31672d6a330aa1cdad4929662d68fa0a830349da429eef342fef43125b97fea87c16fa2f6607",
            "source": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
            "source_commitments": [
                {
                    "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                    "commitment": [...],
                    "proof": {
                        "Y_0": [...],
                        "Y_1": [...],
                        "Y_2": [...],
                        "z_r": [...],
                        "z_s": [...],
                        "z_x": [...]
                    }
                }
            ],
            "version": 0
        }
    ]
}
```


#### Get Transaction Executor
Fetch the block hash where the transaction was executed and its topoheight.

##### Method `get_transaction_executor`

##### Parameters
| Name | Type | Required |            Note           |
|:----:|:----:|:--------:|:-------------------------:|
| hash | Hash | Required | Transaction hash to fetch |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_transaction_executor",
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
        "block_topoheight": 22285,
        "block_hash": "000000000bc1070fda6b86eb31fbf3f15e89be9c10928415b2254fcab96088a8",
        "block_timestamp": 1711665284
    }
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
                        "commitment": [...],
                        "ct_validity_proof": {
                            "Y_0": [...],
                            "Y_1": [...],
                            "z_r": [...],
                            "z_x": [...]
                        },
                        "destination": "xet:q622pz5exf5hmw98d73dlqhwjvfwd5g9k0tpuay90ga634c64cgsqczfmvx",
                        "extra_data": null,
                        "receiver_handle": [...],
                        "sender_handle": [...]
                    }
                ]
            },
            "executed_in_block": "000000000bc1070fda6b86eb31fbf3f15e89be9c10928415b2254fcab96088a8",
            "fee": 25000,
            "hash": "cb26c0a203cd75206ebd122213e442ffabf5dc21286fbe92e46c864ba723dcdd",
            "in_mempool": false,
            "nonce": 1460,
            "range_proof": [...],
            "reference": {
                "hash": "00000000040f90c8bcbb33bc832c1cd9f0683204af1c099a0af52c7a247840f5",
                "topoheight": 22284
            },
            "signature": "afe694d96aa7a4ea44e57e7f7090a19a84105fc49df40c35cb5c1bfe4a949303d8b918e2ccbc38c8058449edcb334883471265743c99be39180a574d2adbfd05",
            "source": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
            "source_commitments": [
                {
                    "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                    "commitment": [...],
                    "proof": {
                        "Y_0": [...],
                        "Y_1": [...],
                        "Y_2": [...],
                        "z_r": [...],
                        "z_s": [...],
                        "z_x": [...]
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
|        Name        |   Type  | Required |                               Note                              |
|:------------------:|:-------:|:--------:|:---------------------------------------------------------------:|
|       address      | Address | Required |                Valid address registered on chain                |
|        asset       |   Hash  | Optional |                          Asset to track                         |
| minimum_topoheight | Integer | Optional |                  minimum topoheight for history                 |
| maximum_topoheight | Integer | Optional |                  Maximum topoheight for history                 |
|    outgoing_flow   | Boolean | Optional |       Set to true by default, filter outgoing transactions      |
|    incoming_flow   | Boolean | Optional | Set to true by default, filter incoming transactions / coinbase |

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
            "reward": 146229454,
            "miner_reward": 131606509,
            "dev_reward": 14622945,
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
            "reward": 146229454,
            "miner_reward": 131606509,
            "dev_reward": 14622945,
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
            "reward": 146229454,
            "miner_reward": 131606509,
            "dev_reward": 14622945,
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
            "reward": 146229454,
            "miner_reward": 131606509,
            "dev_reward": 14622945,
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
            "reward": 146229454,
            "miner_reward": 131606509,
            "dev_reward": 14622945,
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
            "reward": 146229454,
            "miner_reward": 131606509,
            "dev_reward": 14622945,
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
                "commitment": [...],
                "handle": [...]
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

#### Get Multisig
Retrieve the latest multisig information for a specific address.

##### Method `get_multisig`

##### Parameters
|   Name  |   Type  | Required |                Note               |
|:-------:|:-------:|:--------:|:---------------------------------:|
| address | Address | Required | Valid address registered on chain |

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "get_multisig",
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
        "state": {
            "participants": ["xet:yfxcjh7aua5lmpvmyh4fmhrjzlg9xx9p6uvel0248hxc42yja9usq27dz7s"],
            "threshold": 1
        },
        "topoheight": 57
    }
}
```

#### Get Multisig at TopoHeight
Retrieve the multisig information at a specific topoheight.

##### Method `get_multisig_at_topoheight`

##### Parameters

|        Name        |   Type  | Required |                Note               |
|:------------------:|:-------:|:--------:|:---------------------------------:|
|       address      | Address | Required | Valid address registered on chain |
|      topoheight    | Integer | Required | Topoheight to retrieve the state  |

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "get_multisig_at_topoheight",
    "params": {
        "address": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
        "topoheight": 57
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "state": {
            "participants": ["xet:yfxcjh7aua5lmpvmyh4fmhrjzlg9xx9p6uvel0248hxc42yja9usq27dz7s"],
            "threshold": 1
        }
    }
}
```

**NOTE**: If the address has disabled its multig setup setup, a `state` with value `inactive` will be returned instead.


#### Has Multisig

Verify if the address has a multisig setup.

##### Method `has_multisig`

##### Parameters

|   Name  |   Type  | Required |                Note               |
|:-------:|:-------:|:--------:|:---------------------------------:|
| address | Address | Required | Valid address registered on chain |

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "has_multisig",
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
    "result": true
}
```

**NOTE**:
- If the address has an inactive multisig state, it will returns `false`.

#### Has Multisig at TopoHeight

Verify if the address has a multisig setup at a specific topoheight.

##### Method `has_multisig_at_topoheight`

##### Parameters

|        Name        |   Type  | Required |                Note               |
|:------------------:|:-------:|:--------:|:---------------------------------:|
|       address      | Address | Required | Valid address registered on chain |
|      topoheight    | Integer | Required | Topoheight to retrieve the state  |

##### Request
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "has_multisig_at_topoheight",
    "params": {
        "address": "xet:6eadzwf5xdacts6fs4y3csmnsmy4mcxewqt3xyygwfx0hm0tm32sqxdy9zk",
        "topoheight": 57
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

**NOTE**:
- If the address has an inactive multisig state, it will returns `false`.
- If a version is not found at requested topoheight, an error will be returned.

#### Decrypt Extra Data
Decrypt the extra data from a transaction.

##### Method `decrypt_extra_data`

##### Parameters

|    Name    |     Type    | Required |                         Note                         |
|:----------:|:-----------:|:--------:|:----------------------------------------------------:|
| shared_key | Hexadecimal | Required | Shared Key in hexadecimal format used for decryption |
| extra_data |  Byte Array | Required |    Byte array containing the encrypted extra data    |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "decrypt_extra_data",
    "id": 1,
    "params": {
        "shared_key": "<hexadecimal shared key>",
        "extra_data": [
            ...
        ]
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "hello": "world!"
    }
}
```

#### Get Contract Outputs
Retrieve the contract outputs that have occurred in the requested transaction hash.

It contains, the refunded gas amount, exit code and transfers.

##### Method `get_contract_outputs`

##### Parameters

|    Name    |     Type    | Required |                         Note                         |
|:----------:|:-----------:|:--------:|:----------------------------------------------------:|
| shared_key | Hexadecimal | Required | Shared Key in hexadecimal format used for decryption |
| extra_data |  Byte Array | Required |    Byte array containing the encrypted extra data    |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_contract_outputs",
    "id": 1,
    "params": {
        "transaction": "8a354baac1d53d02249aadee92c5a3e0585b126439947cb4a3c3aa9baaea5f17"
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
            "exit_code": 0
        },
        {
            "refund_gas": {
                "amount": 99593
            }
        }
    ]
}
```

#### Get Contract Data
Retrieve the contract data with the requested key.

##### Method `get_contract_data`

##### Parameters

|    Name    |     Type    | Required |                         Note                         |
|:----------:|:-----------:|:--------:|:----------------------------------------------------:|
|  contract  |   Address   | Required |       Contract address to search for the key         |
|     key    |  ValueCell  | Required |           ValueCell representing the key             |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_contract_data",
    "id": 1,
    "params": {
        "contract": "b756566452b2c7bfea785f1b87b90d7bf075cb45a0dc33fb524e5e25f7e85fb4",
        "key": {
            "type": "default",
            "value": {
                "type": "string",
                "value": "my beautiful key"
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
    "result": {
        "topoheight": 70,
        "data": {
            "type": "default",
            "value": {
                "type": "string",
                "value": "my beautiful value"
            }
        },
        "previous_topoheight": 68
    }
}
```

#### Get Contract Data At TopoHeight
Retrieve the contract data with the requested key at a specific topoheight.

##### Method `get_contract_data_at_topoheight`

##### Parameters
|    Name    |     Type    | Required |                         Note                         |
|:----------:|:-----------:|:--------:|:----------------------------------------------------:|
|  contract  |   Address   | Required |       Contract address to search for the key         |
|     key    |   ValueCell | Required |           ValueCell representing the key             |
| topoheight |   Integer   | Required |           Topoheight to retrieve the data            |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_contract_data_at_topoheight",
    "id": 1,
    "params": {
        "contract": "b756566452b2c7bfea785f1b87b90d7bf075cb45a0dc33fb524e5e25f7e85fb4",
        "topoheight": 70,
        "key": {
            "type": "default",
            "value": {
                "type": "string",
                "value": "my beautiful key"
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
    "result": {
        "data": {
            "type": "default",
            "value": {
                "type": "string",
                "value": "my beautiful value"
            }
        },
        "previous_topoheight": 68
    }
}
```

#### Get Contract Balance
Retrieve the contract balance

##### Method `get_contract_balance`

##### Parameters
|    Name    |     Type    | Required |                         Note                         |
|:----------:|:-----------:|:--------:|:----------------------------------------------------:|
|  contract  |   Address   | Required |       Contract address to search for the key         |
|    asset   |  ValueCell  | Required |   The asset ID to determine which balance to fetch   |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_contract_balance",
    "id": 1,
    "params": {
        "contract": "b756566452b2c7bfea785f1b87b90d7bf075cb45a0dc33fb524e5e25f7e85fb4",
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
        "topoheight": 70,
        "data": 99900000,
        "previous_topoheight": null
    }
}
```

#### Get Contract Balance At TopoHeight
Retrieve the contract balance at a specific topoheight.

##### Method `get_contract_balance_at_topoheight`

##### Parameters
|    Name    |     Type    | Required |                         Note                         |
|:----------:|:-----------:|:--------:|:----------------------------------------------------:|
|  contract  |   Address   | Required |       Contract address to search for the key         |
|    asset   |     Hash    | Required |   The asset ID to determine which balance to fetch   |
| topoheight |   Integer   | Required |           Topoheight to retrieve the data            |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_contract_balance",
    "id": 1,
    "params": {
        "contract": "b756566452b2c7bfea785f1b87b90d7bf075cb45a0dc33fb524e5e25f7e85fb4",
        "asset": "0000000000000000000000000000000000000000000000000000000000000000",
        "topoheight": 70
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "data": 99900000,
        "previous_topoheight": null
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
        "until_topoheight": 1337
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
|        Name       |       Type      | Required |                                    Note                                    |
|:-----------------:|:---------------:|:--------:|:--------------------------------------------------------------------------:|
|     tx_version    |     Integer     | Optional | Set the transaction version to use. By default take the version from wallet|
|        fee        |    FeeBuilder   | Optional |                   Set an exact fee value or a multiplier                   |
|       nonce       |     Integer     | Optional | Set the nonce to use by the transaction. By default its provided by wallet |
|     broadcast     |     Boolean     | Optional |               Broadcast TX to daemon. By default set to true               |
|     tx_as_hex     |     Boolean     | Optional |            Serialize TX to hexadecimal. By default set to false            |
| transfers OR burn | TransactionType | Required |                         Transaction Type parameter                         |
|      signers      |	  Array       | Optional |              List of signers to use for the transaction multisig.          |

###### Fee Builder
Fee builder has two variants:
- One to provide a multiplier applied on estimated fees.
```json
{"multiplier":1.0}
```

- One to provide a fixed amount of fee to pay
```json
{"value":100}
```
When it's not provided, Fee Builder is set by default to multiplier 1 to pay what is estimated.

###### MultiSig Signers
Signers is a list of `SignerId` to use to sign a transaction multisig.
Example of one `SignerId`:
```json
{
    "private_key": "<private key in hexadecimal>",
    "id": 0
}
```
where `id` is the index of the signer in the multisig setup.

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
        "tx_as_hex": true,
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
                    "commitment": [...],
                    "ct_validity_proof": {
                        "Y_0": [...],
                        "Y_1": [...],
                        "z_r": [...],
                        "z_x": [...]
                    },
                    "destination": [...],
                    "extra_data": null,
                    "receiver_handle": [...],
                    "sender_handle": [...]
                }
            ]
        },
        "fee": 25000,
        "hash": "f8bd7c15e3a94085f8130cc67e1fefd89192cdd208b68b10e1cc6e1a83afe5d6",
        "nonce": 1463,
        "range_proof": [...],
        "reference": {
            "hash": "000000000c1845717b0820bd32b57d1928af1b4ae80bdec71b73ab8d60f9eb74",
            "topoheight": 25770
        },
        "signature": "6731b973cb5c06c7e4e6fa9135acf4ea7c1b2e2bd0a63e41110aad3b39174204067bf7de87f3c3e2042cbcf6899a307e480d80e7c7f96638eabbf1fe6cfded09",
        "source": [...],
        "source_commitments": [
            {
                "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                "commitment": [...],
                "proof": {
                    "Y_0": [...],
                    "Y_1": [...],
                    "Y_2": [...],
                    "z_r": [...],
                    "z_s": [...],
                    "z_x": [...]
                }
            }
        ],
        "tx_as_hex": "00d67ad13934337b85c34985491c437386c95de0d97017131088724cfbedebdc55010100000000000000000000000000000000000000000000000000000000000000005aa2e3842578a127d601a0e232c24114580f0cd875c8d4d04bfdb594de7c864700ee1e827a43c220f6c8502e8ddebbd02b2ef1edcbd5cd90cd6af497129fcee11b109a4e8b947caa52b1919cfad615e027a89af8adf6cb42e947b129d9ad77a00f465ca3472da66f0ad670b202f80c4adec695e8a97abb2050d1fe21d73524403122a109b128214df24d70d1323b1128496389976315248b628b21244e0d115604f6e3e1d56226b3c7c21a69ffb6fc7ed6ce527921f9af5f9b61adc01a3a7c817b84ae6344ff62dbd33519ab3aba151330460af77c22af20c72721f4be6f32e20c95c7eb09a0cafc8971e7640da47f6599c600ea7d14f5139c6b98de19817b810100000000000061a800000000000005b701345fac2a77aa1d9955170d1a24dec26d60f49bc9cdd574bfe6d7add0bf016a441ccf887fd77976d92c8be87a547e103da5167ebe4a9c99e7419251738dc3b643fe85694f0060b0cccd77a534f08108c13689d59119716450f9234fcee4f8dd2fe8e98f6f4ad6c85f13df78670c926be2043bb75dd26104816c0a32b54f00f715f0613286ae1bcf64938bb43edd3be32bf65e5816eb8444a1244013ec1cd33e03c14082bca938d54fbb4de56e36ab2806d97c56ff279346230d2c6b130c0bcb0c89a862f3398d12a5b94e1db086cde28c903cf23af135178976ecdddced617306000000000000000000000000000000000000000000000000000000000000000002e0169af51116d0631ba9706d824dfb48c244b1cd76ca1442a8e652e0b285e6492aa2857f5cf78f922213477524a67fb3e1c0d68d62f8a4b1eb2bb695e2f8e4d035a6d04b9b14d70c6e8e84684adb0ad9b8c28416db2826a9583b582c3f81cf7b224276b0aa297556816b1b4954e2cef4dc6cb4f7ca95860545b265604765c64d6aecd989896801e013ebe92c57e4a38ace5c86ec41a50c6f6ed75015f0033b5504246781c4da478fe3c9f945a56edb29899be585ba4096c4212b92425fe4cc5905cf410456db21df087eebcebe31d37c1c514b73cd561f633214921bed393fce04fceec94193840cacf90b375c41235cabfc56635f4164f6f717db538c3cc28e56e22042ea1176ce1441a9d57796cb4a27849a71a30b7aaee98002b0d63bb98024da3b24a954f08e152eb8ff84334fff0b8271e4d3b59ace30aeb21b7fd26b79382e0648211a4aec78ea9844e60bf6a730b79184ac372cb8d5d7efc8c3b447ac3c1c609c4e478abbecf59fdddbb466510173a701dde050953813f2558d3d1c485c8a74c21ffc7a6bd436133c5219caf64bd3925c47fe9f81a536d2745ed1f070131cd0508d387a8a98cce61bab9bb4708ea490e483be60eac36277458ed1d6ba776c0da7424fc2c888f1264249f3185654468d1f344470cff3776c0f5071f50065ca383a0b68561d1d9fbb4b62c052e7139151122c121bd0e667a4320c7372356dd2059e4dff4ff983c17a55d1c645a8b9841273f9b6970e5a76ae10cdcb2c7b2c8cbf0134f39a11baa708e2a2d761d7215067cd61bb282eeda651159a3c18250a2a993ef99cc450c50a1dbf070f882619ab822e3506b3039128dea3b62106263d221753d1946b786c49d6e0a677bdd512d7c502a647a7f2c71c0373d225593e2e12aeb50e5a4a9849662d9b098f86145aa742b601afa485945e6b0ff34d71a35f303981d11d7ade050220ce4be49044e8793379c38f120a9136f5d64da61b2c02f30d306e11c35051f4474063ad1aaa2cd1b599d1ac3ed60c86b8aeb7af014604000000000c1845717b0820bd32b57d1928af1b4ae80bdec71b73ab8d60f9eb7400000000000064aa6731b973cb5c06c7e4e6fa9135acf4ea7c1b2e2bd0a63e41110aad3b39174204067bf7de87f3c3e2042cbcf6899a307e480d80e7c7f96638eabbf1fe6cfded09",
        "version": 0
    }
}
```

#### Build Transaction Offline
Build a transaction offline in the wallet by providing directly exact balances and reference.
It cannot be broadcasted by the wallet directly.

**NOTE**: Amount set are in atomic units, for XELIS it would be `100000000` to represents 1 XELIS because of 8 decimals precision.

##### Method `build_transaction_offline`

##### Parameters
|        Name       |       Type      | Required |                                    Note                                    |
|:-----------------:|:---------------:|:--------:|:--------------------------------------------------------------------------:|
|        fee        |    FeeBuilder   | Optional |                   Set an exact fee value or a multiplier                   |
|       nonce       |     Integer     | Required | Set the nonce to use by the transaction. By default its provided by wallet |
|     tx_version    |     Integer     | Optional | Set the transaction version to use. By default take the version from wallet|
|     tx_as_hex     |     Boolean     | Optional |            Serialize TX to hexadecimal. By default set to false            |
| transfers OR burn | TransactionType | Required |                         Transaction Type parameter                         |
|      balances     |     Array       | Required |              Map of asset<->balance to use for the transaction.            |
|	 reference      |    Reference    | Required | Reference to use for the transaction. It contains the hash and topoheight  |
|      signers      |	  Array       | Optional |              List of signers to use for the transaction multisig.          |

###### Fee Builder
Fee builder has two variants:
- One to provide a multiplier applied on estimated fees.
```json
{"multiplier":1.0}
```

- One to provide a fixed amount of fee to pay
```json
{"value":100}
```
When it's not provided, Fee Builder is set by default to multiplier 1 to pay what is estimated.

###### MultiSig Signers
Signers is a list of `SignerId` to use to sign a transaction multisig.
Example of one `SignerId`:
```json
{
    "private_key": "<private key in hexadecimal>",
    "id": 0
}
```
where `id` is the index of the signer in the multisig setup.

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "build_transaction_offline",
    "id": 1,
    "params": {
        "transfers": [
            {
                "amount": 1000,
                "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                "destination": "xet:t23w8pp90zsj04sp5r3r9sjpz3vq7rxcwhydf5ztlk6efhnusersqvf8sny"
            }
        ],
        "tx_version": 0,
        "nonce": 1463,
        "balances": {
            "0000000000000000000000000000000000000000000000000000000000000000": {
                "commitment": [...],
                "handle": [...]
            }
        },
        "reference": {
            "hash": "000000000c1845717b0820bd32b57d1928af1b4ae80bdec71b73ab8d60f9eb74",
            "topoheight": 25770
        },
        "tx_as_hex": true,
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
                    "commitment": [...],
                    "ct_validity_proof": {
                        "Y_0": [...],
                        "Y_1": [...],
                        "z_r": [...],
                        "z_x": [...]
                    },
                    "destination": [...],
                    "extra_data": null,
                    "receiver_handle": [...],
                    "sender_handle": [...]
                }
            ]
        },
        "fee": 25000,
        "hash": "f8bd7c15e3a94085f8130cc67e1fefd89192cdd208b68b10e1cc6e1a83afe5d6",
        "nonce": 1463,
        "range_proof": [...],
        "reference": {
            "hash": "000000000c1845717b0820bd32b57d1928af1b4ae80bdec71b73ab8d60f9eb74",
            "topoheight": 25770
        },
        "signature": "6731b973cb5c06c7e4e6fa9135acf4ea7c1b2e2bd0a63e41110aad3b39174204067bf7de87f3c3e2042cbcf6899a307e480d80e7c7f96638eabbf1fe6cfded09",
        "source": [...],
        "source_commitments": [
            {
                "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                "commitment": [...],
                "proof": {
                    "Y_0": [...],
                    "Y_1": [...],
                    "Y_2": [...],
                    "z_r": [...],
                    "z_s": [...],
                    "z_x": [...]
                }
            }
        ],
        "tx_as_hex": "00d67ad13934337b85c34985491c437386c95de0d97017131088724cfbedebdc55010100000000000000000000000000000000000000000000000000000000000000005aa2e3842578a127d601a0e232c24114580f0cd875c8d4d04bfdb594de7c864700ee1e827a43c220f6c8502e8ddebbd02b2ef1edcbd5cd90cd6af497129fcee11b109a4e8b947caa52b1919cfad615e027a89af8adf6cb42e947b129d9ad77a00f465ca3472da66f0ad670b202f80c4adec695e8a97abb2050d1fe21d73524403122a109b128214df24d70d1323b1128496389976315248b628b21244e0d115604f6e3e1d56226b3c7c21a69ffb6fc7ed6ce527921f9af5f9b61adc01a3a7c817b84ae6344ff62dbd33519ab3aba151330460af77c22af20c72721f4be6f32e20c95c7eb09a0cafc8971e7640da47f6599c600ea7d14f5139c6b98de19817b810100000000000061a800000000000005b701345fac2a77aa1d9955170d1a24dec26d60f49bc9cdd574bfe6d7add0bf016a441ccf887fd77976d92c8be87a547e103da5167ebe4a9c99e7419251738dc3b643fe85694f0060b0cccd77a534f08108c13689d59119716450f9234fcee4f8dd2fe8e98f6f4ad6c85f13df78670c926be2043bb75dd26104816c0a32b54f00f715f0613286ae1bcf64938bb43edd3be32bf65e5816eb8444a1244013ec1cd33e03c14082bca938d54fbb4de56e36ab2806d97c56ff279346230d2c6b130c0bcb0c89a862f3398d12a5b94e1db086cde28c903cf23af135178976ecdddced617306000000000000000000000000000000000000000000000000000000000000000002e0169af51116d0631ba9706d824dfb48c244b1cd76ca1442a8e652e0b285e6492aa2857f5cf78f922213477524a67fb3e1c0d68d62f8a4b1eb2bb695e2f8e4d035a6d04b9b14d70c6e8e84684adb0ad9b8c28416db2826a9583b582c3f81cf7b224276b0aa297556816b1b4954e2cef4dc6cb4f7ca95860545b265604765c64d6aecd989896801e013ebe92c57e4a38ace5c86ec41a50c6f6ed75015f0033b5504246781c4da478fe3c9f945a56edb29899be585ba4096c4212b92425fe4cc5905cf410456db21df087eebcebe31d37c1c514b73cd561f633214921bed393fce04fceec94193840cacf90b375c41235cabfc56635f4164f6f717db538c3cc28e56e22042ea1176ce1441a9d57796cb4a27849a71a30b7aaee98002b0d63bb98024da3b24a954f08e152eb8ff84334fff0b8271e4d3b59ace30aeb21b7fd26b79382e0648211a4aec78ea9844e60bf6a730b79184ac372cb8d5d7efc8c3b447ac3c1c609c4e478abbecf59fdddbb466510173a701dde050953813f2558d3d1c485c8a74c21ffc7a6bd436133c5219caf64bd3925c47fe9f81a536d2745ed1f070131cd0508d387a8a98cce61bab9bb4708ea490e483be60eac36277458ed1d6ba776c0da7424fc2c888f1264249f3185654468d1f344470cff3776c0f5071f50065ca383a0b68561d1d9fbb4b62c052e7139151122c121bd0e667a4320c7372356dd2059e4dff4ff983c17a55d1c645a8b9841273f9b6970e5a76ae10cdcb2c7b2c8cbf0134f39a11baa708e2a2d761d7215067cd61bb282eeda651159a3c18250a2a993ef99cc450c50a1dbf070f882619ab822e3506b3039128dea3b62106263d221753d1946b786c49d6e0a677bdd512d7c502a647a7f2c71c0373d225593e2e12aeb50e5a4a9849662d9b098f86145aa742b601afa485945e6b0ff34d71a35f303981d11d7ade050220ce4be49044e8793379c38f120a9136f5d64da61b2c02f30d306e11c35051f4474063ad1aaa2cd1b599d1ac3ed60c86b8aeb7af014604000000000c1845717b0820bd32b57d1928af1b4ae80bdec71b73ab8d60f9eb7400000000000064aa6731b973cb5c06c7e4e6fa9135acf4ea7c1b2e2bd0a63e41110aad3b39174204067bf7de87f3c3e2042cbcf6899a307e480d80e7c7f96638eabbf1fe6cfded09",
        "version": 0
    }
}
```


#### Build Unsigned Transaction
Build a transaction without signing it.
This is useful in case of a MultiSig setup where you need to sign the transaction with other signers.

##### Method `build_unsigned_transaction`

##### Parameters

|        Name       |       Type      | Required |                                    Note                                    |
|:-----------------:|:---------------:|:--------:|:--------------------------------------------------------------------------:|
|        fee        |    FeeBuilder   | Optional |                   Set an exact fee value or a multiplier                   |
|       nonce       |     Integer     | Optional | Set the nonce to use by the transaction. By default its provided by wallet |
|     tx_version    |     Integer     | Optional | Set the transaction version to use. By default take the version from wallet|
|     tx_as_hex     |     Boolean     | Optional |            Serialize TX to hexadecimal. By default set to false            |
| transfers OR burn | TransactionType | Required |                         Transaction Type parameter                         |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "build_unsigned_transaction",
    "id": 1,
    "params": {
        "transfers": [
            {
                "amount": 1000,
                "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                "destination": "xet:t23w8pp90zsj04sp5r3r9sjpz3vq7rxcwhydf5ztlk6efhnusersqvf8sny"
            }
        ],
        "tx_as_hex": true,
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
                    "commitment": [...],
                    "ct_validity_proof": {
                        "Y_0": [...],
                        "Y_1": [...],
                        "z_r": [...],
                        "z_x": [...]
                    },
                    "destination": [...],
                    "extra_data": null,
                    "receiver_handle": [...],
                    "sender_handle": [...]
                }
            ]
        },
        "fee": 25000,
        "hash": "f8bd7c15e3a94085f8130cc67e1fefd89192cdd208b68b10e1cc6e1a83afe5d6",
        "nonce": 1463,
        "range_proof": [...],
        "reference": {
            "hash": "000000000c1845717b0820bd32b57d1928af1b4ae80bdec71b73ab8d60f9eb74",
            "topoheight": 25770
        },
        "source": [...],
        "source_commitments": [
            {
                "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                "commitment": [...],
                "proof": {
                    "Y_0": [...],
                    "Y_1": [...],
                    "Y_2": [...],
                    "z_r": [...],
                    "z_s": [...],
                    "z_x": [...]
                }
            }
        ],
        "multisig": null,
        "tx_as_hex": "<hexadecimal transaction>",
        "version": 0,
        "threshold": 0
    }
}
```

**NOTE**: If the wallet is offline, it can't determine the exact `threshold` needed to sign the transaction.
It will be set to 0.

#### Finalize Unsigned Transaction
Finalize an unsigned transaction by signing it with the wallet key pair.
Once signed, the transaction can be broadcasted to the network.

##### Method `finalize_unsigned_transaction`

##### Parameters

|        Name       |        Type       | Required |                                    Note                                    |
|:-----------------:|:-----------------:|:--------:|:--------------------------------------------------------------------------:|
|      unsigned     |UnsignedTransaction| Required | Hexadecimal/JSON representation of the unsigned transaction to sign        |
|     signatures    |        Array      | Optional | List of signatures to use for the transaction multisig.                    |
|     broadcast     |       Boolean     | Optional | Broadcast TX to daemon. By default set to true                             |
|     tx_as_hex     |       Boolean     | Optional | Serialize TX to hexadecimal. By default set to false                       |
##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "finalize_unsigned_transaction",
    "id": 1,
    "params": {
        "unsigned": "<hexadecimal transaction>",
        "tx_as_hex": true
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
                    "commitment": [...],
                    "ct_validity_proof": {
                        "Y_0": [...],
                        "Y_1": [...],
                        "z_r": [...],
                        "z_x": [...]
                    },
                    "destination": [...],
                    "extra_data": null,
                    "receiver_handle": [...],
                    "sender_handle": [...]
                }
            ]
        },
        "fee": 25000,
        "hash": "f8bd7c15e3a94085f8130cc67e1fefd89192cdd208b68b10e1cc6e1a83afe5d6",
        "nonce": 1463,
        "range_proof": [...],
        "reference": {
            "hash": "000000000c1845717b0820bd32b57d1928af1b4ae80bdec71b73ab8d60f9eb74",
            "topoheight": 25770
        },
        "source": [...],
        "source_commitments": [
            {
                "asset": "0000000000000000000000000000000000000000000000000000000000000000",
                "commitment": [...],
                "proof": {
                    "Y_0": [...],
                    "Y_1": [...],
                    "Y_2": [...],
                    "z_r": [...],
                    "z_s": [...],
                    "z_x": [...]
                }
            }
        ],
        "multisig": null,
        "tx_as_hex": "<hexadecimal transaction>",
        "version": 0
    }
}
```

**NOTE**:
- The response is the same as `build_transaction` but without the signature.
- `hash` field is not the real hash of the transaction because it's not signed yet. Its a hash used for multisig signing.

#### Sign Unsigned Transaction
Sign an unsigned transaction hash with the wallet key pair.
This is useful in case you are a part of the multisig of another wallet and you need to sign a transaction.

##### Method `sign_unsigned_transaction`

##### Parameters

|        Name       |        Type       | Required |                                    Note                                    |
|:-----------------:|:-----------------:|:--------:|:--------------------------------------------------------------------------:|
|        hash       |        Hash       | Required | Hash of the unsigned transaction to sign                                   |
|     signer_id     |      Integer      | Required | Index of the signer in the multisig setup to use for signing               |

#### Request
```json
{
    "jsonrpc": "2.0",
    "method": "sign_unsigned_transaction",
    "id": 1,
    "params": {
        "hash": "f8bd7c15e3a94085f8130cc67e1fefd89192cdd208b68b10e1cc6e",
        "signer_id": 0
    },
}
```

#### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "signature": "6731b973cb5c06c7e4e6fa9135acf4ea7c1b2e2bd0a63e41110aad3b39174204067bf7de87f3c3e2042cbcf6899a307e480d80e7c7f96638eabbf1fe6cfded09",
        "id": 0
    }
}
```

**NOTE**: The response is the signature of the hash provided. You can use this `SignatureId` returned to finalize the transaction by adding it to the Unsigned Transaction multisig.

#### Clear TX Cache
In case of a failure while broadcasting a TX from this wallet by yourself, you can erase the TX cache stored in the wallet.

##### Method `clear_tx_cache`

##### Parameters
No parameters

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "clear_tx_cache",
    "id": 1
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

#### List Transactions
Search transactions based on various parameters.
By default it accepts every TXs.

For `address` param, it is compared to the sender if it's an incoming TX, and to destination address for outgoing TX.

Topoheight range if specified is inclusive.
Meaning if you set max_topoheight at 10 and you have a TX at 10 its returned.

##### Method `list_transactions`

##### Parameters
|       Name      |   Type  | Required |                              Note                             |
|:---------------:|:-------:|:--------:|:-------------------------------------------------------------:|
|      asset      |   Hash  | Optional | Filter on a specific asset only. By default accept all assets |
|  min_topoheight | Integer | Optional |                    Start from specific topo                   |
|  max_topoheight | Integer | Optional |                      End at specific topo                     |
|     address     |  String | Optional |                      Filter with address                      |
| accept_incoming | Boolean | Optional |                        Filter incoming                        |
| accept_outgoing | Boolean | Optional |                        Filter outgoing                        |
| accept_coinbase | Boolean | Optional |                        Filter coinbase                        |
|   accept_burn   | Boolean | Optional |                          Filter burn                          |
|      query      |  Query  | Optional |                 Allow to filter on extra data                 |

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
    "method": "sign_data",
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

#### Is Online
Determine if the wallet is connected to a node or not (offline / online mode).

##### Method `is_online`

##### Parameters
No parameter

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "is_online",
    "id": 1
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

#### Network Info
Fetch all information about the current node to which the wallet is connected to.

##### Method `network_info`

##### Parameters
No parameter

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "network_info",
    "id": 1
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "average_block_time": 15954,
        "block_reward": 137924147,
        "block_time_target": 15000,
        "circulating_supply": 104512595148870,
        "connected_to": "ws://127.0.0.1:8080/json_rpc",
        "dev_reward": 13792414,
        "difficulty": "107844053400",
        "height": 725025,
        "maximum_supply": 1840000000000000,
        "mempool_size": 0,
        "miner_reward": 124131733,
        "network": "Mainnet",
        "pruned_topoheight": null,
        "stableheight": 725017,
        "top_block_hash": "1914802b64b28386adc37927081beb6ac4677b6f85ee2149f7a143339c99d309",
        "topoheight": 761761,
        "version": "1.13.4-d33986a"
    }
}
```

#### Decrypt Extra Data
Decrypt the extra data from a transaction.
This function is useful in case your wallet is offline and you want it to decrypt a extra data without having it in online mode.

##### Method `decrypt_extra_data`

##### Parameters
|    Name    |     Type    | Required |                          Note                         |
|:----------:|:-----------:|:--------:|:-----------------------------------------------------:|
| extra_data |  Byte Array | Required |     Byte array containing the encrypted extra data    |
|	 role    |    String   | Required |Role of the wallet in the transaction (sender/receiver)|

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "decrypt_extra_data",
    "id": 1,
    "params": {
        "role": "receiver",
        "extra_data": [
            ...
        ]
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "hello": "world!"
    }
}
```

#### Decrypt Ciphertext
Decrypt a ciphertext from its compressed format.

If you want to decrypt the ciphertext of a Transaction, you need to take the Transfer `commitment` field.
For the `handle` field, you need to select either `receiver_handle` or `sender_handle` based on the flow of the transaction.

Please note that the value returned is in atomic units.

##### Method `decrypt_ciphertext`

##### Parameters
|    Name    |     Type    | Required |               Note                 |
|:----------:|:-----------:|:--------:|:----------------------------------:|
| ciphertext | Compressed  | Required |    Ciphertext compressed format    |

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "decrypt_ciphertext",
    "id": 1,
    "params": {
        "ciphertext": {
            "handle": [ ... ],
            "commitment": [ ... ]
}
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": 5700000000
}
```

### Storage

XELIS Wallet has the ability to have a built-in encrypted DB that can be used to store / fetch entries easily.
This can be really helpful for small services / applications that don't want to setup a whole database system.

It is a key / value DB with support of multiples Trees, everything is stored in encrypted form on the disk.

You can either access it directly through Rust code, or through the following JSON-RPC methods.

Every types are allowed and are automatically serialized.

A query system is available to make advanced filter over encrypted keys and values from DB.
This feature is planned to be improved in future. For now, the follow are implemented:
- Filter over numbers values (`>=`, `>`, `<`, `<=`, `==`).
- Regex over stringified values
- `Is Of Type` (built-in types are `bool`, `string`, `u8`, `u16`, `u32`, `u64`, `u128`, `hash`, `blob`)
- `Starts with`
- `Ends With`
- `Contains Value`
- `Equal to`

Those filters can be used together or alone, using the `Not`, `And`, `Or` operations.

If key or value is a map or an array, you can also do filter on them:
- `Has Key` (with expected key value and an optional query on the value if present)
- `At Key` (same as above but query is mandatory)
- `Len` (check the map/array size using a `query number`)
- `Contains Element` (check if the array contains the requested element)
- `At Position` (check at array index if the value match using a query)
- `Type` (check which kind of type it is)

Please note that these functionalities are also available from XSWD calls, which mean, any accepted Application through XSWD can have its own DB like a local storage on web JavaScript.

This query system will be used in daemon also once Smart Contracts are deployed to easily search entries in the Smart Contract database.

#### Store
Store a new key / value entry in the requested Tree.

##### Method `store`

##### Parameters
TODO

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "store",
    "id": 1,
    "params": {
        "tree": "test",
        "key": "my_list",
        "value": ["hello", " ", "world", "!"]
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

#### Delete
Delete a key / value entry in the requested Tree.

##### Method `delete`

##### Parameters
TODO

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "delete",
    "id": 1,
    "params": {
        "tree": "test",
        "key": "my_list"
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

#### Has Key
Verify if the key is present in the requested Tree.

##### Method `has_key`

##### Parameters
TODO

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "has_key",
    "id": 1,
    "params": {
        "tree": "test",
        "key": "my_list"
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

#### Get Value From Key
Get a value using its key in the requested Tree.

##### Method `get_value_from_key`

##### Parameters
TODO

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "get_value_from_key",
    "id": 1,
    "params": {
        "tree": "test",
        "key": "my_list"
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": [
        "hello",
        " ",
        "world",
        "!"
    ]
}
```

#### Query DB
Query the DB in the requested Tree with filters.

##### Method `query_db`

##### Parameters
TODO

##### Request
```json
{
    "jsonrpc": "2.0",
    "method": "query_db",
    "id": 1,
    "params": {
        "tree": "test",
        "value": {
            "or": [
                {
                    "equal": "welcome"
                },
                {
                    "equal": "test"
                },
                {
                    "equal": "!"
                }
            ]
        }
    }
}
```

##### Response
```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "entries": {
            "my_list": [
                "hello",
                " ",
                "world",
                "!"
            ]
        },
        "next": null
    }
}
```
