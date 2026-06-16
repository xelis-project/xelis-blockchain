use xelis_vm::Primitive;

use crate::{
    config::{COST_PER_ASSET, XELIS_ASSET},
    contract::{
        ContractLog,
        ContractVersion,
        ExitError,
        tests::{create_contract, invoke_contract},
        vm::{ExecutionResult, ExitValue, InvokeContract}
    },
    crypto::Hash,
    transaction::mock::MockChainState,
};

fn funded_contract(state: &mut MockChainState, code: &str) -> Hash {
    let contract = create_contract(state, code, ContractVersion::V1).expect("create contract");
    state.set_contract_balance(&contract, &XELIS_ASSET, COST_PER_ASSET * 4);
    contract
}

fn created_asset_hash(state: &MockChainState) -> Hash {
    state.assets
        .keys()
        .find(|hash| **hash != XELIS_ASSET)
        .cloned()
        .expect("created asset")
}

fn has_contract_log(state: &MockChainState, predicate: impl Fn(&ContractLog) -> bool) -> bool {
    state.contract_logs
        .values()
        .flatten()
        .any(predicate)
}

fn assert_runtime_error(result: &ExecutionResult, expected: &str) {
    match &result.exit_value {
        ExitValue::Error(ExitError::RuntimeError(msg)) => {
            assert!(
                msg.contains(expected),
                "expected runtime error containing {:?}, got {:?}",
                expected,
                msg
            );
        },
        value => panic!("expected runtime error containing {:?}, got {:?}", expected, value)
    }
}

#[tokio::test]
async fn asset_create_and_read_metadata() {
    let code = r#"
        entry main() {
            let asset = Asset::create(7, "Unit Token", "UNIT", 4, MaxSupplyMode::Mintable { max_supply: 1000 }).expect("asset created");

            require(asset.get_name() == "Unit Token", "bad name");
            require(asset.get_ticker() == "UNIT", "bad ticker");
            require(asset.get_decimals() == 4, "bad decimals");
            require(asset.get_max_supply().expect("max supply") == 1000, "bad max supply");
            require(asset.get_supply() == 0, "bad initial supply");
            require(asset.is_mintable(), "asset must be mintable");
            require(!asset.is_read_only(), "creator must own asset");
            require(asset.get_id().expect("id") == 7, "bad owner id");
            require(asset.get_creator_id().expect("creator id") == 7, "bad creator id");
            require(asset.get_owner().expect("owner") == asset.get_creator().expect("creator"), "owner and creator should match");

            let by_id = Asset::get_by_id(7).expect("asset by id");
            require(by_id.get_hash() == asset.get_hash(), "get by id mismatch");

            let by_hash = Asset::get_by_hash(asset.get_hash()).expect("asset by hash");
            require(by_hash.get_hash() == asset.get_hash(), "get by hash mismatch");

            return 0
        }
    "#;

    let mut state = MockChainState::new();
    let contract = funded_contract(&mut state, code);
    let result = invoke_contract(&mut state, &contract, InvokeContract::Entry(0), vec![])
        .await
        .expect("invoke");

    assert!(result.is_success(), "asset metadata checks failed: {:?}", result);

    let asset = created_asset_hash(&state);
    assert_eq!(state.get_contract_balance(&contract, &asset), 0);
    assert_eq!(state.get_contract_balance(&contract, &XELIS_ASSET), COST_PER_ASSET * 3);
    assert!(has_contract_log(&state, |log| matches!(
        log,
        ContractLog::NewAsset { contract: c, asset: a } if c == &contract && a == &asset
    )));
}

#[tokio::test]
async fn asset_get_by_hash_returns_null_for_unknown_hash() {
    let code = r#"
        entry main(hash: Hash) {
            require(Asset::get_by_hash(hash) == null, "unknown asset must return null");
            return 0
        }
    "#;

    let mut state = MockChainState::new();
    let contract = funded_contract(&mut state, code);
    let unknown = Hash::new([7u8; 32]);
    let result = invoke_contract(
        &mut state,
        &contract,
        InvokeContract::Entry(0),
        vec![Primitive::Opaque(unknown.into()).into()],
    )
    .await
    .expect("invoke");

    assert!(result.is_success(), "unknown hash lookup failed: {:?}", result);
}

#[tokio::test]
async fn asset_mint_updates_supply_balance_and_logs() {
    let code = r#"
        entry main() {
            let asset = Asset::create(1, "Mintable Token", "MINT", 8, MaxSupplyMode::Mintable { max_supply: 100 }).expect("asset created");

            require(asset.mint(40), "first mint failed");
            require(asset.get_supply() == 40, "bad supply after first mint");
            require(asset.mint(60), "second mint failed");
            require(asset.get_supply() == 100, "bad supply after second mint");
            require(!asset.mint(1), "mint above max supply must fail");

            return 0
        }
    "#;

    let mut state = MockChainState::new();
    let contract = funded_contract(&mut state, code);
    let result = invoke_contract(&mut state, &contract, InvokeContract::Entry(0), vec![])
        .await
        .expect("invoke");

    assert!(result.is_success(), "mint flow failed: {:?}", result);

    let asset = created_asset_hash(&state);
    assert_eq!(state.get_contract_balance(&contract, &asset), 100);
    assert!(has_contract_log(&state, |log| matches!(
        log,
        ContractLog::Mint { contract: c, asset: a, amount: 40 } if c == &contract && a == &asset
    )));
    assert!(has_contract_log(&state, |log| matches!(
        log,
        ContractLog::Mint { contract: c, asset: a, amount: 60 } if c == &contract && a == &asset
    )));
}

#[tokio::test]
async fn asset_unlimited_supply_can_mint_without_max_supply() {
    let code = r#"
        entry main() {
            let asset = Asset::create(8, "Unlimited Token", "UNLIM", 8, MaxSupplyMode::None).expect("asset created");

            require(asset.get_max_supply() == null, "unlimited asset should have no max supply");
            require(asset.is_mintable(), "unlimited asset should be mintable");
            require(asset.mint(100), "first mint failed");
            require(asset.mint(250), "second mint failed");
            require(asset.get_supply() == 350, "bad unlimited supply");

            return 0
        }
    "#;

    let mut state = MockChainState::new();
    let contract = funded_contract(&mut state, code);
    let result = invoke_contract(&mut state, &contract, InvokeContract::Entry(0), vec![])
        .await
        .expect("invoke");

    assert!(result.is_success(), "unlimited mint flow failed: {:?}", result);

    let asset = created_asset_hash(&state);
    assert_eq!(state.get_contract_balance(&contract, &asset), 350);
}

#[tokio::test]
async fn asset_unlimited_supply_mint_overflow_fails_without_mutating_balance() {
    let code = r#"
        entry create() {
            let asset = Asset::create(9, "Overflow Token", "OVER", 8, MaxSupplyMode::None).expect("asset created");
            require(asset.mint(18446744073709551615), "max mint failed");
            return 0
        }

        entry overflow() {
            let asset = Asset::get_by_id(9).expect("asset by id");
            asset.mint(1);
            return 0
        }
    "#;

    let mut state = MockChainState::new();
    let contract = funded_contract(&mut state, code);
    let create = invoke_contract(&mut state, &contract, InvokeContract::Entry(0), vec![])
        .await
        .expect("create");

    assert!(create.is_success(), "max mint setup failed: {:?}", create);

    let asset = created_asset_hash(&state);
    assert_eq!(state.get_contract_balance(&contract, &asset), u64::MAX);

    let overflow = invoke_contract(&mut state, &contract, InvokeContract::Entry(1), vec![])
        .await
        .expect("overflow");

    assert!(!overflow.is_success(), "overflow mint should fail: {:?}", overflow);
    assert_eq!(state.get_contract_balance(&contract, &asset), u64::MAX);
}

#[tokio::test]
async fn asset_fixed_supply_is_minted_once_and_not_mintable() {
    let code = r#"
        entry main() {
            let asset = Asset::create(2, "Fixed Token", "FIXED", 2, MaxSupplyMode::Fixed { max_supply: 77 }).expect("asset created");

            require(asset.get_supply() == 77, "fixed supply should be minted at creation");
            require(asset.get_max_supply().expect("max supply") == 77, "bad fixed max supply");
            require(!asset.is_mintable(), "fixed supply must not be mintable");
            require(!asset.mint(1), "fixed supply mint must fail");

            return 0
        }
    "#;

    let mut state = MockChainState::new();
    let contract = funded_contract(&mut state, code);
    let result = invoke_contract(&mut state, &contract, InvokeContract::Entry(0), vec![])
        .await
        .expect("invoke");

    assert!(result.is_success(), "fixed supply flow failed: {:?}", result);

    let asset = created_asset_hash(&state);
    assert_eq!(state.get_contract_balance(&contract, &asset), 77);
}

#[tokio::test]
async fn asset_create_rejects_invalid_metadata_and_zero_supply() {
    let cases = [
        (
            r#"
                entry main() {
                    Asset::create(1, "Valid Name", "TOOLONGTK", 8, MaxSupplyMode::None);
                    return 0
                }
            "#,
            "Asset ticker is too long",
        ),
        (
            r#"
                entry main() {
                    Asset::create(1, "Valid Name", "bad", 8, MaxSupplyMode::None);
                    return 0
                }
            "#,
            "Asset ticker must be ASCII only",
        ),
        (
            r#"
                entry main() {
                    Asset::create(1, " Bad Name", "GOOD", 8, MaxSupplyMode::None);
                    return 0
                }
            "#,
            "Asset name must be ASCII only",
        ),
        (
            r#"
                entry main() {
                    Asset::create(1, "Zero Supply", "ZERO", 8, MaxSupplyMode::Mintable { max_supply: 0 });
                    return 0
                }
            "#,
            "Max supply cannot be zero",
        ),
    ];

    for (code, error) in cases {
        let mut state = MockChainState::new();
        let contract = funded_contract(&mut state, code);
        let result = invoke_contract(&mut state, &contract, InvokeContract::Entry(0), vec![])
            .await
            .expect("invoke");

        assert!(!result.is_success(), "invalid asset creation should fail: {:?}", result);
        assert_runtime_error(&result, error);
        assert_eq!(state.assets.keys().filter(|hash| **hash != XELIS_ASSET).count(), 0);
    }
}

#[tokio::test]
async fn asset_create_rejects_insufficient_xel_balance() {
    let code = r#"
        entry main() {
            Asset::create(1, "No Funds", "NOFUND", 8, MaxSupplyMode::None);
            return 0
        }
    "#;

    let mut state = MockChainState::new();
    let contract = create_contract(&mut state, code, ContractVersion::V1).expect("create contract");
    let result = invoke_contract(&mut state, &contract, InvokeContract::Entry(0), vec![])
        .await
        .expect("invoke");

    assert!(!result.is_success(), "asset creation without funds should fail: {:?}", result);
    assert_runtime_error(&result, "Insufficient XEL funds");
    assert_eq!(state.assets.keys().filter(|hash| **hash != XELIS_ASSET).count(), 0);
}

#[tokio::test]
async fn asset_duplicate_id_returns_null() {
    let code = r#"
        entry main() {
            let first = Asset::create(3, "Duplicate Token", "DUP", 8, MaxSupplyMode::None).expect("first asset");
            require(Asset::create(3, "Duplicate Token", "DUP", 8, MaxSupplyMode::None) == null, "duplicate id must return null");
            require(Asset::get_by_id(3).expect("asset by id").get_hash() == first.get_hash(), "first asset must remain");

            return 0
        }
    "#;

    let mut state = MockChainState::new();
    let contract = funded_contract(&mut state, code);
    let result = invoke_contract(&mut state, &contract, InvokeContract::Entry(0), vec![])
        .await
        .expect("invoke");

    assert!(result.is_success(), "duplicate id flow failed: {:?}", result);
    assert_eq!(state.assets.keys().filter(|hash| **hash != XELIS_ASSET).count(), 1);
}

#[tokio::test]
async fn asset_native_xelis_is_read_only_and_has_no_owner() {
    let code = r#"
        entry main(asset_hash: Hash) {
            let asset = Asset::get_by_hash(asset_hash).expect("native asset");

            require(asset.get_name() == "XELIS", "bad native name");
            require(asset.get_ticker() == "XELIS", "bad native ticker");
            require(asset.get_decimals() == 8, "bad native decimals");
            require(asset.get_max_supply() == null, "native max supply should be null");
            require(asset.get_supply() == u64::MAX, "bad native supply");
            require(asset.get_owner() == null, "native owner should be null");
            require(asset.get_creator() == null, "native creator should be null");
            require(asset.get_id() == null, "native id should be null");
            require(asset.get_creator_id() == null, "native creator id should be null");
            require(asset.is_read_only(), "native asset should be read only");
            require(!asset.mint(1), "native asset mint should fail");

            return 0
        }
    "#;

    let mut state = MockChainState::new();
    let contract = funded_contract(&mut state, code);
    let result = invoke_contract(
        &mut state,
        &contract,
        InvokeContract::Entry(0),
        vec![Primitive::Opaque(XELIS_ASSET.into()).into()],
    )
    .await
    .expect("invoke");

    assert!(result.is_success(), "native xelis checks failed: {:?}", result);
}

#[tokio::test]
async fn asset_transfer_ownership_allows_new_owner_to_mint() {
    let owner_code = r#"
        entry create_and_transfer(new_owner: Hash) {
            let asset = Asset::create(4, "Transfer Token", "MOVE", 8, MaxSupplyMode::Mintable { max_supply: 100 }).expect("asset created");

            require(!asset.transfer_ownership(get_contract_hash()), "transfer to self must fail");
            require(asset.transfer_ownership(new_owner), "transfer ownership failed");
            require(asset.is_read_only(), "old owner should become read only");
            require(!asset.mint(1), "old owner must not mint after transfer");

            return 0
        }
    "#;
    let new_owner_code = r#"
        entry mint(asset_hash: Hash) {
            let asset = Asset::get_by_hash(asset_hash).expect("asset by hash");

            require(!asset.is_read_only(), "new owner must own asset");
            require(asset.get_owner().expect("owner") == get_contract_hash(), "bad new owner");
            require(asset.get_creator().expect("creator") != get_contract_hash(), "creator should stay original");
            require(asset.mint(25), "new owner mint failed");

            return 0
        }
    "#;

    let mut state = MockChainState::new();
    let owner = funded_contract(&mut state, owner_code);
    let new_owner = funded_contract(&mut state, new_owner_code);
    state.provider.contracts.entry(new_owner.clone()).or_default();

    let transfer = invoke_contract(
        &mut state,
        &owner,
        InvokeContract::Entry(0),
        vec![Primitive::Opaque(new_owner.clone().into()).into()],
    )
    .await
    .expect("transfer");

    assert!(transfer.is_success(), "ownership transfer failed: {:?}", transfer);

    let asset = created_asset_hash(&state);
    let mint = invoke_contract(
        &mut state,
        &new_owner,
        InvokeContract::Entry(0),
        vec![Primitive::Opaque(asset.clone().into()).into()],
    )
    .await
    .expect("mint");

    assert!(mint.is_success(), "new owner mint failed: {:?}", mint);
    assert_eq!(state.get_contract_balance(&owner, &asset), 0);
    assert_eq!(state.get_contract_balance(&new_owner, &asset), 25);
}

#[tokio::test]
async fn asset_non_owner_cannot_transfer_ownership() {
    let owner_code = r#"
        entry create() {
            Asset::create(10, "Owner Token", "OWNER", 8, MaxSupplyMode::Mintable { max_supply: 100 }).expect("asset created");
            return 0
        }
    "#;
    let other_code = r#"
        entry try_transfer(asset_hash: Hash, new_owner: Hash) {
            let asset = Asset::get_by_hash(asset_hash).expect("asset by hash");

            require(asset.is_read_only(), "non-owner should be read only");
            require(!asset.transfer_ownership(new_owner), "non-owner transfer should fail");
            require(!asset.mint(1), "non-owner mint should fail");

            return 0
        }
    "#;

    let mut state = MockChainState::new();
    let owner = funded_contract(&mut state, owner_code);
    let other = funded_contract(&mut state, other_code);
    state.provider.contracts.entry(other.clone()).or_default();

    let create = invoke_contract(&mut state, &owner, InvokeContract::Entry(0), vec![])
        .await
        .expect("create");
    assert!(create.is_success(), "asset creation failed: {:?}", create);

    let asset = created_asset_hash(&state);
    let result = invoke_contract(
        &mut state,
        &other,
        InvokeContract::Entry(0),
        vec![
            Primitive::Opaque(asset.clone().into()).into(),
            Primitive::Opaque(other.clone().into()).into(),
        ],
    )
    .await
    .expect("invoke");

    assert!(result.is_success(), "non-owner checks failed: {:?}", result);
    assert_eq!(state.get_contract_balance(&owner, &asset), 0);
    assert_eq!(state.get_contract_balance(&other, &asset), 0);
}

#[tokio::test]
async fn asset_ownership_can_transfer_again_and_original_id_still_resolves() {
    let owner_code = r#"
        entry create_and_transfer(new_owner: Hash) {
            let asset = Asset::create(11, "Chain Token", "CHAIN", 8, MaxSupplyMode::Mintable { max_supply: 100 }).expect("asset created");
            require(asset.transfer_ownership(new_owner), "first transfer failed");
            return 0
        }

        entry verify_original_id(asset_hash: Hash) {
            let asset = Asset::get_by_id(11).expect("asset by original id");
            require(asset.get_hash() == asset_hash, "original creator id should still resolve");
            require(asset.is_read_only(), "original owner should be read only after transfer");
            return 0
        }
    "#;
    let middle_code = r#"
        entry transfer_again(asset_hash: Hash, next_owner: Hash) {
            let asset = Asset::get_by_hash(asset_hash).expect("asset by hash");

            require(!asset.is_read_only(), "middle owner must own asset");
            require(asset.get_id().expect("id") == 11, "origin id should remain");
            require(asset.transfer_ownership(next_owner), "second transfer failed");
            require(asset.is_read_only(), "middle owner should become read only");

            return 0
        }
    "#;
    let final_code = r#"
        entry verify(asset_hash: Hash) {
            let asset = Asset::get_by_hash(asset_hash).expect("asset by hash");

            require(!asset.is_read_only(), "final owner must own asset");
            require(asset.get_owner().expect("owner") == get_contract_hash(), "bad final owner");
            require(asset.get_creator().expect("creator") != get_contract_hash(), "creator should remain original");
            require(asset.get_id().expect("id") == 11, "origin id should remain after transfers");
            require(Asset::get_by_id(11) == null, "new owner should not resolve original creator id");
            require(asset.mint(33), "final owner mint failed");

            return 0
        }
    "#;
    let mut state = MockChainState::new();
    let owner = funded_contract(&mut state, owner_code);
    let middle = funded_contract(&mut state, middle_code);
    let final_owner = funded_contract(&mut state, final_code);
    state.provider.contracts.entry(middle.clone()).or_default();
    state.provider.contracts.entry(final_owner.clone()).or_default();

    let first = invoke_contract(
        &mut state,
        &owner,
        InvokeContract::Entry(0),
        vec![Primitive::Opaque(middle.clone().into()).into()],
    )
    .await
    .expect("first transfer");
    assert!(first.is_success(), "first transfer failed: {:?}", first);

    let asset = created_asset_hash(&state);
    let second = invoke_contract(
        &mut state,
        &middle,
        InvokeContract::Entry(0),
        vec![
            Primitive::Opaque(asset.clone().into()).into(),
            Primitive::Opaque(final_owner.clone().into()).into(),
        ],
    )
    .await
    .expect("second transfer");
    assert!(second.is_success(), "second transfer failed: {:?}", second);

    let final_check = invoke_contract(
        &mut state,
        &final_owner,
        InvokeContract::Entry(0),
        vec![Primitive::Opaque(asset.clone().into()).into()],
    )
    .await
    .expect("final check");
    assert!(final_check.is_success(), "final owner checks failed: {:?}", final_check);

    let original_check = invoke_contract(
        &mut state,
        &owner,
        InvokeContract::Entry(1),
        vec![Primitive::Opaque(asset.clone().into()).into()],
    )
    .await
    .expect("original check");
    assert!(original_check.is_success(), "original id check failed: {:?}", original_check);
    assert_eq!(state.get_contract_balance(&final_owner, &asset), 33);
}

#[tokio::test]
async fn asset_transfer_ownership_rejects_missing_contract() {
    let code = r#"
        entry main(new_owner: Hash) {
            let asset = Asset::create(5, "Missing Owner Token", "MISS", 8, MaxSupplyMode::Mintable { max_supply: 100 }).expect("asset created");

            require(!asset.transfer_ownership(new_owner), "transfer to missing contract must fail");
            require(!asset.is_read_only(), "owner should stay unchanged");
            require(asset.mint(10), "current owner should still mint");

            return 0
        }
    "#;

    let mut state = MockChainState::new();
    let contract = funded_contract(&mut state, code);
    let missing = Hash::new([42u8; 32]);
    let result = invoke_contract(
        &mut state,
        &contract,
        InvokeContract::Entry(0),
        vec![Primitive::Opaque(missing.into()).into()],
    )
    .await
    .expect("invoke");

    assert!(result.is_success(), "missing owner transfer flow failed: {:?}", result);

    let asset = created_asset_hash(&state);
    assert_eq!(state.get_contract_balance(&contract, &asset), 10);
}
