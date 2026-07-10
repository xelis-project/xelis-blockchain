use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use futures::{TryStreamExt, stream};
use std::{
    collections::HashMap,
    hint::black_box,
    sync::{Arc, OnceLock},
};
use tokio::runtime::{Builder, Runtime};
use xelis_common::{
    account::{CiphertextCache, Nonce},
    config::{COIN_VALUE, XELIS_ASSET},
    crypto::{
        elgamal::Ciphertext,
        Hash,
        Hashable,
        PublicKey,
    },
    transaction::{
        builder::{
            AccountState,
            FeeBuilder,
            FeeHelper,
            TransactionBuilder,
            TransactionTypeBuilder,
            TransferBuilder,
        },
        mock::{
            MockAccount,
            MockChainState,
            TrackedAccount,
            TrackedBalance,
        },
        verify::NoZKPCache,
        Reference,
        Transaction,
        TxVersion,
    },
    utils::detect_available_parallelism,
};

const TRANSFER_COUNTS: [usize; 4] = [1, 16, 64, 255];
const BATCH_SIZES: [usize; 8] = [1, 4, 8, 16, 32, 64, 128, 256];
const MAX_BATCH_SIZE: usize = 256;
const TRANSFER_AMOUNT: u64 = 0;

struct TransactionsFixture {
    txs: Vec<(Arc<Transaction>, Hash)>,
    base_state: MockChainState,
}

struct BenchAccountState {
    balances: HashMap<Hash, TrackedBalance>,
    reference: Reference,
    nonce: Nonce,
}

static TRANSFERS_1_FIXTURE: OnceLock<TransactionsFixture> = OnceLock::new();
static TRANSFERS_16_FIXTURE: OnceLock<TransactionsFixture> = OnceLock::new();
static TRANSFERS_64_FIXTURE: OnceLock<TransactionsFixture> = OnceLock::new();
static TRANSFERS_255_FIXTURE: OnceLock<TransactionsFixture> = OnceLock::new();

fn reference() -> Reference {
    Reference {
        topoheight: 0,
        hash: Hash::zero(),
    }
}

fn insert_account(state: &mut MockChainState, account: &TrackedAccount) {
    let balances = account
        .balances
        .iter()
        .map(|(asset, balance)| {
            (
                asset.clone(),
                balance
                    .ciphertext
                    .clone()
                    .take_ciphertext()
                    .expect("tracked ciphertext should be valid"),
            )
        })
        .collect::<HashMap<_, _>>();

    state.accounts.insert(
        account.keypair.get_public_key().compress(),
        MockAccount {
            balances,
            nonce: account.nonce,
        },
    );
}

fn build_transfers(destination: &TrackedAccount, count: usize) -> Vec<TransferBuilder> {
    let destination = destination.address();
    (0..count)
        .map(|_| TransferBuilder {
            amount: TRANSFER_AMOUNT,
            destination: destination.clone(),
            asset: XELIS_ASSET,
            extra_data: None,
            encrypt_extra_data: true,
        })
        .collect()
}

impl FeeHelper for BenchAccountState {
    type Error = &'static str;

    fn get_max_fee(&self, fee: u64) -> u64 {
        fee
    }

    fn account_exists(&self, _: &PublicKey) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

impl AccountState for BenchAccountState {
    fn is_mainnet(&self) -> bool {
        false
    }

    fn get_account_balance(&self, asset: &Hash) -> Result<u64, Self::Error> {
        self.balances
            .get(asset)
            .map(|balance| balance.balance)
            .ok_or("account balance not found")
    }

    fn get_account_ciphertext(&self, asset: &Hash) -> Result<CiphertextCache, Self::Error> {
        self.balances
            .get(asset)
            .map(|balance| balance.ciphertext.clone())
            .ok_or("account ciphertext not found")
    }

    fn get_reference(&self) -> Reference {
        self.reference.clone()
    }

    fn update_account_balance(
        &mut self,
        asset: &Hash,
        balance: u64,
        ciphertext: Ciphertext,
    ) -> Result<(), Self::Error> {
        self.balances.insert(
            asset.clone(),
            TrackedBalance {
                balance,
                ciphertext: CiphertextCache::Decompressed(None, ciphertext),
            },
        );
        Ok(())
    }

    fn get_nonce(&self) -> Result<Nonce, Self::Error> {
        Ok(self.nonce)
    }

    fn update_nonce(&mut self, new_nonce: Nonce) -> Result<(), Self::Error> {
        self.nonce = new_nonce;
        Ok(())
    }
}

fn build_fixture(transfers_count: usize) -> TransactionsFixture {
    // Create a single destination and a base state. For each transaction we
    // will generate a fresh random source account, insert it into the base
    // state and build the transaction from that source.
    let mut destination = TrackedAccount::new();
    destination.set_balance(XELIS_ASSET, 0);

    let mut base_state = MockChainState::new();
    insert_account(&mut base_state, &destination);

    let mut txs = Vec::with_capacity(MAX_BATCH_SIZE);

    for _ in 0..MAX_BATCH_SIZE {
        // Generate a fresh random source account for this tx
        let mut source = TrackedAccount::new();
        source.set_balance(XELIS_ASSET, 1000 * COIN_VALUE);

        // Insert the source into the base state so verification/apply can
        // find and update it.
        insert_account(&mut base_state, &source);

        let mut account_state = BenchAccountState {
            balances: source.balances.clone(),
            reference: reference(),
            nonce: source.nonce,
        };

        let builder = TransactionBuilder::new(
            TxVersion::V3,
            source.keypair.get_public_key().compress(),
            None,
            TransactionTypeBuilder::Transfers(build_transfers(&destination, transfers_count)),
            FeeBuilder::default(),
        );

        let tx = Arc::new(
            builder
                .build(&mut account_state, &source.keypair)
                .expect("transaction fixture should build"),
        );
        let hash = tx.hash();

        txs.push((tx, hash));
    }

    TransactionsFixture { txs, base_state }
}

fn fixture_for(transfers_count: usize) -> &'static TransactionsFixture {
    match transfers_count {
        1 => TRANSFERS_1_FIXTURE.get_or_init(|| build_fixture(1)),
        16 => TRANSFERS_16_FIXTURE.get_or_init(|| build_fixture(16)),
        64 => TRANSFERS_64_FIXTURE.get_or_init(|| build_fixture(64)),
        255 => TRANSFERS_255_FIXTURE.get_or_init(|| build_fixture(255)),
        _ => unreachable!("unsupported transfer count"),
    }
}

async fn verify_batch(
    batches: Vec<Vec<(Arc<Transaction>, Hash)>>,
    state: &MockChainState,
    parallelism: usize,
) {
    // Run verification for already-prepared batches concurrently.
    stream::iter(batches.into_iter().map(Ok))
        .try_for_each_concurrent(parallelism, |batch| async move {
            let mut chain_state = state.clone();
            Transaction::verify_batch(
                batch.iter().map(|(tx, hash)| (tx, hash)),
                &mut chain_state,
                &NoZKPCache,
            )
            .await
        })
        .await
        .expect("transaction batch should verify");
}

async fn apply_batch(txs: &[(Arc<Transaction>, Hash)], state: &mut MockChainState) {
    for (tx, hash) in txs {
        tx.apply_with_partial_verify(hash, state)
            .await
            .expect("transaction should apply");
    }
}

fn bench_verify(
    c: &mut Criterion,
    runtime: &Runtime,
) {
    let parallelism = detect_available_parallelism();
    let mut group = c.benchmark_group("transactions_verify_batch");

    for transfers_count in TRANSFER_COUNTS {
        for batch_size in BATCH_SIZES {
            let fixture = fixture_for(transfers_count);
            let txs = &fixture.txs[..batch_size];

            // Prepare the batches once using the detected parallelism.
            let batch_size_for_split = (txs.len() + parallelism - 1) / parallelism;
            let prepared_batches: Vec<Vec<(Arc<Transaction>, Hash)>> = txs
                .chunks(batch_size_for_split)
                .map(|chunk| chunk.to_vec())
                .collect();

            assert!(prepared_batches.len() <= parallelism);
            assert_eq!(prepared_batches.iter().map(|b| b.len()).sum::<usize>(), txs.len());

            group.bench_function(
                format!("transfers_{transfers_count}/txs_{batch_size}"),
                |b| b.iter_batched_ref(
                    || fixture.base_state.clone(),
                    |state| runtime.block_on(verify_batch(prepared_batches.clone(), state, parallelism)),
                    BatchSize::SmallInput,
                ),
            );
        }
    }

    group.finish();
}

fn bench_apply(
    c: &mut Criterion,
    runtime: &Runtime,
) {
    let mut group = c.benchmark_group("transactions_apply_partial_verify");

    for transfers_count in TRANSFER_COUNTS {
        for batch_size in BATCH_SIZES {
            group.bench_function(
                format!("transfers_{transfers_count}/txs_{batch_size}"),
                |b| {
                    let fixture = fixture_for(transfers_count);
                    let txs = &fixture.txs[..batch_size];
                    b.iter_batched_ref(
                        || fixture.base_state.clone(),
                        |state| runtime.block_on(apply_batch(black_box(txs), state)),
                        BatchSize::SmallInput,
                    )
                },
            );
        }
    }

    group.finish();
}

fn bench_transactions(c: &mut Criterion) {
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime should build");

    bench_verify(c, &runtime);
    bench_apply(c, &runtime);
}

criterion_group!(transaction_benches, bench_transactions);
criterion_main!(transaction_benches);
