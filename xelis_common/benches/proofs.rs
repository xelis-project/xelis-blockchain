use bulletproofs::RangeProof;
use criterion::{criterion_group, criterion_main, Criterion};
use merlin::Transcript;
use xelis_common::crypto::{
    elgamal::{PedersenCommitment, PedersenOpening},
    proofs::{
        BatchCollector,
        CiphertextValidityProof,
        CommitmentEqProof,
        BP_GENS,
        PC_GENS,
        BULLET_PROOF_SIZE,
    },
    KeyPair
};

// CommitmentEqProof is a ZK Proof proving that the final balance (commitment) is equal to the initial balance minus the amount
fn bench_commitment_eq_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment_eq_proof");

    let balance = 100u64;
    let amount = 5;
    let keypair = KeyPair::new();
    // Generate our initial balance
    let source_balance = keypair.get_public_key().encrypt(balance);

    // Generate the ciphertext representing the TX amount
    let ciphertext = keypair.get_public_key().encrypt(amount);
    // Commitment of the final balance using the same Opening
    let opening = PedersenOpening::generate_new();
    let commitment = PedersenCommitment::new_with_opening(balance - amount, &opening);

    // Compute the final balance
    let final_balance = source_balance - ciphertext;
    
    let mut transcript = Transcript::new(b"test");
    // Generate the proof
    let proof = CommitmentEqProof::new(&keypair, &final_balance, &opening, balance - amount, &mut transcript);

    group.bench_function("pre_verify", |b| {
        b.iter(|| {
            proof.pre_verify(
                keypair.get_public_key(),
                &final_balance,
                &commitment,
                &mut Transcript::new(b"test"),
                &mut BatchCollector::default()
            ).expect("Failed to verify proof");
        })
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            let mut batch_collector = BatchCollector::default();
            proof.pre_verify(
                keypair.get_public_key(),
                &final_balance,
                &commitment,
                &mut Transcript::new(b"test"),
                &mut batch_collector
            ).expect("Failed to verify proof");
            batch_collector.verify().expect("Failed to verify batch");
        })
    });
}

// CiphertextValidityProof is a ZK Proof proving that the ciphertext well formed for both the sender and receiver
fn bench_ciphertext_validity_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("ciphertext_validity_proof");

    let destination = KeyPair::new();
    let source = KeyPair::new();

    // Generate the commitment representing the transfer amount
    let amount = 5u64;
    let opening = PedersenOpening::generate_new();
    let commitment = PedersenCommitment::new_with_opening(amount, &opening);

    // Create the receiver handle
    let receiver_handle = destination.get_public_key().decrypt_handle(&opening);
    // Create the sender handle
    let sender_handle = source.get_public_key().decrypt_handle(&opening);

    // Generate the proof
    let mut transcript = Transcript::new(b"test");
    let proof = CiphertextValidityProof::new(destination.get_public_key(), Some(source.get_public_key()), amount, &opening, &mut transcript);

    group.bench_function("pre_verify", |b| {
        b.iter(|| {
            // Verify the proof
            proof.pre_verify(
                &commitment,
                destination.get_public_key(),
                source.get_public_key(),
                &receiver_handle,
                &sender_handle,
                true,
                &mut Transcript::new(b"test"),
                &mut BatchCollector::default(),
            ).expect("Failed to verify proof");
        })
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            // Verify the proof
            let mut batch_collector = BatchCollector::default();
            proof.pre_verify(
                &commitment,
                destination.get_public_key(),
                source.get_public_key(),
                &receiver_handle,
                &sender_handle,
                true,
                &mut Transcript::new(b"test"),
                &mut batch_collector,
            ).expect("Failed to verify proof");
            batch_collector.verify().expect("Failed to verify batch");
        })
    });
}

fn bench_range_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_proof");

    // Generate the commitment representing the transfer amount
    let amount = 5u64;

    // Generate the proof
    let mut transcript = Transcript::new(b"test");
    let opening = PedersenOpening::generate_new();
    let (range_proof, commitment) = RangeProof::prove_single(
        &BP_GENS,
        &PC_GENS,
        &mut transcript,
        amount,
        &opening.as_scalar(),
        BULLET_PROOF_SIZE
    ).expect("Failed to generate proof");

    let decompressed_commitment = commitment.decompress().expect("Failed to decompress commitment");

    group.bench_function("verify", |b| {
        b.iter(|| {
            range_proof.verify_single(
                &BP_GENS,
                &PC_GENS,
                &mut Transcript::new(b"test"),
                &(decompressed_commitment.clone(), commitment.clone()),
                BULLET_PROOF_SIZE
            ).expect("Failed to verify proof");
        })
    });
}

criterion_group!(
    proofs_benches,
    bench_commitment_eq_proof,
    bench_ciphertext_validity_proof,
    bench_range_proof
);
criterion_main!(proofs_benches);