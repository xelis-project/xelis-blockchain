use curve25519_dalek::{ristretto::{RistrettoPoint, CompressedRistretto}, scalar::Scalar, constants::RISTRETTO_BASEPOINT_TABLE, traits::Identity};

// Number of elements present in the lookup table
// memory usage is following:
// 2^N * BYTES_PER_POINT
// current implementation:
// 2^24 * 5 = 80MiB
const TABLE_SIZE: usize = 2usize.pow(24);

// number of bytes to use for the lookup table
// memory can be reduced by using less bytes
// but it will increase the number of HE operations
// Recommended values are 4 or 5
const BYTES_PER_POINT: usize = 5;

// elements per batch when generating the table
const ELEMENTS_PER_BATCH: usize = 256;

// Simple structure to store the last B bytes of a compressed point
#[derive(PartialEq, Debug, Clone, Copy)]
struct C([u8; BYTES_PER_POINT]);

// LookupTable generate a Precomputed table of TABLE_SIZE elements
// Each element is a B bytes value of the last B bytes of the compressed point
// The table is used to speed up the decryption
// And use the HE subtraction operation for values higher than the computed table
// It is generic and can be used by several wallets at same time
pub struct LookupTable {
    table: Vec<C>
}

fn compressed_to_c(compressed: CompressedRistretto) -> C {
    let bytes = compressed.to_bytes();
    let mut data: [u8; BYTES_PER_POINT] = [0; BYTES_PER_POINT];
    for i in 0..BYTES_PER_POINT {
        data[i] = bytes[bytes.len() - i - 1];
    }

    C(data)
}

fn double_point(point: &RistrettoPoint) -> C {
    compressed_to_c((point + point).compress())
}

impl LookupTable {
    pub fn new() -> Self {
        let mut table = Vec::with_capacity(TABLE_SIZE);
        let mut val = &Scalar::from(0u64) * &RISTRETTO_BASEPOINT_TABLE;
        // Register 0 value
        table.push(double_point(&val));

        let one = &Scalar::from(1u64) * &RISTRETTO_BASEPOINT_TABLE;
        for _ in 0..TABLE_SIZE / ELEMENTS_PER_BATCH {
            let mut tmp = [RistrettoPoint::identity(); ELEMENTS_PER_BATCH];
            for i in 0..tmp.len() {
                val += one;
                tmp[i] = val;
            }

            RistrettoPoint::double_and_compress_batch(&tmp)
            .into_iter()
            .map(compressed_to_c)
            .for_each(|c| {
                table.push(c);
            });
        }

        LookupTable {
            table
        }
    }

    // Decode a Ristretto Point to a u64 value by searching in the table
    // which value is the closest to the given point and its index
    // Even if the real value is not found, we use HE subtraction to reduce the
    // value to search and try again
    pub fn lookup(&self, value: &RistrettoPoint) -> u64 {
        let table_size = self.table.len() as u64;
        // amount to subtract to the value to search at each iteration
        let sub = &Scalar::from(table_size) * &RISTRETTO_BASEPOINT_TABLE;

        let mut local_value = value.clone();
        let mut plaintext = 0;
        loop {
            let c = double_point(&local_value);
            if let Some(part) = self.table.iter().position(|v| *v == c) {
                let total = plaintext + part as u64;
                if &Scalar::from(total) * &RISTRETTO_BASEPOINT_TABLE == *value {
                    return total;
                }
            }

            // Value to search is bigger than table, use HE to reduce it
            local_value -= sub;
            plaintext += table_size;
        }
    }
}

impl Default for LookupTable {
    fn default() -> Self {
        Self::new()
    }
}

mod tests {
    fn _assert_value(value: u64) {
        let m = &super::Scalar::from(value) * &super::RISTRETTO_BASEPOINT_TABLE;
        let table = super::LookupTable::default();
        assert_eq!(table.lookup(&m), value);
    }

    #[test]
    fn test_lookup_find_0() {
        _assert_value(0);
    }

    #[test]
    fn test_lookup_find_1_000_000() {
        _assert_value(1_000_000);
    }

    #[test]
    fn test_lookup_find_100_000_00000() {
        _assert_value(100_000_00000);
    }
}