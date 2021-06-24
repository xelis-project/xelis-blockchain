pub const BLOCK_TIME: u64 = 30;
pub const MINIMUM_DIFFICULTY: u64 = BLOCK_TIME * 50_000;
pub const WINDOW_DIFFICULTY_BLOCK: u64 = 15;
pub const MAX_DIFFICULTY_CHANGE_PER_BLOCK: f32 = 0.05; //5% max
pub const MAX_BLOCK_SIZE: usize = (1024 * 1024) + (256 * 1024); // 1.25 MB
pub const FEE_PER_KB: u64 = 1000;
//pub const DEV_FEE_PERCENT: f32 = 0.05; //5% per block going to dev address

pub const MAX_SUPPLY: u64 = 18_400_000_00000; //18.4M
pub const EMISSION_SPEED_FACTOR: u64 = 21;