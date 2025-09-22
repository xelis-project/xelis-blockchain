// NOTE: we don't use f64 to prevent any issue that could occurs
// based on the platform/rust version differences
// see `f64::powf`
pub struct BlockSizeEma {
    value: u128,
    alpha_inc: u128,
    alpha_dec: u128,
}

impl BlockSizeEma {
    pub const SCALE: u128 = 1_000_000;

    pub fn default(initial: usize) -> Self {
        Self::new(initial, 0.05, 0.01)
    }

    pub fn new(initial: usize, alpha_inc: f64, alpha_dec: f64) -> Self {
        let value_scaled = (initial as u128) * Self::SCALE;

        Self {
            value: value_scaled,
            alpha_inc: (alpha_inc * Self::SCALE as f64).round() as u128,
            alpha_dec: (alpha_dec * Self::SCALE as f64).round() as u128,
        }
    }

    pub fn add(&mut self, block_size: usize) {
        let block_scaled = (block_size as u128) * Self::SCALE;

        // pick alpha depending on direction
        let alpha = if block_scaled > self.value {
            self.alpha_inc
        } else {
            self.alpha_dec
        };

        self.value = (alpha * block_scaled + (Self::SCALE - alpha) * self.value)
            / Self::SCALE;
    }

    pub fn current(&self) -> u32 {
        (self.value / Self::SCALE) as u32
    }
}

#[cfg(test)]
mod tests {
    use xelis_common::config::MAX_BLOCK_SIZE;
    use super::*;

    #[test]
    fn test_deterministic_ema() {
        let mut ema = BlockSizeEma::new(0, 0.18, 0.18);
        let blocks = [1000, 2000, 1500, 3000];

        for &b in &blocks {
            ema.add(b);
        }

        // Check value is deterministic
        assert_eq!(ema.current(), 1102);
    }

    #[test]
    fn test_ema_increase() {
        // initial block empty
        let mut ema = BlockSizeEma::default(124);
        ema.add(MAX_BLOCK_SIZE);

        assert_eq!(ema.current(), 65_653);

        ema.add(MAX_BLOCK_SIZE);
        assert_eq!(ema.current(), 127_907);
    }

    #[test]
    fn test_ema_decrease() {
        // initial full block
        let mut ema = BlockSizeEma::default(MAX_BLOCK_SIZE);
        ema.add(124);
        assert_eq!(ema.current(), 1_245_190);

        ema.add(124);
        assert_eq!(ema.current(), 1_182_936);
    }

    #[test]
    fn test_single_update() {
        let mut ema = BlockSizeEma::new(0, 0.5, 0.5);
        ema.add(100);
        // value = 0.5 * 100 + 0.5 * 0
        assert_eq!(ema.current(), 50);
    }

    #[test]
    fn test_alpha_effect() {
        // With alpha=1.0, EMA should always equal the last value
        let mut ema = BlockSizeEma::new(0, 1.0, 1.0);
        ema.add(100);
        assert_eq!(ema.current(), 100);
        ema.add(200);
        assert_eq!(ema.current(), 200);

        // With alpha=0.0, EMA should never change from initial
        let mut ema = BlockSizeEma::new(0, 0.0, 0.0);
        ema.add(100);
        assert_eq!(ema.current(), 0);
        ema.add(200);
        assert_eq!(ema.current(), 0);
    }

    #[test]
    fn test_converges_towards_constant_input() {
        let mut ema = BlockSizeEma::new(0, 0.2, 0.2);
        for _ in 0..50 {
            ema.add(100);
        }
        // After enough iterations, EMA should be very close to 100
        let v = ema.current();
        assert_eq!(v, 99);
    }
}