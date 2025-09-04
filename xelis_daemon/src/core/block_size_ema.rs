pub struct BlockSizeEma {
    value: f64,
    alpha: f64
}

impl BlockSizeEma {
    pub fn new(alpha: f64) -> Self {
        Self {
            value: 0f64,
            alpha
        }
    }

    pub fn add(&mut self, block_size: f64) {
        self.value = self.alpha * block_size + (1.0 - self.alpha) * self.value;
    }

    pub fn alpha(&self) -> f64 {
        self.alpha
    }

    pub fn current(&self) -> f64 {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_update() {
        let mut ema = BlockSizeEma::new(0.5);
        ema.add(100.0);
        // value = 0.5 * 100 + 0.5 * 0
        assert_eq!(ema.current(), 50.0);
    }

    #[test]
    fn test_alpha_effect() {
        // With alpha=1.0, EMA should always equal the last value
        let mut ema = BlockSizeEma::new(1.0);
        ema.add(100.0);
        assert_eq!(ema.current(), 100.0);
        ema.add(200.0);
        assert_eq!(ema.current(), 200.0);

        // With alpha=0.0, EMA should never change from initial
        let mut ema = BlockSizeEma::new(0.0);
        ema.add(100.0);
        assert_eq!(ema.current(), 0.0);
        ema.add(200.0);
        assert_eq!(ema.current(), 0.0);
    }

    #[test]
    fn test_converges_towards_constant_input() {
        let mut ema = BlockSizeEma::new(0.2);
        for _ in 0..50 {
            ema.add(100.0);
        }
        // After enough iterations, EMA should be very close to 100
        let v = ema.current();
        assert!(v > 99f64 && v < 100f64);
    }
}