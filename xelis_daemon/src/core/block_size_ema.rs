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