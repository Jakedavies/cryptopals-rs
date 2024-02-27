use std::num::Wrapping;


const W: usize = 32;
const N: usize = 624;
const M: usize = 397;
const R: usize = 31;
const A: u32 = 0x9908B0DF;

const L: u32 = 18;

const F: u32 = 1812433253;

const LOWER_MASK: u32 = (1 << R) -1;
const UPPER_MASK: u32 = !LOWER_MASK;


struct Mt19937 {
    state: [Wrapping<u32>; N],
    index: usize,
}

impl Mt19937 {
    fn twist(&mut self) {
        for i in 0..(N-1) {
            let x = self.state[i] & Wrapping(UPPER_MASK) | self.state[i+1 % N] & Wrapping(LOWER_MASK);
            let mut x_a = x >> 1;
            if x % Wrapping(2) != Wrapping(0) {
                x_a ^= A;
            }
            self.state[i] = self.state[(i + M) % N] ^ x_a;
        }
        self.index = 0;
    }

    fn int(&mut self) -> u32 {
        if self.index >= N {
            self.twist();
        }

        let mut y = self.state[self.index];
        y = y ^ (y >> 11) & Wrapping(0xFFFFFFFF);
        y = y ^ (y << 7) & Wrapping(0x9D2C5680);
        y = y ^ (y << 15) & Wrapping(0xEFC60000);
        y = y ^ (y >> 18);

        self.index += 1;

        y.0
    }
}


fn rng(seed: u32) -> Mt19937 {
    let mut rng = Mt19937 {
        state: [Wrapping(0); N],
        index: N,
    };
    rng.state[0] = Wrapping(seed);
    for i in 1..N {
        rng.state[i] = Wrapping(F) * (rng.state[i-1] ^ (rng.state[i-1] >> (W-2))) + Wrapping(i as u32); 
    };
    rng
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seeded_mt() {
        let mut rng = rng(5489_u32);
        assert_eq!(rng.int(), 3499211612);
        assert_eq!(rng.int(), 581869302);
    }

}
