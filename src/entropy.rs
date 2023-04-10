use std::fs::File;
use std::io::Read;

/// Contains metadata about the file that's being used in the Entropy calculation.
///
/// `byte_count` is a lookup table that contains the number of occurances of
/// a byte specified by the index, e.g. 0x00 is `byte_count[0]`.
///
/// `length` is the number of bytes in the file.
pub struct Entropy {
    pub byte_count: [u64; 256],
}

impl Entropy {
    /// Gets metadata for the Entropy calculation from a File reference
    pub fn new() -> Entropy {
        let mut byte_count = [0u64; 256];
        // file metadata unwrap len()
        Entropy { byte_count }
    }

    /// Gets metadata for the Entropy calculation from a File reference
    pub fn update(&mut self, buffer: &[u8]) {
        for byte in buffer.iter() {
            let x = *byte as usize;
            self.byte_count[x] += 1
        }
    }

    /// Measures the Shannon entropy based on the frequency table and returns
    /// it as a float.
    ///
    /// The equation is defined as: H(X) = - \sum_{i=0}^{n} P(x_i) log_2 P(x_i)
    /// It can be described as the minimum number of bits (per symbol) to encode
    /// the input. Thus the output will be between 0 and 8.
    /// See https://en.wikipedia.org/wiki/Entropy_(information_theory) for
    /// more information.
    pub fn shannon_entropy(&self, length: f32) -> f32 {
        let mut entropy = 0f32;
        for &count in self.byte_count.iter() {
            if count != 0 {
                let symbol_probability = count as f32 / length;
                entropy += symbol_probability * symbol_probability.log2();
            }
        }
        -entropy
    }

    /// Measures the metric entropy based on the Shannon entropy of the
    /// generated frequency table and returns it as a float between 0 and 1.
    ///
    /// Metric entropy is derived by dividing the Shannon entropy by the length
    /// of the string being measured.
    /// It can be described as the uncertainty or randomness of a string, where
    /// 1 means information is uniformly distributed across the string.
    pub fn metric_entropy(&self, length: f32) -> f32 {
        self.shannon_entropy(length) / 8f32
    }
}
