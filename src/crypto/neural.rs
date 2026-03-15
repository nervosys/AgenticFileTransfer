//! Neural Network Encoder-Decoder Cipher.
//!
//! A trainable symmetric cipher where the encryption and decryption
//! functions are learned by neural networks (an autoencoder). The
//! trained model weights serve as the symmetric key — both parties
//! must share the same `.aft.nn` model file.
//!
//! Architecture:
//!   Encoder: Dense(16→128, ReLU) → Dense(128→64, ReLU) → Dense(64→16, Sigmoid)
//!   Decoder: Dense(16→64, ReLU)  → Dense(64→128, ReLU) → Dense(128→16, Sigmoid)
//!
//! Mode of operation: CBC (Cipher Block Chaining) with 16-byte blocks.
//! Padding: PKCS7.
//!
//! **Security note**: Neural network ciphers are an active research area.
//! This implementation is experimental. For production DoD use, prefer
//! the PQC (Kyber1024 + AES-256-GCM) method.

use std::io::Write;
use std::path::Path;

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use crate::error::{AftError, AftResult};

/// Block size in bytes (128-bit blocks, matching AES).
pub const BLOCK_SIZE: usize = 16;

const MODEL_MAGIC: &[u8; 4] = b"AFTN";
const MODEL_VERSION: u8 = 1;

// ── Activation functions ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum Activation {
    ReLU,
    Sigmoid,
}

impl Activation {
    fn apply(self, x: f32) -> f32 {
        match self {
            Activation::ReLU => x.max(0.0),
            Activation::Sigmoid => 1.0 / (1.0 + (-x.clamp(-30.0, 30.0)).exp()),
        }
    }

    fn derivative(self, x: f32) -> f32 {
        match self {
            Activation::ReLU => {
                if x > 0.0 {
                    1.0
                } else {
                    0.0
                }
            }
            Activation::Sigmoid => {
                let s = self.apply(x);
                s * (1.0 - s)
            }
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            Activation::ReLU => 0,
            Activation::Sigmoid => 1,
        }
    }

    fn from_byte(b: u8) -> Self {
        match b {
            0 => Activation::ReLU,
            _ => Activation::Sigmoid,
        }
    }
}

// ── Dense layer ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DenseLayer {
    weights: Vec<f32>, // row-major: [output_dim × input_dim]
    biases: Vec<f32>,  // [output_dim]
    input_dim: usize,
    output_dim: usize,
    activation: Activation,
    // Training cache
    last_input: Vec<f32>,
    last_z: Vec<f32>, // pre-activation values
}

impl DenseLayer {
    fn new(input_dim: usize, output_dim: usize, activation: Activation, rng: &mut StdRng) -> Self {
        // Xavier uniform initialization
        let limit = (6.0 / (input_dim + output_dim) as f32).sqrt();
        let weights: Vec<f32> = (0..output_dim * input_dim)
            .map(|_| rng.gen_range(-limit..limit))
            .collect();
        let biases = vec![0.0; output_dim];

        Self {
            weights,
            biases,
            input_dim,
            output_dim,
            activation,
            last_input: Vec::new(),
            last_z: Vec::new(),
        }
    }

    /// Forward pass (mutable — caches values for backpropagation).
    fn forward(&mut self, input: &[f32]) -> Vec<f32> {
        self.last_input = input.to_vec();
        let mut z = vec![0.0f32; self.output_dim];

        for o in 0..self.output_dim {
            let mut sum = self.biases[o];
            let row_start = o * self.input_dim;
            for i in 0..self.input_dim {
                sum += self.weights[row_start + i] * input[i];
            }
            z[o] = sum;
        }

        self.last_z = z.clone();

        // Apply activation
        let mut output = z;
        for v in &mut output {
            *v = self.activation.apply(*v);
        }
        output
    }

    /// Immutable forward pass (inference only, no caching).
    fn forward_inference(&self, input: &[f32]) -> Vec<f32> {
        let mut output = vec![0.0f32; self.output_dim];
        for o in 0..self.output_dim {
            let mut sum = self.biases[o];
            let row_start = o * self.input_dim;
            for i in 0..self.input_dim {
                sum += self.weights[row_start + i] * input[i];
            }
            output[o] = self.activation.apply(sum);
        }
        output
    }

    /// Backward pass: compute gradients, update weights, return input gradient.
    fn backward(&mut self, grad_output: &[f32], lr: f32) -> Vec<f32> {
        // Gradient through activation
        let mut grad_z = vec![0.0f32; self.output_dim];
        for o in 0..self.output_dim {
            grad_z[o] = grad_output[o] * self.activation.derivative(self.last_z[o]);
        }

        // Gradient w.r.t. input (pass to previous layer)
        let mut grad_input = vec![0.0f32; self.input_dim];
        for i in 0..self.input_dim {
            let mut sum = 0.0f32;
            for o in 0..self.output_dim {
                sum += self.weights[o * self.input_dim + i] * grad_z[o];
            }
            grad_input[i] = sum;
        }

        // Update weights and biases (SGD)
        for o in 0..self.output_dim {
            let row_start = o * self.input_dim;
            for i in 0..self.input_dim {
                self.weights[row_start + i] -= lr * grad_z[o] * self.last_input[i];
            }
            self.biases[o] -= lr * grad_z[o];
        }

        grad_input
    }

    fn num_params(&self) -> usize {
        self.weights.len() + self.biases.len()
    }
}

// ── Network ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Network {
    layers: Vec<DenseLayer>,
}

impl Network {
    fn forward(&mut self, input: &[f32]) -> Vec<f32> {
        let mut x = input.to_vec();
        for layer in &mut self.layers {
            x = layer.forward(&x);
        }
        x
    }

    fn forward_inference(&self, input: &[f32]) -> Vec<f32> {
        let mut x = input.to_vec();
        for layer in &self.layers {
            x = layer.forward_inference(&x);
        }
        x
    }

    fn backward(&mut self, grad_output: &[f32], lr: f32) -> Vec<f32> {
        let mut grad = grad_output.to_vec();
        for layer in self.layers.iter_mut().rev() {
            grad = layer.backward(&grad, lr);
        }
        grad
    }

    fn num_params(&self) -> usize {
        self.layers.iter().map(|l| l.num_params()).sum()
    }
}

// ── Training configuration ──────────────────────────────────────────────────

/// Configuration for training a neural cipher.
pub struct TrainConfig {
    /// Number of training epochs.
    pub epochs: usize,
    /// Initial learning rate (decays linearly).
    pub learning_rate: f32,
    /// Number of random samples per epoch.
    pub batch_size: usize,
    /// Random seed for reproducible training.
    pub seed: u64,
}

impl Default for TrainConfig {
    fn default() -> Self {
        Self {
            epochs: 5000,
            learning_rate: 0.01,
            batch_size: 256,
            seed: 42,
        }
    }
}

// ── Neural Cipher ───────────────────────────────────────────────────────────

/// A symmetric cipher backed by trained encoder/decoder neural networks.
///
/// The encoder transforms plaintext blocks into ciphertext blocks,
/// and the decoder inverts the transformation. Both networks are
/// trained as an autoencoder so that Decoder(Encoder(x)) ≈ x.
/// The model weights serve as the symmetric key.
pub struct NeuralCipher {
    encoder: Network,
    decoder: Network,
}

impl NeuralCipher {
    /// Train a new neural cipher from scratch.
    ///
    /// This creates matched encoder/decoder networks using adversarial
    /// autoencoder training with quantization-aware loss. Training
    /// progress is printed to stderr.
    pub fn train(config: &TrainConfig) -> Self {
        let mut rng = StdRng::seed_from_u64(config.seed);

        // Encoder: 16 → 128 (ReLU) → 64 (ReLU) → 16 (Sigmoid)
        let encoder = Network {
            layers: vec![
                DenseLayer::new(BLOCK_SIZE, 128, Activation::ReLU, &mut rng),
                DenseLayer::new(128, 64, Activation::ReLU, &mut rng),
                DenseLayer::new(64, BLOCK_SIZE, Activation::Sigmoid, &mut rng),
            ],
        };

        // Decoder: 16 → 64 (ReLU) → 128 (ReLU) → 16 (Sigmoid)
        let decoder = Network {
            layers: vec![
                DenseLayer::new(BLOCK_SIZE, 64, Activation::ReLU, &mut rng),
                DenseLayer::new(64, 128, Activation::ReLU, &mut rng),
                DenseLayer::new(128, BLOCK_SIZE, Activation::Sigmoid, &mut rng),
            ],
        };

        let mut cipher = NeuralCipher { encoder, decoder };
        let total_params = cipher.encoder.num_params() + cipher.decoder.num_params();
        eprintln!(
            "  Training neural cipher ({} parameters, {} KB model)...",
            total_params,
            total_params * 4 / 1024
        );

        // Training loop
        for epoch in 0..config.epochs {
            let mut total_loss = 0.0f64;
            // Linear learning rate decay (keep 10% at the end)
            let lr = config.learning_rate * (1.0 - epoch as f32 / config.epochs as f32 * 0.9);

            for _ in 0..config.batch_size {
                // Random plaintext block (normalized to [0, 1])
                let plaintext: Vec<f32> = (0..BLOCK_SIZE)
                    .map(|_| rng.gen::<u8>() as f32 / 255.0)
                    .collect();

                // Forward: encoder → quantize (STE) → decoder
                let encoded = cipher.encoder.forward(&plaintext);

                // Quantization with straight-through estimator
                let quantized: Vec<f32> = encoded
                    .iter()
                    .map(|&x| (x * 255.0).round() / 255.0)
                    .collect();

                let decoded = cipher.decoder.forward(&quantized);

                // MSE loss
                let mut loss = 0.0f32;
                let mut grad = vec![0.0f32; BLOCK_SIZE];
                for i in 0..BLOCK_SIZE {
                    let diff = decoded[i] - plaintext[i];
                    loss += diff * diff;
                    grad[i] = 2.0 * diff / BLOCK_SIZE as f32;
                }
                total_loss += (loss / BLOCK_SIZE as f32) as f64;

                // Backward through decoder, then encoder (STE passes gradient through)
                let grad_quantized = cipher.decoder.backward(&grad, lr);
                cipher.encoder.backward(&grad_quantized, lr);
            }

            if (epoch + 1) % 1000 == 0 || epoch == 0 {
                let avg_loss = total_loss / config.batch_size as f64;
                eprintln!(
                    "  Epoch {}/{}: loss = {:.8}",
                    epoch + 1,
                    config.epochs,
                    avg_loss
                );
            }
        }

        // Validate reconstruction accuracy
        let mut perfect = 0usize;
        let test_samples = 1000;
        for _ in 0..test_samples {
            let input_bytes: Vec<u8> = (0..BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect();
            let input: Vec<f32> = input_bytes.iter().map(|&b| b as f32 / 255.0).collect();

            let encoded = cipher.encoder.forward_inference(&input);
            let quantized: Vec<f32> = encoded
                .iter()
                .map(|&x| (x * 255.0).round() / 255.0)
                .collect();
            let decoded = cipher.decoder.forward_inference(&quantized);
            let output_bytes: Vec<u8> = decoded
                .iter()
                .map(|&x| (x * 255.0).round().clamp(0.0, 255.0) as u8)
                .collect();

            if input_bytes == output_bytes {
                perfect += 1;
            }
        }

        let accuracy = perfect as f32 / test_samples as f32 * 100.0;
        eprintln!(
            "  Validation: {}/{} blocks perfect ({:.1}%)",
            perfect, test_samples, accuracy
        );
        if accuracy < 100.0 {
            eprintln!(
                "  WARNING: Model does not achieve 100% accuracy. \
                 Consider increasing epochs or adjusting learning rate."
            );
        }

        cipher
    }

    /// Encrypt a single 16-byte block.
    fn encrypt_block(&self, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let input: Vec<f32> = block.iter().map(|&b| b as f32 / 255.0).collect();
        let encoded = self.encoder.forward_inference(&input);
        let mut output = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            output[i] = (encoded[i] * 255.0).round().clamp(0.0, 255.0) as u8;
        }
        output
    }

    /// Decrypt a single 16-byte block.
    #[allow(dead_code)]
    fn decrypt_block(&self, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let input: Vec<f32> = block.iter().map(|&b| b as f32 / 255.0).collect();
        let decoded = self.decoder.forward_inference(&input);
        let mut output = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            output[i] = (decoded[i] * 255.0).round().clamp(0.0, 255.0) as u8;
        }
        output
    }

    /// Encrypt data using OFB (Output Feedback) mode with PKCS7 padding.
    ///
    /// The encoder generates a deterministic keystream from a random IV,
    /// and data is encrypted via XOR. This avoids reconstruction accuracy
    /// issues since only the encoder is used at runtime.
    ///
    /// Output format: `[16-byte IV] [encrypted blocks...]`
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        // PKCS7 padding
        let pad_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
        let mut padded = data.to_vec();
        padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));

        let num_blocks = padded.len() / BLOCK_SIZE;

        // Random IV
        let mut iv = [0u8; BLOCK_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut iv);

        let mut result = Vec::with_capacity(BLOCK_SIZE + padded.len());
        result.extend_from_slice(&iv);

        // OFB mode: encoder generates keystream, XOR encrypts
        let mut feedback = iv;
        for i in 0..num_blocks {
            let start = i * BLOCK_SIZE;

            // Generate keystream block from feedback
            let keystream = self.encrypt_block(&feedback);

            // XOR plaintext with keystream
            let mut ct_block = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                ct_block[j] = padded[start + j] ^ keystream[j];
            }

            result.extend_from_slice(&ct_block);
            // OFB: feed the encoder output back (not the ciphertext)
            feedback = keystream;
        }

        result
    }

    /// Decrypt OFB-encrypted data with PKCS7 unpadding.
    ///
    /// Uses the same encoder-based keystream generation as encryption.
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < BLOCK_SIZE * 2 || data.len() % BLOCK_SIZE != 0 {
            return Vec::new();
        }

        // Extract IV
        let mut iv = [0u8; BLOCK_SIZE];
        iv.copy_from_slice(&data[..BLOCK_SIZE]);

        let ciphertext = &data[BLOCK_SIZE..];
        let num_blocks = ciphertext.len() / BLOCK_SIZE;

        let mut result = Vec::with_capacity(ciphertext.len());

        // OFB decryption: same keystream as encryption
        let mut feedback = iv;
        for i in 0..num_blocks {
            let start = i * BLOCK_SIZE;

            // Generate same keystream block from feedback
            let keystream = self.encrypt_block(&feedback);

            // XOR ciphertext with keystream to recover plaintext
            for j in 0..BLOCK_SIZE {
                result.push(ciphertext[start + j] ^ keystream[j]);
            }

            // OFB: feed the encoder output back (same as encryption)
            feedback = keystream;
        }

        // Remove PKCS7 padding
        if let Some(&pad_len) = result.last() {
            let pad_len = pad_len as usize;
            if pad_len > 0 && pad_len <= BLOCK_SIZE && result.len() >= pad_len {
                let pad_start = result.len() - pad_len;
                if result[pad_start..].iter().all(|&b| b == pad_len as u8) {
                    result.truncate(pad_start);
                }
            }
        }

        result
    }

    /// Save the trained model to a file.
    ///
    /// File format: `AFTN` magic, version, block_size, then serialized
    /// encoder and decoder networks.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut file = std::fs::File::create(path)?;
        file.write_all(MODEL_MAGIC)?;
        file.write_all(&[MODEL_VERSION, BLOCK_SIZE as u8])?;
        write_network(&mut file, &self.encoder)?;
        write_network(&mut file, &self.decoder)?;
        Ok(())
    }

    /// Load a trained model from a file.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let data = std::fs::read(path)?;
        if data.len() < 6 || &data[..4] != MODEL_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Not an AFT neural model file",
            ));
        }
        if data[4] != MODEL_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unsupported model version: {}", data[4]),
            ));
        }

        let mut pos = 6;
        let encoder = read_network(&data, &mut pos)?;
        let decoder = read_network(&data, &mut pos)?;

        Ok(Self { encoder, decoder })
    }
}

// ── Serialization helpers ───────────────────────────────────────────────────

fn write_network(w: &mut impl Write, net: &Network) -> std::io::Result<()> {
    w.write_all(&(net.layers.len() as u16).to_le_bytes())?;
    for layer in &net.layers {
        w.write_all(&(layer.input_dim as u32).to_le_bytes())?;
        w.write_all(&(layer.output_dim as u32).to_le_bytes())?;
        w.write_all(&[layer.activation.to_byte()])?;
        for &weight in &layer.weights {
            w.write_all(&weight.to_le_bytes())?;
        }
        for &bias in &layer.biases {
            w.write_all(&bias.to_le_bytes())?;
        }
    }
    Ok(())
}

fn read_network(data: &[u8], pos: &mut usize) -> std::io::Result<Network> {
    if *pos + 2 > data.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Truncated model file",
        ));
    }
    let num_layers = u16::from_le_bytes([data[*pos], data[*pos + 1]]) as usize;
    *pos += 2;

    let mut layers = Vec::with_capacity(num_layers);
    for _ in 0..num_layers {
        if *pos + 9 > data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Truncated layer header",
            ));
        }
        let input_dim =
            u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]])
                as usize;
        *pos += 4;
        let output_dim =
            u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]])
                as usize;
        *pos += 4;
        let activation = Activation::from_byte(data[*pos]);
        *pos += 1;

        let weight_count = output_dim * input_dim;
        let float_bytes_needed = (weight_count + output_dim) * 4;
        if *pos + float_bytes_needed > data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Truncated layer weights",
            ));
        }

        let mut weights = Vec::with_capacity(weight_count);
        for _ in 0..weight_count {
            let val =
                f32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
            weights.push(val);
            *pos += 4;
        }

        let mut biases = Vec::with_capacity(output_dim);
        for _ in 0..output_dim {
            let val =
                f32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
            biases.push(val);
            *pos += 4;
        }

        layers.push(DenseLayer {
            weights,
            biases,
            input_dim,
            output_dim,
            activation,
            last_input: Vec::new(),
            last_z: Vec::new(),
        });
    }

    Ok(Network { layers })
}

// ── Public helpers for file-level operations ────────────────────────────────

/// Verify a neural model file against its `.sha256` sidecar signature.
/// If no sidecar exists, the model is accepted (backward-compatible).
/// If a sidecar exists, the hash must match or the load is rejected.
fn verify_model_signature(model_path: &Path) -> AftResult<()> {
    let sig_path = model_path.with_extension("aftnn.sha256");
    if !sig_path.exists() {
        return Ok(());
    }

    let expected_hash = std::fs::read_to_string(&sig_path)
        .map_err(|e| AftError::Other(format!("Cannot read model signature {:?}: {}", sig_path, e)))?
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();

    if expected_hash.len() != 64 || !expected_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AftError::Other(format!(
            "Invalid SHA-256 hash in {:?}: expected 64 hex chars",
            sig_path,
        )));
    }

    let model_bytes = std::fs::read(model_path)
        .map_err(|e| AftError::Other(format!("Cannot read model file {:?}: {}", model_path, e)))?;

    use sha2::Digest;
    let actual_hash = hex::encode(sha2::Sha256::digest(&model_bytes));

    if actual_hash != expected_hash {
        return Err(AftError::PermissionDenied(format!(
            "Neural model signature mismatch for {:?}: expected {}, got {}. \
             Model may have been tampered with.",
            model_path, expected_hash, actual_hash,
        )));
    }

    Ok(())
}

/// Encrypt file data using a saved neural model.
pub fn encrypt_file_data(plaintext: &[u8], model_path: &Path) -> AftResult<Vec<u8>> {
    verify_model_signature(model_path)?;
    let cipher = NeuralCipher::load(model_path)
        .map_err(|e| AftError::Other(format!("Failed to load neural model: {}", e)))?;
    Ok(cipher.encrypt(plaintext))
}

/// Decrypt file data using a saved neural model.
pub fn decrypt_file_data(ciphertext: &[u8], model_path: &Path) -> AftResult<Vec<u8>> {
    verify_model_signature(model_path)?;
    let cipher = NeuralCipher::load(model_path)
        .map_err(|e| AftError::Other(format!("Failed to load neural model: {}", e)))?;
    Ok(cipher.decrypt(ciphertext))
}
