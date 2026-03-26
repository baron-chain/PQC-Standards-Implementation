# ml-kem

Pure Rust implementation of **ML-KEM** (FIPS 203), the NIST post-quantum key encapsulation mechanism.

## Features

- ML-KEM-512, ML-KEM-768, ML-KEM-1024
- Pure Rust, `no_std` compatible, zero `unsafe` code
- Constant-time operations via `subtle` crate
- Implicit rejection (IND-CCA2 secure)
- Validated against C2SP/CCTV official test vectors

## Usage

```rust
use ml_kem::{MlKem768, keygen, encapsulate, decapsulate};
use rand::rngs::OsRng;

let (ek, dk) = keygen::<MlKem768>(&mut OsRng);
let (shared_secret, ciphertext) = encapsulate::<MlKem768>(&ek, &mut OsRng);
let recovered = decapsulate::<MlKem768>(&dk, &ciphertext);
assert_eq!(shared_secret, recovered);
```

## Performance

Benchmarked on Apple M-series (no SIMD), single-threaded:

| Operation | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|-----------|-----------|-----------|------------|
| KeyGen    | 50 us     | 76 us     | 108 us     |
| Encaps    | 39 us     | 57 us     | 83 us      |
| Decaps    | 37 us     | 55 us     | 79 us      |

## License

MIT
