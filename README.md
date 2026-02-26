# Privacy Precompiles

Go cryptographic library implementing EVM privacy precompiles, including:

- BabyJubJub elliptic curve operations
- EdDSA over BabyJubJub
- Poseidon hash function
- Groth16 zkSNARK verifier (BN254)
- Shared cryptographic utilities

---

## Module


Install:

```bash
go get github.com/privacy-ethereum/privacy-precompiles@latest
```

## Project Structure

```bash
babyjubjub/
  add/          # Point addition
  mul/          # Scalar multiplication
  eddsa/        # EdDSA verification
  utils/        # Curve helpers
  validation/   # Point validation

poseidon/       # Poseidon hash implementation

verifier/
  groth16/      # Groth16 verifier logic
  groth16/bn254 # BN254 pairing implementation

common/         # Shared cryptographic utilities
utils/          # General helpers
```

## Development

This repository includes a security-focused Makefile with formatting, static analysis, and vulnerability checks.

### Install Development Tools

```bash
make tools
```

### Format Code

```bash
make fmt
```

### Build

```bash
make build
```

### Static Analysis

```bash
make vet
make lint
```

### Security Checks

```bash
make security
```

### Run Tests

```bash
make test
```

### Full CI Pipeline

```bash
make ci
```

## Example Usage

```go
import "github.com/privacy-ethereum/privacy-precompiles/babyjubjub/add"
```

```go
import "github.com/privacy-ethereum/privacy-precompiles/verifier/groth16"
```

