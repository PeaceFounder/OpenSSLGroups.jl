# OpenSSLGroups.jl

OpenSSLGroups.jl provides high-performance cryptographic group operations by wrapping OpenSSL's implementation while maintaining full compatibility with the [CryptoGroups.jl](https://github.com/PeaceFounder/CryptoGroups.jl) interface. This package offers a 10-20x performance improvement for exponentiations over pure Julia implementations while preserving type safety and ease of use.

## Features

- **Full CryptoGroups.jl Compatibility**: Drop-in replacement for CryptoGroups.jl with identical API
- **High Performance**: 10-20x faster group exponentiations using OpenSSL's optimized implementation
- **Type Safety**: Maintains all type safety guarantees from CryptoGroups.jl
- **Comprehensive Curve Support**: Implements all standard curves available in OpenSSL

## Installation

```julia
using Pkg
Pkg.add("OpenSSLGroups")
```

## Basic Usage

```julia
using OpenSSLGroups

P = OpenSSLGroups.SecP256k1
point = P()

point * 3 == point + 2 * point
P(octet(point)) == point
P(octet(point; mode=:compressed)) == point
P(value(point)) == point
```

## Integration with CryptoGroups.jl

OpenSSLGroups.jl can be used as a drop-in replacement for CryptoGroups.jl:

```julia
using OpenSSLGroups
using CryptoGroups

# Using with ECGroup macro
G = @ECGroup{OpenSSLGroups.SecP256k1}
g = G()

# Basic group operations work identically
g^3 * g^5 / g^2 == (g^3)^2 == g^6
g^(order(G) - 1) * g == one(G)
```

## Supported Curves

### Prime Field Curves

#### NIST Curves (SECG)
| Curve Name | OpenSSLGroups Type | Alternate Names |
|------------|-------------------|-----------------|
| P-192 | `Prime192v1` | (secp192r1, prime192v1) |
| P-224 | `SecP224r1` | (secp224r1) |
| P-256 | `Prime256v1` | (secp256r1, prime256v1) |
| P-384 | `SecP384r1` | (secp384r1) |
| P-521 | `SecP521r1` | (secp521r1) |

#### Koblitz Curves (SECG)
| Curve Name | OpenSSLGroups Type | Alternate Names |
|------------|-------------------|-----------------|
| secp160k1 | `SecP160k1` | |
| secp192k1 | `SecP192k1` | |
| secp224k1 | `SecP224k1` | |
| secp256k1 | `SecP256k1` | (Bitcoin curve) |

#### Brainpool Curves
| Curve Name | OpenSSLGroups Type | Notes |
|------------|-------------------|--------|
| brainpoolP160r1 | `BrainpoolP160r1` | Random curve |
| brainpoolP192r1 | `BrainpoolP192r1` | Random curve |
| brainpoolP224r1 | `BrainpoolP224r1` | Random curve |
| brainpoolP256r1 | `BrainpoolP256r1` | Random curve |
| brainpoolP320r1 | `BrainpoolP320r1` | Random curve |
| brainpoolP384r1 | `BrainpoolP384r1` | Random curve |
| brainpoolP512r1 | `BrainpoolP512r1` | Random curve |

### Binary Field Curves

#### NIST Koblitz Curves
| Curve Name | OpenSSLGroups Type | Alternate Names |
|------------|-------------------|-----------------|
| K-163 | `SecT163k1` | (sect163k1) |
| K-233 | `SecT233k1` | (sect233k1) |
| K-283 | `SecT283k1` | (sect283k1) |
| K-409 | `SecT409k1` | (sect409k1) |
| K-571 | `SecT571k1` | (sect571k1) |

#### NIST Pseudorandom Curves
| Curve Name | OpenSSLGroups Type | Alternate Names |
|------------|-------------------|-----------------|
| B-163 | `SecT163r2` | (sect163r2) |
| B-233 | `SecT233r1` | (sect233r1) |
| B-283 | `SecT283r1` | (sect283r1) |
| B-409 | `SecT409r1` | (sect409r1) |
| B-571 | `SecT571r1` | (sect571r1) |

#### Other Notable Curves
| Curve Name | OpenSSLGroups Type | Notes |
|------------|-------------------|--------|
| SM2 | `SM2` | Chinese standard curve |
| WTLS | `WtlsCurve1` through `WtlsCurve12` | WAP/TLS specific curves |
| IPSec | `IpsecCurve3`, `IpsecCurve4` | IPSec specific curves |

Additional curves (c2pnb/c2tnb series) are also implemented but are less commonly used in modern cryptographic applications.

## Integration with Higher-Level Protocols

The package works seamlessly with cryptographic protocol implementations:

```julia
using OpenSSLGroups
using ShuffleProofs
using SigmaProofs.ElGamal
using SigmaProofs.Verificatum

# Set up ElGamal encryption with OpenSSL curve
g = @ECGroup{OpenSSLGroups.Prime256v1}()
sk = 123
pk = g^sk

# Create encryption helper
enc = Enc(pk, g)

# Example encryption and shuffle proof
𝐦 = [g^4, g^2, g^3]
𝐞 = enc(𝐦, [2, 3, 4]) .|> ElGamalRow

verifier = ProtocolSpec(; g)
simulator = shuffle(𝐞, g, pk, verifier)
@assert verify(simulator)
```

## Performance Comparison

Here's a simple benchmark comparing OpenSSLGroups with CryptoGroups:

```julia
using BenchmarkTools
using OpenSSLGroups
using CryptoGroups

# OpenSSL implementation
P1 = SecP256k1
p1 = P1()
@btime $p1 ^ 123

# Pure Julia implementation
P2 = @ECGroup{P_256}
p2 = P2()
@btime $p2 ^ 123

# Results show ~10-20x speedup for typical operations
```
