module OpenSSLGroups

using CryptoGroups.Utils: @check, static
using CryptoGroups.Fields: Field, FP, @F2PB, bitlength
using CryptoGroups.Curves: AbstractPoint
import CryptoGroups.Curves: octet, order, cofactor, oncurve, gx, gy, field, value
import CryptoGroups.Fields: modulus

import CryptoGroups: spec
using CryptoGroups.Specs: EC2N, ECP

import Base: zero

using OpenSSL_jll
using Base.GMP

export octet, order, value

const ctx = ccall((:BN_CTX_new, libcrypto), Ptr{Cvoid}, ()) # may need to be set at runtime and etc... 

include("utils.jl")
include("point.jl")
include("curves.jl")

end # module OpenSSLGroups
