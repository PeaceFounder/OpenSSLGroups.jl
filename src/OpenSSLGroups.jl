module OpenSSLGroups

using CryptoGroups.Utils: @check, static
using CryptoGroups.Fields: Field, FP, @F2PB, bitlength
using CryptoGroups.Curves: AbstractPoint
import CryptoGroups.Curves: octet, order, cofactor, oncurve, gx, gy, field, value, ECPoint, double
import CryptoGroups.Fields: modulus

import CryptoGroups: spec, concretize_type
using CryptoGroups.Specs: EC2N, ECP

import Base: zero

using OpenSSL_jll
using Base.GMP

export octet, order, value

mutable struct OpenSSLContext
    ctx::Ptr{Nothing}
    
    function OpenSSLContext()
        ctx = ccall((:BN_CTX_new, libcrypto), Ptr{Nothing}, ())
        if ctx == C_NULL
            throw(OpenSSLError("Failed to create BN_CTX"))
        end
        obj = new(ctx)
        finalizer(obj) do x
            if x.ctx != C_NULL
                @ccall libcrypto.BN_CTX_free(x.ctx::Ptr{Nothing})::Cvoid
                x.ctx = C_NULL
            end
        end
        return obj
    end
end

function get_ctx()
    ctx = get!(OpenSSLContext, task_local_storage(), :ctx)::OpenSSLContext
    return ctx.ctx
end

include("utils.jl")
include("point.jl")
include("curves.jl")

# Some compatability methods for ECPoint and ECGroup

(::Type{ECPoint{P, S}})() where {P <: OpenSSLPoint, S} = ECPoint{P, S}(P())
(::Type{ECPoint{P}})() where P <: OpenSSLPoint = ECPoint(P(), order(P), cofactor(P); name = nameof(P))
(::Type{ECPoint{P}})(x::F, y::F) where {P <: OpenSSLPoint, F <: Field} = ECPoint(P(x, y), order(P), cofactor(P); name = nameof(P))

double(x::OpenSSLPoint) = x + x # openssl implementation is safe
oncurve(x::OpenSSLPoint) = true # OpenSSL checks validity of the point in the constructor

spec(::Type{ECPoint{P}}) where {P <: OpenSSLPoint} = spec(P)
spec(::Type{ECPoint{P, S}}) where {P <: OpenSSLPoint, S} = spec(P)


function Base.convert(::Type{P}, x::NTuple{2, BitVector}) where P <: OpenSSLBinaryPoint 
    F = field(P)
    if iszero(F(x[1])) && iszero(F(x[2]))
        return zero(P)
    else
        return P(x)
    end
end

function Base.convert(::Type{P}, x::NTuple{2, <:Integer}) where P <: OpenSSLPrimePoint 
    if iszero(x[1]) && iszero(x[2])
        return zero(P)
    else
        return P(x)
    end
end

function Base.convert(::Type{P}, x::AbstractVector{UInt8}) where P <: OpenSSLPoint 
    if iszero(x[1])
        return zero(P)
    else
        return P(x)
    end
end

function Base.convert(::Type{ECPoint{P, S}}, x::AbstractVector{UInt8}; allow_zero=false) where {P <: OpenSSLPoint, S}
    return ECPoint{P, S}(convert(P, x); allow_zero)
end

function Base.convert(::Type{ECPoint{P, S}}, x::NTuple{2}; allow_zero=false) where {P <: OpenSSLPoint, S}
    return ECPoint{P, S}(convert(P, x); allow_zero)
end

# OpenSSL already provides all the checks
function Base.:+(x::ECPoint{P, S}, y::ECPoint{P, S}) where {P <: OpenSSLPoint, S}
    return ECPoint{P, S}(x.p + y.p; skip_validation=true)
end

octet(x::ECPoint{P}; mode = :uncompressed) where P <: OpenSSLPoint = octet(x.p; mode)

end # module OpenSSLGroups
