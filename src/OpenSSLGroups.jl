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

include("utils.jl")
include("context.jl")
include("point.jl")
include("curves.jl")

# The context is a scratchspace and never leaves internal function boundary, hence, using threadid is appropriate
global THREAD_CTXS::ThreadLocal{OpenSSLContext}

function get_ctx()
    @assert haskey(THREAD_CTXS) "Thread context not initialized"
    return THREAD_CTXS[].ctx
end

function __init__()

    global THREAD_CTXS = ThreadLocal{OpenSSLContext}()

    for tid in 1:Threads.nthreads()
        THREAD_CTXS[tid] = OpenSSLContext()
    end
end

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

function Base.convert(::Type{P}, x::Vector{UInt8}) where P <: OpenSSLPoint 
    if iszero(x[1])
        return zero(P)
    else
        return P(x)
    end
end

function Base.convert(::Type{ECPoint{P, S}}, x::Vector{UInt8}; allow_zero=false) where {P <: OpenSSLPoint, S}
    return ECPoint{P, S}(convert(P, x); allow_zero)
end

function Base.convert(::Type{ECPoint{P, S}}, x::NTuple{2}; allow_zero=false) where {P <: OpenSSLPoint, S}
    return ECPoint{P, S}(convert(P, x); allow_zero)
end

# OpenSSL already provides all the checks
function Base.:+(x::ECPoint{P, S}, y::ECPoint{P, S}) where {P <: OpenSSLPoint, S}
    return ECPoint{P, S}(x.p + y.p; skip_validation=true)
end


end # module OpenSSLGroups
