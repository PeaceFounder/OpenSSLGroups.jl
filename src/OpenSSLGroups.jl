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

include("utils.jl")
include("context.jl")
include("point.jl")
include("curves.jl")

# The context is a scratchspace and never leaves internal function boundary, hence, using threadid is appropriate
const THREAD_CTXS = ThreadLocal{OpenSSLContext}()

function get_ctx()
    @assert haskey(THREAD_CTXS) "Thread context not initialized"
    return THREAD_CTXS[].ctx
end

function __init__()
    @sync begin
        for tid in 1:Threads.nthreads()
            Threads.@spawn begin
                THREAD_CTXS[] = OpenSSLContext()
            end
        end
    end
end


end # module OpenSSLGroups
