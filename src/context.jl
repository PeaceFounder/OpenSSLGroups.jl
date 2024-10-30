mutable struct ThreadLocal{T}
    values::Vector{Union{Nothing, T}}
    
    ThreadLocal{T}() where T = new(fill(nothing, Base.Threads.nthreads()))
end

# Check if value exists for current thread
function Base.haskey(t::ThreadLocal)
    tid = Base.Threads.threadid()
    return t.values[tid] !== nothing
end

# Get value for current thread
function Base.getindex(t::ThreadLocal)
    tid = Base.Threads.threadid()
    val = t.values[tid]
    if val === nothing
        throw(KeyError("No value for thread $tid"))
    end
    return val
end

# Set value for current thread
function Base.setindex!(t::ThreadLocal{T}, v::T) where T
    tid = Base.Threads.threadid()
    t.values[tid] = v
end

# Delete value for current thread
function Base.delete!(t::ThreadLocal)
    tid = Base.Threads.threadid()
    t.values[tid] = nothing
end


# Thread context structure
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


