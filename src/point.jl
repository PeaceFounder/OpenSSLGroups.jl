abstract type OpenSSLPoint <: AbstractPoint end

function generator(::Type{P}) where P <: OpenSSLPoint
    group = group_pointer(P)
    result = @ccall libcrypto.EC_POINT_new(group::Ptr{Cvoid})::Ptr{Cvoid}
    point = @ccall libcrypto.EC_GROUP_get0_generator(group::Ptr{Cvoid})::Ptr{Cvoid}
    return P(point; skip_finalizer=true)
end

(::Type{P})() where P <: OpenSSLPoint = generator(P)

function Base.:(==)(x::P, y::P) where P <: OpenSSLPoint
    ctx = get_ctx()
    group = group_pointer(P)
    ret = @ccall libcrypto.EC_POINT_cmp(
        group::Ptr{Cvoid}, 
        pointer(x)::Ptr{Cvoid}, 
        pointer(y)::Ptr{Cvoid}, 
        ctx::Ptr{Cvoid}
    )::Cint
    return ret == 0
end

Base.pointer(p::OpenSSLPoint) = p.pointer

function Base.iszero(point::P) where P <: OpenSSLPoint
    group = group_pointer(P)
    ret = @ccall libcrypto.EC_POINT_is_at_infinity(
        group::Ptr{Cvoid}, 
        pointer(point)::Ptr{Cvoid}
    )::Cint
    return ret == 1
end

# The performance could be improved by evaluating it only once per group element
function Base.zero(::Type{P}) where P <: OpenSSLPoint 
    group = group_pointer(P)
    result = @ccall libcrypto.EC_POINT_new(group::Ptr{Cvoid})::Ptr{Cvoid}
    ret = @ccall libcrypto.EC_POINT_set_to_infinity(
        group::Ptr{Cvoid}, 
        result::Ptr{Cvoid}
    )::Cint
    if ret != 1
        error("Failed to set point at infinity")
    end
    return P(result)
end

function (::Type{P})(bytes::Vector{UInt8}) where P <: OpenSSLPoint
    ctx = get_ctx()
    group = group_pointer(P)
    point = @ccall OpenSSL_jll.libcrypto.EC_POINT_new(group::Ptr{Cvoid})::Ptr{Cvoid}
    if point == C_NULL
        error("Failed to create new EC_POINT")
    end

    ret = @ccall OpenSSL_jll.libcrypto.EC_POINT_oct2point(
        group::Ptr{Cvoid},
        point::Ptr{Cvoid},
        bytes::Ptr{UInt8},
        length(bytes)::Csize_t,
        ctx::Ptr{Cvoid}
    )::Cint
    if ret != 1
        @ccall OpenSSL_jll.libcrypto.EC_POINT_free(point::Ptr{Cvoid})::Cvoid
        error("Failed to initialize point from bytes")
    end
    return P(point)    
end

function octet_legacy(point::P) where P <: OpenSSLPoint
    ctx = get_ctx()
    group = group_pointer(P)
    buffer_size = 200  # Adjust if needed
    buffer = Vector{UInt8}(undef, buffer_size)

    GC.@preserve buffer begin
        _length = @ccall libcrypto.EC_POINT_point2oct(
            group::Ptr{Cvoid},
            pointer(point)::Ptr{Cvoid},
            4::Cint,
            buffer::Ptr{UInt8},
            buffer_size::Csize_t,
            ctx::Ptr{Cvoid}
        )::Csize_t
    end

    if _length == 0
        error("Failed to convert result to octet string")
    end
    return buffer[1:_length]
end

function Base.:+(x::P, y::P) where P <: OpenSSLPoint
    ctx = get_ctx()
    group = group_pointer(P)
    result = @ccall libcrypto.EC_POINT_new(group::Ptr{Cvoid})::Ptr{Cvoid}

    ret = @ccall libcrypto.EC_POINT_add(
        group::Ptr{Cvoid},
        result::Ptr{Cvoid},
        pointer(x)::Ptr{Cvoid},
        pointer(y)::Ptr{Cvoid},
        ctx::Ptr{Cvoid}
    )::Cint
    if ret != 1
        error("Failed in point addition")
    end
    return P(result)
end

function Base.:*(k::Integer, point::P) where P <: OpenSSLPoint
    scalar = @ccall libcrypto.BN_new()::Ptr{Cvoid}
    scalar_hex = string(k, base=16)
    ret = @ccall libcrypto.BN_hex2bn(
        Ref(scalar)::Ptr{Ptr{Cvoid}}, 
        scalar_hex::Cstring
    )::Cint
    if ret == 0
        error("Failed to set scalar")
    end

    ctx = get_ctx()
    group = group_pointer(P)
    result = @ccall libcrypto.EC_POINT_new(group::Ptr{Cvoid})::Ptr{Cvoid}    

    ret = @ccall libcrypto.EC_POINT_mul(
        group::Ptr{Cvoid},
        result::Ptr{Cvoid},
        C_NULL::Ptr{Cvoid},
        pointer(point)::Ptr{Cvoid},
        scalar::Ptr{Cvoid},
        ctx::Ptr{Cvoid}
    )::Cint
    if ret != 1
        error("Failed in point multiplication")
    end

    openssl_bignum_free(scalar)
    return P(result)
end

Base.:*(point::OpenSSLPoint, k::Integer) = k * point

function Base.:-(point::P) where P <: OpenSSLPoint
    ctx = get_ctx()
    group = group_pointer(P)
    inverted_point = copy(point)

    ret = @ccall libcrypto.EC_POINT_invert(
        group::Ptr{Cvoid},
        pointer(inverted_point)::Ptr{Cvoid},
        ctx::Ptr{Cvoid}
    )::Cint
    if ret != 1
        error("Failed to invert point")
    end
    return P(inverted_point)
end

function Base.copy(point::P) where P <: OpenSSLPoint
    group = group_pointer(P)
    result = @ccall libcrypto.EC_POINT_new(group::Ptr{Cvoid})::Ptr{Cvoid}
    
    ret = @ccall libcrypto.EC_POINT_copy(
        result::Ptr{Cvoid},
        pointer(point)::Ptr{Cvoid}
    )::Cint
    if ret != 1
        error("Failed to copy point")
    end
    return P(result)
end

function order(::Type{P}) where P <: OpenSSLPoint
    ctx = get_ctx()
    group = group_pointer(P)
    order = @ccall libcrypto.BN_new()::Ptr{Cvoid}

    ret = @ccall libcrypto.EC_GROUP_get_order(
        group::Ptr{Cvoid},
        order::Ptr{Cvoid},
        ctx::Ptr{Cvoid}
    )::Cint
    if ret != 1
        error("Failed to get order")
    end

    order_bigint = order |> bn2bigint
    openssl_bignum_free(order)
    return order_bigint
end

function cofactor(::Type{P}) where P <: OpenSSLPoint
    ctx = get_ctx()
    group = group_pointer(P)
    cofactor = @ccall libcrypto.BN_new()::Ptr{Cvoid}
    
    ret = @ccall libcrypto.EC_GROUP_get_cofactor(
        group::Ptr{Cvoid},
        cofactor::Ptr{Cvoid},
        ctx::Ptr{Cvoid}
    )::Cint

    cofactor_bigint = cofactor |> bn2bigint
    openssl_bignum_free(cofactor)
    return cofactor_bigint
end

function gx(point::P) where P <: OpenSSLPoint
    F = field(P)
    x, y = value(point)
    return F(x)
end

function gy(point::P) where P <: OpenSSLPoint
    F = field(P)
    x, y = value(point)
    return F(y)
end

function (::Type{P})(x::F, y::F) where {P <: OpenSSLPoint, F <: Field}
    @check F == field(P)
    x_bytes = octet(x)
    y_bytes = octet(y)
    po = UInt8[4, x_bytes..., y_bytes...]
    return P(po)
end

### Binary curve point specializations

abstract type OpenSSLBinaryPoint <: OpenSSLPoint end

function value(point::P) where P <: OpenSSLBinaryPoint

    if iszero(point)

        F = field(P)
        return convert(BitVector, F(0)), convert(BitVector, F(0))

    else

        ctx = get_ctx()
        group = group_pointer(P)
        gx = @ccall libcrypto.BN_new()::Ptr{Cvoid}
        gy = @ccall libcrypto.BN_new()::Ptr{Cvoid}
        
        ret = @ccall libcrypto.EC_POINT_get_affine_coordinates_GF2m(
            group::Ptr{Cvoid},
            pointer(point)::Ptr{Cvoid},
            gx::Ptr{Cvoid},
            gy::Ptr{Cvoid},
            ctx::Ptr{Cvoid}
        )::Cint
        if ret != 1
            error("Failed to get generator coordinates")
        end

        F = field(P)
        M = div(bitlength(F), 8, RoundUp)
        xf, yf = F(bn2octet(gx, M)), F(bn2octet(gy, M))

        openssl_bignum_free(gx)
        openssl_bignum_free(gy)
        
        return convert(BitVector, xf), convert(BitVector, yf)
    end
end

function reducer(bytes::Vector{UInt8})
    # Create a BitVector with enough space for all bits
    bits = BitVector(undef, length(bytes) * 8)
    
    # Process each byte
    for (byte_idx, byte) in enumerate(bytes)
        # Calculate base index for this byte
        base_idx = (byte_idx - 1) * 8 + 1
        
        # Extract bits from byte
        for bit_idx in 0:7
            bits[base_idx + bit_idx] = ((byte >> (7 - bit_idx)) & 1) == 1
        end
    end

    N = findfirst(isequal(true), bits)
    
    return bits[N:end]
end

function curve_parameters(::Type{P}) where P <: OpenSSLBinaryPoint
    ctx = get_ctx()
    group = group_pointer(P)

    p = @ccall libcrypto.BN_new()::Ptr{Cvoid}
    a = @ccall libcrypto.BN_new()::Ptr{Cvoid}
    b = @ccall libcrypto.BN_new()::Ptr{Cvoid}

    ret = @ccall libcrypto.EC_GROUP_get_curve_GF2m(
        group::Ptr{Cvoid},
        p::Ptr{Cvoid},
        a::Ptr{Cvoid},
        b::Ptr{Cvoid},
        ctx::Ptr{Cvoid}
    )::Cint

    hex_str = unsafe_string(@ccall libcrypto.BN_bn2hex(p::Ptr{Cvoid})::Ptr{UInt8})

    m = reducer(hex2bytes(hex_str))
    a_octet = bn2octet(a)
    b_octet = bn2octet(b)
    
    openssl_bignum_free(p)
    openssl_bignum_free(a)
    openssl_bignum_free(b)

    return m, a_octet, b_octet
end

function field(::Type{P}) where P <: OpenSSLBinaryPoint
    reducer, = curve_parameters(P)
    return @F2PB{reducer}
end

(::Type{P})((x, y)::Tuple{BitVector, BitVector}) where P <: OpenSSLBinaryPoint = P(x, y)

function (::Type{P})(x::T, y::T) where {P <: OpenSSLBinaryPoint, T <: Union{BitVector, Vector{UInt8}}}
    F = field(P)
    return P(F(x), F(y))
end

function spec(::Type{P}) where P <: OpenSSLBinaryPoint
    _, a_octet, b_octet = curve_parameters(P)
    F = field(P)
    basis = spec(F)
    n = order(P)
    M = div(bitlength(F), 8, RoundUp)
    
    a_bits = convert(BitVector, F(expand(a_octet, M)))
    b_bits = convert(BitVector, F(expand(b_octet, M)))
    
    _cofactor = cofactor(P) |> Int
    gx, gy = value(generator(P))
    names = [string(lowercase(string(nameof(P))))]
    
    return EC2N(basis, n, a_bits, b_bits, _cofactor, gx, gy; names)
end

### Prime curve point specializations

abstract type OpenSSLPrimePoint <: OpenSSLPoint end

function (::Type{P})(x::Integer, y::Integer) where P <: OpenSSLPrimePoint
    F = field(P)
    return P(F(x), F(y))
end

(::Type{P})((x, y)::Tuple{Integer, Integer}) where P <: OpenSSLPrimePoint = P(x, y)

modulus(::Type{P}) where P <: OpenSSLPrimePoint = curve_parameters(P) |> first

field(::Type{P}) where P <: OpenSSLPrimePoint = FP{static(modulus(P))}

function curve_parameters(::Type{P}) where P <: OpenSSLPrimePoint
    ctx = get_ctx()
    group = group_pointer(P)

    p = @ccall libcrypto.BN_new()::Ptr{Cvoid}
    a = @ccall libcrypto.BN_new()::Ptr{Cvoid}
    b = @ccall libcrypto.BN_new()::Ptr{Cvoid}
    
    ret = @ccall libcrypto.EC_GROUP_get_curve_GFp(
        group::Ptr{Cvoid},
        p::Ptr{Cvoid},
        a::Ptr{Cvoid},
        b::Ptr{Cvoid},
        ctx::Ptr{Cvoid}
    )::Cint
    if ret != 1
        error("Failed to get curve parameters")
    end

    p_bigint = bn2bigint(p)
    a_bigint = bn2bigint(a)
    b_bigint = bn2bigint(b)

    openssl_bignum_free(p)
    openssl_bignum_free(a)
    openssl_bignum_free(b)

    return p_bigint, a_bigint, b_bigint
end

function spec(::Type{P}) where P <: OpenSSLPoint
    p, a, b = curve_parameters(P)
    n = order(P)
    _cofactor = cofactor(P) |> Int
    gx, gy = value(generator(P))
    names = [string(lowercase(string(nameof(P))))]
    return ECP(p, n, a, b, _cofactor, gx, gy; names)
end

function value(point::P) where P <: OpenSSLPrimePoint
    ctx = get_ctx()
    group = group_pointer(P)

    gx = @ccall libcrypto.BN_new()::Ptr{Cvoid}
    gy = @ccall libcrypto.BN_new()::Ptr{Cvoid}

    ret = @ccall libcrypto.EC_POINT_get_affine_coordinates(
        group::Ptr{Cvoid},
        pointer(point)::Ptr{Cvoid},
        gx::Ptr{Cvoid},
        gy::Ptr{Cvoid},
        ctx::Ptr{Cvoid}
    )::Cint

    gx_bigint = bn2bigint(gx)
    gy_bigint = bn2bigint(gy)

    openssl_bignum_free(gx)
    openssl_bignum_free(gy)

    return gx_bigint, gy_bigint
end
