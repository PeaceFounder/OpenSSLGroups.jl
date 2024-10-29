abstract type OpenSSLPoint <: AbstractPoint end

function generator(::Type{P}) where P <: OpenSSLPoint

    group = group_pointer(P)

    result = ccall((:EC_POINT_new, libcrypto), Ptr{Cvoid}, (Ptr{Cvoid},), group)

    point = ccall((:EC_GROUP_get0_generator, libcrypto), Ptr{Cvoid}, 
                      (Ptr{Cvoid},), group)

    return P(point) # copy is not necessary as the public API is nonmutating
end

(::Type{P})() where P <: OpenSSLPoint = generator(P)


function Base.:(==)(x::P, y::P) where P <: OpenSSLPoint

    group = group_pointer(P)

    ret = ccall((:EC_POINT_cmp, libcrypto), Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                group, pointer(x), pointer(y), ctx)

    return ret == 0
end


Base.pointer(p::OpenSSLPoint) = p.pointer

function Base.iszero(point::P) where P <: OpenSSLPoint

    group = group_pointer(P)

    # Check if point is at infinity
    ret = ccall((:EC_POINT_is_at_infinity, libcrypto), Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}),
                group, pointer(point))

    return ret == 1
end


function Base.zero(::Type{P}) where P <: OpenSSLPoint

    group = group_pointer(P)

    result = ccall((:EC_POINT_new, libcrypto), Ptr{Cvoid}, (Ptr{Cvoid},), group)

    # Set point at infinity
    ret = ccall((:EC_POINT_set_to_infinity, libcrypto), Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}), group, result)
    if ret != 1
        error("Failed to set point at infinity")
    end

    return P(result)
end


function (::Type{P})(bytes::Vector{UInt8}) where P <: OpenSSLPoint

    group = group_pointer(P)

    point = ccall((:EC_POINT_new, OpenSSL_jll.libcrypto), Ptr{Cvoid}, (Ptr{Cvoid},), group)
    if point == C_NULL
        error("Failed to create new EC_POINT")
    end

    ret = ccall((:EC_POINT_oct2point, OpenSSL_jll.libcrypto), Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{Cvoid}),
                group, point, bytes, length(bytes), ctx)
    if ret != 1
        ccall((:EC_POINT_free, OpenSSL_jll.libcrypto), Cvoid, (Ptr{Cvoid},), point)
        error("Failed to initialize point from bytes")
    end

    return P(point)    
end

function octet_legacy(point::P) where P <: OpenSSLPoint
    
    group = group_pointer(P)

    buffer_size = 200  # Adjust if needed
    buffer = Vector{UInt8}(undef, buffer_size)

    _length = ccall((:EC_POINT_point2oct, libcrypto), Csize_t,
                    (Ptr{Cvoid}, Ptr{Cvoid}, Cint, Ptr{UInt8}, Csize_t, Ptr{Cvoid}),
                    group, pointer(point), 4, buffer, buffer_size, ctx)  # 4 is POINT_CONVERSION_UNCOMPRESSED
    if _length == 0
        error("Failed to convert result to octet string")
    end

    return buffer[1:_length]
end

function Base.:+(x::P, y::P) where P <: OpenSSLPoint

    group = group_pointer(P)
    result = ccall((:EC_POINT_new, libcrypto), Ptr{Cvoid}, (Ptr{Cvoid},), group)

    # Perform point addition: result = result + point2
    ret = ccall((:EC_POINT_add, libcrypto), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), group, result, pointer(x), pointer(y), ctx)
    if ret != 1
        error("Failed in point addition")
    end

    return P(result)
end


function Base.:*(k::Integer, point::P) where P <: OpenSSLPoint

    scalar = ccall((:BN_new, libcrypto), Ptr{Cvoid}, ())

    scalar_hex = string(k, base=16)
    ret = ccall((:BN_hex2bn, libcrypto), Cint, (Ptr{Ptr{Cvoid}}, Cstring), Ref(scalar), scalar_hex)
    if ret == 0
        error("Failed to set scalar")
    end

    group = group_pointer(P)
    result = ccall((:EC_POINT_new, libcrypto), Ptr{Cvoid}, (Ptr{Cvoid},), group)    

    ret = ccall((:EC_POINT_mul, libcrypto), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), group, result, C_NULL, pointer(point), scalar, ctx)
    if ret != 1
        error("Failed in point multiplication")
    end

    return P(result)
end

Base.:*(point::OpenSSLPoint, k::Integer) = k * point

function Base.:-(point::P) where P <: OpenSSLPoint # the substraction then is ensured by AbstractPoint

    group = group_pointer(P)

    # Create a temporary point for the inverted point
    inverted_point = copy(point)

    ret = ccall((:EC_POINT_invert, libcrypto), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), group, pointer(inverted_point), ctx)
    if ret != 1
        error("Failed to invert point")
    end

    return P(inverted_point)
end

function Base.copy(point::P) where P <: OpenSSLPoint

    group = group_pointer(P)
    result = ccall((:EC_POINT_new, libcrypto), Ptr{Cvoid}, (Ptr{Cvoid},), group)
    
    ret = ccall((:EC_POINT_copy, libcrypto), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), result, pointer(point))
    if ret != 1
        error("Failed to copy point")
    end

    return P(result)
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


function order(::Type{P}) where P <: OpenSSLPoint

    group = group_pointer(P)

    order = ccall((:BN_new, libcrypto), Ptr{Cvoid}, ())

    # Get the order of the curve
    ret = ccall((:EC_GROUP_get_order, libcrypto), Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                group, order, ctx)
    if ret != 1
        error("Failed to get order")
    end

    return order |> bn2bigint
end


function cofactor(::Type{P}) where P <: OpenSSLPoint

    group = group_pointer(P)

    cofactor = ccall((:BN_new, libcrypto), Ptr{Cvoid}, ())
    ret = ccall((:EC_GROUP_get_cofactor, libcrypto), Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                group, cofactor, ctx)

    return cofactor |> bn2bigint
end


### Binary curve point specializations

abstract type OpenSSLBinaryPoint <: OpenSSLPoint end

function value(point::P) where P <: OpenSSLBinaryPoint

    group = group_pointer(P)

    gx = ccall((:BN_new, libcrypto), Ptr{Cvoid}, ())
    gy = ccall((:BN_new, libcrypto), Ptr{Cvoid}, ())
    
    ret = ccall((:EC_POINT_get_affine_coordinates_GF2m, libcrypto), Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                group, pointer(point), gx, gy, ctx)
    if ret != 1
        error("Failed to get generator coordinates")
    end

    F = field(P)
    M = div(bitlength(F), 8, RoundUp)

    xf, yf = F(bn2octet(gx, M)), F(bn2octet(gy, M))

    return convert(BitVector, xf), convert(BitVector, yf) # Perhaps I should rather return a tuole of field elements here?
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

    group = group_pointer(P)

    p = ccall((:BN_new, libcrypto), Ptr{Cvoid}, ())  # Field characteristic (prime p)

    #m = Ref{Cint}()
    a = ccall((:BN_new, libcrypto), Ptr{Cvoid}, ())  # Curve parameter a
    b = ccall((:BN_new, libcrypto), Ptr{Cvoid}, ())  # Curve parameter b
    

    # For binary curves, we use EC_GROUP_get_curve_GF2m instead of GFp
    ret = ccall((:EC_GROUP_get_curve_GF2m, libcrypto), Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                group, p, a, b, ctx)

    hex_str = unsafe_string(ccall((:BN_bn2hex, libcrypto), Ptr{UInt8}, 
                                  (Ptr{Cvoid},), p))

    m = reducer(hex2bytes(hex_str))

    return m, bn2octet(a), bn2octet(b)
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

    group = group_pointer(P)

    p = ccall((:BN_new, libcrypto), Ptr{Cvoid}, ())  # Field characteristic (prime p)
    a = ccall((:BN_new, libcrypto), Ptr{Cvoid}, ())  # Curve parameter a
    b = ccall((:BN_new, libcrypto), Ptr{Cvoid}, ())  # Curve parameter b
    
    # Get field parameters
    ret = ccall((:EC_GROUP_get_curve_GFp, libcrypto), Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                group, p, a, b, ctx)
    if ret != 1
        error("Failed to get curve parameters")
    end

    return bn2bigint(p), bn2bigint(a), bn2bigint(b)
end


function spec(::Type{P}) where P  <: OpenSSLPoint
    
    p, a, b = curve_parameters(P)
    n = order(P)

    _cofactor = cofactor(P) |> Int

    gx, gy = value(generator(P))

    names = [string(lowercase(string(nameof(P))))]

    return ECP(p, n, a, b, _cofactor, gx, gy; names)
end


function value(point::P) where P <: OpenSSLPrimePoint

    group = group_pointer(P)

    gx = ccall((:BN_new, libcrypto), Ptr{Cvoid}, ())
    gy = ccall((:BN_new, libcrypto), Ptr{Cvoid}, ())

    ret = ccall((:EC_POINT_get_affine_coordinates, libcrypto), Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                group, pointer(point), gx, gy, ctx)

    return bn2bigint(gx), bn2bigint(gy)
end
