# Common functionality for curve operations
function get_curves_buffer()
    # Get the built-in curves count
    curves_count = @ccall libcrypto.EC_get_builtin_curves(
        C_NULL::Ptr{Cvoid},
        0::Cint
    )::Cint
    
    # Allocate memory for curve information
    # EC_builtin_curve struct is { nid: nid, comment: *c_char }
    # Size is typically 16 bytes on 64-bit systems
    buffer_size = 16  # sizeof(EC_builtin_curve)
    curves_buffer = Vector{UInt8}(undef, curves_count * buffer_size)

    # Get the actual curve information
    GC.@preserve curves_buffer begin
        ret = @ccall libcrypto.EC_get_builtin_curves(
            curves_buffer::Ptr{UInt8},
            curves_count::Cint
        )::Cint
    end

    return curves_buffer, curves_count, buffer_size
end

function iterate_curves(callback::Function)
    curves_buffer, curves_count, buffer_size = get_curves_buffer()
    
    for i in 0:(curves_count-1)
        # Extract NID from the buffer (first field of EC_builtin_curve struct)
        nid = unsafe_load(Ptr{Cint}(pointer(curves_buffer) + i * buffer_size))
        
        # Get the curve name using NID
        sn = @ccall libcrypto.OBJ_nid2sn(nid::Cint)::Ptr{UInt8}
        if sn != C_NULL
            name = unsafe_string(sn)
            
            # Get long name (description)
            ln = @ccall libcrypto.OBJ_nid2ln(nid::Cint)::Ptr{UInt8}
            description = ln != C_NULL ? unsafe_string(ln) : ""
            
            callback(nid, name, description)
        end
    end
end

function list_curves()
    println("Total number of supported curves: ", get_curves_buffer()[2])
    println("\nSupported curves:")
    println("NID\tCurve Name")
    println("-" ^ 50)
    
    iterate_curves() do nid, name, description
        println("$nid\t$name\t$description")
    end
end

function get_curve_nid(name::String)
    result = Ref{Int}()
    found = false
    
    iterate_curves() do nid, curve_name, description
        if curve_name == name || description == name
            result[] = nid
            found = true
        end
    end
    
    found || error("Curve $name not found")
    return result[]
end

function bn2bigint(bn::Ptr{Cvoid})
    # Convert BIGNUM to hex string
    hex_str = @ccall OpenSSL_jll.libcrypto.BN_bn2hex(bn::Ptr{Cvoid})::Ptr{UInt8}
    if hex_str == C_NULL
        error("Failed to convert BIGNUM to hex")
    end
    
    # Convert C string to Julia string
    jl_hex_str = unsafe_string(hex_str)
    
    # Convert hex string to BigInt
    return parse(BigInt, jl_hex_str, base=16)
end

function bn2octet(bn::Ptr{Cvoid})
    # Convert BIGNUM to hex string
    hex_str = @ccall OpenSSL_jll.libcrypto.BN_bn2hex(bn::Ptr{Cvoid})::Ptr{UInt8}
    if hex_str == C_NULL
        error("Failed to convert BIGNUM to hex")
    end
    
    # Convert C string to Julia string
    jl_hex_str = unsafe_string(hex_str)

    if length(jl_hex_str) % 2 == 1
        jl_hex_str = "0" * jl_hex_str
    end
        
    return hex2bytes(jl_hex_str)
end

function expand(x::Vector{UInt8}, n::Int)
    return UInt8[(0 for i in 1:n-length(x))..., x...]
end

bn2octet(bn::Ptr{Cvoid}, n::Int) = expand(bn2octet(bn), n)

function group_pointer(enum::Int)
    # Create a new EC_GROUP object for the secp256k1 curve
    group = @ccall libcrypto.EC_GROUP_new_by_curve_name(enum::Cint)::Ptr{Cvoid}
    if group == C_NULL
        error("Failed to create EC_GROUP")
    end
    return group
end

function openssl_point_free(ptr::Ptr{Nothing})
    if ptr != C_NULL
        @debug "Freeing OpenSSL point" pointer=ptr
        @ccall libcrypto.EC_POINT_free(ptr::Ptr{Nothing})::Cvoid
    end
end

function openssl_bignum_free(ptr::Ptr{Nothing})
    if ptr != C_NULL
        @debug "Freeing OpenSSL bignum" pointer=ptr
        @ccall libcrypto.BN_free(ptr::Ptr{Cvoid})::Cvoid
    end
end
