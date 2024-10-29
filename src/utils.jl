function bn2bigint(bn::Ptr{Cvoid})
    
    # Convert BIGNUM to hex string
    hex_str = ccall((:BN_bn2hex, OpenSSL_jll.libcrypto), Ptr{UInt8}, (Ptr{Cvoid},), bn)
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
    hex_str = ccall((:BN_bn2hex, OpenSSL_jll.libcrypto), Ptr{UInt8}, (Ptr{Cvoid},), bn)
    if hex_str == C_NULL
        error("Failed to convert BIGNUM to hex")
    end
    
    # Convert C string to Julia string
    jl_hex_str = unsafe_string(hex_str)

    if length(jl_hex_str) % 2 == 1
        jl_hex_str = "0" * jl_hex_str
    end
        
    return hex2bytes(jl_hex_str) # May need a reverse to match specification here
end

function expand(x::Vector{UInt8}, n::Int)
    return UInt8[(0 for i in 1:n-length(x))..., x...]
end

bn2octet(bn::Ptr{Cvoid}, n::Int) = expand(bn2octet(bn), n)
#bn2octet(bn::Ptr{Cvoid}, n::Int) = reverse(expand(reverse(bn2octet(bn)), n))

function list_curves()
    #libcrypto = OpenSSL_jll.libcrypto

    # Get the built-in curves count
    curves_count = ccall((:EC_get_builtin_curves, libcrypto), Cint, 
                        (Ptr{Cvoid}, Cint), C_NULL, 0)
    
    println("Total number of supported curves: ", curves_count)
    
    # Allocate memory for curve information
    # EC_builtin_curve struct is { nid: nid, comment: *c_char }
    # Size is typically 16 bytes on 64-bit systems
    buffer_size = 16  # sizeof(EC_builtin_curve)
    curves_buffer = Vector{UInt8}(undef, curves_count * buffer_size)
    
    # Get the actual curve information
    ret = ccall((:EC_get_builtin_curves, libcrypto), Cint,
                (Ptr{UInt8}, Cint),
                curves_buffer, curves_count)

    println("\nSupported curves:")
    println("NID\tCurve Name")
    println("-" ^ 50)

    # Process each curve
    for i in 0:(curves_count-1)
        # Extract NID from the buffer (first field of EC_builtin_curve struct)
        nid = unsafe_load(Ptr{Cint}(pointer(curves_buffer) + i * buffer_size))
        
        # Get the curve name using NID
        sn = ccall((:OBJ_nid2sn, libcrypto), Ptr{UInt8}, (Cint,), nid)
        if sn != C_NULL
            name = unsafe_string(sn)
            
            # Get long name (description)
            ln = ccall((:OBJ_nid2ln, libcrypto), Ptr{UInt8}, (Cint,), nid)
            description = ""
            if ln != C_NULL
                description = unsafe_string(ln)
            end
            
            println("$nid\t$name\t$description")
        end
    end
end

function group_pointer(enum::Int)

    # Create a new EC_GROUP object for the secp256k1 curve
    group = ccall((:EC_GROUP_new_by_curve_name, libcrypto), Ptr{Cvoid}, (Cint,), enum)
    if group == C_NULL
        error("Failed to create EC_GROUP")
    end
    
    return group
end

function get_curve_nid(name::String)

    # Get the built-in curves count
    curves_count = ccall((:EC_get_builtin_curves, libcrypto), Cint, 
                        (Ptr{Cvoid}, Cint), C_NULL, 0)
    

    buffer_size = 16  # sizeof(EC_builtin_curve)
    curves_buffer = Vector{UInt8}(undef, curves_count * buffer_size)
    
    # Get the actual curve information
    ret = ccall((:EC_get_builtin_curves, libcrypto), Cint,
                (Ptr{UInt8}, Cint),
                curves_buffer, curves_count)

    # Process each curve
    for i in 0:(curves_count-1)
        # Extract NID from the buffer (first field of EC_builtin_curve struct)
        nid = unsafe_load(Ptr{Cint}(pointer(curves_buffer) + i * buffer_size))
        
        # Get the curve name using NID
        sn = ccall((:OBJ_nid2sn, libcrypto), Ptr{UInt8}, (Cint,), nid)
        if sn != C_NULL
            _name = unsafe_string(sn)
            
            if _name == name
                return nid |> Int
            end

            # Get long name (description)
            ln = ccall((:OBJ_nid2ln, libcrypto), Ptr{UInt8}, (Cint,), nid)

            if ln != C_NULL && name == unsafe_string(ln)
                return nid |> Int
            end
        end
    end

    error("Curve $name not found")
end
