# julia> OpenSSLGroups.list_curves()
# Total number of supported curves: 82

# Supported curves:
# NID	Curve Name
# --------------------------------------------------
# 704	secp112r1	secp112r1
# 705	secp112r2	secp112r2
# 706	secp128r1	secp128r1
# 707	secp128r2	secp128r2
# 708	secp160k1	secp160k1
# 709	secp160r1	secp160r1
# 710	secp160r2	secp160r2
# 711	secp192k1	secp192k1
# 712	secp224k1	secp224k1
# 713	secp224r1	secp224r1
# 714	secp256k1	secp256k1
# 715	secp384r1	secp384r1
# 716	secp521r1	secp521r1
# 409	prime192v1	prime192v1
# 410	prime192v2	prime192v2
# 411	prime192v3	prime192v3
# 412	prime239v1	prime239v1
# 413	prime239v2	prime239v2
# 414	prime239v3	prime239v3
# 415	prime256v1	prime256v1
# 717	sect113r1	sect113r1
# 718	sect113r2	sect113r2
# 719	sect131r1	sect131r1
# 720	sect131r2	sect131r2
# 721	sect163k1	sect163k1
# 722	sect163r1	sect163r1
# 723	sect163r2	sect163r2
# 724	sect193r1	sect193r1
# 725	sect193r2	sect193r2
# 726	sect233k1	sect233k1
# 727	sect233r1	sect233r1
# 728	sect239k1	sect239k1
# 729	sect283k1	sect283k1
# 730	sect283r1	sect283r1
# 731	sect409k1	sect409k1
# 732	sect409r1	sect409r1
# 733	sect571k1	sect571k1
# 734	sect571r1	sect571r1
# 684	c2pnb163v1	c2pnb163v1
# 685	c2pnb163v2	c2pnb163v2
# 686	c2pnb163v3	c2pnb163v3
# 687	c2pnb176v1	c2pnb176v1
# 688	c2tnb191v1	c2tnb191v1
# 689	c2tnb191v2	c2tnb191v2
# 690	c2tnb191v3	c2tnb191v3
# 693	c2pnb208w1	c2pnb208w1
# 694	c2tnb239v1	c2tnb239v1
# 695	c2tnb239v2	c2tnb239v2
# 696	c2tnb239v3	c2tnb239v3
# 699	c2pnb272w1	c2pnb272w1
# 700	c2pnb304w1	c2pnb304w1
# 701	c2tnb359v1	c2tnb359v1
# 702	c2pnb368w1	c2pnb368w1
# 703	c2tnb431r1	c2tnb431r1
# 735	wap-wsg-idm-ecid-wtls1	wap-wsg-idm-ecid-wtls1
# 736	wap-wsg-idm-ecid-wtls3	wap-wsg-idm-ecid-wtls3
# 737	wap-wsg-idm-ecid-wtls4	wap-wsg-idm-ecid-wtls4
# 738	wap-wsg-idm-ecid-wtls5	wap-wsg-idm-ecid-wtls5
# 739	wap-wsg-idm-ecid-wtls6	wap-wsg-idm-ecid-wtls6
# 740	wap-wsg-idm-ecid-wtls7	wap-wsg-idm-ecid-wtls7
# 741	wap-wsg-idm-ecid-wtls8	wap-wsg-idm-ecid-wtls8
# 742	wap-wsg-idm-ecid-wtls9	wap-wsg-idm-ecid-wtls9
# 743	wap-wsg-idm-ecid-wtls10	wap-wsg-idm-ecid-wtls10
# 744	wap-wsg-idm-ecid-wtls11	wap-wsg-idm-ecid-wtls11
# 745	wap-wsg-idm-ecid-wtls12	wap-wsg-idm-ecid-wtls12
# 749	Oakley-EC2N-3	ipsec3
# 750	Oakley-EC2N-4	ipsec4
# 921	brainpoolP160r1	brainpoolP160r1
# 922	brainpoolP160t1	brainpoolP160t1
# 923	brainpoolP192r1	brainpoolP192r1
# 924	brainpoolP192t1	brainpoolP192t1
# 925	brainpoolP224r1	brainpoolP224r1
# 926	brainpoolP224t1	brainpoolP224t1
# 927	brainpoolP256r1	brainpoolP256r1
# 928	brainpoolP256t1	brainpoolP256t1
# 929	brainpoolP320r1	brainpoolP320r1
# 930	brainpoolP320t1	brainpoolP320t1
# 931	brainpoolP384r1	brainpoolP384r1
# 932	brainpoolP384t1	brainpoolP384t1
# 933	brainpoolP512r1	brainpoolP512r1
# 934	brainpoolP512t1	brainpoolP512t1
# 1172	SM2	sm2


macro prime_curve(curve_name, struct_name::Symbol)

    # Handle both Symbol and String representations
    curve_str = if curve_name isa Symbol
        String(curve_name)
    else
        string(curve_name) 
    end

    group_nid = get_curve_nid(curve_str)
    
    return quote
        mutable struct $(esc(struct_name)) <: OpenSSLPrimePoint
            pointer::Ptr{Nothing}
            function $(esc(struct_name))(x::Ptr{Nothing}; skip_finalizer::Bool=false)
                point = new(x)

                if !skip_finalizer
                    finalizer(point) do p
                        if p.pointer != C_NULL
                            @ccall libcrypto.EC_POINT_free(p.pointer::Ptr{Nothing})::Cvoid
                            p.pointer = C_NULL
                        end
                    end
                end

                return point
            end
        end

        $(esc(:get_curve_nid))(::Type{$(esc(struct_name))}) = $group_nid

        # We are implicitly allso setting group pointer here
        let field_type = field($(esc(struct_name)))
            global $(esc(:field))(::Type{$(esc(struct_name))}) = field_type
        end

        let _cofactor = cofactor($(esc(struct_name)))
            global $(esc(:cofactor))(::Type{$(esc(struct_name))}) = _cofactor
        end

        let _group_ptr = nothing
            global function $(esc(:group_pointer))(::Type{$(esc(struct_name))})
                if _group_ptr === nothing
                    _group_ptr = $(esc(:group_pointer))($group_nid)
                end
                return _group_ptr
            end
        end
    end
end


macro binary_curve(curve_name, struct_name::Symbol)

    # Handle both Symbol and String representations
    curve_str = if curve_name isa Symbol
        String(curve_name)
    else
        string(curve_name) 
    end
    
    group_nid = get_curve_nid(curve_str)

    return quote
        mutable struct $(esc(struct_name)) <: OpenSSLBinaryPoint
            pointer::Ptr{Nothing}
            function $(esc(struct_name))(x::Ptr{Nothing}; skip_finalizer::Bool=false)
                point = new(x)
                
                if !skip_finalizer
                    finalizer(point) do p
                        if p.pointer != C_NULL
                            @ccall libcrypto.EC_POINT_free(p.pointer::Ptr{Nothing})::Cvoid
                            p.pointer = C_NULL
                        end
                    end
                end

                return point
            end
        end

        $(esc(:get_curve_nid))(::Type{$(esc(struct_name))}) = $group_nid

        # We are implicitly allso setting group pointer here
        let field_type = field($(esc(struct_name)))
            global $(esc(:field))(::Type{$(esc(struct_name))}) = field_type
        end

        let _cofactor = cofactor($(esc(struct_name)))
            global $(esc(:cofactor))(::Type{$(esc(struct_name))}) = _cofactor
        end

        let _group_ptr = nothing
            global function $(esc(:group_pointer))(::Type{$(esc(struct_name))})
                if _group_ptr === nothing
                    _group_ptr = $(esc(:group_pointer))($group_nid)
                end
                return _group_ptr
            end
        end
    end
end

# Prime Curves (secp, prime, brainpoolP)
@prime_curve secp112r1 SecP112r1
@prime_curve secp112r2 SecP112r2
@prime_curve secp128r1 SecP128r1
@prime_curve secp128r2 SecP128r2
@prime_curve secp160k1 SecP160k1
@prime_curve secp160r1 SecP160r1
@prime_curve secp160r2 SecP160r2
@prime_curve secp192k1 SecP192k1
@prime_curve secp224k1 SecP224k1
@prime_curve secp224r1 SecP224r1
@prime_curve secp256k1 SecP256k1
@prime_curve secp384r1 SecP384r1
@prime_curve secp521r1 SecP521r1

@prime_curve prime192v1 Prime192v1
@prime_curve prime192v2 Prime192v2
@prime_curve prime192v3 Prime192v3
@prime_curve prime239v1 Prime239v1
@prime_curve prime239v2 Prime239v2
@prime_curve prime239v3 Prime239v3
@prime_curve prime256v1 Prime256v1

@prime_curve brainpoolP160r1 BrainpoolP160r1
@prime_curve brainpoolP160t1 BrainpoolP160t1
@prime_curve brainpoolP192r1 BrainpoolP192r1
@prime_curve brainpoolP192t1 BrainpoolP192t1
@prime_curve brainpoolP224r1 BrainpoolP224r1
@prime_curve brainpoolP224t1 BrainpoolP224t1
@prime_curve brainpoolP256r1 BrainpoolP256r1
@prime_curve brainpoolP256t1 BrainpoolP256t1
@prime_curve brainpoolP320r1 BrainpoolP320r1
@prime_curve brainpoolP320t1 BrainpoolP320t1
@prime_curve brainpoolP384r1 BrainpoolP384r1
@prime_curve brainpoolP384t1 BrainpoolP384t1
@prime_curve brainpoolP512r1 BrainpoolP512r1
@prime_curve brainpoolP512t1 BrainpoolP512t1

@prime_curve sm2 SM2

@prime_curve "wap-wsg-idm-ecid-wtls9" WtlsCurve9
@prime_curve "wap-wsg-idm-ecid-wtls8" WtlsCurve8
@prime_curve "wap-wsg-idm-ecid-wtls7" WtlsCurve7
@prime_curve "wap-wsg-idm-ecid-wtls6" WtlsCurve6
@prime_curve "wap-wsg-idm-ecid-wtls12" WtlsCurve12

# Binary Curves (sect, c2pnb, c2tnb, wap-wsg)
@binary_curve sect113r1 SecT113r1
@binary_curve sect113r2 SecT113r2
@binary_curve sect131r1 SecT131r1
@binary_curve sect131r2 SecT131r2
@binary_curve sect163k1 SecT163k1
@binary_curve sect163r1 SecT163r1
@binary_curve sect163r2 SecT163r2
@binary_curve sect193r1 SecT193r1
@binary_curve sect193r2 SecT193r2
@binary_curve sect233k1 SecT233k1
@binary_curve sect233r1 SecT233r1
@binary_curve sect239k1 SecT239k1
@binary_curve sect283k1 SecT283k1
@binary_curve sect283r1 SecT283r1
@binary_curve sect409k1 SecT409k1
@binary_curve sect409r1 SecT409r1
@binary_curve sect571k1 SecT571k1
@binary_curve sect571r1 SecT571r1

@binary_curve c2pnb163v1 C2pnb163v1
@binary_curve c2pnb163v2 C2pnb163v2
@binary_curve c2pnb163v3 C2pnb163v3
@binary_curve c2pnb176v1 C2pnb176v1
@binary_curve c2tnb191v1 C2tnb191v1
@binary_curve c2tnb191v2 C2tnb191v2
@binary_curve c2tnb191v3 C2tnb191v3
@binary_curve c2pnb208w1 C2pnb208w1
@binary_curve c2tnb239v1 C2tnb239v1
@binary_curve c2tnb239v2 C2tnb239v2
@binary_curve c2tnb239v3 C2tnb239v3
@binary_curve c2pnb272w1 C2pnb272w1
@binary_curve c2pnb304w1 C2pnb304w1
@binary_curve c2tnb359v1 C2tnb359v1
@binary_curve c2pnb368w1 C2pnb368w1
@binary_curve c2tnb431r1 C2tnb431r1

@binary_curve "wap-wsg-idm-ecid-wtls1" WtlsCurve1
@binary_curve "wap-wsg-idm-ecid-wtls3" WtlsCurve3
@binary_curve "wap-wsg-idm-ecid-wtls4" WtlsCurve4
@binary_curve "wap-wsg-idm-ecid-wtls5" WtlsCurve5
@binary_curve "wap-wsg-idm-ecid-wtls10" WtlsCurve10
@binary_curve "wap-wsg-idm-ecid-wtls11" WtlsCurve11

@binary_curve ipsec3 IpsecCurve3
@binary_curve ipsec4 IpsecCurve4
