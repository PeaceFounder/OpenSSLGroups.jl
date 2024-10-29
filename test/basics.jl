using Test
using InteractiveUtils

using OpenSSLGroups
import OpenSSLGroups: SecP256k1, gx, gy, order, cofactor, curve_parameters, value, list_curves, field, spec, octet_legacy
import CryptoGroups: concretize_type
import CryptoGroups.Curves: ECPoint

function test_curve(P)

    p1 = P()

    @test P(octet(p1)) == p1
    @test P(octet(p1; mode = :compressed)) == p1
    @test P(gx(p1), gy(p1)) == p1
    @test P(value(p1)) == p1

    p2 = p1 * 2

    @test p1 * 4 == p2 * 2
    @test p2 + p1 ==  p1 * 3
    @test p2 - p1 == p1
    @test p1 + p1 == 2 * p1

    @test iszero(p1 - p1)
    @test iszero(p1 + (-p1))
    @test iszero(zero(P))
    @test iszero(zero(P) * 3)
    @test iszero(zero(P) * 3) # What happens here?
    @test iszero(p2) == false
    @test iszero(p1 * order(P))

    @test copy(p1) == p1

    _spec = spec(P)
    @test cofactor(_spec) == cofactor(P)
    @test order(_spec) == order(P)

    # testing 
    Q = concretize_type(ECPoint, _spec)
    p = P()
    q = Q(octet(p))
    @test octet(p) == octet(q)
    @test octet(p * 3) == octet(q * 3)

    return nothing
end

# Test all prime curves
@testset "Prime curves" begin
    for P in subtypes(OpenSSLGroups.OpenSSLPrimePoint)
        try
            test_curve(P)
            @info "Successfully tested $(nameof(P))"
        catch e
            @warn "Failed testing $(nameof(P))" exception=(e, catch_backtrace())
        end
    end
end

# Test all binary curves
@testset "Binary curves" begin
    for P in subtypes(OpenSSLGroups.OpenSSLBinaryPoint)
        try
            test_curve(P)
            @info "Successfully tested $(nameof(P))"
        catch e
            @warn "Failed testing $(nameof(P))" exception=(e, catch_backtrace())
        end
    end
end
