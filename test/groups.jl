using Test

using CryptoGroups.Curves: ECPoint
using CryptoGroups: @ECGroup, ECGroup, ECPoint, @ECPoint, spec, concretize_type
using OpenSSLGroups
import OpenSSLGroups: SecP256k1, Prime256v1, SecT283k1

@test @ECPoint{SecP256k1}() == @ECPoint{OpenSSLGroups.SecP256k1}()

@test ECPoint{SecP256k1}(value(@ECPoint{SecP256k1}())...) == @ECPoint{SecP256k1}()

@test @ECPoint{SecP256k1} <: ECPoint{SecP256k1}

function test_group(G)

    g = G()

    @test g^3 * g^5 / g^2 == (g^3)^2 == g^6
    @test g^(order(G) - 1) * g == one(G)
    @test g*g*g == g^3 # Checking multiplication

    @test g == G(octet(g)) == G(value(g))

    # edge cases

    @test_warn "A bad exponent" g^0
    @test_warn "A bad exponent" g^order(G)
    
    @test isone(g * g^(-1))
    @test g * one(G) == g

    @test isone(g/g)

#    @infiltrate

    @test G(octet(one(G)); allow_one=true) == one(G)
    @test G(value(one(G)); allow_one=true) == one(G)

    # some benchmarks
    _spec = spec(G)
    Q = concretize_type(ECGroup, _spec)
    q = Q(_spec.Gx, _spec.Gy)
    @test octet(q) == octet(g)

    println("Group $(G)")

    @time qinv = q^(order(G) - 1)
    @time ginv = g^(order(G) - 1)
    @test octet(qinv) == octet(ginv)
    
    return
end

test_group(@ECGroup{SecP256k1})
test_group(@ECGroup{Prime256v1})
test_group(@ECGroup{SecT283k1})
