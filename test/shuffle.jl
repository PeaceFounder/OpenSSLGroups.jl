using CryptoGroups
using OpenSSLGroups
import ShuffleProofs: shuffle, verify
import SigmaProofs.ElGamal: Enc, Dec, ElGamalRow 
import SigmaProofs.Verificatum: ProtocolSpec

g = @ECGroup{OpenSSLGroups.Prime256v1}()

verifier = ProtocolSpec(; g)

sk = 123
pk = g^sk

enc = Enc(pk, g)

𝐦 = [g^4, g^2, g^3] .|> tuple
𝐞 = enc(𝐦, [2, 3, 4]) 

𝐫′ = [4, 2, 10]
e_enc = enc(𝐞, 𝐫′)

simulator = shuffle(𝐞, g, pk, verifier)
@test verify(simulator)

### Testing width

𝐦 = [
    (g^2, g^4),
    (g^4, g^5),
    (g^7, g^3)
]

𝐫 = [
    2 5;
    4 6;
    9 8;
]

𝐞 = enc(𝐦, 𝐫)

simulator = shuffle(𝐞, g, pk, verifier)
@test verify(simulator)

dec = Dec(sk)
@test sort(𝐦) == sort(dec(simulator.proposition.𝐞′))
