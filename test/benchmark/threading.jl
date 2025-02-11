using BenchmarkTools
using Base.Threads
using CryptoGroups: @ECGroup, ECGroup
import OpenSSLGroups: Prime256v1

g = @ECGroup{Prime256v1}()

# Parallel power computation

list = Vector{typeof(g)}(undef, 1000000)
@threads for i in eachindex(list)
    list[i] = g^i
end

n = div(length(list), 2)
gn = g^n

# Parallel comparison
result = Vector{Bool}(undef, length(list))
@btime begin
    @threads for i in eachindex($list)
        $result[i] = $list[i] == $gn
    end
end
