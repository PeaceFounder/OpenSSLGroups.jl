using SafeTestsets

@safetestset "Testing point arithmetics and serialization" begin
    include("basics.jl")
end

@safetestset "Testing group API" begin
    include("groups.jl")
end

@safetestset "Integration test with ShuffleProofs" begin
    include("shuffle.jl")
end

