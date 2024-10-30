using SafeTestsets

sleep(1)

@safetestset "Testing point arithmetics and serialization" begin
    include("basics.jl")
end


