using BenchmarkDotNet.Attributes;
using Scrypt.Bouncy;
using Scrypt.CryptSharp;
using Scrypt.ScryptGpu;

namespace Scrypt.Benchmarks;

[MemoryDiagnoser]
[Config(typeof(BenchmarkConfig))]
public class ScryptBatchBenchmark
{
    [Params(128, 16348)]
    public int N { get; set; }

    [Params(4)]
    public int P { get; set; }
    [Params(10, 100)]
    public int BatchSize { get; set; }

    private static int R => 8;
    private IReadOnlyList<(byte[] P, byte[] S)> _sourceVector =[];

    private const int DkLen = 32;

    [GlobalSetup]
    public void Setup()
    {
        var sourceVector = new List<(byte[] P, byte[] S)>
        {
            Capacity = BatchSize
        };
        
        for (var i = 0; i < BatchSize; ++i)
        {
            sourceVector.Add(("The quick brown fox jumps over the lazy dog"u8.ToArray(), "The quick brown fox jumps over the lazy dog"u8.ToArray()));
        }
        _sourceVector = sourceVector;
    }

    [Benchmark]
    public void ScryptBouncy_Generate()
    {
        foreach (var valueTuple in _sourceVector)
        {
            _ = ScryptBouncy.Generate(valueTuple.P, valueTuple.S, N, R, P, DkLen);
        }
    }

    [Benchmark]
    public void SCryptCryptSharp_Generate()
    {
        foreach (var valueTuple in _sourceVector)
        {
            _ = SCryptCryptSharp.Generate(valueTuple.P, valueTuple.S, N, R, P, DkLen);
        }
    }

    [Benchmark]
    public void SCryptILGPU_Generate()
        => ScryptILGPU.GenerateBatch(_sourceVector, N, R, P, DkLen);
}