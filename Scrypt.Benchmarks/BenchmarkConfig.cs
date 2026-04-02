using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;

namespace Scrypt.Benchmarks;

internal class BenchmarkConfig : ManualConfig
{
    public BenchmarkConfig() => AddJob(Job.Default
        .WithWarmupCount(1)
        .WithIterationCount(5)
        .WithInvocationCount(1)
        .WithUnrollFactor(1));
}