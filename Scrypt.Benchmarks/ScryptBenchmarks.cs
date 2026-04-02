using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using Scrypt.Bouncy;
using Scrypt.CryptSharp;
using Scrypt.Scrypt;
using Scrypt.ScryptGpu;

namespace Scrypt.Benchmarks;

[MemoryDiagnoser]
[Config(typeof(BenchmarkConfig))]
public class ScryptBenchmarks
{
    [Params(1024, 16384)]
    public int N { get; set; }

    [Params(1, 4, 16)]
    public int P { get; set; }

    public int R => 8;

    private byte[] _password = null!;
    private byte[] _salt = null!;

    private const int DkLen = 64;

    [GlobalSetup]
    public void Setup()
    {
        _password = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam gravida ac purus et varius. Duis sed tristique mi. In finibus porta velit nec maximus. Maecenas eget enim vel diam euismod aliquet. Fusce viverra quam eu nunc lobortis, sit amet maximus est tincidunt. Pellentesque rutrum pharetra ipsum id accumsan. Vivamus placerat elit sed laoreet euismod. Morbi eget eros a purus finibus bibendum. Nullam tristique commodo eros vitae porta. Aenean non mauris urna. Integer tristique ultrices bibendum.\r\n\r\nPellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Phasellus ante nisl, volutpat vel volutpat a, blandit rutrum elit. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; Sed nisi velit, posuere a luctus quis, vestibulum vitae enim. Ut eu accumsan libero. Mauris malesuada, felis vel mattis porta, elit neque porttitor felis, id pellentesque enim dolor commodo quam. Phasellus id massa a mauris ultrices sodales ac ut quam. Pellentesque eget mauris sapien. Nulla facilisi. Aliquam et magna eu nibh porttitor molestie vel a est.\r\n\r\nProin a magna sed purus sollicitudin suscipit et in urna. Pellentesque sit amet tristique leo, id feugiat ligula. Donec rhoncus condimentum dui in pretium. Maecenas interdum, lorem in pulvinar ullamcorper, risus nibh commodo est, et molestie dui nisl vel justo. Donec vel elit fringilla magna malesuada lacinia. Maecenas arcu dui, sollicitudin ut odio eget, finibus facilisis neque. Ut ultrices laoreet orci in convallis. Vestibulum sem nisi, maximus viverra justo nec, tristique ultrices odio. Etiam laoreet nisl bibendum dignissim euismod. Proin sapien nisi, euismod sit amet est vitae, interdum condimentum ex.\r\n\r\nEtiam nibh enim, sagittis sed lobortis vitae, lacinia eget ex. Sed laoreet, quam vel dictum malesuada, ante lectus fermentum metus, condimentum fringilla nisi purus eu eros. Aenean egestas nibh sem, ac viverra nulla molestie eget. Donec sed magna eget urna rhoncus sodales eget ut ipsum. Integer non ipsum ac eros consequat elementum. Nullam venenatis et erat vel ullamcorper. Fusce semper sodales mi, non iaculis velit euismod in. Proin varius dignissim tortor at fringilla. Praesent fermentum dignissim ligula vitae hendrerit. Phasellus mattis ornare iaculis. Nulla facilisi. Vestibulum justo mi, consequat sit amet suscipit a, faucibus sit amet odio. Proin vehicula elementum urna, ac pellentesque justo venenatis a. Donec vestibulum varius pretium.\r\n\r\nDonec et ex vel arcu vehicula pretium. Quisque nunc elit, placerat nec varius eu, vulputate sed lorem. Cras sodales, quam sed congue convallis, dui nulla sodales eros, non tempor augue sapien sit amet velit. Nulla dapibus sapien eget vehicula aliquam. Donec id metus eleifend, ullamcorper neque sit amet, vulputate purus. Aenean ultrices accumsan enim. Nulla egestas ac nunc id lobortis. Mauris ac sapien lorem. Vivamus volutpat odio a consequat venenatis. Praesent vitae tincidunt tortor. Etiam tempus sem nec magna gravida cursus. Etiam eget luctus ligula. Sed non mi sed ante dictum venenatis eu et mi. Nam tempus metus turpis, nec elementum ex varius auctor."u8.ToArray();
        _salt = "The quick brown fox jumps over the lazy dog"u8.ToArray();
    }

    [Benchmark(Baseline = true)]
    public byte[] SCrypt_Generate()
        => SCrypt.Generate(_password, _salt, N, R, P, DkLen);

    [Benchmark]
    public byte[] ScryptBouncy_Generate()
        => ScryptBouncy.Generate(_password, _salt, N, R, P, DkLen);

    [Benchmark]
    public byte[] SCryptCryptSharp_Generate()
        => SCryptCryptSharp.Generate(_password, _salt, N, R, P, DkLen);

    [Benchmark]
    public byte[] SCryptILGPU_Generate()
        => ScryptILGPU.Generate(_password, _salt, N, R, P, DkLen, true);
}

internal class BenchmarkConfig : ManualConfig
{
    public BenchmarkConfig() => AddJob(Job.Default
            .WithWarmupCount(1)
            .WithIterationCount(5)
            .WithInvocationCount(1)
            .WithUnrollFactor(1));
}
