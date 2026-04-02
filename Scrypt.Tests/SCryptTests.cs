using Scrypt.Bouncy;
using Scrypt.CryptSharp;
using Scrypt.Scrypt;
using Scrypt.ScryptGpu;
using Xunit;

namespace Scrypt.Tests;

// RFC 7914 §12 test vectors: https://www.rfc-editor.org/rfc/rfc7914#section-12
public class SCryptTests
{
    [Fact]
    public void Generate_Rfc7914_Vector1_EmptyPasswordAndSalt()
    {
        // scrypt("", "", N=16, r=1, p=1, dkLen=64)
        var result = SCrypt.Generate([], [], 16, 1, 1, 64);

        Assert.Equal(
            "77d6576238657b203b19ca42c18a0497" +
            "f16b4844e3074ae8dfdffa3fede21442" +
            "fcd0069ded0948f8326a753a0fc81f17" +
            "e8d3e0fb2e0d3628cf35e20c38d18906",
            ToHex(result));
    }
    [Fact]
    public void Generate_Rfc7914_Vector1_EmptyPasswordAndSalt_Bouncy()
    {
        // scrypt("", "", N=16, r=1, p=1, dkLen=64)
        var result = ScryptBouncy.Generate([], [], 16, 1, 1, 64);

        Assert.Equal(
            "77d6576238657b203b19ca42c18a0497" +
            "f16b4844e3074ae8dfdffa3fede21442" +
            "fcd0069ded0948f8326a753a0fc81f17" +
            "e8d3e0fb2e0d3628cf35e20c38d18906",
            ToHex(result));
    }
    [Fact]
    public void Generate_Rfc7914_Vector1_EmptyPasswordAndSalt_CryptSharp()
    {
        // scrypt("", "", N=16, r=1, p=1, dkLen=64)
        var result = SCryptCryptSharp.Generate([], [], 16, 1, 1, 64);

        Assert.Equal(
            "77d6576238657b203b19ca42c18a0497" +
            "f16b4844e3074ae8dfdffa3fede21442" +
            "fcd0069ded0948f8326a753a0fc81f17" +
            "e8d3e0fb2e0d3628cf35e20c38d18906",
            ToHex(result));
    }
    [Fact]
    public void Generate_Rfc7914_Vector2_PasswordNaCl()
    {
        // scrypt("password", "NaCl", N=1024, r=8, p=16, dkLen=64)
        var result = SCrypt.Generate(
            "password"u8.ToArray(),
            "NaCl"u8.ToArray(),
            1024, 8, 16, 64);

        Assert.Equal(
            "fdbabe1c9d3472007856e7190d01e9fe" +
            "7c6ad7cbc8237830e77376634b373162" +
            "2eaf30d92e22a3886ff109279d9830da" +
            "c727afb94a83ee6d8360cbdfa2cc0640",
            ToHex(result));
    }
    [Fact]
    public void Generate_Rfc7914_Vector2_PasswordNaCl_Bouncy()
    {
        // scrypt("password", "NaCl", N=1024, r=8, p=16, dkLen=64)
        var result = ScryptBouncy.Generate(
            "password"u8.ToArray(),
            "NaCl"u8.ToArray(),
            1024, 8, 16, 64);

        Assert.Equal(
            "fdbabe1c9d3472007856e7190d01e9fe" +
            "7c6ad7cbc8237830e77376634b373162" +
            "2eaf30d92e22a3886ff109279d9830da" +
            "c727afb94a83ee6d8360cbdfa2cc0640",
            ToHex(result));
    }
    [Fact]
    public void Generate_Rfc7914_Vector2_PasswordNaCl_CryptSharp()
    {
        // scrypt("password", "NaCl", N=1024, r=8, p=16, dkLen=64)
        var result = SCryptCryptSharp.Generate(
            "password"u8.ToArray(),
            "NaCl"u8.ToArray(),
            1024, 8, 16, 64);

        Assert.Equal(
            "fdbabe1c9d3472007856e7190d01e9fe" +
            "7c6ad7cbc8237830e77376634b373162" +
            "2eaf30d92e22a3886ff109279d9830da" +
            "c727afb94a83ee6d8360cbdfa2cc0640",
            ToHex(result));
    }

    [Fact]
    public void Generate_Rfc7914_Vector3_PleaseletmeinSodiumChloride()
    {
        // scrypt("pleaseletmein", "SodiumChloride", N=16384, r=8, p=1, dkLen=64)
        var result = SCrypt.Generate(
            "pleaseletmein"u8.ToArray(),
            "SodiumChloride"u8.ToArray(),
            16384, 8, 1, 64);

        Assert.Equal(
            "7023bdcb3afd7348461c06cd81fd38eb" +
            "fda8fbba904f8e3ea9b543f6545da1f2" +
            "d5432955613f0fcf62d49705242a9af9" +
            "e61e85dc0d651e40dfcf017b45575887",
            ToHex(result));
    }
    [Fact]
    public void Generate_Rfc7914_Vector3_PleaseletmeinSodiumChloride_Bouncy()
    {
        // scrypt("pleaseletmein", "SodiumChloride", N=16384, r=8, p=1, dkLen=64)
        var result = ScryptBouncy.Generate(
            "pleaseletmein"u8.ToArray(),
            "SodiumChloride"u8.ToArray(),
            16384, 8, 1, 64);

        Assert.Equal(
            "7023bdcb3afd7348461c06cd81fd38eb" +
            "fda8fbba904f8e3ea9b543f6545da1f2" +
            "d5432955613f0fcf62d49705242a9af9" +
            "e61e85dc0d651e40dfcf017b45575887",
            ToHex(result));
    }
    [Fact]
    public void Generate_Rfc7914_Vector3_PleaseletmeinSodiumChloride_CryptSharp()
    {
        // scrypt("pleaseletmein", "SodiumChloride", N=16384, r=8, p=1, dkLen=64)
        var result = SCryptCryptSharp.Generate(
            "pleaseletmein"u8.ToArray(),
            "SodiumChloride"u8.ToArray(),
            16384, 8, 1, 64);

        Assert.Equal(
            "7023bdcb3afd7348461c06cd81fd38eb" +
            "fda8fbba904f8e3ea9b543f6545da1f2" +
            "d5432955613f0fcf62d49705242a9af9" +
            "e61e85dc0d651e40dfcf017b45575887",
            ToHex(result));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(15)]
    public void Generate_InvalidN_ThrowsArgumentException(int N)
    {
        Assert.Throws<ArgumentException>(() => SCrypt.Generate([], [], N, 1, 1, 32));
    }

    [Fact]
    public void Generate_NullPassword_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => SCrypt.Generate(null!, [], 16, 1, 1, 32));
    }

    [Fact]
    public void Generate_NullSalt_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => SCrypt.Generate([], null!, 16, 1, 1, 32));
    }

    [Theory]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    public void Generate_ReturnsExactRequestedLength(int dkLen)
    {
        var result = SCrypt.Generate([], [], 16, 1, 1, dkLen);
        Assert.Equal(dkLen, result.Length);
    }

    [Fact]
    public void Generate_DifferentPasswords_ProduceDifferentKeys()
    {
        var a = SCrypt.Generate("password1"u8.ToArray(), [], 16, 1, 1, 32);
        var b = SCrypt.Generate("password2"u8.ToArray(), [], 16, 1, 1, 32);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Generate_DifferentSalts_ProduceDifferentKeys()
    {
        var a = SCrypt.Generate([], "salt1"u8.ToArray(), 16, 1, 1, 32);
        var b = SCrypt.Generate([], "salt2"u8.ToArray(), 16, 1, 1, 32);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Generate_SameInputs_ProduceSameKey()
    {
        var P = "password"u8.ToArray();
        var S = "salt"u8.ToArray();
        var a = SCrypt.Generate(P, S, 16, 1, 1, 32);
        var b = SCrypt.Generate(P, S, 16, 1, 1, 32);
        Assert.Equal(a, b);
    }

    [Fact]
    public void Generate_Rfc7914_Vector1_EmptyPasswordAndSalt_ILGPU()
    {
        // scrypt("", "", N=16, r=1, p=1, dkLen=64)
        var result = ScryptILGPU.Generate([], [], 16, 1, 1, 64);

        Assert.Equal(
            "77d6576238657b203b19ca42c18a0497" +
            "f16b4844e3074ae8dfdffa3fede21442" +
            "fcd0069ded0948f8326a753a0fc81f17" +
            "e8d3e0fb2e0d3628cf35e20c38d18906",
            ToHex(result));
    }

    [Fact]
    public void Generate_Rfc7914_Vector2_PasswordNaCl_ILGPU()
    {
        // scrypt("password", "NaCl", N=1024, r=8, p=16, dkLen=64)
        var result = ScryptILGPU.Generate(
            "password"u8.ToArray(),
            "NaCl"u8.ToArray(),
            1024, 8, 16, 64);

        Assert.Equal(
            "fdbabe1c9d3472007856e7190d01e9fe" +
            "7c6ad7cbc8237830e77376634b373162" +
            "2eaf30d92e22a3886ff109279d9830da" +
            "c727afb94a83ee6d8360cbdfa2cc0640",
            ToHex(result));
    }

    [Fact]
    public void Generate_Rfc7914_Vector3_PleaseletmeinSodiumChloride_ILGPU()
    {
        // scrypt("pleaseletmein", "SodiumChloride", N=16384, r=8, p=1, dkLen=64)
        var result = ScryptILGPU.Generate(
            "pleaseletmein"u8.ToArray(),
            "SodiumChloride"u8.ToArray(),
            16384, 8, 1, 64);

        Assert.Equal(
            "7023bdcb3afd7348461c06cd81fd38eb" +
            "fda8fbba904f8e3ea9b543f6545da1f2" +
            "d5432955613f0fcf62d49705242a9af9" +
            "e61e85dc0d651e40dfcf017b45575887",
            ToHex(result));
    }

    private static string ToHex(byte[] bytes)
    {
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
