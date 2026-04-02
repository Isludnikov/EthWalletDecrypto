using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Scrypt.Scrypt;

public static class SCrypt
{
    /// <summary>
    /// Derives a key using the scrypt password-based key derivation function (RFC 7914).
    /// Equivalent to Org.BouncyCastle.Crypto.Generators.SCrypt.Generate.
    /// </summary>
    /// <param name="P">Password</param>
    /// <param name="S">Salt</param>
    /// <param name="N">CPU/memory cost parameter — must be a power of 2 greater than 1</param>
    /// <param name="r">Block size parameter</param>
    /// <param name="p">Parallelization parameter</param>
    /// <param name="dkLen">Desired output length in bytes</param>
    public static byte[] Generate(byte[] P, byte[] S, int N, int r, int p, int dkLen)
    {
        ArgumentNullException.ThrowIfNull(P);
        ArgumentNullException.ThrowIfNull(S);
        if (N <= 1 || (N & (N - 1)) != 0)
        {
            throw new ArgumentException("N must be a power of 2 greater than 1.", nameof(N));
        }

        var blockSize = 128 * r;
        var B = Pbkdf2(P, S, 1, p * blockSize);

        for (var i = 0; i < p; i++)
        {
            var block = B.AsSpan(i * blockSize, blockSize).ToArray();
            block = ScryptROMix(r, block, N);
            block.AsSpan().CopyTo(B.AsSpan(i * blockSize));
        }

        return Pbkdf2(P, B, 1, dkLen);
    }

    private static byte[] Pbkdf2(byte[] password, byte[] salt, int iterations, int outputLength)
    {
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, outputLength);
    }

    private static byte[] ScryptROMix(int r, byte[] B, int N)
    {
        var X = ToUInt32LE(B);
        var V = new uint[N][];

        for (var i = 0; i < N; i++)
        {
            V[i] = (uint[])X.Clone();
            X = ScryptBlockMix(r, X);
        }

        for (var i = 0; i < N; i++)
        {
            var j = (int)(X[(2 * r - 1) * 16] % (uint)N);
            XorInto(X, V[j]);
            X = ScryptBlockMix(r, X);
        }

        return FromUInt32LE(X);
    }

    private static uint[] ScryptBlockMix(int r, uint[] B)
    {
        var blocks = 2 * r;
        var X = new uint[16];
        Array.Copy(B, (blocks - 1) * 16, X, 0, 16);

        var result = new uint[blocks * 16];
        for (var i = 0; i < blocks; i += 2)
        {
            // Even block
            for (var k = 0; k < 16; k++)
            {
                X[k] ^= B[i * 16 + k];
            }

            Salsa20_8(X);
            Array.Copy(X, 0, result, i / 2 * 16, 16);

            // Odd block
            for (var k = 0; k < 16; k++)
            {
                X[k] ^= B[(i + 1) * 16 + k];
            }

            Salsa20_8(X);
            Array.Copy(X, 0, result, (r + i / 2) * 16, 16);
        }
        return result;
    }

    internal static byte[] TestBlockMix(int r, byte[] B)
    {
        return FromUInt32LE(ScryptBlockMix(r, ToUInt32LE(B)));
    }

    private static void Salsa20_8(uint[] B)
    {
        var x = (uint[])B.Clone();
        for (var i = 0; i < 8; i += 2)
        {
            x[4] ^= R(x[0] + x[12], 7); x[8] ^= R(x[4] + x[0], 9);
            x[12] ^= R(x[8] + x[4], 13); x[0] ^= R(x[12] + x[8], 18);
            x[9] ^= R(x[5] + x[1], 7); x[13] ^= R(x[9] + x[5], 9);
            x[1] ^= R(x[13] + x[9], 13); x[5] ^= R(x[1] + x[13], 18);
            x[14] ^= R(x[10] + x[6], 7); x[2] ^= R(x[14] + x[10], 9);
            x[6] ^= R(x[2] + x[14], 13); x[10] ^= R(x[6] + x[2], 18);
            x[3] ^= R(x[15] + x[11], 7); x[7] ^= R(x[3] + x[15], 9);
            x[11] ^= R(x[7] + x[3], 13); x[15] ^= R(x[11] + x[7], 18);
            x[1] ^= R(x[0] + x[3], 7); x[2] ^= R(x[1] + x[0], 9);
            x[3] ^= R(x[2] + x[1], 13); x[0] ^= R(x[3] + x[2], 18);
            x[6] ^= R(x[5] + x[4], 7); x[7] ^= R(x[6] + x[5], 9);
            x[4] ^= R(x[7] + x[6], 13); x[5] ^= R(x[4] + x[7], 18);
            x[11] ^= R(x[10] + x[9], 7); x[8] ^= R(x[11] + x[10], 9);
            x[9] ^= R(x[8] + x[11], 13); x[10] ^= R(x[9] + x[8], 18);
            x[12] ^= R(x[15] + x[14], 7); x[13] ^= R(x[12] + x[15], 9);
            x[14] ^= R(x[13] + x[12], 13); x[15] ^= R(x[14] + x[13], 18);
        }
        for (var i = 0; i < 16; i++)
        {
            B[i] += x[i];
        }
    }

    private static uint R(uint v, int n)
    {
        return (v << n) | (v >> (32 - n));
    }

    private static void XorInto(uint[] a, uint[] b)
    {
        for (var i = 0; i < a.Length; i++)
        {
            a[i] ^= b[i];
        }
    }

    private static uint[] ToUInt32LE(byte[] bytes)
    {
        var result = new uint[bytes.Length / 4];
        for (var i = 0; i < result.Length; i++)
        {
            result[i] = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i * 4));
        }

        return result;
    }

    private static byte[] FromUInt32LE(uint[] ints)
    {
        var result = new byte[ints.Length * 4];
        for (var i = 0; i < ints.Length; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(i * 4), ints[i]);
        }

        return result;
    }
}
