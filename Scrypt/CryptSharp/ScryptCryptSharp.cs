using Scrypt.CryptSharp.Utils;
using System.Security.Cryptography;

namespace Scrypt.CryptSharp;

public static class SCryptCryptSharp
{
    private const int hLen = 32;

    public static byte[] Generate(byte[] key, byte[] salt,
                                           int cost, int blockSize, int parallel,
                                           int derivedKeyLength)
    {
        Check.Range("derivedKeyLength", derivedKeyLength, 0, int.MaxValue);

        using var kdf = GetStream(key, salt, cost, blockSize, parallel, null);
        return kdf.Read(derivedKeyLength);
    }

    public static byte[] GetEffectivePbkdf2Salt(byte[] key, byte[] salt,
                                                int cost, int blockSize, int parallel, int? maxThreads)
    {
        Check.Null("key", key); Check.Null("salt", salt);
        return MFcrypt(key, salt, cost, blockSize, parallel, maxThreads);
    }

    public static Pbkdf2 GetStream(byte[] key, byte[] salt,
                                   int cost, int blockSize, int parallel, int? maxThreads)
    {
        var B = GetEffectivePbkdf2Salt(key, salt, cost, blockSize, parallel, maxThreads);
        var kdf = new Pbkdf2(new HMACSHA256(key), B, 1);
        Security.Clear(B); return kdf;
    }

    private static byte[] MFcrypt(byte[] P, byte[] S,
                          int cost, int blockSize, int parallel, int? maxThreads)
    {
        var MFLen = blockSize * 128;
        maxThreads ??= int.MaxValue;

        if (!BitMath.IsPositivePowerOf2(cost))
        { throw new ArgumentOutOfRangeException("cost", "Cost must be a positive power of 2."); }
        Check.Range("blockSize", blockSize, 1, int.MaxValue / 128);
        Check.Range("parallel", parallel, 1, int.MaxValue / MFLen);
        Check.Range("maxThreads", (int)maxThreads, 1, int.MaxValue);

        var B = Pbkdf2.ComputeDerivedKey(new HMACSHA256(P), S, 1, parallel * MFLen);

        var B0 = new uint[B.Length / 4];
        for (var i = 0; i < B0.Length; i++) { B0[i] = BitPacking.UInt32FromLEBytes(B, i * 4); } // code is easier with uint[]
        ThreadSMixCalls(B0, MFLen, cost, blockSize, parallel, (int)maxThreads);
        for (var i = 0; i < B0.Length; i++) { BitPacking.LEBytesFromUInt32(B0[i], B, i * 4); }
        Security.Clear(B0);

        return B;
    }

    private static void ThreadSMixCalls(uint[] B0, int MFLen,
                                int cost, int blockSize, int parallel, int maxThreads)
    {
        var current = 0;
        ThreadStart workerThread = delegate ()
        {
            while (true)
            {
                var j = Interlocked.Increment(ref current) - 1;
                if (j >= parallel) { break; }

                SMix(B0, j * MFLen / 4, B0, j * MFLen / 4, (uint)cost, blockSize);
            }
        };

        var threadCount = Math.Max(1, Math.Min(Environment.ProcessorCount, Math.Min(maxThreads, parallel)));
        var threads = new Thread[threadCount - 1];
        for (var i = 0; i < threads.Length; i++) { (threads[i] = new Thread(workerThread, 8192)).Start(); }
        workerThread();
        foreach (var t in threads)
        {
            t.Join();
        }
    }

    private static void SMix(uint[] B, int Boffset, uint[] Bp, int Bpoffset, uint N, int r)
    {
        var Nmask = N - 1; var Bs = 16 * 2 * r;
        var scratch1 = new uint[16];
        uint[] scratchX = new uint[16], scratchY = new uint[Bs];
        var scratchZ = new uint[Bs];

        var x = new uint[Bs]; var v = new uint[N][];
        for (var i = 0; i < v.Length; i++) { v[i] = new uint[Bs]; }

        Array.Copy(B, Boffset, x, 0, Bs);
        for (uint i = 0; i < N; i++)
        {
            Array.Copy(x, v[i], Bs);
            BlockMix(x, 0, x, 0, scratchX, scratchY, scratch1, r);
        }
        for (uint i = 0; i < N; i++)
        {
            var j = x[Bs - 16] & Nmask; var vj = v[j];
            for (var k = 0; k < scratchZ.Length; k++) { scratchZ[k] = x[k] ^ vj[k]; }
            BlockMix(scratchZ, 0, x, 0, scratchX, scratchY, scratch1, r);
        }
        Array.Copy(x, 0, Bp, Bpoffset, Bs);

        foreach (var t in v)
        {
            Security.Clear(t);
        }
        Security.Clear(v); Security.Clear(x);
        Security.Clear(scratchX); Security.Clear(scratchY); Security.Clear(scratchZ);
        Security.Clear(scratch1);
    }

    private static void BlockMix
        (uint[] B,        // 16*2*r
         int Boffset,
         uint[] Bp,       // 16*2*r
         int Bpoffset,
         uint[] x,        // 16
         uint[] y,        // 16*2*r -- unnecessary but it allows us to alias B and Bp
         uint[] scratch,  // 16
         int r)
    {
        int k = Boffset, m = 0, n = 16 * r;
        Array.Copy(B, (2 * r - 1) * 16, x, 0, 16);

        for (var i = 0; i < r; i++)
        {
            for (var j = 0; j < scratch.Length; j++) { scratch[j] = x[j] ^ B[j + k]; }
            Salsa20Core.Compute(8, scratch, 0, x, 0);
            Array.Copy(x, 0, y, m, 16);
            k += 16;

            for (var j = 0; j < scratch.Length; j++) { scratch[j] = x[j] ^ B[j + k]; }
            Salsa20Core.Compute(8, scratch, 0, x, 0);
            Array.Copy(x, 0, y, m + n, 16);
            k += 16;

            m += 16;
        }

        Array.Copy(y, 0, Bp, Bpoffset, y.Length);
    }
}
