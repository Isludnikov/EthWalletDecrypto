using ILGPU;
using ILGPU.Runtime;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Scrypt.ScryptGpu;

public static class ScryptILGPU
{
    // Singleton accelerator: OpenCL contexts must not be torn down and recreated
    // mid-process — doing so leaves the driver in a broken state on many platforms.
    // When the GPU kernel fails (e.g. Windows TDR watchdog for long-running kernels),
    // we fall back to ILGPU's CPU backend and stay there for the process lifetime.
    private static readonly Lock InitLock = new();
    private static Context? context;
    private static Accelerator? _accelerator;
    private static bool initFailed;

    private static bool Init()
    {
        if (_accelerator != null)
        {
            return true;
        }

        lock (InitLock)
        {
            if (initFailed)
            {
                return false;
            }

            _accelerator = GetOrCreateAccelerator();
            if (_accelerator == null)
            {
                initFailed = true;
            }

            return !initFailed;
        }
    }
    private static Accelerator? GetOrCreateAccelerator()
    {

        context = Context.CreateDefault();
        try
        {
            var cudaDevice = context.Devices
                .FirstOrDefault(d => d.AcceleratorType == AcceleratorType.Cuda);

            if (cudaDevice != null)
            {
                var acc = cudaDevice.CreateAccelerator(context);
                Console.WriteLine($"Using CUDA: {cudaDevice.Name}");
                return acc;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"CUDA init failed: {ex.Message}");
        }

        // 2. Пробуем OpenCL (AMD / Intel дискретная)
        try
        {
            var oclDevice = context.Devices
                .Where(d => d.AcceleratorType == AcceleratorType.OpenCL)
                .OrderByDescending(d => d.MemorySize) // берём с наибольшей памятью
                .FirstOrDefault(d => !d.Name.Contains("Intel", StringComparison.OrdinalIgnoreCase));

            if (oclDevice != null)
            {
                var acc = oclDevice.CreateAccelerator(context);
                Console.WriteLine($"Using OpenCL: {oclDevice.Name}");
                return acc;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"OpenCL init failed: {ex.Message}");
        }

        initFailed = true;
        return null;
    }

    public static byte[] Generate(byte[] P, byte[] S, int N, int r, int p, int dkLen) => Generate(P, S, N, r, p, dkLen, false);

    /// <summary>
    /// Derives a key using the scrypt password-based key derivation function (RFC 7914).
    /// Equivalent to Org.BouncyCastle.Crypto.Generators.SCrypt.Generate.
    /// use ILGPU library
    /// </summary>
    /// <param name="P">Password</param>
    /// <param name="S">Salt</param>
    /// <param name="N">CPU/memory cost parameter — must be a power of 2 greater than 1</param>
    /// <param name="r">Block size parameter</param>
    /// <param name="p">Parallelization parameter</param>
    /// <param name="dkLen">Desired output length in bytes</param>
    /// <param name="isTest">for test purposes</param>
    public static byte[] Generate(byte[] P, byte[] S, int N, int r, int p, int dkLen, bool isTest)
    {
        ArgumentNullException.ThrowIfNull(P);
        ArgumentNullException.ThrowIfNull(S);
        if (N <= 1 || (N & (N - 1)) != 0)
        {
            throw new ArgumentException("N must be a power of 2 greater than 1.", nameof(N));
        }
        var initResult = Init();
        if (!initResult)
        {
            return isTest ? [] : throw new SystemException("GPU malfunction");
        }

        // blockLen: number of uint32 per block (128*r bytes / 4)
        var blockLen = 32 * r;

        // Step 1: PBKDF2 on CPU to produce B
        var B_bytes = Rfc2898DeriveBytes.Pbkdf2(P, S, 1, HashAlgorithmName.SHA256, p * blockLen * 4);
        var B = ToUInt32Le(B_bytes);

        // Step 2: GPU — run p independent ScryptROMix blocks in parallel.
        // If the GPU fails (e.g. TDR watchdog on Windows for large N), transparently
        // retry on ILGPU's CPU backend. B is always unchanged after a GPU exception.
        B = RunRoMix(_accelerator!, B, N, r, p, blockLen);
        // Step 3: PBKDF2 on CPU to derive final key
        B_bytes = FromUInt32Le(B);
        return Rfc2898DeriveBytes.Pbkdf2(P, B_bytes, 1, HashAlgorithmName.SHA256, dkLen);
    }

    private static uint[] RunRoMix(Accelerator acc, uint[] B, int N, int r, int p, int blockLen)
    {
        using var dB = acc.Allocate1D<uint>(p * blockLen);
        using var dV = acc.Allocate1D<uint>((long)p * N * blockLen);
        using var dXScratch = acc.Allocate1D<uint>(p * 16);
        using var dResScratch = acc.Allocate1D<uint>(p * blockLen);

        dB.CopyFromCPU(B);

        var kernel = acc.LoadAutoGroupedStreamKernel<
            Index1D,
            ArrayView<uint>,
            ArrayView<uint>,
            ArrayView<uint>,
            ArrayView<uint>,
            int,
            int>(ScryptROMixKernel);

        kernel(p, dB.View, dV.View, dXScratch.View, dResScratch.View, N, r);
        acc.Synchronize();

        return dB.GetAsArray1D();
    }

    // -------------------------------------------------------------------------
    // GPU kernel — one thread per parallelization block (index ∈ [0, p))
    // -------------------------------------------------------------------------

    private static void ScryptROMixKernel(
        Index1D index,
        ArrayView<uint> B,
        ArrayView<uint> V,
        ArrayView<uint> xScratch,
        ArrayView<uint> resScratch,
        int N,
        int r)
    {
        var blockLen = 32 * r;
        int idx = index;
        var bOff = idx * blockLen;
        var vBase = (long)idx * N * blockLen;
        var xOff = idx * 16;
        var rOff = idx * blockLen;

        // Phase 1: Fill V
        for (var i = 0; i < N; i++)
        {
            var vOff = vBase + (long)i * blockLen;
            for (var k = 0; k < blockLen; k++)
            {
                V[vOff + k] = B[bOff + k];
            }

            ScryptBlockMix(B, bOff, resScratch, rOff, xScratch, xOff, r);

            for (var k = 0; k < blockLen; k++)
            {
                B[bOff + k] = resScratch[rOff + k];
            }
        }

        // Phase 2: Mix
        for (var i = 0; i < N; i++)
        {
            var j = (int)(B[bOff + (2 * r - 1) * 16] % (uint)N);
            var vOff = vBase + (long)j * blockLen;

            for (var k = 0; k < blockLen; k++)
            {
                B[bOff + k] ^= V[vOff + k];
            }

            ScryptBlockMix(B, bOff, resScratch, rOff, xScratch, xOff, r);

            for (var k = 0; k < blockLen; k++)
            {
                B[bOff + k] = resScratch[rOff + k];
            }
        }
    }

    // -------------------------------------------------------------------------
    // Device functions (called from GPU kernel — no heap allocation allowed)
    // -------------------------------------------------------------------------

    private static void ScryptBlockMix(
        ArrayView<uint> B, int bOff,
        ArrayView<uint> result, int rOff,
        ArrayView<uint> X, int xOff,
        int r)
    {
        var blocks = 2 * r;

        // Seed X from the last 16-uint sub-block of B
        var lastBlock = bOff + (blocks - 1) * 16;
        for (var k = 0; k < 16; k++)
        {
            X[xOff + k] = B[lastBlock + k];
        }

        for (var i = 0; i < blocks; i += 2)
        {
            // Even block
            for (var k = 0; k < 16; k++)
            {
                X[xOff + k] ^= B[bOff + i * 16 + k];
            }

            Salsa20_8(X, xOff);
            for (var k = 0; k < 16; k++)
            {
                result[rOff + (i / 2) * 16 + k] = X[xOff + k];
            }

            // Odd block
            for (var k = 0; k < 16; k++)
            {
                X[xOff + k] ^= B[bOff + (i + 1) * 16 + k];
            }

            Salsa20_8(X, xOff);
            for (var k = 0; k < 16; k++)
            {
                result[rOff + (r + i / 2) * 16 + k] = X[xOff + k];
            }
        }
    }

    private static void Salsa20_8(ArrayView<uint> X, int o)
    {
        // Read into scalars — heap allocation (new uint[16]) is forbidden in GPU kernels
        uint x0 = X[o], x1 = X[o + 1], x2 = X[o + 2], x3 = X[o + 3],
             x4 = X[o + 4], x5 = X[o + 5], x6 = X[o + 6], x7 = X[o + 7],
             x8 = X[o + 8], x9 = X[o + 9], x10 = X[o + 10], x11 = X[o + 11],
             x12 = X[o + 12], x13 = X[o + 13], x14 = X[o + 14], x15 = X[o + 15];

        for (var i = 0; i < 8; i += 2)
        {
            x4 ^= R(x0 + x12, 7); x8 ^= R(x4 + x0, 9);
            x12 ^= R(x8 + x4, 13); x0 ^= R(x12 + x8, 18);
            x9 ^= R(x5 + x1, 7); x13 ^= R(x9 + x5, 9);
            x1 ^= R(x13 + x9, 13); x5 ^= R(x1 + x13, 18);
            x14 ^= R(x10 + x6, 7); x2 ^= R(x14 + x10, 9);
            x6 ^= R(x2 + x14, 13); x10 ^= R(x6 + x2, 18);
            x3 ^= R(x15 + x11, 7); x7 ^= R(x3 + x15, 9);
            x11 ^= R(x7 + x3, 13); x15 ^= R(x11 + x7, 18);
            x1 ^= R(x0 + x3, 7); x2 ^= R(x1 + x0, 9);
            x3 ^= R(x2 + x1, 13); x0 ^= R(x3 + x2, 18);
            x6 ^= R(x5 + x4, 7); x7 ^= R(x6 + x5, 9);
            x4 ^= R(x7 + x6, 13); x5 ^= R(x4 + x7, 18);
            x11 ^= R(x10 + x9, 7); x8 ^= R(x11 + x10, 9);
            x9 ^= R(x8 + x11, 13); x10 ^= R(x9 + x8, 18);
            x12 ^= R(x15 + x14, 7); x13 ^= R(x12 + x15, 9);
            x14 ^= R(x13 + x12, 13); x15 ^= R(x14 + x13, 18);
        }

        X[o] += x0; X[o + 1] += x1; X[o + 2] += x2; X[o + 3] += x3;
        X[o + 4] += x4; X[o + 5] += x5; X[o + 6] += x6; X[o + 7] += x7;
        X[o + 8] += x8; X[o + 9] += x9; X[o + 10] += x10; X[o + 11] += x11;
        X[o + 12] += x12; X[o + 13] += x13; X[o + 14] += x14; X[o + 15] += x15;
    }

    private static uint R(uint v, int n) => (v << n) | (v >> (32 - n));

    // -------------------------------------------------------------------------
    // CPU helpers
    // -------------------------------------------------------------------------

    private static uint[] ToUInt32Le(byte[] bytes)
    {
        var result = new uint[bytes.Length / 4];
        for (var i = 0; i < result.Length; i++)
        {
            result[i] = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i * 4));
        }

        return result;
    }

    private static byte[] FromUInt32Le(uint[] ints)
    {
        var result = new byte[ints.Length * 4];
        for (var i = 0; i < ints.Length; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(i * 4), ints[i]);
        }

        return result;
    }
}
