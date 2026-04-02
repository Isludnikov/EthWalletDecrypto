using System.Security.Cryptography;

namespace Scrypt.CryptSharp.Utils;

public class Pbkdf2 : Stream
{
    #region PBKDF2
    private readonly byte[] _saltBuffer;
    private readonly byte[] _digest;
    private readonly byte[] _digestT1;
    private readonly KeyedHashAlgorithm _hmacAlgorithm;
    private readonly int _iterations;

    /// <summary>
    /// Creates a new PBKDF2 stream.
    /// </summary>
    /// <param name="hmacAlgorithm">
    ///     The HMAC algorithm to use, for example <see cref="HMACSHA256"/>.
    ///     Make sure to set <see cref="KeyedHashAlgorithm.Key"/>.
    /// </param>
    /// <param name="salt">
    ///     The salt.
    ///     A unique salt means a unique PBKDF2 stream, even if the original key is identical.
    /// </param>
    /// <param name="iterations">The number of iterations to apply.</param>
    public Pbkdf2(KeyedHashAlgorithm hmacAlgorithm, byte[] salt, int iterations)
    {
        Check.Null("hmacAlgorithm", hmacAlgorithm);
        Check.Null("salt", salt);
        Check.Length("salt", salt, 0, int.MaxValue - 4);
        Check.Range("iterations", iterations, 1, int.MaxValue);
        if (hmacAlgorithm.HashSize == 0 || hmacAlgorithm.HashSize % 8 != 0)
        {
            throw new ArgumentException("hmacAlgorithm", "Unsupported hash size.");
        }

        var hmacLength = hmacAlgorithm.HashSize / 8;
        _saltBuffer = new byte[salt.Length + 4]; Array.Copy(salt, _saltBuffer, salt.Length);
        _iterations = iterations; _hmacAlgorithm = hmacAlgorithm;
        _digest = new byte[hmacLength]; _digestT1 = new byte[hmacLength];
    }

    /// <summary>
    /// Reads from the derived key stream.
    /// </summary>
    /// <param name="count">The number of bytes to read.</param>
    /// <returns>Bytes from the derived key stream.</returns>
    public byte[] Read(int count)
    {
        Check.Range("count", count, 0, int.MaxValue);

        var buffer = new byte[count];
        var bytes = Read(buffer, 0, count);
        return bytes < count ? throw new ArgumentException("count", $"Can only return {bytes} bytes.") : buffer;
    }

    /// <summary>
    /// Computes a derived key.
    /// </summary>
    /// <param name="hmacAlgorithm">
    ///     The HMAC algorithm to use, for example <see cref="HMACSHA256"/>.
    ///     Make sure to set <see cref="KeyedHashAlgorithm.Key"/>.
    /// </param>
    /// <param name="salt">
    ///     The salt.
    ///     A unique salt means a unique derived key, even if the original key is identical.
    /// </param>
    /// <param name="iterations">The number of iterations to apply.</param>
    /// <param name="derivedKeyLength">The desired length of the derived key.</param>
    /// <returns>The derived key.</returns>
    public static byte[] ComputeDerivedKey(KeyedHashAlgorithm hmacAlgorithm, byte[] salt, int iterations, int derivedKeyLength)
    {
        Check.Range("derivedKeyLength", derivedKeyLength, 0, int.MaxValue);

        using var kdf = new Pbkdf2(hmacAlgorithm, salt, iterations);
        return kdf.Read(derivedKeyLength);
    }

    /// <summary>
    /// Closes the stream, clearing memory and disposing of the HMAC algorithm.
    /// </summary>
    public override void Close()
    {
        Security.Clear(_saltBuffer);
        Security.Clear(_digest);
        Security.Clear(_digestT1);
        _hmacAlgorithm.Clear();
    }

    private void ComputeBlock(uint pos)
    {
        BitPacking.BEBytesFromUInt32(pos, _saltBuffer, _saltBuffer.Length - 4);
        ComputeHmac(_saltBuffer, _digestT1);
        Array.Copy(_digestT1, _digest, _digestT1.Length);

        for (var i = 1; i < _iterations; i++)
        {
            ComputeHmac(_digestT1, _digestT1);
            for (var j = 0; j < _digest.Length; j++) { _digest[j] ^= _digestT1[j]; }
        }

        Security.Clear(_digestT1);
    }

    private void ComputeHmac(byte[] input, byte[] output)
    {
        _hmacAlgorithm.Initialize();
        _hmacAlgorithm.TransformBlock(input, 0, input.Length, input, 0);
        _hmacAlgorithm.TransformFinalBlock([], 0, 0);
        Array.Copy(_hmacAlgorithm.Hash ?? [], output, output.Length);
    }
    #endregion

    #region Stream
    private long _blockStart, _blockEnd;

    /// <exclude />
    public override void Flush()
    {

    }

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count)
    {
        Check.Bounds("buffer", buffer, offset, count); var bytes = 0;

        while (count > 0)
        {
            if (Position < _blockStart || Position >= _blockEnd)
            {
                if (Position >= Length) { break; }

                var pos = Position / _digest.Length;
                ComputeBlock((uint)(pos + 1));
                _blockStart = pos * _digest.Length;
                _blockEnd = _blockStart + _digest.Length;
            }

            var bytesSoFar = (int)(Position - _blockStart);
            var bytesThisTime = Math.Min(_digest.Length - bytesSoFar, count);
            Array.Copy(_digest, bytesSoFar, buffer, bytes, bytesThisTime);
            count -= bytesThisTime; bytes += bytesThisTime; Position += bytesThisTime;
        }

        return bytes;
    }

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin)
    {
        var pos = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => Position + offset,
            SeekOrigin.End => Length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin), "Unknown seek type.")
        };

        if (pos < 0) { throw new ArgumentException("offset", "Can't seek before the stream start."); }
        Position = pos; return pos;
    }

    /// <exclude />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <exclude />
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    /// <exclude />
    public override bool CanRead => true;

    /// <exclude />
    public override bool CanSeek => true;

    /// <exclude />
    public override bool CanWrite => false;

    /// <summary>
    /// The maximum number of bytes that can be derived is 2^32-1 times the HMAC size.
    /// </summary>
    public override long Length => _digest.Length * uint.MaxValue;

    /// <summary>
    /// The position within the derived key stream.
    /// </summary>
    public override long Position
    {
        get;
        set
        {
            if (field < 0)
            {
                throw new ArgumentException(null, "Can't seek before the stream start.");
            }

            field = value;
        }
    }

    #endregion
}
