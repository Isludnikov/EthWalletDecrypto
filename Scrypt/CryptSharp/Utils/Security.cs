using System.Security.Cryptography;

namespace Scrypt.CryptSharp.Utils;

internal static class Security
{
    public static void Clear(Array? array)
    {
        if (array != null) { Array.Clear(array, 0, array.Length); }
    }

    public static byte[] GenerateRandomBytes(int count)
    {
        Check.Range("count", count, 0, int.MaxValue);

        var rng = RandomNumberGenerator.Create();
        var bytes = new byte[count]; rng.GetBytes(bytes); return bytes;
    }
}
