namespace EthWalletDecryptor.Utils;

public static class PasswordGenerator
{
    public static IEnumerable<string> BruteForce(string charset, int minLen, int maxLen)
    {
        for (var length = minLen; length <= maxLen; length++)
        {
            var indices = new int[length];
            var buf = new char[length];
            while (true)
            {
                for (var i = 0; i < length; i++)
                {
                    buf[i] = charset[indices[i]];
                }
                yield return new string(buf);

                var pos = length - 1;
                while (pos >= 0)
                {
                    if (++indices[pos] < charset.Length)
                    {
                        break;
                    }
                    indices[pos--] = 0;
                }
                if (pos < 0) break;
            }
        }
    }
}
