namespace Scrypt.Bouncy;

public class ScryptBouncy
{
    public static byte[] Generate(byte[] password, byte[] salt, int n, int r, int p, int dkLen)
    {
        return Org.BouncyCastle.Crypto.Generators.SCrypt.Generate(password, salt, n, r, p, dkLen);
    }
}
