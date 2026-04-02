using Org.BouncyCastle.Crypto.Digests;
using Scrypt.ScryptGpu;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace EthWalletDecryptor.Utils;

public static class EthereumKeystore
{
    private static readonly JsonSerializerOptions JsonSerializerOptions = new() { WriteIndented = true };
    // ─── Расшифровка ────────────────────────────────────────────────────────────
    public static byte[] Decrypt(KeystoreFile keystore, string password) => Decrypt(keystore, password, false);

    public static byte[] Decrypt(KeystoreFile keystore, string password, bool useGpu)
    {
        var crypto = keystore.Crypto;

        // 1. Проверка алгоритмов
        if (!crypto.Kdf.Equals("scrypt", StringComparison.OrdinalIgnoreCase))
        {
            throw new NotSupportedException($"KDF не поддерживается: {crypto.Kdf}");
        }

        if (!crypto.Cipher.Equals("aes-128-ctr", StringComparison.OrdinalIgnoreCase))
        {
            throw new NotSupportedException($"Cipher не поддерживается: {crypto.Cipher}");
        }

        // 2. Вывод ключа через scrypt
        var salt = Convert.FromHexString(crypto.KdfParams.Salt);
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var derivedKey = useGpu ? ScryptILGPU.Generate(passwordBytes, salt, crypto.KdfParams.N, crypto.KdfParams.R, crypto.KdfParams.P, crypto.KdfParams.DkLen)
            : ScryptLocal(passwordBytes, salt, crypto.KdfParams.N, crypto.KdfParams.R, crypto.KdfParams.P, crypto.KdfParams.DkLen);

        // 3. Проверка MAC (первые 16 байт derivedKey — macKey — в Ethereum это байты [16..31])
        var macKey = derivedKey[16..32];
        var ciphertext = Convert.FromHexString(crypto.CipherText);
        var expectedMac = Convert.FromHexString(crypto.Mac);
        var actualMac = Keccak256(Concat(macKey, ciphertext));

        if (!CryptographicOperations.FixedTimeEquals(actualMac, expectedMac))
        {
            throw new CryptographicException("Неверный пароль или повреждённый keystore (MAC не совпадает).");
        }

        // 4. Расшифровка AES-128-CTR
        var encKey = derivedKey[..16];
        var iv = Convert.FromHexString(crypto.CipherParams.Iv);
        return AesCtr(encKey, iv, ciphertext);
    }

    // ─── Шифрование ─────────────────────────────────────────────────────────────
    public static string Serialize(this KeystoreFile file) => JsonSerializer.Serialize(file, JsonSerializerOptions);

    public static KeystoreFile Encrypt(byte[] privateKey, string password,
        int n = 16384, int r = 8, int p = 4, byte[]? salt = null, byte[]? iv = null)
    {
        // 1. Генерация случайных salt и iv
        var usedSalt = salt ?? RandomNumberGenerator.GetBytes(32);
        var usedIv = iv ?? RandomNumberGenerator.GetBytes(16);
        var id = Guid.NewGuid().ToString();

        // 2. Вывод ключа
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var derivedKey = ScryptLocal(passwordBytes, usedSalt, n, r, p, dkLen: 32);

        // 3. Шифрование
        var encKey = derivedKey[..16];
        var ciphertext = AesCtr(encKey, usedIv, privateKey);

        // 4. MAC
        var macKey = derivedKey[16..32];
        var mac = Keccak256(Concat(macKey, ciphertext));

        return new KeystoreFile
        {
            Id = id,
            Version = 3,
            Crypto = new CryptoSection
            {
                Cipher = "aes-128-ctr",
                CipherParams = new CipherParams { Iv = Convert.ToHexString(usedIv).ToLowerInvariant() },
                CipherText = Convert.ToHexString(ciphertext).ToLowerInvariant(),
                Kdf = "scrypt",
                KdfParams = new KdfParams { DkLen = 32, N = n, R = r, P = p, Salt = Convert.ToHexString(usedSalt).ToLowerInvariant() },
                Mac = Convert.ToHexString(mac).ToLowerInvariant()
            }
        };
    }

    // ─── Вспомогательные методы ──────────────────────────────────────────────────

    /// <summary>scrypt через BouncyCastle</summary>
    private static byte[] ScryptLocal(byte[] password, byte[] salt, int n, int r, int p, int dkLen) => Org.BouncyCastle.Crypto.Generators.SCrypt.Generate(password, salt, n, r, p, dkLen);

    /// <summary>AES-128 в режиме CTR (совместим с OpenSSL / Go / Python web3)</summary>
    private static byte[] AesCtr(byte[] key, byte[] iv, byte[] input)
    {
        // .NET не имеет встроенного CTR — реализуем вручную через ECB
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        var output = new byte[input.Length];
        var counter = (byte[])iv.Clone();
        var keystream = new byte[16];

        using var enc = aes.CreateEncryptor();

        for (var i = 0; i < input.Length; i += 16)
        {
            // Шифруем счётчик, чтобы получить keystream-блок
            enc.TransformBlock(counter, 0, 16, keystream, 0);

            // XOR с plaintext/ciphertext
            var blockLen = Math.Min(16, input.Length - i);
            for (var j = 0; j < blockLen; j++)
            {
                output[i + j] = (byte)(input[i + j] ^ keystream[j]);
            }

            // Инкремент счётчика (big-endian, как в Ethereum)
            IncrementCounter(counter);
        }

        return output;
    }

    /// <summary>Инкремент 128-битного счётчика big-endian</summary>
    private static void IncrementCounter(byte[] counter)
    {
        for (var i = 15; i >= 0; i--)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }
    }

    /// <summary>Keccak-256 (не SHA3-256!) через BouncyCastle</summary>
    private static byte[] Keccak256(byte[] data)
    {
        var digest = new KeccakDigest(256);
        digest.BlockUpdate(data, 0, data.Length);
        var hash = new byte[32];
        digest.DoFinal(hash, 0);
        return hash;
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result, 0);
        b.CopyTo(result, a.Length);
        return result;
    }
}

// ─── Модели JSON ─────────────────────────────────────────────────────────────

public record KeystoreFile
{
    [JsonPropertyName("crypto")] public CryptoSection Crypto { get; init; } = new();
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("version")] public int Version { get; init; } = 3;
}

public record CryptoSection
{
    [JsonPropertyName("cipher")] public string Cipher { get; init; } = "";
    [JsonPropertyName("cipherparams")] public CipherParams CipherParams { get; init; } = new();
    [JsonPropertyName("ciphertext")] public string CipherText { get; init; } = "";
    [JsonPropertyName("kdf")] public string Kdf { get; init; } = "";
    [JsonPropertyName("kdfparams")] public KdfParams KdfParams { get; init; } = new();
    [JsonPropertyName("mac")] public string Mac { get; init; } = "";
}

public record CipherParams
{
    [JsonPropertyName("iv")] public string Iv { get; init; } = "";
}

public record KdfParams
{
    [JsonPropertyName("dklen")] public int DkLen { get; init; }
    [JsonPropertyName("n")] public int N { get; init; }
    [JsonPropertyName("p")] public int P { get; init; }
    [JsonPropertyName("r")] public int R { get; init; }
    [JsonPropertyName("salt")] public string Salt { get; init; } = "";
}
