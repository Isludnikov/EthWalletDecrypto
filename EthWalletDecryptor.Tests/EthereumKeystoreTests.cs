using System.Security.Cryptography;
using System.Text.Json;
using EthWalletDecryptor.Utils;

namespace EthWalletDecryptor.Tests;

public class EthereumKeystoreTests
{
    private static readonly byte[] TestKey = Convert.FromHexString(
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

    // n=4, r=1, p=1 — minimal scrypt params for fast unit tests
    private static KeystoreFile FastEncrypt(byte[] key, string password,
        byte[]? salt = null, byte[]? iv = null) =>
        EthereumKeystore.Encrypt(key, password, n: 4, r: 1, p: 1, salt: salt, iv: iv);

    // ── Round-trip ───────────────────────────────────────────────────────────

    [Fact]
    public void EncryptDecrypt_RoundTrip_ReturnsOriginalKey()
    {
        var keystore = FastEncrypt(TestKey, "test-password");
        var decrypted = EthereumKeystore.Decrypt(keystore, "test-password");
        Assert.Equal(TestKey, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_EmptyPrivateKey_RoundTrips()
    {
        var empty = Array.Empty<byte>();
        var keystore = FastEncrypt(empty, "password");
        Assert.Equal(empty, EthereumKeystore.Decrypt(keystore, "password"));
    }

    [Fact]
    public void EncryptDecrypt_EmptyPassword_RoundTrips()
    {
        var keystore = FastEncrypt(TestKey, "");
        Assert.Equal(TestKey, EthereumKeystore.Decrypt(keystore, ""));
    }

    [Fact]
    public void EncryptDecrypt_UnicodePassword_RoundTrips()
    {
        var keystore = FastEncrypt(TestKey, "пароль123");
        Assert.Equal(TestKey, EthereumKeystore.Decrypt(keystore, "пароль123"));
    }

    // ── Error cases ──────────────────────────────────────────────────────────

    [Fact]
    public void Decrypt_WrongPassword_ThrowsCryptographicException()
    {
        var keystore = FastEncrypt(TestKey, "correct");
        Assert.Throws<CryptographicException>(() =>
            EthereumKeystore.Decrypt(keystore, "wrong"));
    }

    [Fact]
    public void Decrypt_CorruptedMac_ThrowsCryptographicException()
    {
        var keystore = FastEncrypt(TestKey, "password");
        var corrupted = keystore with
        {
            Crypto = keystore.Crypto with { Mac = new string('0', 64) }
        };
        Assert.Throws<CryptographicException>(() =>
            EthereumKeystore.Decrypt(corrupted, "password"));
    }

    [Fact]
    public void Decrypt_UnsupportedKdf_ThrowsNotSupportedException()
    {
        var keystore = FastEncrypt(TestKey, "password");
        var modified = keystore with
        {
            Crypto = keystore.Crypto with { Kdf = "pbkdf2" }
        };
        Assert.Throws<NotSupportedException>(() =>
            EthereumKeystore.Decrypt(modified, "password"));
    }

    [Fact]
    public void Decrypt_UnsupportedCipher_ThrowsNotSupportedException()
    {
        var keystore = FastEncrypt(TestKey, "password");
        var modified = keystore with
        {
            Crypto = keystore.Crypto with { Cipher = "aes-256-cbc" }
        };
        Assert.Throws<NotSupportedException>(() =>
            EthereumKeystore.Decrypt(modified, "password"));
    }

    [Theory]
    [InlineData("SCRYPT")]
    [InlineData("Scrypt")]
    public void Decrypt_KdfCaseInsensitive_DoesNotThrow(string kdf)
    {
        var keystore = FastEncrypt(TestKey, "password");
        var modified = keystore with
        {
            Crypto = keystore.Crypto with { Kdf = kdf }
        };
        var result = EthereumKeystore.Decrypt(modified, "password");
        Assert.Equal(TestKey, result);
    }

    [Theory]
    [InlineData("AES-128-CTR")]
    [InlineData("Aes-128-Ctr")]
    public void Decrypt_CipherCaseInsensitive_DoesNotThrow(string cipher)
    {
        var keystore = FastEncrypt(TestKey, "password");
        var modified = keystore with
        {
            Crypto = keystore.Crypto with { Cipher = cipher }
        };
        var result = EthereumKeystore.Decrypt(modified, "password");
        Assert.Equal(TestKey, result);
    }

    // ── Encrypt output shape ─────────────────────────────────────────────────

    [Fact]
    public void Encrypt_SetsVersion3()
    {
        var keystore = FastEncrypt(TestKey, "password");
        Assert.Equal(3, keystore.Version);
    }

    [Fact]
    public void Encrypt_SetsCorrectAlgorithmNames()
    {
        var keystore = FastEncrypt(TestKey, "password");
        Assert.Equal("aes-128-ctr", keystore.Crypto.Cipher);
        Assert.Equal("scrypt", keystore.Crypto.Kdf);
    }

    [Fact]
    public void Encrypt_GeneratesNonEmptyId()
    {
        var keystore = FastEncrypt(TestKey, "password");
        Assert.False(string.IsNullOrEmpty(keystore.Id));
    }

    [Fact]
    public void Encrypt_DifferentSalts_ProduceDifferentCiphertext()
    {
        var salt1 = new byte[32];
        var salt2 = new byte[32];
        salt2[0] = 1;
        var ks1 = FastEncrypt(TestKey, "password", salt: salt1);
        var ks2 = FastEncrypt(TestKey, "password", salt: salt2);
        Assert.NotEqual(ks1.Crypto.CipherText, ks2.Crypto.CipherText);
    }

    [Fact]
    public void Encrypt_DifferentIvs_ProduceDifferentCiphertext()
    {
        var salt = new byte[32];
        var iv1 = new byte[16];
        var iv2 = new byte[16];
        iv2[0] = 1;
        var ks1 = FastEncrypt(TestKey, "password", salt: salt, iv: iv1);
        var ks2 = FastEncrypt(TestKey, "password", salt: salt, iv: iv2);
        Assert.NotEqual(ks1.Crypto.CipherText, ks2.Crypto.CipherText);
    }

    [Fact]
    public void Encrypt_StoredSaltMatchesKdfParams()
    {
        var salt = Convert.FromHexString("aabbccdd" + new string('0', 56));
        var keystore = FastEncrypt(TestKey, "password", salt: salt);
        Assert.Equal(Convert.ToHexString(salt).ToLowerInvariant(), keystore.Crypto.KdfParams.Salt);
    }

    [Fact]
    public void Encrypt_StoredIvMatchesCipherParams()
    {
        var iv = Convert.FromHexString("aabbccdd" + new string('0', 24));
        var keystore = FastEncrypt(TestKey, "password", iv: iv);
        Assert.Equal(Convert.ToHexString(iv).ToLowerInvariant(), keystore.Crypto.CipherParams.Iv);
    }

    // ── Serialize ────────────────────────────────────────────────────────────

    [Fact]
    public void Serialize_ProducesValidJson()
    {
        var keystore = FastEncrypt(TestKey, "password");
        var json = keystore.Serialize();
        var doc = JsonDocument.Parse(json); // throws if invalid
        Assert.Equal(3, doc.RootElement.GetProperty("version").GetInt32());
        Assert.True(doc.RootElement.TryGetProperty("crypto", out _));
        Assert.True(doc.RootElement.TryGetProperty("id", out _));
    }

    [Fact]
    public void Serialize_RoundTripsViaDeserialize()
    {
        var keystore = FastEncrypt(TestKey, "password");
        var json = keystore.Serialize();
        var restored = JsonSerializer.Deserialize<KeystoreFile>(json)!;
        Assert.Equal(keystore.Crypto.CipherText, restored.Crypto.CipherText);
        Assert.Equal(keystore.Crypto.Mac, restored.Crypto.Mac);
    }
}
