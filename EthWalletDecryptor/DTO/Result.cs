namespace EthWalletDecryptor.DTO;

internal record Result(string Password, byte[] PrivateKey)
{
    public bool IsEmpty => PrivateKey.Length == 0;
}