using CommandLine;

namespace EthWalletDecryptor.Options;

internal abstract class BaseOptions
{
    [Value(0, MetaName = "keyfile", Required = true, HelpText = "Путь к файлу keystore")]
    public string Keystore { get; set; } = "";

    [Option("parallelism", Default = 1, HelpText = "Число потоков")]
    public int Parallelism { get; set; }
    [Option("gpu", Default = false, HelpText = "Использовать GPU")]
    public bool GPU { get; set; }
}