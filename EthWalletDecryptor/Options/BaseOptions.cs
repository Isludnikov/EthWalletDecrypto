using CommandLine;

namespace EthWalletDecryptor.Options;

abstract class BaseOptions
{
    [Value(0, MetaName = "keyfile", Required = true, HelpText = "Путь к файлу keystore")]
    public string Keystore { get; set; } = "";

    [Option("parallelism", Default = 4, HelpText = "Число потоков")]
    public int Parallelism { get; set; }
}