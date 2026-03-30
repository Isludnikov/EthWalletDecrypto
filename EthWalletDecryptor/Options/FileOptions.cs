using CommandLine;

namespace EthWalletDecryptor.Options;

[Verb("file", HelpText = "Атака по словарю из файла")]
class FileOptions : BaseOptions
{
    [Option("path", Required = true, HelpText = "Путь к файлу со словарём")]
    public string Path { get; set; } = "";
}