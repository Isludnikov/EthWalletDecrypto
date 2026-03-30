using CommandLine;

namespace EthWalletDecryptor.Options;

[Verb("brute", HelpText = "Перебор по заданному набору символов")]
class BruteOptions : BaseOptions
{
    [Option("min", Default = 1, HelpText = "Минимальная длина пароля")]
    public int Min { get; set; }

    [Option("max", Default = 4, HelpText = "Максимальная длина пароля")]
    public int Max { get; set; }

    [Option("lower", HelpText = "Добавить a-z")]
    public bool Lower { get; set; }

    [Option("upper", HelpText = "Добавить A-Z")]
    public bool Upper { get; set; }

    [Option("digits", HelpText = "Добавить 0-9")]
    public bool Digits { get; set; }

    [Option("special", HelpText = "Добавить спецсимволы")]
    public bool Special { get; set; }

    [Option("chars", HelpText = "Произвольные символы")]
    public string? Chars { get; set; }
}