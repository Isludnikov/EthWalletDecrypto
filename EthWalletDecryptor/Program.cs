using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using CommandLine;
using EthWalletDecryptor.DTO;
using EthWalletDecryptor.Options;
using EthWalletDecryptor.Utils;
using FileOptions = EthWalletDecryptor.Options.FileOptions;

namespace EthWalletDecryptor;

internal class Program
{
    private static async Task<int> Main(string[] args) 
        => await Parser.Default.ParseArguments<BruteOptions, FileOptions>(args)
            .MapResult(
                (BruteOptions opts) => RunBrute(opts),
                (FileOptions opts) => RunFile(opts),
                _ => Task.FromResult(1));

    private static async Task<int> RunBrute(BruteOptions opts)
    {
        var charset = BuildCharset(opts);
        if (charset.Length == 0)
        {
            Console.WriteLine("Не указан набор символов (--lower, --upper, --digits, --special, --chars)");
            return 1;
        }
        Console.WriteLine($"Перебор: длина {opts.Min}–{opts.Max}, символы ({charset.Length}): {charset}");
        return await Run(opts.Keystore, opts.Parallelism, PasswordGenerator.BruteForce(charset, opts.Min, opts.Max));
    }

    private static async Task<int> RunFile(FileOptions opts)
    {
        Console.WriteLine($"Словарь: {opts.Path}");
        return await Run(opts.Keystore, opts.Parallelism, File.ReadLines(opts.Path));
    }

    private static string BuildCharset(BruteOptions opts)
    {
        var sb = new StringBuilder();
        if (opts.Lower)   sb.Append("abcdefghijklmnopqrstuvwxyz");
        if (opts.Upper)   sb.Append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        if (opts.Digits)  sb.Append("0123456789");
        if (opts.Special) sb.Append("!@#$%^&*()-_=+[]{}|;:',.<>?/`~");
        if (opts.Chars != null) sb.Append(opts.Chars);
        return new string([.. sb.ToString().Distinct()]);
    }

    private static async Task<int> Run(string keystorePath, int parallelism, IEnumerable<string> passwords)
    {
        var keystore = JsonSerializer.Deserialize<KeystoreFile>(await File.ReadAllTextAsync(keystorePath))
                       ?? throw new Exception("Cant parse file");

        ulong counter = 0;
        var startTime = Stopwatch.StartNew();
        var cts = new CancellationTokenSource();
        var channel = Channel.CreateUnbounded<Result>();

        var producer = Task.Run(() =>
        {
            try
            {
                Parallel.ForEach(passwords, new ParallelOptions { MaxDegreeOfParallelism = parallelism, CancellationToken = cts.Token }, item =>
                {
                    byte[] privateKey;
                    try { privateKey = EthereumKeystore.Decrypt(keystore, item); }
                    catch (CryptographicException) { privateKey = []; }
                    channel.Writer.TryWrite(new Result(item, privateKey));
                });
            }
            catch (OperationCanceledException) { }
            finally { channel.Writer.Complete(); }
        }, cts.Token);

        await foreach (var output in channel.Reader.ReadAllAsync(cts.Token))
        {
            ++counter;
            if (!output.IsEmpty)
            {
                await cts.CancelAsync();
                await producer;
                Console.WriteLine("Приватный ключ: " + Convert.ToHexString(output.PrivateKey));
                Console.WriteLine("Пароль: " + output.Password);
                return 0;
            }

            if (counter % 10 != 0) continue;
            var ps = counter / Math.Max(startTime.Elapsed.TotalSeconds, 0.001);
            Console.WriteLine($"[{DateTime.UtcNow}] Паролей обработано {counter} ({ps:F0} п/с)");
        }

        await producer;
        Console.WriteLine("Приватный ключ не декодирован");
        return 1;
    }
}