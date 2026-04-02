using Scrypt.Bouncy;
using Scrypt.CryptSharp;
using Scrypt.Scrypt;
using Scrypt.ScryptGpu;
using System.Diagnostics;
using System.Text;

namespace Scrypt;

public class Program
{
    private delegate byte[] ScryptGenerator(byte[] P, byte[] S, int N, int r, int p, int dkLen);
    public static int Main()
    {
        const string data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam vitae sollicitudin urna. Proin hendrerit quam ut laoreet facilisis. Etiam egestas elit nunc, eu iaculis purus efficitur vel. Pellentesque et libero posuere, rutrum nisl sit amet, rhoncus velit. Sed risus erat, mollis ut bibendum ac, ullamcorper eget mi. Nullam vulputate ipsum vel metus porttitor, ut rutrum orci aliquam. In augue libero, venenatis a aliquet at, tempus non augue. Proin lectus lectus, mollis iaculis turpis et, pulvinar sollicitudin lorem. Sed vitae mi a elit luctus tristique ultricies et mi. Donec egestas tellus nisl, quis pellentesque mauris fermentum nec. Nunc lectus ex, placerat eget turpis quis, auctor egestas augue. Maecenas cursus velit id nulla vestibulum, eu eleifend orci dictum. Etiam at metus egestas velit sagittis ultrices vitae luctus orci. Aenean et pellentesque mi. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas.\r\n\r\nCras eu urna id magna feugiat placerat aliquam ac massa. Phasellus lorem ligula, pulvinar vitae porta ac, bibendum id risus. Mauris eu mi magna. Sed auctor, erat quis dictum aliquam, erat justo mollis felis, quis tempor felis ipsum vitae ipsum. Phasellus eros mauris, gravida quis viverra non, rutrum vel erat. Nullam rutrum velit at dui pulvinar auctor sit amet sit amet dui. Donec justo diam, mollis id odio et, ornare sagittis mi.\r\n\r\nMauris at nisi risus. Aliquam quis libero orci. Nullam lorem augue, consequat a nunc vitae, ultrices fringilla nisl. Donec id nibh mi. Vestibulum tempus nisl nec scelerisque ornare. Integer rutrum diam ut hendrerit ullamcorper. Cras sollicitudin, justo id semper aliquam, libero eros euismod eros, quis euismod purus purus sed felis. Suspendisse in malesuada felis, at auctor est. Nulla enim mauris, luctus ut bibendum in, iaculis a urna. Fusce ex orci, facilisis non nulla vitae, dapibus efficitur leo. Sed ante nibh, mollis vitae auctor sed, ullamcorper ac urna.\r\n\r\nNunc ac quam posuere eros facilisis rutrum. Nam aliquam nec metus quis fringilla. Sed vel ligula eu mi ultrices varius sed id massa. Aliquam congue metus id dui ornare ultrices. Pellentesque laoreet porta dolor id egestas. Etiam purus mauris, mollis tristique mattis non, suscipit et dui. Integer at dolor vel purus suscipit aliquam. Phasellus pharetra lectus sit amet pulvinar consequat. Curabitur pretium mi leo, eget dapibus justo placerat at.\r\n\r\nEtiam semper ligula ut arcu convallis porttitor. Nulla nulla dolor, ullamcorper sit amet nisi ut, interdum mattis felis. Vivamus quis dui placerat, ornare lorem sit amet, hendrerit dui. In tristique, nunc sit amet sollicitudin molestie, arcu eros iaculis dolor, et posuere felis libero non orci. Donec finibus lacinia orci. In nec rutrum felis. Praesent sollicitudin lobortis ultricies. Phasellus nec sem luctus, vehicula est eu, lobortis turpis. In at nisl in quam porttitor fringilla et eget sapien.";
        const string password = "The quick brown fox jumps over the lazy dog";
        var sw = new Stopwatch();
        var dataBytes = Encoding.ASCII.GetBytes(data);
        var passwordBytes = Encoding.ASCII.GetBytes(password);

        const int n = 1024;
        const int r = 8;
        const int p = 16;
        const int dkLen = 64;

        var handlers = new HashSet<ScryptGenerator> { SCrypt.Generate, ScryptBouncy.Generate, SCryptCryptSharp.Generate, ScryptILGPU.Generate };
        foreach (var handler in handlers)
        {
            var methodName = $"{handler.Method.DeclaringType?.Name}.{handler.Method.Name}";
            try
            {
                sw.Start();
                _ = handler(passwordBytes, dataBytes, n, r, p, dkLen);
                sw.Stop();
            }
            catch (NotImplementedException)
            {
                Console.WriteLine($"{methodName} не реализован");
                sw.Reset();
                continue;
            }
            catch (SystemException)
            {
                Console.WriteLine($"{methodName} не имеет возможности запуститься. Проверьте доступность видеокарты CUDA/OpenGL");
                sw.Reset();
                continue;
            }

            Console.WriteLine($"Результаты {methodName}");
            Console.WriteLine($"Затрачено времени: {sw.Elapsed}");
            Console.WriteLine($"В миллисекундах: {sw.ElapsedMilliseconds} ms");
            Console.WriteLine($"В тиках: {sw.ElapsedTicks}");
            sw.Reset();
        }

        return 0;
    }
}
