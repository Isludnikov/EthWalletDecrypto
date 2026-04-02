namespace Scrypt.CryptSharp.Utils;

internal static class Check
{
    public static void Bounds(string valueName, Array value, int offset, int count)
    {
        Null(valueName, value);

        if (offset < 0 || count < 0 || count > value.Length - offset)
        {
            throw new ArgumentOutOfRangeException(valueName, $"Range [{offset}, {offset + count}) is outside array bounds [0, {value.Length}).");
        }
    }

    public static void Length(string valueName, Array value, int minimum, int maximum)
    {
        Null(valueName, value);

        if (value.Length < minimum || value.Length > maximum)
        {
            throw new ArgumentOutOfRangeException(valueName, $"Length must be in the range [{minimum}, {maximum}].");
        }
    }

    public static void Null<T>(string valueName, T value)
    {
        if (value == null)
        {
            throw new ArgumentNullException(valueName);
        }
    }

    public static void Range(string valueName, int value, int minimum, int maximum)
    {
        if (value < minimum || value > maximum)
        {
            throw new ArgumentOutOfRangeException(valueName, $"Value must be in the range [{minimum}, {maximum}].");
        }
    }
}
