using System.Text;

namespace Netcorext.Algorithms;

public static class Base32
{
    private const string BASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string ToBase32String(this byte[] value)
    {
        if (value == null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        var sb = new StringBuilder();

        for (var i = 0; i < value.Length;)
        {
            var charsNumber = GetCharMapping(value, ref i, out var a, out var b, out var c, out var d, out var e, out var f, out var g, out var h);

            sb.Append(charsNumber >= 1 ? BASE_CHARS[a] : '=');
            sb.Append(charsNumber >= 2 ? BASE_CHARS[b] : '=');
            sb.Append(charsNumber >= 3 ? BASE_CHARS[c] : '=');
            sb.Append(charsNumber >= 4 ? BASE_CHARS[d] : '=');
            sb.Append(charsNumber >= 5 ? BASE_CHARS[e] : '=');
            sb.Append(charsNumber >= 6 ? BASE_CHARS[f] : '=');
            sb.Append(charsNumber >= 7 ? BASE_CHARS[g] : '=');
            sb.Append(charsNumber >= 8 ? BASE_CHARS[h] : '=');
        }

        return sb.ToString();
    }

    public static byte[] FromBase32String(this string value)
    {
        if (value == null) throw new ArgumentNullException(nameof(value));

        value = value.TrimEnd('=').ToUpperInvariant();

        if (value.Length == 0) return Array.Empty<byte>();

        var result = new byte[value.Length * 5 / 8];
        var bitIndex = 0;
        var valueIndex = 0;
        var resultBits = 0;
        var resultIndex = 0;

        while (resultIndex < result.Length)
        {
            var byteIndex = BASE_CHARS.IndexOf(value[valueIndex]);

            if (byteIndex < 0) throw new FormatException();

            var bits = Math.Min(5 - bitIndex, 8 - resultBits);
            result[resultIndex] <<= bits;
            result[resultIndex] |= (byte)(byteIndex >> (5 - (bitIndex + bits)));

            bitIndex += bits;

            if (bitIndex >= 5)
            {
                valueIndex++;
                bitIndex = 0;
            }

            resultBits += bits;

            if (resultBits < 8) continue;

            resultIndex++;
            resultBits = 0;
        }

        return result;
    }

    private static int GetCharMapping(byte[] value, ref int offset, out byte a, out byte b, out byte c, out byte d, out byte e, out byte f, out byte g, out byte h)
    {
        var result = (offset - value.Length) switch
                     {
                         1 => 2,
                         2 => 4,
                         3 => 5,
                         4 => 7,
                         _ => 8
                     };

        var b1 = offset < value.Length ? value[offset++] : 0U;
        var b2 = offset < value.Length ? value[offset++] : 0U;
        var b3 = offset < value.Length ? value[offset++] : 0U;
        var b4 = offset < value.Length ? value[offset++] : 0U;
        var b5 = offset < value.Length ? value[offset++] : 0U;

        a = (byte)(b1 >> 3);
        b = (byte)(((b1 & 0x07) << 2) | (b2 >> 6));
        c = (byte)((b2 >> 1) & 0x1f);
        d = (byte)(((b2 & 0x01) << 4) | (b3 >> 4));
        e = (byte)(((b3 & 0x0f) << 1) | (b4 >> 7));
        f = (byte)((b4 >> 2) & 0x1f);
        g = (byte)(((b4 & 0x3) << 3) | (b5 >> 5));
        h = (byte)(b5 & 0x1f);

        return result;
    }
}