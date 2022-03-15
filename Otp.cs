using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Netcorext.Algorithms;

public static class Otp
{
    private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly Encoding EncodingUtf8 = new UTF8Encoding(false, true);
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

    private static readonly TimeSpan TimeStep = TimeSpan.FromSeconds(30);
    private const int DIGITS = 6;

    // Generates a new 80-bit security token
    public static byte[] GenerateRandomKey(int length = 10)
    {
        var bytes = new byte[length];

        Rng.GetBytes(bytes);

        return bytes;
    }

    private static int ComputeTotp(HashAlgorithm hashAlgorithm, ulong timeStepNumber, string modifier)
    {
        var mod = (int)Math.Pow(10, DIGITS);

        // https://tools.ietf.org/html/rfc4226
        var timeStepAsBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder((long)timeStepNumber));
        var hash = hashAlgorithm.ComputeHash(ApplyModifier(timeStepAsBytes, modifier));

        var offset = hash[hash.Length - 1] & 0xf;

        var binaryCode = ((hash[offset] & 0x7f) << 24) |
                         ((hash[offset + 1] & 0xff) << 16) |
                         ((hash[offset + 2] & 0xff) << 8) |
                         (hash[offset + 3] & 0xff);

        return binaryCode % mod;
    }

    private static byte[] ApplyModifier(byte[] input, string modifier)
    {
        if (string.IsNullOrEmpty(modifier))
        {
            return input;
        }

        var modifierBytes = EncodingUtf8.GetBytes(modifier);
        var combined = new byte[checked(input.Length + modifierBytes.Length)];
        Buffer.BlockCopy(input, 0, combined, 0, input.Length);
        Buffer.BlockCopy(modifierBytes, 0, combined, input.Length, modifierBytes.Length);

        return combined;
    }

    // https://tools.ietf.org/html/rfc6238#section-4
    private static ulong GetCurrentTimeStepNumber()
    {
        var delta = DateTime.UtcNow - UnixEpoch;

        return (ulong)(delta.Ticks / TimeStep.Ticks);
    }

    public static int GenerateCode(byte[] securityToken, string modifier = null)
    {
        if (securityToken == null)
        {
            throw new ArgumentNullException(nameof(securityToken));
        }

        var currentTimeStep = GetCurrentTimeStepNumber();

        using var hashAlgorithm = new HMACSHA1(securityToken);

        return ComputeTotp(hashAlgorithm, currentTimeStep, modifier);
    }

    public static bool ValidateCode(string securityToken, string code, string modifier = null)
    {
        return ValidateCode(securityToken.FromBase32String(), int.Parse(code), modifier);
    }
    public static bool ValidateCode(byte[] securityToken, string code, string modifier = null)
    {
        return ValidateCode(securityToken, int.Parse(code), modifier);
    }
    public static bool ValidateCode(string securityToken, int code, string modifier = null)
    {
        return ValidateCode(securityToken.FromBase32String(), code, modifier);
    }
    public static bool ValidateCode(byte[] securityToken, int code, string modifier = null)
    {
        if (securityToken == null)
        {
            throw new ArgumentNullException(nameof(securityToken));
        }

        var currentTimeStep = GetCurrentTimeStepNumber();

        using var hashAlgorithm = new HMACSHA1(securityToken);

        for (var i = -2; i <= 2; i++)
        {
            var computedTotp = ComputeTotp(hashAlgorithm, (ulong)((long)currentTimeStep + i), modifier);

            if (computedTotp == code) return true;
        }

        return false;
    }

    public static int GenerateTotpCode(byte[] securityToken, string modifier = null)
    {
        if (securityToken == null)
        {
            throw new ArgumentNullException(nameof(securityToken));
        }

        var currentTimeStep = GetCurrentTimeStepNumber();

        using var hashAlgorithm = new HMACSHA1(securityToken);

        var computedTotp = ComputeTotp(hashAlgorithm, (ulong)(long)currentTimeStep, modifier);

        return computedTotp;
    }
}