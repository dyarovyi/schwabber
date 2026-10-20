using System.Text;

namespace CaptureCore;

/// <summary>
/// Compiled once per filter change. Plain text matches addresses, ports and protocol details case-insensitively,
/// or exact UTF-8 bytes in individual packet payloads; "x00x01xFF" searches payloads for hexadecimal bytes.
/// </summary>
public sealed class SessionFilter
{
    private readonly string text;
    private readonly byte[]? pattern;
    private readonly bool hex;

    public bool InvalidHex { get; }

    public SessionFilter(string query)
    {
        text = query;
        var bytes = Encoding.UTF8.GetBytes(query);
        static int Digit(byte b) => b switch { >= 48 and <= 57 => b - 48, >= 65 and <= 70 => b - 55, >= 97 and <= 102 => b - 87, _ => -1 };
        hex = bytes.Length >= 3 && (bytes[0] == 120 || bytes[0] == 88) && Digit(bytes[1]) >= 0 && Digit(bytes[2]) >= 0;
        if (hex)
        {
            var decoded = new List<byte>();
            var valid = bytes.Length % 3 == 0;
            for (var i = 0; valid && i < bytes.Length; i += 3)
            {
                int a = Digit(bytes[i + 1]), b = Digit(bytes[i + 2]);
                if ((bytes[i] != 120 && bytes[i] != 88) || a < 0 || b < 0) { valid = false; break; }
                decoded.Add((byte)(a * 16 + b));
            }
            InvalidHex = !valid;
            pattern = valid ? decoded.ToArray() : null;
        }
        else
        {
            InvalidHex = false;
            pattern = query.Length == 0 ? null : bytes;
        }
    }

    public bool Matches(Session session)
    {
        if (text.Length == 0) return true;
        if (InvalidHex) return false;
        if (!hex && session.Matches(text)) return true;
        if (pattern is not { Length: > 0 } needle) return false;
        foreach (var packet in session.Packets)
            if (packet.Payload.IndexOf(needle) >= 0) return true;
        return false;
    }
}
