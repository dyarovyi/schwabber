using System.ComponentModel;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using CaptureCore;

namespace Schwabber;

/// <summary>A timeline row. Created once per capture so selections survive filter changes.</summary>
public sealed class SessionItem : INotifyPropertyChanged
{
    // macOS system colors used by the Mac app, with their dark-appearance variants.
    private enum Hue { Purple, Pink, Teal, Green, Indigo, Blue, Orange, Mint, Cyan }
    private static readonly Color[] LightColors =
    {
        Color.FromRgb(0xAF, 0x52, 0xDE), Color.FromRgb(0xFF, 0x2D, 0x55), Color.FromRgb(0x30, 0xB0, 0xC7), Color.FromRgb(0x28, 0xB4, 0x46),
        Color.FromRgb(0x58, 0x56, 0xD6), Color.FromRgb(0x00, 0x7A, 0xFF), Color.FromRgb(0xFF, 0x95, 0x00), Color.FromRgb(0x00, 0xC7, 0xBE),
        Color.FromRgb(0x32, 0xAD, 0xE6),
    };
    private static readonly Color[] DarkColors =
    {
        Color.FromRgb(0xBF, 0x5A, 0xF2), Color.FromRgb(0xFF, 0x37, 0x5F), Color.FromRgb(0x40, 0xC8, 0xE0), Color.FromRgb(0x30, 0xD1, 0x58),
        Color.FromRgb(0x5E, 0x5C, 0xE6), Color.FromRgb(0x0A, 0x84, 0xFF), Color.FromRgb(0xFF, 0x9F, 0x0A), Color.FromRgb(0x63, 0xE6, 0xE2),
        Color.FromRgb(0x64, 0xD2, 0xFF),
    };

    private static Brush UncheckedBrush => Frozen(new SolidColorBrush(Color.FromRgb(0x8E, 0x8E, 0x93)));
    private static Brush Frozen(Brush brush) { brush.Freeze(); return brush; }

    private readonly Hue hue;
    private Brush? accentBrush, shareBrush, selectedBackground, checkedBrush;

    public SessionItem(Session session, long captureBytes)
    {
        Session = session;
        hue = HueFor(session);
        Share = captureBytes > 0 ? (double)session.Bytes / captureBytes : 0;
    }

    /// <summary>Drops cached brushes and re-reads every binding after the theme changes.</summary>
    public void RefreshTheme()
    {
        accentBrush = shareBrush = selectedBackground = checkedBrush = null;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(null));
    }

    /// <summary>Fraction of all bytes in the capture file that belong to this session.</summary>
    public double Share { get; }
    /// <summary>The share fill uses the session color at 45% opacity, as on macOS.</summary>
    public Brush ShareBrush => shareBrush ??= Frozen(new SolidColorBrush(Color.FromArgb(115, Accent.R, Accent.G, Accent.B)));
    public string ShareText => Share switch
    {
        0 => "0%",
        < 0.001 => "<0.1%",
        < 0.1 => (Share * 100).ToString("F1", CultureInfo.InvariantCulture) + "%",
        _ => (Share * 100).ToString("F0", CultureInfo.InvariantCulture) + "%",
    };
    public string ShareToolTip => $"{(Share * 100).ToString("F2", CultureInfo.InvariantCulture)}% of all capture bytes " +
                                  $"({Session.Bytes.ToString("N0", CultureInfo.CurrentCulture)} bytes)";

    public Session Session { get; }
    public Color Accent => (ThemeManager.IsDark ? DarkColors : LightColors)[(int)hue];
    public Brush AccentBrush => accentBrush ??= Frozen(new SolidColorBrush(Accent));
    public string ProtocolLabel => Session.ProtocolLabel;
    public string Number => $"#{Session.Id + 1}";
    public string PacketCount => $"{Session.Packets.Count} packets";
    public string Endpoints => $"{Session.EndpointA} ↔ {Session.EndpointB}";
    public string? Summary => Session.Summary.Length == 0 ? null : Session.Summary;
    public string AccessibleName => $"Select session {Session.Id + 1}";

    private bool isChecked;
    public bool IsChecked
    {
        get => isChecked;
        set
        {
            if (isChecked == value) return;
            isChecked = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(null));
        }
    }
    // Segoe Fluent/MDL2 glyphs: filled checkbox and empty checkbox.
    public string CheckGlyph => isChecked ? "" : "";
    private Color Blue => (ThemeManager.IsDark ? DarkColors : LightColors)[(int)Hue.Blue];
    public Brush CheckBrush => isChecked ? checkedBrush ??= Frozen(new SolidColorBrush(Blue)) : UncheckedBrush;
    public Brush RowBackground => isChecked
        ? selectedBackground ??= Frozen(new SolidColorBrush(Color.FromArgb(ThemeManager.IsDark ? (byte)56 : (byte)31, Blue.R, Blue.G, Blue.B)))
        : Brushes.Transparent;

    public event PropertyChangedEventHandler? PropertyChanged;

    private static Hue HueFor(Session session)
    {
        var protocols = session.ApplicationProtocols;
        if (protocols.Any(p => p is "RTCP" or "SIP" or "DTLS" or "TURN")) return Hue.Mint;
        if (protocols.Contains("RTP")) return Hue.Cyan;
        if (session.HasDns) return Hue.Purple;
        if (protocols.Contains("QUIC")) return Hue.Pink;
        if (protocols.Contains("TLS")) return Hue.Teal;
        if (protocols.Contains("HTTP")) return Hue.Green;
        if (protocols.Contains("STUN")) return Hue.Indigo;
        return session.Transport == "TCP" ? Hue.Blue : Hue.Orange;
    }
}

/// <summary>Share fill width: share × session column width, at least 2 px when non-zero.</summary>
public sealed class ShareWidthConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture) =>
        values is [double share, double width] && share > 0 ? Math.Max(2, share * width) : 0.0;
    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>One packet inspector row with display strings precomputed.</summary>
public sealed class PacketRow
{
    public PacketRow(Packet packet, int index, double captureStart, Packet? previous)
    {
        Packet = packet;
        Index = index;
        Id = packet.Id.ToString(CultureInfo.InvariantCulture);
        RelativeTime = (packet.Time - captureStart).ToString("F6", CultureInfo.InvariantCulture) + " s";
        DeltaTime = previous is null ? "—" : (packet.Time - previous.Time).ToString("F6", CultureInfo.InvariantCulture) + " s";
        Source = packet.Source;
        Destination = packet.Destination;
        Bytes = packet.Length.ToString(CultureInfo.InvariantCulture);
        Details = packet.Details;
    }
    public Packet Packet { get; }
    public int Index { get; }
    public string Id { get; }
    public string RelativeTime { get; }
    /// <summary>Time since the previous packet in this session, in either direction.</summary>
    public string DeltaTime { get; }
    public string Source { get; }
    public string Destination { get; }
    public string Bytes { get; }
    public string Details { get; }
}
