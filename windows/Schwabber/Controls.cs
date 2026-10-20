using System.Globalization;
using System.Windows;
using System.Windows.Media;
using CaptureCore;

namespace Schwabber;

/// <summary>Picks a readable time step (1, 2 or 5 x 10^n seconds) so labels stay about 110 px apart at any zoom.</summary>
public static class TimeAxis
{
    public const double MinSpacing = 110;

    public static (double Step, int Decimals) Choose(double duration, double width)
    {
        if (width <= 0 || duration <= 0) return (Math.Max(duration, 1e-6), 3);
        var raw = duration * MinSpacing / width;
        var magnitude = Math.Pow(10, Math.Floor(Math.Log10(raw)));
        var step = new[] { 1.0, 2, 5, 10 }.Select(m => m * magnitude).First(v => v >= raw * (1 - 1e-9));
        var decimals = Math.Clamp(-(int)Math.Floor(Math.Log10(step) + 1e-9), 0, 6);
        return (step, decimals);
    }

    /// <summary>Tick times from 0 to duration inclusive.</summary>
    public static IEnumerable<double> Ticks(double duration, double step)
    {
        var count = (long)Math.Floor(duration / step + 1e-9);
        for (long k = 0; k <= count && k <= 100_000; k++) yield return k * step;
    }
}

/// <summary>A run of consecutive packets of a session drawn as one block on the timeline.</summary>
public readonly record struct TimelineChunk(int Start, int Count, double Left, double Right);

/// <summary>
/// Groups a session's packets into the blocks drawn on the timeline. A packet joins the previous chunk when its 2 px tick
/// would start less than <see cref="MergeDistance"/> px after the previous tick, so neighbors that cannot be told apart
/// at the current zoom form one chunk; zooming in splits them again.
/// </summary>
public static class TimelineChunks
{
    public const double TickWidth = 2;
    public const double MergeDistance = 4;

    public static double X(Packet packet, double captureStart, double duration, double width) =>
        Math.Min(width - TickWidth, (packet.Time - captureStart) / duration * width);

    public static IEnumerable<TimelineChunk> Split(IReadOnlyList<Packet> packets, double captureStart, double duration, double width)
    {
        if (packets.Count == 0 || width <= 0 || duration <= 0) yield break;
        int start = 0;
        double left = X(packets[0], captureStart, duration, width), last = left;
        for (var i = 1; i < packets.Count; i++)
        {
            var x = X(packets[i], captureStart, duration, width);
            if (x - last < MergeDistance) { last = Math.Max(last, x); continue; }
            yield return new TimelineChunk(start, i - start, left, last + TickWidth);
            start = i;
            left = last = x;
        }
        yield return new TimelineChunk(start, packets.Count - start, left, last + TickWidth);
    }

    /// <summary>The chunk holding the packet at <paramref name="index"/>.</summary>
    public static TimelineChunk? Containing(IReadOnlyList<Packet> packets, int index, double captureStart, double duration, double width)
    {
        foreach (var chunk in Split(packets, captureStart, duration, width))
            if (index < chunk.Start + chunk.Count) return index >= chunk.Start ? chunk : null;
        return null;
    }
}

/// <summary>Draws one session on the shared timeline: grid lines, a duration bar and a tick per packet arrival (or chunk of close arrivals).</summary>
public sealed class TimelineBar : FrameworkElement
{
    public static readonly DependencyProperty SessionProperty = Register(nameof(Session), typeof(Session));
    public static readonly DependencyProperty AccentProperty = Register(nameof(Accent), typeof(Color), Colors.Gray);
    public static readonly DependencyProperty CaptureStartProperty = Register(nameof(CaptureStart), typeof(double), 0.0);
    public static readonly DependencyProperty DurationProperty = Register(nameof(Duration), typeof(double), 1.0);
    public static readonly DependencyProperty HighlightPacketIdProperty = Register(nameof(HighlightPacketId), typeof(int), -1);
    /// <summary>Id of the packet open in the packet viewer; its tick gets a high-contrast marker. -1 for none.</summary>
    public int HighlightPacketId { get => (int)GetValue(HighlightPacketIdProperty); set => SetValue(HighlightPacketIdProperty, value); }

    private static DependencyProperty Register(string name, Type type, object? value = null) =>
        DependencyProperty.Register(name, type, typeof(TimelineBar), new FrameworkPropertyMetadata(value, FrameworkPropertyMetadataOptions.AffectsRender));

    public Session? Session { get => (Session?)GetValue(SessionProperty); set => SetValue(SessionProperty, value); }
    public Color Accent { get => (Color)GetValue(AccentProperty); set => SetValue(AccentProperty, value); }
    public double CaptureStart { get => (double)GetValue(CaptureStartProperty); set => SetValue(CaptureStartProperty, value); }
    public double Duration { get => (double)GetValue(DurationProperty); set => SetValue(DurationProperty, value); }

    private static readonly Pen GridPen = Freeze(new Pen(new SolidColorBrush(Color.FromArgb(38, 128, 128, 128)), 1));
    private static T Freeze<T>(T value) where T : Freezable { value.Freeze(); return value; }

    /// <summary>Half heights of the duration bar and packet ticks: 9 and 12 px in full rows, shrinking to fit compact rows.</summary>
    private double BarHalf => Math.Min(9, (ActualHeight - 8) / 2);
    private double TickHalf => Math.Min(12, ActualHeight / 2 - 2);

    /// <summary>
    /// The tick or chunk under the pointer, matching the drawing, with 3 px of slop. Clicks above or below the tick band
    /// return null.
    /// </summary>
    public TimelineChunk? ChunkAt(Point point)
    {
        if (Session is not { } session || ActualWidth <= 0) return null;
        var middle = ActualHeight / 2;
        if (point.Y < middle - TickHalf - 3 || point.Y > middle + TickHalf + 3) return null;
        TimelineChunk? closest = null;
        var best = double.MaxValue;
        foreach (var chunk in TimelineChunks.Split(session.Packets, CaptureStart, Duration, ActualWidth))
        {
            var distance = Math.Max(0, Math.Max(chunk.Left - point.X, point.X - chunk.Right));
            if (distance < best) { best = distance; closest = chunk; }
            if (chunk.Left > point.X + 3) break;
        }
        return best <= 3 ? closest : null;
    }

    protected override void OnRender(DrawingContext context)
    {
        var width = ActualWidth;
        var height = ActualHeight;
        context.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, width, height));
        var duration = Duration;
        if (width > 0)
        {
            var (step, _) = TimeAxis.Choose(duration, width);
            foreach (var t in TimeAxis.Ticks(duration, step))
            {
                var x = Math.Min(width - 0.5, t / duration * width + 0.5);
                context.DrawLine(GridPen, new Point(x, 0), new Point(x, height));
            }
        }
        if (Session is not { } session || width <= 0) return;
        var start = (session.Start - CaptureStart) / duration * width;
        var end = (session.End - CaptureStart) / duration * width;
        var fill = Freeze(new SolidColorBrush(Color.FromArgb(77, Accent.R, Accent.G, Accent.B)));
        var middle = height / 2;
        double barHalf = BarHalf, tickHalf = TickHalf;
        context.DrawRoundedRectangle(fill, null, new Rect(start, middle - barHalf, Math.Max(4, end - start), 2 * barHalf), 4, 4);
        // Single packets are 2 px ticks; packets too close to tell apart merge into one chunk block spanning them.
        var brush = Freeze(new SolidColorBrush(Accent));
        var geometry = new StreamGeometry();
        using (var g = geometry.Open())
        {
            foreach (var chunk in TimelineChunks.Split(session.Packets, CaptureStart, duration, width))
            {
                g.BeginFigure(new Point(chunk.Left, middle - tickHalf), true, true);
                g.LineTo(new Point(chunk.Right, middle - tickHalf), false, false);
                g.LineTo(new Point(chunk.Right, middle + tickHalf), false, false);
                g.LineTo(new Point(chunk.Left, middle + tickHalf), false, false);
            }
        }
        geometry.Freeze();
        context.DrawGeometry(brush, null, geometry);
        DrawHighlight(context, session, width, height, duration);
    }

    /// <summary>
    /// The inspected packet: a soft glow the full row height, a solid tick in the text color, and a small triangle on top,
    /// so it stands out from the session's own ticks in both themes.
    /// </summary>
    private void DrawHighlight(DrawingContext context, Session session, double width, double height, double duration)
    {
        var id = HighlightPacketId;
        if (id < 0) return;
        Packet? packet = null;
        foreach (var candidate in session.Packets) if (candidate.Id == id) { packet = candidate; break; }
        if (packet is null) return;
        var x = Math.Min(width - 2, (packet.Time - CaptureStart) / duration * width) + 1;
        var ink = ThemeManager.Brush(this, "PrimaryText", Brushes.Black);
        var glow = ink.CloneCurrentValue();
        glow.Opacity = 0.22;
        glow.Freeze();
        context.DrawRectangle(glow, null, new Rect(x - 4, 0, 8, height));
        context.DrawRectangle(ink, null, new Rect(x - 1.5, 1, 3, height - 2));
        var triangle = new StreamGeometry();
        using (var g = triangle.Open())
        {
            g.BeginFigure(new Point(x - 5, 0), true, true);
            g.LineTo(new Point(x + 5, 0), true, false);
            g.LineTo(new Point(x, 6), true, false);
        }
        triangle.Freeze();
        context.DrawGeometry(ink, null, triangle);
    }
}

/// <summary>Relative-time labels above the timeline.</summary>
public sealed class TimelineHeader : FrameworkElement
{
    public static readonly DependencyProperty DurationProperty = DependencyProperty.Register(nameof(Duration), typeof(double), typeof(TimelineHeader),
        new FrameworkPropertyMetadata(1.0, FrameworkPropertyMetadataOptions.AffectsRender));
    public double Duration { get => (double)GetValue(DurationProperty); set => SetValue(DurationProperty, value); }

    protected override void OnRender(DrawingContext context)
    {
        var dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var typeface = new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
        var brush = (Brush)Application.Current.Resources["SecondaryText"];
        var width = ActualWidth;
        // Transparent fill makes the whole ruler clickable for adding pins, not just its labels.
        context.DrawRectangle(Brushes.Transparent, null, new Rect(RenderSize));
        var (step, decimals) = TimeAxis.Choose(Duration, width);
        var previousEnd = double.NegativeInfinity;
        foreach (var t in TimeAxis.Ticks(Duration, step))
        {
            var label = "+" + t.ToString("F" + decimals, CultureInfo.InvariantCulture) + " s";
            var text = new FormattedText(label, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, typeface, 11, brush, dpi);
            // As on macOS: labels start at their tick, clamped so the last one stays inside the timeline.
            var x = Math.Max(0, Math.Min(width - 85, t / Duration * width));
            // The clamp can push the final label onto its neighbour; skip it rather than overprint.
            if (x < previousEnd + 8) continue;
            context.DrawText(text, new Point(x, 10));
            previousEnd = x + text.Width;
        }
    }
}

/// <summary>
/// Timeline pins: thin vertical lines across the ruler and every session row at fixed times, each with a time label on the
/// ruler, for comparing what different sessions did at the same moment. Drawn as one overlay so lines stay continuous.
/// </summary>
public sealed class PinOverlay : FrameworkElement
{
    public static readonly DependencyProperty LeftEdgeProperty = Register(nameof(LeftEdge), 0.0);
    public static readonly DependencyProperty TimelineWidthProperty = Register(nameof(TimelineWidth), 1.0);
    public static readonly DependencyProperty DurationProperty = Register(nameof(Duration), 1.0);
    public static readonly DependencyProperty ScrollOffsetProperty = Register(nameof(ScrollOffset), 0.0);
    private static DependencyProperty Register(string name, double value) =>
        DependencyProperty.Register(name, typeof(double), typeof(PinOverlay), new FrameworkPropertyMetadata(value, FrameworkPropertyMetadataOptions.AffectsRender));

    /// <summary>X of time zero when not scrolled (left margin + session column + handle strip).</summary>
    public double LeftEdge { get => (double)GetValue(LeftEdgeProperty); set => SetValue(LeftEdgeProperty, value); }
    public double TimelineWidth { get => (double)GetValue(TimelineWidthProperty); set => SetValue(TimelineWidthProperty, value); }
    public double Duration { get => (double)GetValue(DurationProperty); set => SetValue(DurationProperty, value); }
    public double ScrollOffset { get => (double)GetValue(ScrollOffsetProperty); set => SetValue(ScrollOffsetProperty, value); }

    private IReadOnlyList<double> pins = Array.Empty<double>();
    /// <summary>Pin times in seconds from the capture start.</summary>
    public IReadOnlyList<double> Pins { get => pins; set { pins = value; InvalidateVisual(); } }

    public const double RulerHeight = 38;

    /// <summary>Screen X of a time, before clipping to the visible timeline.</summary>
    public double XOf(double time) => LeftEdge + time / Math.Max(Duration, 1e-9) * TimelineWidth - ScrollOffset;

    protected override void OnRender(DrawingContext context)
    {
        if (pins.Count == 0) return;
        // As on macOS: an orange pin marker on the ruler and a thin dashed orange line through every row.
        var brush = ThemeManager.Brush(this, "PinBrush", Brushes.Orange);
        var pen = new Pen(brush, 1) { DashStyle = new DashStyle(new double[] { 4, 3 }, 0) };
        pen.Freeze();
        var dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var icons = new Typeface(new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
        var right = ActualWidth - SystemParameters.VerticalScrollBarWidth;
        foreach (var time in pins)
        {
            var x = Math.Round(XOf(time)) + 0.5;
            if (x < LeftEdge || x > right) continue;
            context.DrawLine(pen, new Point(x, RulerHeight), new Point(x, ActualHeight));
            var marker = new FormattedText("\uE841", CultureInfo.InvariantCulture, FlowDirection.LeftToRight, icons, 12, brush, dpi);
            context.DrawText(marker, new Point(x - marker.Width / 2, RulerHeight - marker.Height - 1));
        }
    }
}

/// <summary>Single-line text that elides the middle when it does not fit, like SwiftUI's .truncationMode(.middle).</summary>
public sealed class MiddleTrimTextBlock : FrameworkElement
{
    public static readonly DependencyProperty TextProperty = Register(nameof(Text), typeof(string), "");
    public static readonly DependencyProperty FontFamilyProperty = Register(nameof(FontFamily), typeof(FontFamily), new FontFamily("Segoe UI"));
    public static readonly DependencyProperty FontSizeProperty = Register(nameof(FontSize), typeof(double), 12.0);
    // Inherits like TextBlock.Foreground, so it follows the window's theme text color.
    public static readonly DependencyProperty ForegroundProperty = System.Windows.Documents.TextElement.ForegroundProperty.AddOwner(typeof(MiddleTrimTextBlock),
        new FrameworkPropertyMetadata(Brushes.Black, FrameworkPropertyMetadataOptions.Inherits | FrameworkPropertyMetadataOptions.AffectsRender));

    private static DependencyProperty Register(string name, Type type, object value) =>
        DependencyProperty.Register(name, type, typeof(MiddleTrimTextBlock),
            new FrameworkPropertyMetadata(value, FrameworkPropertyMetadataOptions.AffectsMeasure | FrameworkPropertyMetadataOptions.AffectsRender));

    public string Text { get => (string)GetValue(TextProperty); set => SetValue(TextProperty, value); }
    public FontFamily FontFamily { get => (FontFamily)GetValue(FontFamilyProperty); set => SetValue(FontFamilyProperty, value); }
    public double FontSize { get => (double)GetValue(FontSizeProperty); set => SetValue(FontSizeProperty, value); }
    public Brush Foreground { get => (Brush)GetValue(ForegroundProperty); set => SetValue(ForegroundProperty, value); }

    private FormattedText Format(string text) =>
        new(text, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, new Typeface(FontFamily, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal),
            FontSize, Foreground, VisualTreeHelper.GetDpi(this).PixelsPerDip);

    protected override Size MeasureOverride(Size available)
    {
        var text = Format(Text ?? "");
        // Round up so layout rounding never makes the element a fraction narrower than its own text.
        return new Size(Math.Min(available.Width, Math.Ceiling(text.WidthIncludingTrailingWhitespace) + 1), text.Height);
    }

    protected override void OnRender(DrawingContext context)
    {
        var full = Text ?? "";
        var text = Format(full);
        if (text.WidthIncludingTrailingWhitespace > ActualWidth && full.Length > 1)
        {
            int low = 0, high = full.Length - 1;
            while (low < high)
            {
                var mid = (low + high + 1) / 2;
                if (Format(Elide(full, mid)).WidthIncludingTrailingWhitespace <= ActualWidth) low = mid; else high = mid - 1;
            }
            text = Format(Elide(full, low));
        }
        context.DrawText(text, new Point(0, 0));
    }

    private static string Elide(string text, int keep)
    {
        var head = (keep + 1) / 2;
        return text[..head] + "…" + text[^(keep - head)..];
    }
}
