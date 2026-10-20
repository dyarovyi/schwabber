using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace Schwabber;

/// <summary>
/// Wireshark-style bytes pane: offset, 16 hex bytes and ASCII per row. Header bytes are tinted, the selected
/// field is highlighted, and clicking a byte reports its absolute frame offset. Only visible rows are drawn.
/// </summary>
public sealed class HexView : FrameworkElement
{
    private const double Pad = 8;
    private static readonly Typeface Mono = new(new FontFamily("Cascadia Mono, Consolas, Courier New"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    // Colors come from the active theme dictionary on every render.
    private Brush Background_ => ThemeManager.Brush(this, "HexBackground", Brushes.White);
    private Brush HeaderTint => ThemeManager.Brush(this, "HexHeaderTint", Brushes.WhiteSmoke);
    private Brush SelectionBrush => ThemeManager.Brush(this, "HexSelection", Brushes.LightBlue);
    private Brush HoverBrush => ThemeManager.Brush(this, "HexHover", Brushes.AliceBlue);
    private Brush OffsetBrush => ThemeManager.Brush(this, "HexOffset", Brushes.Gray);
    private Brush HeaderText => ThemeManager.Brush(this, "HexHeaderText", Brushes.DimGray);
    private Brush TextBrush => ThemeManager.Brush(this, "PrimaryText", Brushes.Black);

    private byte[] bytes = Array.Empty<byte>();
    private int start, count, payloadOffset, payloadEnd;
    private bool textOnly;

    /// <summary>"ASCII only": hide the hex columns and show just the printable characters.</summary>
    public bool TextOnly
    {
        get => textOnly;
        set { if (textOnly == value) return; textOnly = value; InvalidateMeasure(); InvalidateVisual(); }
    }
    private int selectionStart = -1, selectionLength;
    private int hover = -1;
    private double charWidth = 7, lineHeight = 16;
    private const double FontSize = 12;
    private ScrollViewer? scroller;

    public event Action<int>? ByteClicked;
    /// <summary>Raised while dragging across bytes: absolute start and length of the dragged range.</summary>
    public event Action<int, int>? RangeSelected;
    private int anchor = -1;
    private bool dragging, dragged;
    public Func<int, string?>? DescribeByte { get; set; }

    public HexView()
    {
        Cursor = Cursors.Hand;
        Focusable = true;
        FocusVisualStyle = null;
        Loaded += (_, _) =>
        {
            scroller = FindScroller(this);
            if (scroller is not null) scroller.ScrollChanged += (_, _) => InvalidateVisual();
        };
        ToolTipService.SetInitialShowDelay(this, 250);
        ContextMenu = new ContextMenu();
    }

    private static ScrollViewer? FindScroller(DependencyObject element)
    {
        for (var parent = VisualTreeHelper.GetParent(element); parent is not null; parent = VisualTreeHelper.GetParent(parent))
            if (parent is ScrollViewer viewer) return viewer;
        return null;
    }

    /// <summary>Shows bytes[start..start+count]. Bytes outside [payloadStart, payloadStop) are shaded as headers or trailer.</summary>
    public void SetData(byte[] data, int from, int length, int payloadStart, int payloadStop)
    {
        bytes = data; start = from; count = Math.Max(0, length); payloadOffset = payloadStart; payloadEnd = payloadStop;
        hover = -1;
        InvalidateMeasure();
        InvalidateVisual();
        scroller?.ScrollToTop();
    }

    /// <summary>Highlights an absolute byte range and scrolls it into view.</summary>
    public void SetSelection(int from, int length, bool scroll = true)
    {
        selectionStart = from; selectionLength = length;
        InvalidateVisual();
        if (!scroll) return;
        var first = Math.Max(from, start) - start;
        if (length > 0 && first < count)
        {
            var row = first / 16;
            var rows = Math.Max(1, Math.Min(length, count - first) / 16);
            BringIntoView(new Rect(0, Pad + row * lineHeight, 1, Math.Min(rows, 6) * lineHeight));
        }
    }

    private const int OffsetDigits = 6;
    private int Rows => (count + 15) / 16;
    private double HexX(int column) => Pad + (OffsetDigits + 2 + column * 3 + (column >= 8 ? 1 : 0)) * charWidth;
    private double AsciiX(int column) => Pad + (OffsetDigits + 2 + (textOnly ? 0 : 49 + 2) + column) * charWidth;

    private FormattedText Text(string text, Brush brush) =>
        new(text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, Mono, FontSize, brush, VisualTreeHelper.GetDpi(this).PixelsPerDip);

    protected override Size MeasureOverride(Size availableSize)
    {
        var probe = Text("0", Brushes.Black);
        charWidth = probe.WidthIncludingTrailingWhitespace;
        lineHeight = Math.Ceiling(probe.Height + 2);
        return new Size(AsciiX(16) + Pad, Pad * 2 + Rows * lineHeight);
    }

    protected override void OnRender(DrawingContext dc)
    {
        dc.DrawRectangle(Background_, null, new Rect(RenderSize));
        Brush headerTint = HeaderTint, hoverBrush = HoverBrush, selectionBrush = SelectionBrush, offsetBrush = OffsetBrush, headerText = HeaderText, textBrush = TextBrush;
        if (count == 0) return;
        double top = 0, height = ActualHeight;
        if (scroller is not null) { top = scroller.VerticalOffset; height = scroller.ViewportHeight; }
        var firstRow = Math.Max(0, (int)((top - Pad) / lineHeight) - 1);
        var lastRow = Math.Min(Rows - 1, (int)((top + height) / lineHeight) + 1);
        for (var row = firstRow; row <= lastRow; row++)
        {
            var y = Pad + row * lineHeight;
            var rowStart = start + row * 16;
            var rowEnd = Math.Min(start + count, rowStart + 16);
            DrawRun(dc, headerTint, y, rowStart, rowEnd, start, payloadOffset);
            DrawRun(dc, headerTint, y, rowStart, rowEnd, payloadEnd, start + count);
            if (hover >= 0) DrawRun(dc, hoverBrush, y, rowStart, rowEnd, hover, hover + 1);
            if (selectionLength > 0) DrawRun(dc, selectionBrush, y, rowStart, rowEnd, selectionStart, selectionStart + selectionLength);
            // Offsets count from the first shown byte: frame offsets with headers, payload offsets without.
            dc.DrawText(Text((row * 16).ToString("x6"), offsetBrush), new Point(Pad, y + 1));
            var hex = new char[49];
            Array.Fill(hex, ' ');
            var ascii = new char[16];
            var used = 0;
            for (var column = 0; column < 16; column++)
            {
                var index = row * 16 + column;
                if (index >= count) break;
                var value = bytes[start + index];
                var at = column * 3 + (column >= 8 ? 1 : 0);
                var digits = value.ToString("x2");
                hex[at] = digits[0]; hex[at + 1] = digits[1];
                ascii[column] = value >= 32 && value < 127 ? (char)value : '.';
                used++;
            }
            var hexText = Text(new string(hex), textBrush);
            var asciiText = Text(new string(ascii, 0, used), textBrush);
            // Grey out header and trailer bytes so the payload boundary is visible.
            for (var column = 0; column < used; column++)
            {
                var absolute = start + row * 16 + column;
                if (absolute >= payloadOffset && absolute < payloadEnd) continue;
                hexText.SetForegroundBrush(headerText, column * 3 + (column >= 8 ? 1 : 0), 2);
                asciiText.SetForegroundBrush(headerText, column, 1);
            }
            if (!textOnly) dc.DrawText(hexText, new Point(HexX(0), y + 1));
            dc.DrawText(asciiText, new Point(AsciiX(0), y + 1));
        }
    }

    /// <summary>Fills the part of absolute range [from, to) that falls on this row, in both the hex and ASCII columns.</summary>
    private void DrawRun(DrawingContext dc, Brush brush, double y, int rowStart, int rowEnd, int from, int to)
    {
        var first = Math.Max(from, rowStart);
        var last = Math.Min(to, rowEnd);
        if (first >= last) return;
        int c0 = first - rowStart, c1 = last - rowStart - 1;
        if (!textOnly) dc.DrawRectangle(brush, null, new Rect(HexX(c0) - 2, y, HexX(c1) + 2 * charWidth + 4 - HexX(c0), lineHeight));
        dc.DrawRectangle(brush, null, new Rect(AsciiX(c0), y, (c1 - c0 + 1) * charWidth, lineHeight));
    }

    private int HitTest(Point point)
    {
        var row = (int)Math.Floor((point.Y - Pad) / lineHeight);
        if (row < 0 || row >= Rows) return -1;
        int column;
        var hexColumn = (point.X - HexX(0)) / charWidth;
        var asciiColumn = (point.X - AsciiX(0)) / charWidth;
        if (!textOnly && hexColumn >= 0 && hexColumn < 49)
        {
            var adjusted = hexColumn >= 24.5 ? hexColumn - 1 : hexColumn;
            column = Math.Clamp((int)(adjusted / 3), 0, 15);
        }
        else if (asciiColumn >= 0 && asciiColumn < 16) column = (int)asciiColumn;
        else return -1;
        var index = row * 16 + column;
        return index < count ? start + index : -1;
    }

    /// <summary>Like HitTest, but clamps to the nearest shown byte so a drag can run past the edges.</summary>
    private int HitTestClamped(Point point)
    {
        if (count == 0) return -1;
        var row = Math.Clamp((int)Math.Floor((point.Y - Pad) / lineHeight), 0, Rows - 1);
        int column;
        if (!textOnly && point.X < AsciiX(0) - charWidth)
        {
            var hexColumn = Math.Max(0, (point.X - HexX(0)) / charWidth);
            column = Math.Clamp((int)((hexColumn >= 24.5 ? hexColumn - 1 : hexColumn) / 3), 0, 15);
        }
        else column = Math.Clamp((int)((point.X - AsciiX(0)) / charWidth), 0, 15);
        return start + Math.Min(row * 16 + column, count - 1);
    }

    /// <summary>A click selects the field under the byte; dragging selects an arbitrary byte range to copy.</summary>
    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        Focus();
        e.Handled = true;
        var index = HitTest(e.GetPosition(this));
        if (index < 0) return;
        anchor = index;
        dragging = true;
        dragged = false;
        CaptureMouse();
    }

    protected override void OnMouseLeftButtonUp(MouseButtonEventArgs e)
    {
        if (!dragging) return;
        dragging = false;
        ReleaseMouseCapture();
        if (!dragged) ByteClicked?.Invoke(anchor);
        e.Handled = true;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        var position = e.GetPosition(this);
        if (dragging && e.LeftButton == MouseButtonState.Pressed)
        {
            var index = HitTestClamped(position);
            if (index >= 0 && (index != anchor || dragged))
            {
                dragged = true;
                int from = Math.Min(anchor, index), length = Math.Abs(index - anchor) + 1;
                SetSelection(from, length, scroll: false);
                RangeSelected?.Invoke(from, length);
            }
        }
        var hit = HitTest(position);
        if (hit == hover) return;
        hover = hit;
        ToolTip = hit >= 0 && !dragging ? DescribeByte?.Invoke(hit) : null;
        InvalidateVisual();
    }

    // MARK: Copying

    /// <summary>The highlighted bytes that are currently shown (a field partly hidden by "Include headers" is clipped).</summary>
    public byte[] SelectedBytes
    {
        get
        {
            int from = Math.Max(selectionStart, start), to = Math.Min(selectionStart + selectionLength, start + count);
            return selectionLength <= 0 || to <= from ? Array.Empty<byte>() : bytes[from..to];
        }
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.C) { Copy(ByteFormat.Hex(SelectedBytes, spaced: true)); e.Handled = true; }
        else if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.A) { SelectAll(); e.Handled = true; }
        base.OnKeyDown(e);
    }

    private void SelectAll()
    {
        if (count == 0) return;
        SetSelection(start, count, scroll: false);
        RangeSelected?.Invoke(start, count);
    }

    private static void Copy(string text)
    {
        if (text.Length > 0) Clipboard.SetText(text);
    }

    protected override void OnContextMenuOpening(ContextMenuEventArgs e)
    {
        var menu = ContextMenu!;
        menu.Items.Clear();
        var selected = SelectedBytes;
        void Add(string header, Func<string> text, string? gesture = null)
        {
            var item = new MenuItem { Header = header, IsEnabled = selected.Length > 0, InputGestureText = gesture ?? "" };
            item.Click += (_, _) => Copy(text());
            menu.Items.Add(item);
        }
        Add("Copy as hex", () => ByteFormat.Hex(selected, spaced: true), "Ctrl+C");
        Add("Copy as hex stream", () => ByteFormat.Hex(selected, spaced: false));
        Add("Copy as text", () => ByteFormat.Text(selected));
        Add("Copy as hex dump", () => ByteFormat.HexDump(selected, Math.Max(selectionStart, start) - start));
        menu.Items.Add(new Separator());
        var all = new MenuItem { Header = "Select all bytes", InputGestureText = "Ctrl+A", IsEnabled = count > 0 };
        all.Click += (_, _) => SelectAll();
        menu.Items.Add(all);
        base.OnContextMenuOpening(e);
    }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        hover = -1;
        ToolTip = null;
        InvalidateVisual();
    }
}

/// <summary>Clipboard formats for packet bytes.</summary>
public static class ByteFormat
{
    public static string Hex(byte[] data, bool spaced) =>
        spaced ? string.Join(" ", data.Select(b => b.ToString("x2"))) : Convert.ToHexString(data).ToLowerInvariant();

    /// <summary>Printable ASCII, with other bytes shown as dots, like the bytes pane.</summary>
    public static string Text(byte[] data) => new(data.Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());

    /// <summary>Offset, hex and ASCII columns, the same layout as the macOS hex dump.</summary>
    public static string HexDump(byte[] data, int baseOffset)
    {
        var lines = new List<string>();
        for (var offset = 0; offset < data.Length; offset += 16)
        {
            var row = data[offset..Math.Min(offset + 16, data.Length)];
            lines.Add($"{baseOffset + offset:x6}  {Hex(row, spaced: true),-47}  |{Text(row)}|");
        }
        return string.Join(Environment.NewLine, lines);
    }
}
