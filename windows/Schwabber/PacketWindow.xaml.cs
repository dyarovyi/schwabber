using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using CaptureCore;
using Microsoft.Win32;

namespace Schwabber;

/// <summary>Built-in analyzer tree node with two-way expansion and selection state.</summary>
public sealed class FieldItem : INotifyPropertyChanged
{
    public FieldItem(PacketField field, FieldItem? parent, PacketWindow owner)
    {
        Field = field; Parent = parent; this.owner = owner;
        Children = field.Children.Select(c => new FieldItem(c, this, owner)).ToList();
    }
    private readonly PacketWindow owner;
    public PacketField Field { get; }
    public FieldItem? Parent { get; }
    public List<FieldItem> Children { get; }
    public string Label => Field.Label;
    /// <summary>Generated information without bytes is shown in secondary text.</summary>
    public bool IsNote => !Field.HasBytes;
    public FontWeight Weight => Parent is null ? FontWeights.SemiBold : FontWeights.Normal;

    private bool isExpanded;
    public bool IsExpanded
    {
        get => isExpanded;
        set { if (isExpanded == value) return; isExpanded = value; owner.RememberExpansion(this, value); Changed(nameof(IsExpanded)); }
    }
    private bool isSelected;
    public bool IsSelected
    {
        get => isSelected;
        set { if (isSelected == value) return; isSelected = value; Changed(nameof(IsSelected)); }
    }
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Changed(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    public IEnumerable<FieldItem> Descendants() => Children.SelectMany(c => c.Descendants()).Prepend(this);
}

/// <summary>Wireshark tree node.</summary>
public sealed class WiresharkItem : INotifyPropertyChanged
{
    public WiresharkItem(WiresharkField field, WiresharkItem? parent)
    {
        Field = field; Parent = parent;
        Children = field.Children.Select(c => new WiresharkItem(c, this)).ToList();
    }
    public WiresharkField Field { get; }
    public WiresharkItem? Parent { get; }
    public List<WiresharkItem> Children { get; }
    public string Label => Field.Label;
    public bool IsNote => !Field.HasRange;

    private bool isExpanded;
    public bool IsExpanded { get => isExpanded; set { if (isExpanded == value) return; isExpanded = value; Changed(nameof(IsExpanded)); } }
    private bool isSelected;
    public bool IsSelected { get => isSelected; set { if (isSelected == value) return; isSelected = value; Changed(nameof(IsSelected)); } }
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Changed(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    public IEnumerable<WiresharkItem> Descendants() => Children.SelectMany(c => c.Descendants()).Prepend(this);
}

public partial class PacketWindow : Window
{
    public static readonly RoutedUICommand PreviousCommand = new("Previous packet", "Previous", typeof(PacketWindow));
    public static readonly RoutedUICommand NextCommand = new("Next packet", "Next", typeof(PacketWindow));
    private const string Prompt = "Click a byte or a field to see what it is.";

    private Session? session;
    private Capture? capture;
    private int index;
    private PacketDissection? native;
    private readonly Dictionary<PacketField, FieldItem> items = new();
    // Built-in tree expansion and selection are remembered by path so they carry over between packets.
    private readonly HashSet<string> expandedPaths = new();
    private string? selectedPath;
    private bool rebuilding;

    private WiresharkDissection? wireshark;
    private List<WiresharkItem> wiresharkItems = new();
    private WiresharkField? wiresharkSelection;
    private CancellationTokenSource? analysis;
    private string? keyLog;
    private string? error;
    private bool loading;
    /// <summary>0 is the captured frame; n is Wireshark's additional data source n.</summary>
    private int sourceIndex;
    private bool updatingSources;
    /// <summary>A byte range dragged in the bytes pane; replaces the field highlight until a field is chosen.</summary>
    private (int Start, int Length)? customRange;

    /// <summary>Raised when the shown packet changes, so the main window can follow along.</summary>
    public event Action<Session, int>? PacketShown;

    /// <summary>Looks up the timeline chunk (packets merged at the current zoom) holding a session's packet.</summary>
    public Func<Session, int, TimelineChunk?>? ChunkOf { get; init; }

    public PacketWindow()
    {
        InitializeComponent();
        Bytes.ByteClicked += OnByteClicked;
        Bytes.DescribeByte = Describe;
        Bytes.RangeSelected += (start, length) => { customRange = (start, length); UpdateStatus(); };
        SourceInitialized += (_, _) => ThemeManager.ApplyTitleBar(this);
        Loaded += (_, _) => FieldTree.Focus();
        Closed += (_, _) => analysis?.Cancel();
    }

    public void ShowPacket(Session session, int index, Capture capture)
    {
        this.session = session;
        this.capture = capture;
        this.index = Math.Clamp(index, 0, session.Packets.Count - 1);
        Render();
    }

    private Packet? Current => session?.Packets[index];
    private bool HeadersIncluded => IncludeHeaders.IsChecked == true;
    private bool WiresharkMode => UseWireshark.IsChecked == true && wireshark is not null;
    private PacketDataSource? Source => wireshark is { } w && sourceIndex > 0 && sourceIndex <= w.AdditionalSources.Count ? w.AdditionalSources[sourceIndex - 1] : null;

    private static string Bytes_(long count) => $"{count.ToString("N0", CultureInfo.CurrentCulture)} bytes";

    private void Render()
    {
        if (session is null || capture is null || Current is not { } packet) return;
        native = PacketDissector.Dissect(packet, capture.LinkType, capture.Start);
        var d = native;
        UpdatePosition();
        ArrivalText.Text = $"+{(packet.Time - capture.Start).ToString("F6", CultureInfo.InvariantCulture)} s";
        EndpointsText.Text = $"{packet.Source} → {packet.Destination}";
        ProtocolText.Text = session.ProtocolLabel;
        WithHeadersValue.Text = Bytes_(packet.Length);
        WithHeadersDetail.Text = $"{Bytes_(packet.RawBytes.Length)} captured";
        WithoutHeadersValue.Text = Bytes_(d.PayloadWireLength);
        WithoutHeadersDetail.Text = $"{d.PayloadLength.ToString("N0", CultureInfo.CurrentCulture)} payload bytes captured";
        HeadersValue.Text = Bytes_(d.HeaderLength + d.TrailerLength);
        HeadersDetail.Text = string.Join(" + ", d.HeaderParts.Select(p => $"{p.Name} {p.Length}")) + (d.TrailerLength > 0 ? $" + trailer {d.TrailerLength}" : "");
        HeadersDetail.ToolTip = HeadersDetail.Text;
        TruncatedText.Visibility = packet.RawBytes.Length < packet.Length ? Visibility.Visible : Visibility.Collapsed;

        RebuildNativeTree();
        StartAnalysis();
        CommandManager.InvalidateRequerySuggested();
        PacketShown?.Invoke(session, index);
    }

    /// <summary>The packet's place in its session and, when it shares a timeline chunk with neighbors, in that chunk.</summary>
    public void UpdatePosition()
    {
        if (session is null || Current is not { } packet) return;
        static string N(int value) => value.ToString("N0", CultureInfo.CurrentCulture);
        var text = $"Packet #{packet.Id} · {N(index + 1)} of {N(session.Packets.Count)} in session";
        if (ChunkOf?.Invoke(session, index) is { Count: > 1 } chunk)
            text += $" · {N(index - chunk.Start + 1)} of {N(chunk.Count)} in chunk";
        PositionText.Text = text;
    }

    // MARK: Wireshark analysis

    private async void StartAnalysis()
    {
        analysis?.Cancel();
        analysis = null;
        wireshark = null;
        wiresharkItems = new();
        WiresharkTree.ItemsSource = null;
        wiresharkSelection = null;
        sourceIndex = 0;
        error = null;
        if (UseWireshark.IsChecked != true || capture is null || Current is not { } packet)
        {
            loading = false;
            UpdateAll();
            return;
        }
        selectedPath = null;
        loading = true;
        UpdateAll();
        var token = new CancellationTokenSource();
        analysis = token;
        try
        {
            var result = await WiresharkInspection.InspectAsync(packet, capture, keyLog, token.Token);
            if (token.IsCancellationRequested) return;
            wireshark = result;
            wiresharkItems = result.Fields.Select(f => new WiresharkItem(f, null)).ToList();
            foreach (var item in wiresharkItems) item.IsExpanded = true;
            WiresharkTree.ItemsSource = wiresharkItems;
        }
        catch (OperationCanceledException) { return; }
        catch (Exception failure) when (failure is CaptureException or IOException or System.ComponentModel.Win32Exception or System.Text.Json.JsonException or FormatException)
        {
            if (token.IsCancellationRequested) return;
            error = failure.Message;
        }
        loading = false;
        UpdateAll();
    }

    private IEnumerable<WiresharkField> AllWiresharkFields()
    {
        IEnumerable<WiresharkField> Flatten(IEnumerable<WiresharkField> fields) => fields.SelectMany(f => Flatten(f.Children).Prepend(f));
        return wireshark is null ? Enumerable.Empty<WiresharkField>() : Flatten(wireshark.Fields);
    }

    /// <summary>The most specific field covering a byte of the active source; later/deeper nodes win ties.</summary>
    private WiresharkField? WiresharkFieldAt(int offset)
    {
        WiresharkField? best = null;
        foreach (var field in AllWiresharkFields())
        {
            if (field.SourceIndex != sourceIndex || !field.HasRange || offset < field.Start || offset >= field.Start + field.Length) continue;
            if (best is null || field.Length <= best.Length) best = field;
        }
        return best;
    }

    private void SelectWiresharkField(WiresharkField field)
    {
        customRange = null;
        wiresharkSelection = field;
        if (field.HasRange && native is { } d)
        {
            if (field.SourceIndex == 0)
            {
                sourceIndex = 0;
                if (field.Start < d.PayloadOffset || field.Start + field.Length > d.PayloadOffset + d.PayloadLength) IncludeHeaders.IsChecked = true;
            }
            else if (wireshark is { } w && field.SourceIndex - 1 < w.AdditionalSources.Count) sourceIndex = field.SourceIndex;
        }
        var item = wiresharkItems.SelectMany(i => i.Descendants()).FirstOrDefault(i => ReferenceEquals(i.Field, field));
        if (item is not null)
        {
            for (var parent = item.Parent; parent is not null; parent = parent.Parent) parent.IsExpanded = true;
            item.IsSelected = true;
        }
        UpdateSources();
        UpdateBytes();
        UpdateStatus();
    }

    // MARK: Built-in analyzer tree

    private void RebuildNativeTree()
    {
        if (native is null) return;
        rebuilding = true;
        items.Clear();
        var roots = native.Layers.Where(l => HeadersIncluded || l.Kind == LayerKind.Payload).Select(l => new FieldItem(l, null, this)).ToList();
        foreach (var item in roots.SelectMany(r => r.Descendants()))
        {
            items[item.Field] = item;
            if (expandedPaths.Contains(item.Field.Path)) item.IsExpanded = true;
        }
        FieldTree.ItemsSource = roots;
        rebuilding = false;
        var reselect = selectedPath is null ? null : items.Values.FirstOrDefault(i => i.Field.Path == selectedPath && i.Field.HasBytes);
        if (reselect is not null) SelectNative(reselect); else selectedPath = null;
    }

    internal void RememberExpansion(FieldItem item, bool expanded)
    {
        if (rebuilding) return;
        if (expanded) expandedPaths.Add(item.Field.Path); else expandedPaths.Remove(item.Field.Path);
    }

    private PacketField? NativeSelection =>
        selectedPath is null ? null : items.Keys.FirstOrDefault(f => f.Path == selectedPath && (HeadersIncluded || f.Kind == LayerKind.Payload));

    private void SelectNative(FieldItem item)
    {
        customRange = null;
        for (var parent = item.Parent; parent is not null; parent = parent.Parent) parent.IsExpanded = true;
        item.IsSelected = true;
        selectedPath = item.Field.Path;
        UpdateSelectionHighlight();
        UpdateStatus();
    }

    // MARK: Views

    private void UpdateAll()
    {
        var wiresharkMode = WiresharkMode;
        DetailsTitle.Text = UseWireshark.IsChecked == true ? "Packet details · Wireshark" : "Packet details · Built-in analyzer";
        WiresharkTree.Visibility = wiresharkMode ? Visibility.Visible : Visibility.Collapsed;
        FieldTree.Visibility = wiresharkMode ? Visibility.Collapsed : Visibility.Visible;
        AnalyzingPanel.Visibility = loading ? Visibility.Visible : Visibility.Collapsed;
        ErrorText.Text = error ?? "";
        ErrorText.Visibility = error is null ? Visibility.Collapsed : Visibility.Visible;
        KeyLogName.Text = keyLog is null ? "" : Path.GetFileName(keyLog);
        ClearKeysButton.Visibility = keyLog is null ? Visibility.Collapsed : Visibility.Visible;
        UpdateSources();
        UpdateBytes();
        UpdateStatus();
    }

    private void UpdateSources()
    {
        updatingSources = true;
        var names = new List<string> { HeadersIncluded ? "Captured frame" : "Captured transport payload" };
        if (wireshark is not null) names.AddRange(wireshark.AdditionalSources.Select(s => s.Name));
        SourcePicker.ItemsSource = names;
        SourcePicker.SelectedIndex = Math.Min(sourceIndex, names.Count - 1);
        updatingSources = false;
        SourceCaption.Text = Source is { } source
            ? $"Wireshark data source · {source.Bytes.Length.ToString("N0", CultureInfo.CurrentCulture)} bytes · already reassembled/decrypted where applicable; header toggle applies to the captured frame."
            : "Reassembled/decrypted sources appear here when Wireshark produces them for this frame. Some segments reference a later reassembly frame in Packet details.";
    }

    private void UpdateBytes()
    {
        customRange = null;
        if (Current is not { } packet || native is not { } d) return;
        int payloadStart = d.PayloadOffset, payloadEnd = d.PayloadOffset + d.PayloadLength;
        if (Source is { } source) Bytes.SetData(source.Bytes, 0, source.Bytes.Length, 0, source.Bytes.Length);
        else if (HeadersIncluded) Bytes.SetData(packet.RawBytes, 0, packet.RawBytes.Length, payloadStart, payloadEnd);
        else Bytes.SetData(packet.RawBytes, payloadStart, d.PayloadLength, payloadStart, payloadEnd);
        NoPayload.Visibility = Source is null && !HeadersIncluded && d.PayloadLength == 0 ? Visibility.Visible : Visibility.Collapsed;
        UpdateSelectionHighlight();
    }

    private void UpdateSelectionHighlight()
    {
        if (customRange is { } range) Bytes.SetSelection(range.Start, range.Length, scroll: false);
        else if (WiresharkMode)
        {
            if (wiresharkSelection is { HasRange: true } field && field.SourceIndex == sourceIndex) Bytes.SetSelection(field.Start, field.Length);
            else Bytes.SetSelection(-1, 0);
        }
        else if (NativeSelection is { HasBytes: true } field) Bytes.SetSelection(field.Offset, field.Length);
        else Bytes.SetSelection(-1, 0);
    }

    private void UpdateStatus()
    {
        if (customRange is { } range)
        {
            FieldPath.Text = "Selected bytes";
            FieldDetail.Text = $"{(Source is null ? "Frame" : "Source")} bytes {range.Start}–{range.Start + range.Length - 1} · {Bytes_(range.Length)} · " +
                               "Ctrl+C copies as hex; right-click for other formats";
        }
        else if (WiresharkMode)
        {
            FieldPath.Text = wiresharkSelection?.Label ?? Prompt;
            FieldDetail.Text = wiresharkSelection is { HasRange: true } field && field.SourceIndex == sourceIndex
                ? $"Source bytes {field.Start}–{field.Start + field.Length - 1} · {Bytes_(field.Length)}"
                : "Generated fields have no selectable bytes.";
        }
        else if (NativeSelection is { } field)
        {
            FieldPath.Text = field.Path;
            FieldDetail.Text = $"{field.Label} · {RangeText(field)}";
        }
        else
        {
            FieldPath.Text = Prompt;
            FieldDetail.Text = "Hover over bytes for a description. Header bytes are shaded gray.";
        }
        FieldPath.ToolTip = FieldPath.Text;
        FieldDetail.ToolTip = FieldDetail.Text;
    }

    private string RangeText(PacketField field)
    {
        if (!field.HasBytes) return "Generated information; no frame bytes";
        var last = field.Offset + field.Length - 1;
        var text = $"Frame bytes {field.Offset}–{last} (0x{field.Offset:x}) · {Bytes_(field.Length)}";
        if (native is { } d && field.Offset >= d.PayloadOffset && field.Offset < d.PayloadOffset + d.PayloadLength)
            text += $" · payload bytes {field.Offset - d.PayloadOffset}–{last - d.PayloadOffset}";
        else if (field.Kind == LayerKind.Header) text += " · header";
        return text;
    }

    private string? Describe(int offset)
    {
        if (WiresharkMode) return WiresharkFieldAt(offset)?.Label ?? $"Source byte {offset}";
        return native?.FieldAt(offset)?.Label ?? $"Frame byte {offset}";
    }

    // MARK: Event handlers

    private void OnByteClicked(int offset)
    {
        if (WiresharkMode)
        {
            if (WiresharkFieldAt(offset) is { } field) SelectWiresharkField(field);
            return;
        }
        if (native?.FieldAt(offset) is { } nativeField && items.TryGetValue(nativeField, out var item)) SelectNative(item);
    }

    private void OnTreeSelectionChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (rebuilding || e.NewValue is not FieldItem item) return;
        customRange = null;
        selectedPath = item.Field.Path;
        UpdateSelectionHighlight();
        UpdateStatus();
    }

    private void OnWiresharkSelectionChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is WiresharkItem item && !ReferenceEquals(item.Field, wiresharkSelection)) SelectWiresharkField(item.Field);
    }

    private void OnTreeItemSelected(object sender, RoutedEventArgs e)
    {
        if (sender is TreeViewItem container && ReferenceEquals(e.OriginalSource, container)) container.BringIntoView();
    }

    private void OnIncludeHeadersChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        RebuildNativeTree();
        UpdateSources();
        UpdateBytes();
        UpdateStatus();
    }

    private void OnSourceChanged(object sender, SelectionChangedEventArgs e)
    {
        if (updatingSources || SourcePicker.SelectedIndex < 0 || SourcePicker.SelectedIndex == sourceIndex) return;
        sourceIndex = SourcePicker.SelectedIndex;
        if (wiresharkSelection is not null && wiresharkSelection.SourceIndex != sourceIndex) wiresharkSelection = null;
        foreach (var item in wiresharkItems.SelectMany(i => i.Descendants()))
            if (item.Field.SourceIndex == sourceIndex && item.Children.Count > 0) item.IsExpanded = true;
        UpdateSources();
        UpdateBytes();
        UpdateStatus();
    }

    private void OnAsciiOnlyChanged(object sender, RoutedEventArgs e) => Bytes.TextOnly = AsciiOnly.IsChecked == true;

    private void OnUseWiresharkChanged(object sender, RoutedEventArgs e)
    {
        if (IsLoaded) StartAnalysis();
    }

    private void OnChooseKeys(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose TLS key log",
            Filter = "Key log files (*.log;*.txt;*.keys)|*.log;*.txt;*.keys|All files (*.*)|*.*",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) != true) return;
        keyLog = dialog.FileName;
        if (UseWireshark.IsChecked == true) StartAnalysis(); else UseWireshark.IsChecked = true;
    }

    private void OnClearKeys(object sender, RoutedEventArgs e)
    {
        keyLog = null;
        StartAnalysis();
    }

    // MARK: Copying fields

    /// <summary>The selected tree node's label and bytes, from whichever tree is showing.</summary>
    private (string Label, byte[]? Bytes)? SelectedFieldForCopy(TreeView tree)
    {
        if (Current is not { } packet) return null;
        if (tree == FieldTree && FieldTree.SelectedItem is FieldItem native)
            return (native.Label, native.Field.HasBytes && native.Field.Offset + native.Field.Length <= packet.RawBytes.Length
                ? packet.RawBytes[native.Field.Offset..(native.Field.Offset + native.Field.Length)] : null);
        if (tree == WiresharkTree && WiresharkTree.SelectedItem is WiresharkItem { Field: var field } && wireshark is { } w)
        {
            var source = field.SourceIndex == 0 ? packet.RawBytes : field.SourceIndex <= w.AdditionalSources.Count ? w.AdditionalSources[field.SourceIndex - 1].Bytes : null;
            return (field.Label, field.HasRange && source is not null && field.Start + field.Length <= source.Length ? source[field.Start..(field.Start + field.Length)] : null);
        }
        return null;
    }

    /// <summary>"Name: value" labels copy their value; bit fields ("..1. = Flag: Set") copy the text after the flag name.</summary>
    private static string ValueOf(string label)
    {
        var separator = label.IndexOf(": ", StringComparison.Ordinal);
        return separator >= 0 ? label[(separator + 2)..] : label;
    }

    private static void CopyText(string text)
    {
        if (text.Length > 0) Clipboard.SetText(text);
    }

    /// <summary>Right-click selects the node under the pointer (not its ancestors) before the menu opens.</summary>
    private void OnTreeItemRightClick(object sender, MouseButtonEventArgs e)
    {
        var element = e.OriginalSource as DependencyObject;
        while (element is not null and not TreeViewItem) element = System.Windows.Media.VisualTreeHelper.GetParent(element);
        if (ReferenceEquals(element, sender)) ((TreeViewItem)sender).IsSelected = true;
    }

    private void OnTreeContextMenu(object sender, ContextMenuEventArgs e)
    {
        var tree = (TreeView)sender;
        if (tree.ContextMenu is not { } menu || SelectedFieldForCopy(tree) is not { } selected) { e.Handled = true; return; }
        menu.Items.Clear();
        void Add(string header, Func<string> text, bool enabled = true, string gesture = "")
        {
            var item = new MenuItem { Header = header, IsEnabled = enabled, InputGestureText = gesture };
            item.Click += (_, _) => CopyText(text());
            menu.Items.Add(item);
        }
        Add("Copy", () => selected.Label, gesture: "Ctrl+C");
        Add("Copy value", () => ValueOf(selected.Label));
        menu.Items.Add(new Separator());
        var bytes = selected.Bytes ?? Array.Empty<byte>();
        Add("Copy bytes as hex", () => ByteFormat.Hex(bytes, spaced: true), bytes.Length > 0);
        Add("Copy bytes as hex stream", () => ByteFormat.Hex(bytes, spaced: false), bytes.Length > 0);
        Add("Copy bytes as text", () => ByteFormat.Text(bytes), bytes.Length > 0);
    }

    /// <summary>Handled in preview so the trees and byte pane cannot swallow the navigation keys.</summary>
    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        var key = e.Key == Key.System ? e.SystemKey : e.Key;
        var modifiers = Keyboard.Modifiers;
        if (key == Key.F1 && modifiers == ModifierKeys.None)
        {
            HelpWindow.Open(Owner ?? this, "SecPacket");
            e.Handled = true;
            return;
        }
        if (key == Key.C && modifiers == ModifierKeys.Control && (FieldTree.IsKeyboardFocusWithin || WiresharkTree.IsKeyboardFocusWithin))
        {
            if (SelectedFieldForCopy(FieldTree.IsKeyboardFocusWithin ? FieldTree : WiresharkTree) is { } selected) CopyText(selected.Label);
            e.Handled = true;
            return;
        }
        var previous = (key == Key.Left && modifiers is ModifierKeys.Alt or ModifierKeys.Control) || (key == Key.PageUp && modifiers == ModifierKeys.None);
        var next = (key == Key.Right && modifiers is ModifierKeys.Alt or ModifierKeys.Control) || (key == Key.PageDown && modifiers == ModifierKeys.None);
        if (previous || next)
        {
            Navigate(previous ? -1 : 1);
            e.Handled = true;
        }
        base.OnPreviewKeyDown(e);
    }

    private void Navigate(int delta)
    {
        if (session is null) return;
        var target = index + delta;
        if (target < 0 || target >= session.Packets.Count) return;
        index = target;
        Render();
    }

    private void CanPrevious(object sender, CanExecuteRoutedEventArgs e) => e.CanExecute = session is not null && index > 0;
    private void CanNext(object sender, CanExecuteRoutedEventArgs e) => e.CanExecute = session is not null && index < session.Packets.Count - 1;
    private void OnPrevious(object sender, ExecutedRoutedEventArgs e) => Navigate(-1);
    private void OnNext(object sender, ExecutedRoutedEventArgs e) => Navigate(1);
}
