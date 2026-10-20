using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using CaptureCore;
using Microsoft.Win32;

namespace Schwabber;

public partial class MainWindow : Window
{
    public static readonly RoutedUICommand OpenCommand = new("Open capture…", "Open", typeof(MainWindow));
    public static readonly RoutedUICommand SaveCommand = new("Save PCAP…", "Save", typeof(MainWindow));
    public static readonly RoutedUICommand HelpCommand = new("Schwabber Help", "Help", typeof(MainWindow));

    public static readonly DependencyProperty TimelineWidthProperty = Register(nameof(TimelineWidth), 400.0);
    public static readonly DependencyProperty CaptureStartProperty = Register(nameof(CaptureStart), 0.0);
    public static readonly DependencyProperty DurationProperty = Register(nameof(Duration), 1.0);
    public static readonly DependencyProperty HorizontalScrollProperty = Register(nameof(HorizontalScroll), 0.0);
    public static readonly DependencyProperty SessionColumnWidthProperty = Register(nameof(SessionColumnWidth), DefaultColumnWidth);
    public static readonly DependencyProperty HighlightedPacketIdProperty =
        DependencyProperty.Register(nameof(HighlightedPacketId), typeof(int), typeof(MainWindow), new PropertyMetadata(-1));
    /// <summary>The packet open in the packet viewer, marked on the timeline; -1 when the viewer is closed.</summary>
    public int HighlightedPacketId { get => (int)GetValue(HighlightedPacketIdProperty); set => SetValue(HighlightedPacketIdProperty, value); }
    public static readonly DependencyProperty EndpointsVisibilityProperty =
        DependencyProperty.Register(nameof(EndpointsVisibility), typeof(Visibility), typeof(MainWindow), new PropertyMetadata(Visibility.Visible));
    public static readonly DependencyProperty RowHeightProperty = Register(nameof(RowHeight), FullRowHeight);
    /// <summary>Session row height: two lines with endpoints, one compact line without.</summary>
    public double RowHeight { get => (double)GetValue(RowHeightProperty); set => SetValue(RowHeightProperty, value); }
    private const double FullRowHeight = 36, CompactRowHeight = 23;
    /// <summary>View → Show endpoints: the address:port line under each session label.</summary>
    public Visibility EndpointsVisibility { get => (Visibility)GetValue(EndpointsVisibilityProperty); set => SetValue(EndpointsVisibilityProperty, value); }
    private static DependencyProperty Register(string name, double value) =>
        DependencyProperty.Register(name, typeof(double), typeof(MainWindow), new PropertyMetadata(value));

    public double TimelineWidth { get => (double)GetValue(TimelineWidthProperty); set => SetValue(TimelineWidthProperty, value); }
    public double CaptureStart { get => (double)GetValue(CaptureStartProperty); set => SetValue(CaptureStartProperty, value); }
    public double Duration { get => (double)GetValue(DurationProperty); set => SetValue(DurationProperty, value); }
    /// <summary>Horizontal offset of the session list; the left column is shifted by it to stay pinned.</summary>
    public double HorizontalScroll { get => (double)GetValue(HorizontalScrollProperty); set => SetValue(HorizontalScrollProperty, value); }
    /// <summary>Width of the pinned session column, adjustable by dragging its handle (220 px to the timeline's minimum).</summary>
    public double SessionColumnWidth { get => (double)GetValue(SessionColumnWidthProperty); set => SetValue(SessionColumnWidthProperty, value); }

    private const double DefaultColumnWidth = 370;
    private const double DefaultInspectorHeight = 260;
    private static readonly string[] Protocols = { "TCP", "UDP", "ICMP", "ICMPv6", "DNS", "RTP", "RTCP", "SIP", "DTLS", "TURN", "STUN", "HTTP", "HTTP/2", "TLS", "QUIC" };

    private Capture? capture;
    private string filename = "";
    private int? selected;
    private readonly HashSet<int> selectedIds = new();
    private bool exporting;
    private bool loading;
    private string query = "";
    private HashSet<string> enabledProtocols = new() { "All" };
    private bool largestFirst;
    private Dictionary<int, SessionItem> items = new();
    private List<SessionItem> shown = new();
    private Session? inspected;
    private double inspectorHeight = DefaultInspectorHeight;
    private bool? expandedWindow;

    public MainWindow()
    {
        InitializeComponent();
        foreach (var name in Protocols)
        {
            var box = new CheckBox { Content = name, Tag = name, Margin = new Thickness(0, 0, 0, 10) };
            box.Click += OnProtocolToggle;
            ProtocolGrid.Children.Add(box);
        }
        SourceInitialized += (_, _) =>
        {
            ThemeManager.ApplyTitleBar(this);
            // Touchpad two-finger sideways swipes (and tilt wheels) arrive as WM_MOUSEHWHEEL, which WPF does not route.
            System.Windows.Interop.HwndSource.FromHwnd(new System.Windows.Interop.WindowInteropHelper(this).Handle)?.AddHook(OnWindowMessage);
        };
        var showEndpoints = AppSettings.GetBool("showEndpoints", true);
        ShowEndpointsMenuItem.IsChecked = showEndpoints;
        SetShowEndpoints(showEndpoints);
        ThemeManager.Changed += OnThemeApplied;
        Closed += (_, _) => ThemeManager.Changed -= OnThemeApplied;
        Closing += OnClosing;
        Loaded += (_, _) =>
        {
            RefreshInterfaces(showErrors: false);
            // Windows "Open with" and drag-onto-exe pass the capture path as the first argument.
            var arguments = Environment.GetCommandLineArgs();
            if (arguments.Length > 1 && File.Exists(arguments[1])) Open(arguments[1]);
        };
        UpdateHeader();
    }

    // MARK: Derived state

    private static string SizeDescription(long bytes) =>
        $"{bytes.ToString("N0", CultureInfo.CurrentCulture)} bytes ({(bytes / 1000.0).ToString("F2", CultureInfo.InvariantCulture)} kB)";

    private Session? Selection => selected is { } id && items.TryGetValue(id, out var item) ? item.Session : null;

    private void ApplyFilter(bool resetScroll = true)
    {
        if (capture is null) { shown = new(); SessionList.ItemsSource = null; return; }
        var filter = new SessionFilter(query);
        InvalidHexText.Visibility = filter.InvalidHex ? Visibility.Visible : Visibility.Collapsed;
        var all = enabledProtocols.Contains("All");
        var filtered = capture.Sessions.Where(s =>
            (all || enabledProtocols.Contains(s.Transport) || s.ApplicationProtocols.Any(enabledProtocols.Contains)) && filter.Matches(s));
        filtered = largestFirst
            ? filtered.OrderByDescending(s => s.Bytes).ThenBy(s => s.Start).ThenBy(s => s.Id)
            : filtered.OrderBy(s => s.Start).ThenBy(s => s.Id);
        shown = filtered.Select(s => items[s.Id]).ToList();
        SessionList.ItemsSource = shown;
        NoMatches.Visibility = shown.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        UpdateCounts();
        // Filtering resets scrolling to the top, as on macOS.
        if (resetScroll) FindListScroller()?.ScrollToVerticalOffset(0);
    }

    private ScrollViewer? FindListScroller() =>
        SessionList.Template?.FindName("ListScroller", SessionList) as ScrollViewer;

    private void UpdateCounts()
    {
        ShownText.Text = $"{shown.Count} shown · {selectedIds.Count} selected";
        var bytes = selectedIds.Sum(id => items.TryGetValue(id, out var item) ? item.Session.Bytes : 0);
        ShownText.ToolTip = $"Selected sessions total {SizeDescription(bytes)}, including selections hidden by filters.";
    }

    private void UpdateSelection()
    {
        foreach (var item in items.Values) item.IsChecked = selectedIds.Contains(item.Session.Id);
        UpdateCounts();
        UpdateInspector();
    }

    private void UpdateInspector(bool force = false)
    {
        var selection = Selection;
        if (selection is null || capture is null)
        {
            if (InspectorRow.Height.IsAbsolute && Inspector.Visibility == Visibility.Visible) inspectorHeight = InspectorRow.Height.Value;
            inspected = null;
            PacketGrid.ItemsSource = null;
            HintBar.Visibility = Visibility.Visible;
            Inspector.Visibility = Visibility.Collapsed;
            InspectorSplitter.Visibility = Visibility.Collapsed;
            SplitterRow.Height = new GridLength(0);
            InspectorRow.Height = GridLength.Auto;
            InspectorRow.MinHeight = 0;
            return;
        }
        HintBar.Visibility = Visibility.Collapsed;
        Inspector.Visibility = Visibility.Visible;
        InspectorSplitter.Visibility = Visibility.Visible;
        SplitterRow.Height = new GridLength(5);
        InspectorRow.MinHeight = 190;
        if (!InspectorRow.Height.IsAbsolute) InspectorRow.Height = new GridLength(inspectorHeight);
        // Live snapshots replace session objects; only re-render when the selected session actually changed.
        if (!force && inspected is { } prior && prior.Id == selection.Id && prior.Packets.Count == selection.Packets.Count)
        {
            inspected = selection;
            return;
        }
        inspected = selection;
        InspectorTitle.Text = $"{selection.ProtocolLabel} · {selection.EndpointA} ↔ {selection.EndpointB}";
        InspectorTitle.ToolTip = InspectorTitle.Text;
        InspectorDuration.Text = (selection.End - selection.Start).ToString("F6", CultureInfo.InvariantCulture) + " s";
        InspectorSize.Text = $"Session size: {SizeDescription(selection.Bytes)} · {selection.Packets.Count.ToString("N0", CultureInfo.CurrentCulture)} packets";
        InspectorSummary.Text = selection.Summary;
        InspectorSummary.ToolTip = selection.Summary.Length == 0 ? null : selection.Summary;
        InspectorSummary.Visibility = selection.Summary.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
        var start = capture.Start;
        syncingGrid = true;
        var packets = selection.Packets;
        PacketGrid.ItemsSource = packets.Select((p, i) => new PacketRow(p, i, start, i > 0 ? packets[i - 1] : null)).ToList();
        if (PacketGrid.Items.Count > 0) PacketGrid.ScrollIntoView(PacketGrid.Items[0]);
        syncingGrid = false;
    }

    private void UpdateTimelineWidth()
    {
        var area = TimelineArea.ActualWidth;
        if (area <= 0) return;
        var column = Math.Min(SessionColumnWidth, Math.Max(220, area - 260));
        if (column != SessionColumnWidth) SessionColumnWidth = column;
        ColumnThumb.Margin = new Thickness(16 + column, 0, 0, 0);
        Pins.LeftEdge = 16 + column + 12;
        // Windows scrollbars take layout space, unlike macOS overlay scrollbars, so leave room for one.
        TimelineWidth = Math.Max(200, area - 32 - column - 12 - SystemParameters.VerticalScrollBarWidth) * ZoomFactor;
        // Chunks depend on the zoom, so the inspector's "of N in chunk" follows it.
        packetWindow?.UpdatePosition();
    }

    private void UpdateHeader()
    {
        var hasFile = filename.Length > 0;
        Wordmark.Visibility = hasFile ? Visibility.Collapsed : Visibility.Visible;
        FileHeader.Visibility = hasFile ? Visibility.Visible : Visibility.Collapsed;
        HeaderBar.MinHeight = hasFile ? 0 : 65;
        TitleText.Text = filename;
        TitleText.ToolTip = filename;
        CountsText.Text = capture is null ? "" : $"{capture.TotalPackets} packets · {capture.Sessions.Count} sessions";
        Title = hasFile ? $"{filename} — Schwabber" : "Schwabber";
        LoadingIndicator.Visibility = loading || exporting ? Visibility.Visible : Visibility.Collapsed;
        var running = liveCapture is not null;
        RecordingStatus.Visibility = StopButton.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
        RecordingStatus.Text = $"Recording · {dropped} dropped";
        StopButton.IsEnabled = running && !stopping;
        CaptureInterfacePicker.IsEnabled = !running;
        RecordButton.IsEnabled = !running && !loading && CaptureInterfacePicker.SelectedItem is CaptureInterface;
        CommandManager.InvalidateRequerySuggested();
    }

    /// <summary>Like the Mac app: a compact window until a capture or recording needs room, then 1300 × 850 within the screen.</summary>
    private void ApplyWindowSize(bool expanded)
    {
        if (expandedWindow == expanded) return;
        expandedWindow = expanded;
        MinWidth = expanded ? 1000 : 560;
        MinHeight = expanded ? 650 : 420;
        if (WindowState != WindowState.Normal) return;
        var area = SystemParameters.WorkArea;
        Width = Math.Min(expanded ? 1300 : 600, area.Width);
        Height = Math.Min(expanded ? 850 : 420, area.Height);
        Left = Math.Min(Math.Max(Left, area.Left), area.Right - Width);
        Top = Math.Min(Math.Max(Top, area.Top), area.Bottom - Height);
    }

    private void SetExportStatus(string? status)
    {
        ExportStatusText.Text = status ?? "";
        ExportStatusText.ToolTip = status;
        ExportStatusText.Visibility = status is null ? Visibility.Collapsed : Visibility.Visible;
    }

    private void ShowFailure(string message) =>
        MessageBox.Show(this, message, "Unable to complete action", MessageBoxButton.OK, MessageBoxImage.Warning);

    // MARK: Filters, sorting, zoom

    private void OnQueryChanged(object sender, TextChangedEventArgs e)
    {
        query = QueryBox.Text;
        QueryPlaceholder.Visibility = query.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        ApplyFilter();
    }

    private void OnProtocolsClick(object sender, RoutedEventArgs e)
    {
        SyncProtocolBoxes();
        ProtocolsPopup.IsOpen = !ProtocolsPopup.IsOpen;
    }

    private void SyncProtocolBoxes()
    {
        var all = enabledProtocols.Contains("All");
        AllProtocols.IsChecked = all;
        foreach (CheckBox box in ProtocolGrid.Children) box.IsChecked = all || enabledProtocols.Contains((string)box.Tag);
        ProtocolsLabel.Text = all ? "Protocols: All" : $"Protocols: {enabledProtocols.Count}";
    }

    private void SetProtocols(HashSet<string> value)
    {
        enabledProtocols = value;
        SyncProtocolBoxes();
        ApplyFilter();
    }

    private void OnAllProtocolsClick(object sender, RoutedEventArgs e) =>
        SetProtocols(AllProtocols.IsChecked == true ? new HashSet<string> { "All" } : new HashSet<string>());

    /// <summary>Individual protocols combine with OR; checking every box collapses back to All.</summary>
    private void OnProtocolToggle(object sender, RoutedEventArgs e)
    {
        var box = (CheckBox)sender;
        var name = (string)box.Tag;
        var next = enabledProtocols.Contains("All") ? new HashSet<string>(Protocols) : new HashSet<string>(enabledProtocols);
        if (box.IsChecked == true) next.Add(name); else next.Remove(name);
        if (next.SetEquals(Protocols)) next = new HashSet<string> { "All" };
        SetProtocols(next);
    }

    private void OnProtocolsClear(object sender, RoutedEventArgs e) => SetProtocols(new HashSet<string>());
    private void OnProtocolsDone(object sender, RoutedEventArgs e) => ProtocolsPopup.IsOpen = false;

    private void OnSortChanged(object sender, SelectionChangedEventArgs e)
    {
        largestFirst = SortPicker.SelectedIndex == 1;
        if (IsLoaded) ApplyFilter();
    }

    /// <summary>Maximum zoom puts two seconds across the visible timeline; at least 1× for short captures.</summary>
    private double MaximumZoom => Math.Max(1, Duration / 2);
    /// <summary>The slider is logarithmic: position 0 fits the capture, 1 is the maximum zoom.</summary>
    private double ZoomFactor => Math.Pow(MaximumZoom, Math.Clamp(ZoomSlider.Value, 0, 1));

    private void OnZoomChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (IsLoaded) UpdateTimelineWidth();
    }

    private void OnTimelineAreaSizeChanged(object sender, SizeChangedEventArgs e) => UpdateTimelineWidth();

    private void OnColumnDrag(object sender, DragDeltaEventArgs e)
    {
        SessionColumnWidth = Math.Min(Math.Max(220, SessionColumnWidth + e.HorizontalChange), Math.Max(220, TimelineArea.ActualWidth - 260));
        UpdateTimelineWidth();
    }

    private void OnListScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        HeaderScroller.ScrollToHorizontalOffset(e.HorizontalOffset);
        HorizontalScroll = e.HorizontalOffset;
        // Keep pin lines off the horizontal scroll bar when it is shown.
        if (FindListScroller() is { } scroller)
            Pins.Margin = new Thickness(0, 0, 0, scroller.ComputedHorizontalScrollBarVisibility == Visibility.Visible ? 12 : 0);
    }

    // MARK: Selection

    private void OnThemeApplied()
    {
        foreach (var item in items.Values) item.RefreshTheme();
    }

    private void OnToggleClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is SessionItem item) Toggle(item.Session.Id);
        e.Handled = true;
    }

    /// <summary>A plain click on a packet tick opens that packet; anywhere else selects the session.</summary>
    private void OnRowClick(object sender, MouseButtonEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not SessionItem item) return;
        e.Handled = true;
        SessionList.Focus();
        // On the timeline, a plain click opens the packet under a tick, or pins that time on empty space (as on macOS).
        // Ctrl/Shift clicks and clicks on the session label select sessions.
        if (Keyboard.Modifiers == ModifierKeys.None && FindAncestor<TimelineBar>(e.OriginalSource as DependencyObject) is { } bar)
        {
            var position = e.GetPosition(bar);
            if (bar.ChunkAt(position) is { } chunk)
            {
                selected = item.Session.Id;
                selectedIds.Clear();
                selectedIds.Add(item.Session.Id);
                UpdateSelection();
                // A chunk of close packets opens on its first packet.
                ShowPacket(item.Session, chunk.Start, activate: true);
            }
            else AddPin(position.X / Math.Max(1, bar.ActualWidth) * Duration);
            return;
        }
        Select(item.Session.Id);
    }

    /// <summary>
    /// Up/Down move to the previous/next shown session and inspect it; Shift extends the selection; Home/End jump to the ends.
    /// Text boxes, drop-downs and the packet list handle their own arrow keys first.
    /// </summary>
    private void OnWindowKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Handled || capture is null || shown.Count == 0 || e.OriginalSource is TextBox or ComboBox or DataGrid or DataGridCell or MenuItem) return;
        var modifiers = Keyboard.Modifiers;
        if (modifiers is not (ModifierKeys.None or ModifierKeys.Shift)) return;
        var current = selected is { } id ? shown.FindIndex(i => i.Session.Id == id) : -1;
        int target;
        switch (e.Key)
        {
            case Key.Down: target = current < 0 ? 0 : Math.Min(shown.Count - 1, current + 1); break;
            case Key.Up: target = current < 0 ? shown.Count - 1 : Math.Max(0, current - 1); break;
            case Key.Home: target = 0; break;
            case Key.End: target = shown.Count - 1; break;
            default: return;
        }
        e.Handled = true;
        var next = shown[target].Session.Id;
        if (modifiers == ModifierKeys.Shift && current >= 0)
        {
            for (var index = Math.Min(current, target); index <= Math.Max(current, target); index++) selectedIds.Add(shown[index].Session.Id);
        }
        else
        {
            selectedIds.Clear();
            selectedIds.Add(next);
        }
        selected = next;
        UpdateSelection();
        ScrollSessionIntoView(target);
        SessionList.Focus();
    }

    /// <summary>Scrolls the timeline so the highlighted packet's row and tick are visible (no scrolling if they already are).</summary>
    private void RevealPacket(Session session, Packet packet)
    {
        var row = shown.FindIndex(i => i.Session.Id == session.Id);
        if (row < 0 || FindListScroller() is not { } scroller) return;
        ScrollSessionIntoView(row);
        var pinned = 16 + SessionColumnWidth + 12;
        var visible = scroller.ViewportWidth - pinned;
        var x = (packet.Time - CaptureStart) / Duration * TimelineWidth;
        if (visible > 40 && (x < scroller.HorizontalOffset + 20 || x > scroller.HorizontalOffset + visible - 20))
            scroller.ScrollToHorizontalOffset(Math.Max(0, x - visible / 2));
    }

    /// <summary>Rows are 36 px plus a 1 px divider; the list scrolls by pixels.</summary>
    private void ScrollSessionIntoView(int index)
    {
        if (FindListScroller() is not { } scroller) return;
        var rowHeight = RowHeight + 1; // plus the 1 px divider
        double top = index * rowHeight, bottom = top + rowHeight;
        if (top < scroller.VerticalOffset) scroller.ScrollToVerticalOffset(top);
        else if (bottom > scroller.VerticalOffset + scroller.ViewportHeight) scroller.ScrollToVerticalOffset(bottom - scroller.ViewportHeight);
    }

    private static T? FindAncestor<T>(DependencyObject? element) where T : DependencyObject
    {
        for (; element is not null; element = VisualTreeHelper.GetParent(element))
            if (element is T match) return match;
        return null;
    }

    private void OnSelectShown(object sender, RoutedEventArgs e)
    {
        selectedIds.Clear();
        selectedIds.UnionWith(shown.Select(i => i.Session.Id));
        selected = shown.Count > 0 ? shown[0].Session.Id : null;
        UpdateSelection();
    }

    private void OnClear(object sender, RoutedEventArgs e)
    {
        selectedIds.Clear();
        selected = null;
        UpdateSelection();
    }

    private void Toggle(int id)
    {
        if (!selectedIds.Remove(id)) selectedIds.Add(id);
        selected = selectedIds.Contains(id) ? id : selectedIds.Count > 0 ? selectedIds.Min() : null;
        UpdateSelection();
    }

    private void Select(int id)
    {
        var modifiers = Keyboard.Modifiers;
        if (modifiers.HasFlag(ModifierKeys.Control)) { Toggle(id); return; }
        var a = selected is { } anchor ? shown.FindIndex(i => i.Session.Id == anchor) : -1;
        var b = shown.FindIndex(i => i.Session.Id == id);
        if (modifiers.HasFlag(ModifierKeys.Shift) && a >= 0 && b >= 0)
        {
            for (var index = Math.Min(a, b); index <= Math.Max(a, b); index++) selectedIds.Add(shown[index].Session.Id);
        }
        else
        {
            selectedIds.Clear();
            selectedIds.Add(id);
        }
        selected = id;
        UpdateSelection();
    }

    // MARK: Session context menu

    private void OnRowContextMenu(object sender, ContextMenuEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: SessionItem item, ContextMenu: { } menu } || capture is null) return;
        var session = item.Session;
        menu.Items.Clear();
        MenuItem Add(string header, Action action, bool enabled = true, string? tip = null)
        {
            var entry = new MenuItem { Header = header, IsEnabled = enabled, ToolTip = tip };
            entry.Click += (_, _) => action();
            menu.Items.Add(entry);
            return entry;
        }
        var ids = new HashSet<int> { session.Id };
        if (session.Transport == "TCP") Add("Reassemble TCP stream…", () => TcpStreamWindow.Open(session, capture.LinkType, this));
        Add("Inspect session", () => { selected = session.Id; UpdateSelection(); });
        Add("Copy 5-tuple", () => Clipboard.SetText(FiveTuple(session)), tip:
            "Source IP, source port, destination IP, destination port, transport protocol; direction follows the first packet. ICMP ports are N/A.");
        Add("Open session in Wireshark", () => OpenInWireshark(ids), !exporting);
        Add("Export session…", () => ExportSessions(ids), !exporting);
        menu.Items.Add(new Separator());
        Add(selectedIds.Contains(session.Id) ? "Remove from selection" : "Add to selection", () => Toggle(session.Id));
        if (selectedIds.Count > 1 && selectedIds.Contains(session.Id))
        {
            Add("Open selected sessions in Wireshark", () => OpenInWireshark(new HashSet<int>(selectedIds)), !exporting);
            Add("Export selected sessions…", () => ExportSessions(new HashSet<int>(selectedIds)), !exporting);
        }
    }

    private static string FiveTuple(Session session)
    {
        (string Address, string Port) Endpoint(string value)
        {
            var separator = value.LastIndexOf(':');
            if (session.Transport is not ("TCP" or "UDP") || separator < 0) return (value.Trim('[', ']'), "N/A");
            return (value[..separator].Trim('[', ']'), value[(separator + 1)..]);
        }
        var (sourceAddress, sourcePort) = Endpoint(session.EndpointA);
        var (destinationAddress, destinationPort) = Endpoint(session.EndpointB);
        return $"({sourceAddress}, {sourcePort}, {destinationAddress}, {destinationPort}, {session.Transport})";
    }

    // MARK: Menu bar

    private void OnMenuOpened(object sender, RoutedEventArgs e)
    {
        ExportMenuItem.IsEnabled = WiresharkMenuItem.IsEnabled = selectedIds.Count > 0 && !exporting;
        var running = liveCapture is not null;
        InterfaceMenu.Items.Clear();
        foreach (var device in interfaces)
        {
            var entry = new MenuItem { Header = device.Label, IsCheckable = false, IsChecked = device.Id == (CaptureInterfacePicker.SelectedItem as CaptureInterface)?.Id };
            entry.Click += (_, _) => CaptureInterfacePicker.SelectedItem = device;
            InterfaceMenu.Items.Add(entry);
        }
        InterfaceMenu.IsEnabled = !running && interfaces.Count > 0;
        RefreshMenuItem.IsEnabled = !running;
        StartMenuItem.IsEnabled = !running && !loading && CaptureInterfacePicker.SelectedItem is CaptureInterface;
        StopMenuItem.IsEnabled = running;
        ThemeSystem.IsChecked = ThemeManager.Mode == ThemeMode.System;
        ThemeLight.IsChecked = ThemeManager.Mode == ThemeMode.Light;
        ThemeDark.IsChecked = ThemeManager.Mode == ThemeMode.Dark;
        ClearPinsMenuItem.IsEnabled = pins.Count > 0;
    }

    private void OnThemeMenu(object sender, RoutedEventArgs e) =>
        ThemeManager.SetMode((ThemeMode)int.Parse((string)((FrameworkElement)sender).Tag, CultureInfo.InvariantCulture));

    private void OnExit(object sender, RoutedEventArgs e) => Close();

    // MARK: Help

    private void OnHelp(object sender, ExecutedRoutedEventArgs e) => HelpWindow.Open(this);
    private void OnShortcutsHelp(object sender, RoutedEventArgs e) => HelpWindow.Open(this, "SecKeys");

    private void OnAbout(object sender, RoutedEventArgs e)
    {
        var version = typeof(MainWindow).Assembly.GetName().Version;
        MessageBox.Show(this,
            $"Schwabber {version?.ToString(3)}\n\n" +
            "Explore the TCP, UDP and ICMP conversations in packet captures on a shared timeline, and inspect every packet down to the byte.\n\n" +
            "Captures are analysed locally and never uploaded. Press F1 for the user guide.\n\n" +
            "[schwabber] : vibecoded by dyarovyi",
            "About Schwabber", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void OnShowEndpoints(object sender, RoutedEventArgs e)
    {
        SetShowEndpoints(ShowEndpointsMenuItem.IsChecked);
        AppSettings.SetBool("showEndpoints", ShowEndpointsMenuItem.IsChecked);
    }

    /// <summary>Hiding endpoints also makes rows thinner, keeping the selected session in view.</summary>
    private void SetShowEndpoints(bool show)
    {
        EndpointsVisibility = show ? Visibility.Visible : Visibility.Collapsed;
        RowHeight = show ? FullRowHeight : CompactRowHeight;
        var index = selected is { } id ? shown.FindIndex(i => i.Session.Id == id) : -1;
        if (index >= 0) Dispatcher.BeginInvoke(() => ScrollSessionIntoView(index), System.Windows.Threading.DispatcherPriority.Loaded);
    }

    // MARK: Timeline pins

    private sealed class TimelinePin(double time)
    {
        public double Time { get; set; } = time;
        public string Note { get; set; } = "";
        public string Tooltip => $"Pin +{Time.ToString("F6", CultureInfo.InvariantCulture)} s from capture start" +
            (Note.Length == 0 ? "" : "\n" + Note);
    }

    private readonly List<TimelinePin> pins = new();
    private TimelinePin? draggedPin;
    private double dragStartX, dragStartTime;
    private bool pinDragMoved;
    private const double PinSlop = 5;

    private double RulerTime(MouseEventArgs e) =>
        Math.Clamp(e.GetPosition(Ruler).X / Math.Max(1, Ruler.ActualWidth) * Duration, 0, Duration);

    /// <summary>The pin drawn within a few pixels of the pointer on the ruler, if any.</summary>
    private TimelinePin? PinNear(MouseEventArgs e)
    {
        var x = e.GetPosition(Ruler).X;
        TimelinePin? best = null;
        foreach (var pin in pins)
        {
            var distance = Math.Abs(pin.Time / Math.Max(Duration, 1e-9) * Ruler.ActualWidth - x);
            if (distance <= PinSlop && (best is null || distance < Math.Abs(best.Time / Duration * Ruler.ActualWidth - x))) best = pin;
        }
        return best;
    }

    private void SetPins()
    {
        pins.Sort((a, b) => a.Time.CompareTo(b.Time));
        Pins.Pins = pins.Select(pin => pin.Time).ToList();
    }

    /// <summary>Adds a pin unless one is already drawn within 5 px of that time.</summary>
    private void AddPin(double time)
    {
        if (capture is null) return;
        time = Math.Clamp(time, 0, Duration);
        if (pins.Any(pin => Math.Abs(pin.Time - time) / Duration * TimelineWidth < PinSlop)) return;
        pins.Add(new TimelinePin(time));
        SetPins();
    }

    /// <summary>Clicking the ruler pins that time; clicking on an existing pin leaves it alone.</summary>
    private void OnRulerClick(object sender, MouseButtonEventArgs e)
    {
        if (draggedPin is not null)
        {
            if (pinDragMoved)
            {
                draggedPin.Time = Math.Clamp(dragStartTime + (e.GetPosition(Ruler).X - dragStartX) /
                    Math.Max(1, Ruler.ActualWidth) * Duration, 0, Duration);
                SetPins();
            }
            draggedPin = null;
            Ruler.ReleaseMouseCapture();
            e.Handled = true;
            return;
        }
        if (capture is null || PinNear(e) is not null) return;
        AddPin(RulerTime(e));
    }

    private void OnRulerMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (capture is null || PinNear(e) is not { } pin) return;
        dragStartX = e.GetPosition(Ruler).X;
        dragStartTime = pin.Time;
        pinDragMoved = false;
        if (Ruler.CaptureMouse()) draggedPin = pin;
        e.Handled = true;
    }

    private void OnRulerLostMouseCapture(object sender, MouseEventArgs e) => draggedPin = null;

    private void EditPinNote(TimelinePin pin)
    {
        var dialog = new Window
        {
            Title = "Pin note", Owner = this, Width = 420, Height = 280,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize, ShowInTaskbar = false
        };
        dialog.SetResourceReference(BackgroundProperty, "WindowBackground");
        dialog.SetResourceReference(ForegroundProperty, "PrimaryText");
        var panel = new DockPanel { Margin = new Thickness(16) };
        var label = new TextBlock { Text = $"+{pin.Time.ToString("F6", CultureInfo.InvariantCulture)} s from capture start", Margin = new Thickness(0, 0, 0, 12) };
        DockPanel.SetDock(label, Dock.Top);
        panel.Children.Add(label);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 12, 0, 0) };
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 72, Margin = new Thickness(0, 0, 8, 0) };
        var save = new Button { Content = "Save", IsDefault = true, MinWidth = 72 };
        buttons.Children.Add(cancel); buttons.Children.Add(save);
        DockPanel.SetDock(buttons, Dock.Bottom);
        panel.Children.Add(buttons);
        var editor = new TextBox { Text = pin.Note, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        System.Windows.Automation.AutomationProperties.SetName(editor, "Note");
        panel.Children.Add(editor);
        save.Click += (_, _) => { pin.Note = editor.Text; dialog.DialogResult = true; };
        dialog.Content = panel;
        dialog.Loaded += (_, _) => editor.Focus();
        dialog.ShowDialog();
        Ruler.ToolTip = pin.Tooltip;
    }

    /// <summary>Clicks below the last session row also pin a time, like the empty space in a row.</summary>
    private void OnTimelineBlankClick(object sender, MouseButtonEventArgs e)
    {
        SessionList.Focus();
        if (e.Handled || capture is null || Keyboard.Modifiers != ModifierKeys.None) return;
        var x = e.GetPosition(SessionList).X - (16 + SessionColumnWidth + 12) + HorizontalScroll;
        if (x < 0 || x > TimelineWidth) return;
        AddPin(x / Math.Max(1, TimelineWidth) * Duration);
        e.Handled = true;
    }

    private const string RulerTip = "Click to pin a time across all sessions. Drag a pin to move it; right-click to add a note or remove it.";

    /// <summary>Hovering a pin marker shows its exact time.</summary>
    private void OnRulerMouseMove(object sender, MouseEventArgs e)
    {
        if (draggedPin is { } moving && e.LeftButton == MouseButtonState.Pressed)
        {
            var delta = e.GetPosition(Ruler).X - dragStartX;
            if (pinDragMoved || Math.Abs(delta) >= SystemParameters.MinimumHorizontalDragDistance)
            {
                pinDragMoved = true;
                moving.Time = Math.Clamp(dragStartTime + delta / Math.Max(1, Ruler.ActualWidth) * Duration, 0, Duration);
                SetPins();
            }
            e.Handled = true;
        }
        var tip = (draggedPin ?? PinNear(e))?.Tooltip ?? RulerTip;
        if (!Equals(Ruler.ToolTip, tip)) Ruler.ToolTip = tip;
    }

    // MARK: Horizontal scrolling

    private const int WM_MOUSEHWHEEL = 0x020E;

    private void ScrollTimelineBy(double pixels)
    {
        if (FindListScroller() is { } scroller) scroller.ScrollToHorizontalOffset(scroller.HorizontalOffset + pixels);
    }

    /// <summary>Two-finger sideways swipes on a touchpad: positive deltas move right, about 60 px per 120 units.</summary>
    private IntPtr OnWindowMessage(IntPtr hwnd, int message, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (message == WM_MOUSEHWHEEL && capture is not null && TimelineArea.IsMouseOver)
        {
            var delta = (short)((wParam.ToInt64() >> 16) & 0xFFFF);
            ScrollTimelineBy(delta * 0.5);
            handled = true;
        }
        return IntPtr.Zero;
    }

    /// <summary>Shift + mouse wheel scrolls the timeline sideways; the plain wheel keeps scrolling sessions.</summary>
    private void OnTimelineWheel(object sender, MouseWheelEventArgs e)
    {
        if (Keyboard.Modifiers != ModifierKeys.Shift) return;
        ScrollTimelineBy(-e.Delta * 0.5);
        e.Handled = true;
    }

    private void OnRulerContextMenu(object sender, ContextMenuEventArgs e)
    {
        if (Ruler.ContextMenu is not { } menu || capture is null) { e.Handled = true; return; }
        menu.Items.Clear();
        var mouse = Mouse.PrimaryDevice;
        var args = new MouseEventArgs(mouse, Environment.TickCount);
        var near = PinNear(args);
        var time = RulerTime(args);
        MenuItem Add(string header, Action action, bool enabled = true)
        {
            var item = new MenuItem { Header = header, IsEnabled = enabled };
            item.Click += (_, _) => action();
            menu.Items.Add(item);
            return item;
        }
        if (near is { } pin)
        {
            Add(pin.Note.Length == 0 ? "Add note…" : "Edit note…", () => EditPinNote(pin));
            if (pin.Note.Length > 0) Add("Remove note", () => { pin.Note = ""; Ruler.ToolTip = pin.Tooltip; });
            Add($"Remove pin at +{pin.Time.ToString("F6", CultureInfo.InvariantCulture)} s", () => { pins.Remove(pin); SetPins(); });
        }
        else Add($"Pin +{time.ToString("F6", CultureInfo.InvariantCulture)} s", () => { pins.Add(new TimelinePin(time)); SetPins(); });
        menu.Items.Add(new Separator());
        Add("Clear all pins", ClearPins, pins.Count > 0);
    }

    private void OnClearPins(object sender, RoutedEventArgs e) => ClearPins();

    private void ClearPins()
    {
        draggedPin = null;
        Ruler.ReleaseMouseCapture();
        pins.Clear();
        SetPins();
        Ruler.ToolTip = RulerTip;
    }

    // MARK: Packet details

    private PacketWindow? packetWindow;
    private bool syncingGrid;

    private void OnPacketGridClick(object sender, MouseButtonEventArgs e)
    {
        // Only clicks on a row open the packet; header and scrollbar clicks do not.
        for (var element = e.OriginalSource as DependencyObject; element is not null; element = VisualTreeHelper.GetParent(element))
        {
            if (element is DataGridRow { Item: PacketRow row }) { if (inspected is not null) ShowPacket(inspected, row.Index, activate: true); return; }
            if (element is DataGridColumnHeader or ScrollBar) return;
        }
    }

    private void OnPacketSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // Keyboard navigation in the list follows along in an open packet window.
        if (syncingGrid || packetWindow is null || inspected is null) return;
        if (PacketGrid.SelectedItem is PacketRow row) ShowPacket(inspected, row.Index, activate: false);
    }

    private void ShowPacket(Session session, int index, bool activate)
    {
        if (capture is null || index < 0) return;
        if (packetWindow is null)
        {
            packetWindow = new PacketWindow { Owner = this, ChunkOf = ChunkOf };
            packetWindow.PacketShown += OnPacketShown;
            packetWindow.Closed += (_, _) => { packetWindow = null; HighlightedPacketId = -1; };
            packetWindow.ShowPacket(session, index, capture);
            packetWindow.Show();
            return;
        }
        packetWindow.ShowPacket(session, index, capture);
        if (packetWindow.WindowState == WindowState.Minimized) packetWindow.WindowState = WindowState.Normal;
        if (activate) packetWindow.Activate();
    }

    /// <summary>The timeline chunk holding a session's packet at the current zoom.</summary>
    private TimelineChunk? ChunkOf(Session session, int index) =>
        TimelineChunks.Containing(session.Packets, index, CaptureStart, Duration, TimelineWidth);

    private void OnPacketShown(Session session, int index)
    {
        var packet = session.Packets[index];
        HighlightedPacketId = packet.Id;
        RevealPacket(session, packet);
        if (!ReferenceEquals(session, inspected) || index >= PacketGrid.Items.Count) return;
        syncingGrid = true;
        PacketGrid.SelectedIndex = index;
        PacketGrid.ScrollIntoView(PacketGrid.SelectedItem);
        syncingGrid = false;
    }

    // MARK: Opening

    private void CanOpen(object sender, CanExecuteRoutedEventArgs e) => e.CanExecute = !loading && liveCapture is null;

    private void OnOpen(object sender, ExecutedRoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open capture",
            Filter = "Packet captures (*.pcap;*.pcapng;*.cap;*.dmp)|*.pcap;*.pcapng;*.cap;*.dmp|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false,
        };
        if (dialog.ShowDialog(this) == true) Open(dialog.FileName);
    }

    /// <summary>The first dropped path, if it is an existing file (folders and other data are ignored).</summary>
    private static string? DroppedFile(DragEventArgs e) =>
        e.Data.GetDataPresent(DataFormats.FileDrop) && e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files && File.Exists(files[0]) ? files[0] : null;

    private void OnDragOver(object sender, DragEventArgs e)
    {
        var file = DroppedFile(e);
        var accepted = file is not null && !loading && liveCapture is null;
        e.Effects = accepted ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
        if (file is null) { DropOverlay.Visibility = Visibility.Collapsed; return; }
        DropText.Text = accepted ? $"Drop to open {Path.GetFileName(file)}" : "Stop the recording before opening a file";
        DropOverlay.Visibility = Visibility.Visible;
    }

    /// <summary>DragLeave also fires when moving between child elements, so only hide once the pointer is outside the window.</summary>
    private void OnDragLeave(object sender, DragEventArgs e)
    {
        var point = e.GetPosition(this);
        if (point.X <= 0 || point.Y <= 0 || point.X >= ActualWidth || point.Y >= ActualHeight) DropOverlay.Visibility = Visibility.Collapsed;
    }

    private void OnDrop(object sender, DragEventArgs e)
    {
        DropOverlay.Visibility = Visibility.Collapsed;
        if (DroppedFile(e) is { } file) Open(file);
        e.Handled = true;
    }

    private async void Open(string path)
    {
        if (loading || liveCapture is not null) return;
        loading = true;
        UpdateHeader();
        try
        {
            var value = await Task.Run(() => CaptureReader.Read(path));
            packetWindow?.Close();
            ShowCapture(value, Path.GetFileName(path), reset: true);
        }
        catch (Exception error) when (error is CaptureException or IOException or UnauthorizedAccessException or OutOfMemoryException)
        {
            ShowFailure(error.Message);
        }
        finally
        {
            loading = false;
            UpdateHeader();
        }
    }

    /// <summary>Shows a capture. A reset (new file or new recording) clears selection, zoom and the split layout.</summary>
    private void ShowCapture(Capture value, string name, bool reset)
    {
        capture = value;
        filename = name;
        items = value.Sessions.ToDictionary(s => s.Id, s => new SessionItem(s, value.TotalBytes));
        if (reset)
        {
            HighlightedPacketId = -1;
            ClearPins();
            selected = null;
            selectedIds.Clear();
            SetExportStatus(null);
            ZoomSlider.Value = 0;
            SessionColumnWidth = DefaultColumnWidth;
            inspectorHeight = DefaultInspectorHeight;
            InspectorRow.Height = GridLength.Auto;
        }
        selectedIds.IntersectWith(items.Keys);
        if (selected is { } id && !items.ContainsKey(id)) selected = null;
        if (reset) inspected = null;
        CaptureStart = value.Start;
        Duration = Math.Max(2, value.End - value.Start);
        EmptyState.Visibility = Visibility.Collapsed;
        CaptureView.Visibility = Visibility.Visible;
        ApplyWindowSize(true);
        UpdateHeader();
        ApplyFilter(resetScroll: reset);
        UpdateSelection();
        UpdateTimelineWidth();
    }

    // MARK: Live recording

    private LiveCapture? liveCapture;
    private Task? recordingTask;
    private string? recordingPath;
    private bool stopping;
    private uint dropped;
    private List<CaptureInterface> interfaces = new();

    private void RefreshInterfaces(bool showErrors)
    {
        if (liveCapture is not null) return;
        var current = (CaptureInterfacePicker.SelectedItem as CaptureInterface)?.Id;
        try
        {
            interfaces = LiveCapture.Interfaces();
            NpcapHint.Visibility = interfaces.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        catch (Exception error) when (error is CaptureException or DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            interfaces = new();
            NpcapHint.Visibility = Visibility.Visible;
            if (showErrors) ShowFailure("Live capture needs Npcap installed with capture access. " + error.Message);
        }
        CaptureInterfacePicker.ItemsSource = interfaces;
        CaptureInterfacePicker.SelectedItem = interfaces.FirstOrDefault(i => i.Id == current) ?? interfaces.FirstOrDefault(i => i.Preferred) ?? interfaces.FirstOrDefault();
        UpdateHeader();
    }

    private void OnRefreshInterfaces(object sender, RoutedEventArgs e) => RefreshInterfaces(showErrors: true);
    private void OnInterfaceChanged(object sender, SelectionChangedEventArgs e) { if (IsLoaded) UpdateHeader(); }

    private async void OnStartRecording(object sender, RoutedEventArgs e)
    {
        if (liveCapture is not null || loading) return;
        if (CaptureInterfacePicker.SelectedItem is not CaptureInterface device) { RefreshInterfaces(showErrors: true); return; }
        var worker = new LiveCapture();
        try
        {
            var directory = Path.Combine(Path.GetTempPath(), "Schwabber-Recordings");
            Directory.CreateDirectory(directory);
            recordingPath = Path.Combine(directory, $"Recording-{Guid.NewGuid()}.pcap");
        }
        catch (IOException error) { ShowFailure(error.Message); return; }
        packetWindow?.Close();
        selected = null;
        selectedIds.Clear();
        ZoomSlider.Value = 0;
        liveCapture = worker;
        stopping = false;
        dropped = 0;
        ApplyWindowSize(true);
        UpdateHeader();
        var path = recordingPath;
        var name = "Live capture — " + device.Label;
        recordingTask = Task.Run(() => worker.Run(device.Id, path, (value, drops) =>
            Dispatcher.BeginInvoke(() => ReceiveSnapshot(value, drops, name))));
        try { await recordingTask; }
        catch (Exception error) { ShowFailure(error.Message); }
        finally
        {
            liveCapture = null;
            stopping = false;
            UpdateHeader();
        }
    }

    private void ReceiveSnapshot(Capture value, uint drops, string name)
    {
        dropped = drops;
        var first = filename != name;
        if (first) packetWindow?.Close();
        ShowCapture(value, name, reset: first);
    }

    private void OnStopRecording(object sender, RoutedEventArgs e)
    {
        if (liveCapture is null) return;
        stopping = true;
        liveCapture.Stop();
        UpdateHeader();
    }

    private void CanSaveRecording(object sender, CanExecuteRoutedEventArgs e) =>
        e.CanExecute = liveCapture is null && recordingPath is not null && File.Exists(recordingPath);

    /// <summary>Saves the complete recording, including unsupported packets (unlike Export selected).</summary>
    private void OnSaveRecording(object sender, ExecutedRoutedEventArgs e)
    {
        if (liveCapture is not null || recordingPath is null) return;
        var dialog = new SaveFileDialog { Title = "Save recorded capture", Filter = "PCAP capture (*.pcap)|*.pcap", DefaultExt = ".pcap", AddExtension = true, FileName = "Recording.pcap" };
        if (dialog.ShowDialog(this) != true) return;
        try { File.Copy(recordingPath, dialog.FileName, overwrite: true); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { ShowFailure(error.Message); }
    }

    /// <summary>Lets the capture worker flush and close its PCAP before the window closes.</summary>
    private async void OnClosing(object? sender, CancelEventArgs e)
    {
        if (liveCapture is null || recordingTask is null) return;
        e.Cancel = true;
        liveCapture.Stop();
        try { await recordingTask; } catch (Exception) { /* already reported */ }
        liveCapture = null;
        Close();
    }

    // MARK: Export

    private void OnExportSelected(object sender, RoutedEventArgs e) => ExportSessions(new HashSet<int>(selectedIds));
    private void OnOpenInWireshark(object sender, RoutedEventArgs e) => OpenInWireshark(new HashSet<int>(selectedIds));

    private async void ExportSessions(HashSet<int> ids)
    {
        if (capture is not { } current || ids.Count == 0 || exporting) return;
        var dialog = new SaveFileDialog
        {
            Title = $"Export {ids.Count} selected sessions, including both traffic directions",
            Filter = "PCAP capture (*.pcap)|*.pcap",
            DefaultExt = ".pcap",
            AddExtension = true,
            OverwritePrompt = true,
            FileName = Path.GetFileNameWithoutExtension(filename) + "-selected.pcap",
        };
        if (dialog.ShowDialog(this) != true) return;
        var path = dialog.FileName;
        exporting = true;
        SetExportStatus(null);
        UpdateHeader();
        try
        {
            await Task.Run(() => current.Export(ids, path));
            SetExportStatus($"Exported {ids.Count} sessions to {path}");
        }
        catch (Exception error) when (error is CaptureException or IOException or UnauthorizedAccessException)
        {
            ShowFailure(error.Message);
        }
        finally
        {
            exporting = false;
            UpdateHeader();
        }
    }

    private async void OpenInWireshark(HashSet<int> ids)
    {
        if (capture is not { } current || ids.Count == 0 || exporting) return;
        if (FindWireshark() is not { } wireshark)
        {
            ShowFailure("Wireshark was not found. Install Wireshark, then try again.");
            return;
        }
        exporting = true;
        UpdateHeader();
        try
        {
            var path = await Task.Run(() =>
            {
                var directory = Path.Combine(Path.GetTempPath(), "Schwabber-Exports");
                Directory.CreateDirectory(directory);
                var file = Path.Combine(directory, $"Sessions-{Guid.NewGuid().ToString().ToUpperInvariant()}.pcap");
                current.Export(ids, file);
                return file;
            });
            var start = new ProcessStartInfo(wireshark) { UseShellExecute = false };
            start.ArgumentList.Add(path);
            Process.Start(start);
        }
        catch (Exception error) when (error is CaptureException or IOException or UnauthorizedAccessException or Win32Exception)
        {
            ShowFailure(error.Message);
        }
        finally
        {
            exporting = false;
            UpdateHeader();
        }
    }

    /// <summary>Locates Wireshark.exe through its registered App Path or the default install folders.</summary>
    private static string? FindWireshark()
    {
        const string appPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Wireshark.exe";
        foreach (var root in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            try
            {
                using var key = root.OpenSubKey(appPath);
                if (key?.GetValue(null) is string registered && File.Exists(registered.Trim('"'))) return registered.Trim('"');
            }
            catch (System.Security.SecurityException) { }
        }
        foreach (var folder in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
        {
            var candidate = Path.Combine(Environment.GetFolderPath(folder), "Wireshark", "Wireshark.exe");
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }
}
