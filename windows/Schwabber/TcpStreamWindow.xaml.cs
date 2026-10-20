using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using CaptureCore;
using Microsoft.Win32;

namespace Schwabber;

/// <summary>A snapshot of one TCP session reassembled per direction. One window is reused, as on macOS.</summary>
public partial class TcpStreamWindow : Window
{
    private const int PreviewBytes = 65536;
    private static TcpStreamWindow? shared;
    private IReadOnlyList<TcpDirection> directions = Array.Empty<TcpDirection>();

    private TcpStreamWindow()
    {
        InitializeComponent();
        SourceInitialized += (_, _) => ThemeManager.ApplyTitleBar(this);
        Closed += (_, _) => shared = null;
        Bytes.DescribeByte = offset => $"Stream chunk byte {offset}";
    }

    public static void Open(Session session, int linkType, Window owner)
    {
        if (shared is null)
        {
            shared = new TcpStreamWindow { Owner = owner };
            shared.Show();
        }
        if (shared.WindowState == WindowState.Minimized) shared.WindowState = WindowState.Normal;
        shared.Activate();
        shared.Load(session, linkType);
    }

    private async void Load(Session session, int linkType)
    {
        LoadingPanel.Visibility = Visibility.Visible;
        EmptyText.Visibility = StreamPanel.Visibility = ErrorText.Visibility = Visibility.Collapsed;
        directions = await Task.Run(() => TcpReassembly.Reassemble(session, linkType));
        LoadingPanel.Visibility = Visibility.Collapsed;
        if (directions.Count == 0) { EmptyText.Visibility = Visibility.Visible; return; }
        StreamPanel.Visibility = Visibility.Visible;
        DirectionPicker.ItemsSource = directions.Select(d => $"{d.Source} → {d.Destination}").ToList();
        DirectionPicker.SelectedIndex = 0;
    }

    private TcpDirection? Direction => DirectionPicker.SelectedIndex >= 0 && DirectionPicker.SelectedIndex < directions.Count ? directions[DirectionPicker.SelectedIndex] : null;
    private byte[] Data => Direction is { } d && ChunkPicker.SelectedIndex >= 0 && ChunkPicker.SelectedIndex < d.Chunks.Count ? d.Chunks[ChunkPicker.SelectedIndex].Bytes : Array.Empty<byte>();

    private void OnDirectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (Direction is not { } d) return;
        StatsText.Text = $"{d.MissingBytes:N0} missing bytes between chunks · {d.OverlapBytes:N0} overlapping bytes · {d.ConflictingBytes:N0} conflicting bytes";
        StatsText.Foreground = d.MissingBytes > 0 || d.ConflictingBytes > 0
            ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xFF, 0x95, 0x00))
            : (System.Windows.Media.Brush)FindResource("SecondaryText");
        ChunkPicker.ItemsSource = d.Chunks.Select(c => $"Offset {c.Offset:N0} · {c.Bytes.Length:N0} bytes").ToList();
        ChunkPicker.SelectedIndex = 0;
    }

    private void OnChunkChanged(object sender, SelectionChangedEventArgs e) => ShowChunk();
    private void OnPreviewChanged(object sender, RoutedEventArgs e) => ShowChunk();

    private void ShowChunk()
    {
        var data = Data;
        SaveButton.IsEnabled = data.Length > 0;
        var text = TextPreview.IsChecked == true;
        HexScroller.Visibility = text ? Visibility.Collapsed : Visibility.Visible;
        TextBox.Visibility = text ? Visibility.Visible : Visibility.Collapsed;
        PreviewLimit.Visibility = text && data.Length > PreviewBytes ? Visibility.Visible : Visibility.Collapsed;
        if (text) TextBox.Text = Encoding.UTF8.GetString(data, 0, Math.Min(data.Length, PreviewBytes));
        else Bytes.SetData(data, 0, data.Length, 0, data.Length);
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            FileName = $"TCP-direction-{DirectionPicker.SelectedIndex}-chunk-{ChunkPicker.SelectedIndex}.bin",
            Filter = "Binary data (*.bin)|*.bin|All files (*.*)|*.*",
        };
        if (dialog.ShowDialog(this) != true) return;
        try { File.WriteAllBytes(dialog.FileName, Data); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            ErrorText.Text = error.Message;
            ErrorText.Visibility = Visibility.Visible;
        }
    }
}
