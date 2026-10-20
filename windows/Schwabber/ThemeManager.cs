using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using Microsoft.Win32;

namespace Schwabber;

public enum ThemeMode { System, Light, Dark }

/// <summary>
/// Applies the light or dark color dictionary, follows the Windows app theme when set to System,
/// darkens window title bars, and remembers the user's choice.
/// </summary>
public static class ThemeManager
{
    private static readonly string SettingsPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Schwabber", "theme.txt");

    public static ThemeMode Mode { get; private set; } = ThemeMode.System;
    public static bool IsDark { get; private set; }

    /// <summary>Raised after the effective theme is applied, for colors computed in code.</summary>
    public static event Action? Changed;

    public static void Initialize()
    {
        try
        {
            if (File.Exists(SettingsPath) && Enum.TryParse<ThemeMode>(File.ReadAllText(SettingsPath).Trim(), out var saved)) Mode = saved;
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        SystemEvents.UserPreferenceChanged += (_, e) =>
        {
            if (Mode == ThemeMode.System && e.Category is UserPreferenceCategory.General or UserPreferenceCategory.Color or UserPreferenceCategory.VisualStyle)
                Application.Current?.Dispatcher.BeginInvoke(Apply);
        };
        Apply();
    }

    public static void SetMode(ThemeMode mode)
    {
        if (mode == Mode) return;
        Mode = mode;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            File.WriteAllText(SettingsPath, mode.ToString());
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        Apply();
    }

    /// <summary>Windows stores the app theme as AppsUseLightTheme = 0 for dark.</summary>
    private static bool SystemPrefersDark()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
        }
        catch (System.Security.SecurityException) { return false; }
    }

    private static void Apply()
    {
        IsDark = Mode == ThemeMode.Dark || (Mode == ThemeMode.System && SystemPrefersDark());
        var colors = new ResourceDictionary { Source = new Uri($"pack://application:,,,/Themes/{(IsDark ? "Dark" : "Light")}.xaml") };
        var merged = Application.Current.Resources.MergedDictionaries;
        // Index 0 is the color dictionary; index 1 holds the control styles that reference it.
        if (merged.Count > 0) merged[0] = colors; else merged.Add(colors);
        foreach (Window window in Application.Current.Windows)
        {
            ApplyTitleBar(window);
            InvalidateDrawnControls(window);
        }
        Changed?.Invoke();
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
    private const int DwmUseImmersiveDarkMode = 20;

    /// <summary>Matches the title bar to the theme. Call from SourceInitialized; ignored on systems without support.</summary>
    public static void ApplyTitleBar(Window window)
    {
        var handle = new WindowInteropHelper(window).Handle;
        if (handle == IntPtr.Zero) return;
        var dark = IsDark ? 1 : 0;
        DwmSetWindowAttribute(handle, DwmUseImmersiveDarkMode, ref dark, sizeof(int));
    }

    /// <summary>Controls that draw themselves read theme brushes in OnRender, so ask them to redraw.</summary>
    private static void InvalidateDrawnControls(DependencyObject element)
    {
        if (element is TimelineBar or TimelineHeader or HexView or MiddleTrimTextBlock or PinOverlay) ((UIElement)element).InvalidateVisual();
        var count = VisualTreeHelper.GetChildrenCount(element);
        for (var i = 0; i < count; i++) InvalidateDrawnControls(VisualTreeHelper.GetChild(element, i));
    }

    public static Brush Brush(FrameworkElement owner, string key, Brush fallback) => owner.TryFindResource(key) as Brush ?? fallback;
}
