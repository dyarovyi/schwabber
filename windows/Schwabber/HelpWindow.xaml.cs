using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;

namespace Schwabber;

/// <summary>The user guide (Help → Schwabber Help, F1). One window is reused; Open can jump to a section.</summary>
public partial class HelpWindow : Window
{
    private static HelpWindow? shared;

    private HelpWindow()
    {
        InitializeComponent();
        SourceInitialized += (_, _) => ThemeManager.ApplyTitleBar(this);
        Closed += (_, _) => shared = null;
    }

    /// <param name="section">x:Name of a Section in the guide, for example "SecKeys".</param>
    public static void Open(Window owner, string? section = null)
    {
        if (shared is null)
        {
            shared = new HelpWindow { Owner = owner };
            shared.Show();
        }
        if (shared.WindowState == WindowState.Minimized) shared.WindowState = WindowState.Normal;
        shared.Activate();
        if (section is not null)
            shared.Dispatcher.BeginInvoke(() => shared?.ShowSection(section), System.Windows.Threading.DispatcherPriority.Loaded);
    }

    private void ShowSection(string name)
    {
        foreach (ListBoxItem item in Contents.Items)
            if ((string)item.Tag == name) { Contents.SelectedItem = item; return; }
    }

    private void OnContentsSelected(object sender, SelectionChangedEventArgs e)
    {
        if (Contents.SelectedItem is not ListBoxItem { Tag: string name } || Guide.FindName(name) is not Section section) return;
        // Scroll so the section heading is at the top of the reading pane.
        section.Blocks.FirstBlock?.BringIntoView();
        if (FindScroller(Viewer) is { } scroller && section.Blocks.FirstBlock is { } heading)
        {
            var top = heading.ContentStart.GetCharacterRect(LogicalDirection.Forward).Top;
            scroller.ScrollToVerticalOffset(scroller.VerticalOffset + top - 12);
        }
    }

    private static ScrollViewer? FindScroller(DependencyObject element)
    {
        if (element is ScrollViewer viewer) return viewer;
        for (var i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(element); i++)
            if (FindScroller(System.Windows.Media.VisualTreeHelper.GetChild(element, i)) is { } found) return found;
        return null;
    }
}
