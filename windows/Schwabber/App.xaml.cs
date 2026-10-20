using System.Windows;

namespace Schwabber;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ThemeManager.Initialize();
    }
}
