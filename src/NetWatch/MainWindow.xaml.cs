using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using Hardcodet.Wpf.TaskbarNotification;
using NetWatch.ViewModels;

namespace NetWatch;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;
    private readonly TaskbarIcon _tray = new();

    public MainWindow()
    {
        InitializeComponent();
        _vm = new MainViewModel();
        DataContext = _vm;
        _vm.ChartPush += (u, d) => Chart.Push(u, d);
        InitTray();
    }

    private void InitTray()
    {
        try
        {
            _tray.IconSource = new BitmapImage(new Uri("pack://application:,,,/Assets/app.ico"));
        }
        catch { }
        _tray.ToolTipText = "流量哨兵 NetWatch";
        _tray.TrayLeftMouseUp += (_, _) => RestoreFromTray();

        var menu = new ContextMenu();
        var show = new MenuItem { Header = "显示主界面" };
        show.Click += (_, _) => RestoreFromTray();
        var exit = new MenuItem { Header = "退出" };
        exit.Click += (_, _) => Close();
        menu.Items.Add(show);
        menu.Items.Add(exit);
        _tray.ContextMenu = menu;
    }

    private void RestoreFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);
        if (WindowState == WindowState.Minimized) Hide();
    }

    protected override void OnClosed(EventArgs e)
    {
        _tray?.Dispose();
        _vm?.Dispose();
        base.OnClosed(e);
    }

    private void OnSearchChanged(object sender, TextChangedEventArgs e)
    {
        if (SearchHint == null) return; // XAML 解析期触发时元素可能未就绪
        SearchHint.Visibility = SearchBox.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnProcessSort(object sender, DataGridSortingEventArgs e)
    {
        e.Handled = true;
        _vm.ApplySort(e.Column.SortMemberPath ?? "");
    }

    private void OnBannerClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        => _vm.OnlyFlagged = true;

    private void OnDohProviderChanged(object sender, RoutedEventArgs e)
    {
        if (_vm == null) return; // XAML 解析期 IsChecked=True 就会触发，此时 _vm 尚未创建
        if (RbAli.IsChecked == true) _vm.DohProviderIndex = 0;
        else if (RbPod.IsChecked == true) _vm.DohProviderIndex = 1;
        else if (RbCf.IsChecked == true) _vm.DohProviderIndex = 2;
    }
}
