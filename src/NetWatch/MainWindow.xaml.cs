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
        _vm.NavigateToEventsRequested += () => MainTabs.SelectedIndex = 4; // 事件流
        InitTray();
    }

    private void InitTray()
    {
        try
        {
            _tray.IconSource = new BitmapImage(new Uri("pack://application:,,,/Assets/app.ico"));
        }
        catch { }
        _tray.ToolTipText = "NetWatch";
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

    // ---------- 右键菜单（P2 调查联动） ----------

    private void OnCmRelatedEvents(object sender, RoutedEventArgs e) => _vm.ShowRelatedEventsForSelection();
    private void OnCmCopyDetails(object sender, RoutedEventArgs e) => _vm.CopyDetails();
    private void OnCmOpenFolder(object sender, RoutedEventArgs e) => _vm.OpenProcessFolder();
    private void OnCmQueryIntel(object sender, RoutedEventArgs e) => _ = _vm.QuerySelectedFileIntelAsync();
    private void OnCmBlock(object sender, RoutedEventArgs e) => _vm.BlockSelected();
    private void OnCmUnblock(object sender, RoutedEventArgs e) => _vm.UnblockSelectedRow();

    private void OnCmFilterEventPid(object sender, RoutedEventArgs e)
    {
        if ((sender as System.Windows.Controls.ContextMenu)?.PlacementTarget is DataGrid { SelectedItem: EventRowVM ev } && ev.Pid > 0)
            _vm.FilterEventsByPid(ev.Pid);
    }

    // ---------- 数据与隐私设置（P3） ----------

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        // 按已保存设置回填下拉框（XAML 解析期的默认选中已被 _vm==null 守卫忽略）
        SetCombo(CbBaselineDays, _vm.Settings.BaselineRetentionDays);
        SetCombo(CbEvidenceDays, _vm.Settings.EvidenceRetentionDays);
        SetCombo(CbEvidenceCap, _vm.Settings.EvidenceMaxSizeMB);
        ChkPauseBaseline.IsChecked = _vm.Settings.BaselinePaused;
    }

    private static void SetCombo(System.Windows.Controls.ComboBox cb, int tag)
    {
        foreach (ComboBoxItem item in cb.Items)
            if (item.Tag is string s && int.TryParse(s, out var v) && v == tag)
            { cb.SelectedItem = item; return; }
    }

    private void OnBaselineDaysChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_vm == null) return;
        if ((sender as ComboBox)?.SelectedItem is ComboBoxItem it && it.Tag is string s && int.TryParse(s, out var d))
            _vm.SetBaselineRetention(d);
    }

    private void OnEvidenceDaysChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_vm == null) return;
        if ((sender as ComboBox)?.SelectedItem is ComboBoxItem it && it.Tag is string s && int.TryParse(s, out var d))
            _vm.SetEvidenceRetention(d);
    }

    private void OnEvidenceCapChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_vm == null) return;
        if ((sender as ComboBox)?.SelectedItem is ComboBoxItem it && it.Tag is string s && int.TryParse(s, out var v))
            _vm.SetEvidenceCap(v);
    }

    private void OnPauseBaselineChanged(object sender, RoutedEventArgs e)
    {
        if (_vm == null) return;
        _vm.SetBaselinePaused(ChkPauseBaseline.IsChecked == true);
    }

    private void OnCleanupNow(object sender, RoutedEventArgs e) => _vm.RunRetentionCleanup(manual: true);

    private void OnEnableAudit(object sender, RoutedEventArgs e) => _vm.EnableFirewallAudit();
}
