using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using NetWatch.Models;
using NetWatch.Native;
using NetWatch.Services;

namespace NetWatch.ViewModels;

/// 每秒 tick 驱动全部页面数据；ETW/轮询线程只产生事件，UI 线程统一消费
public sealed class MainViewModel : VmBase, IDisposable
{
    private readonly DispatcherTimer _timer;
    private readonly Stopwatch _session = Stopwatch.StartNew();
    private int _tickCount;
    private int _seriousConfigCount;

    public EtwNetworkMonitor Monitor { get; } = new();
    public ProcessTracker Tracker { get; } = new();
    public RateAggregator Agg { get; } = new();
    public DnsService Dns { get; } = new();
    public NetConfigService Config { get; } = new();
    public FirewallService Firewall { get; } = new();
    private DnsCheckService DnsCheck { get; } = new();

    // ---------- 集合 ----------
    public ObservableCollection<ProcessRowVM> Rows { get; } = new();
    public ObservableCollection<EventRowVM> Events { get; } = new();
    public ObservableCollection<ConnRowVM> SelectedConns { get; } = new();
    public ObservableCollection<string> DetailRisks { get; } = new();
    public ObservableCollection<string> DetailDns { get; } = new();
    public ObservableCollection<RemoteRowVM> Destinations { get; } = new();
    public ObservableCollection<DnsRowVM> DnsStream { get; } = new();
    public ObservableCollection<PortRowVM> Ports { get; } = new();
    public ObservableCollection<BlockedAppVM> BlockedApps { get; } = new();
    public ObservableCollection<ConfigChangeRowVM> ConfigHistory { get; } = new();
    public ObservableCollection<DohResultVM> DohResults { get; } = new();
    public ObservableCollection<AdapterRowVM> Adapters { get; } = new();

    private readonly Dictionary<int, ProcessRowVM> _rowsByPid = new();
    private readonly Dictionary<int, DateTime?> _pidStarts = new();
    private readonly Dictionary<string, RemoteRowVM> _destByIp = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, PortRowVM> _portMap = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, AdapterRowVM> _adapterMap = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<int, List<ConnectionInfo>> _connsByPid = new();
    private volatile List<ConnectionInfo> _latestConns = new();
    private HashSet<string> _blockedPaths = new(StringComparer.OrdinalIgnoreCase);
    private ListCollectionView? _rowsView;
    private string? _sortKey = "Total";
    private bool _sortDesc = true;

    public event Action<double, double>? ChartPush;

    public MainViewModel()
    {
        Monitor.OnNetEvent += e => { Dns.InspectNetEvent(e); Agg.Enqueue(e); };
        Monitor.OnDnsEvent += d => Dns.OnDns(d);

        _rowsView = (ListCollectionView)CollectionViewSource.GetDefaultView(Rows);
        _rowsView.Filter = o => o is ProcessRowVM r && MatchSearch(r) && (!OnlyFlagged || r.RiskByte >= 2);

        _ = Task.Run(async () =>
        {
            while (true)
            {
                try { _latestConns = ConnectionTable.Snapshot(); } catch { }
                await Task.Delay(2000);
            }
        });

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => OnTick();
        _timer.Start();

        TogglePauseCommand = new RelayCommand(TogglePause);
        BlockCommand = new RelayCommand(BlockSelected);
        UnblockCommand = new RelayCommand(UnblockSelectedRow);
        UnblockAppCommand = new RelayCommand(() => { if (SelectedBlocked != null) UnblockAppByPath(SelectedBlocked.Path); });
        RefreshBlockedCommand = new RelayCommand(RefreshBlocked);
        CopyCommand = new RelayCommand(CopyDetails);
        FolderCommand = new RelayCommand(OpenProcessFolder);
        ExportCommand = new RelayCommand(ExportEvents);
        ClearEventsCommand = new RelayCommand(Events.Clear);
        DohRunCommand = new RelayCommand(() => _ = RunDnsCheck());
        OpenHostsCommand = new RelayCommand(OpenHostsFile);

        Monitor.Start();
        RefreshBlocked();
        AddSystemEvent("监控已开始。说明：本工具只能看到「谁在连谁、传多少」，看不到加密内容；风险提示 ≠ 确诊病毒。");
    }

    // ================= 选项与顶部 =================

    public bool Paused { get; private set; }
    public RelayCommand TogglePauseCommand { get; }
    public RelayCommand BlockCommand { get; }
    public RelayCommand UnblockCommand { get; }
    public RelayCommand UnblockAppCommand { get; }
    public RelayCommand RefreshBlockedCommand { get; }
    public RelayCommand CopyCommand { get; }
    public RelayCommand FolderCommand { get; }
    public RelayCommand ExportCommand { get; }
    public RelayCommand ClearEventsCommand { get; }
    public RelayCommand DohRunCommand { get; }
    public RelayCommand OpenHostsCommand { get; }

    public void TogglePause()
    {
        Paused = !Paused;
        Raise(nameof(Paused));
        AddSystemEvent(Paused ? "监控已暂停（连接表仍刷新，流量不再累计）" : "监控已恢复");
    }

    public bool HideLoopback
    {
        get => _hideLoopback;
        set { _hideLoopback = value; Raise(nameof(HideLoopback)); }
    }
    private bool _hideLoopback = true;

    public bool OnlyFlagged
    {
        get => _onlyFlagged;
        set { _onlyFlagged = value; Raise(nameof(OnlyFlagged)); _rowsView?.Refresh(); }
    }
    private bool _onlyFlagged;

    public string SearchText
    {
        get => _searchText;
        set { _searchText = value ?? ""; Raise(nameof(SearchText)); _rowsView?.Refresh(); }
    }
    private string _searchText = "";

    public string TotalUpText { get; private set; } = "0 B/s";
    public string TotalDownText { get; private set; } = "0 B/s";
    public string SessionText { get; private set; } = "";
    public string TrayText { get; private set; } = "流量哨兵";
    public string ConnCountText { get; private set; } = "";
    public string BlockedCountText { get; private set; } = "";
    public string BannerText { get; private set; } = "";
    public bool BannerVisible { get; private set; }
    public string StatusText { get; private set; } = "监控启动中…";
    public SolidColorBrush StatusBrush { get; private set; } = UiBrushes.Amber;

    // ================= 选中与详情 =================

    private ProcessRowVM? _selected;
    public ProcessRowVM? Selected
    {
        get => _selected;
        set { _selected = value; Raise(nameof(Selected)); Raise(nameof(HasSelection)); UpdateDetail(); }
    }
    public bool HasSelection => _selected != null;

    public BlockedAppVM? SelectedBlocked { get; set; }

    public string DetailName { get; private set; } = "";
    public string DetailCompany { get; private set; } = "";
    public string DetailPid { get; private set; } = "";
    public string DetailPath { get; private set; } = "";
    public string DetailSignature { get; private set; } = "";
    public SolidColorBrush DetailSignatureBrush { get; private set; } = UiBrushes.Dim;
    public ImageSource? DetailIcon { get; private set; }

    // ================= DNS 页 =================

    public string DnsServersText { get; private set; } = "读取中…";
    public string ProxyText { get; private set; } = "读取中…";
    public string WinHttpText { get; private set; } = "读取中…";
    public string HostsText { get; private set; } = "读取中…";
    public string DnsAlertCountText { get; private set; } = "";

    public string DohProbeDomains { get; set; } = string.Join(", ", DnsCheckService.DefaultProbes);
    public int DohProviderIndex { get; set; }
    public bool DohRunning { get; private set; }
    public string DohStatusText { get; private set; } = "体检未运行。此功能为唯一的主动联网功能：点击后向所选公共 DoH 发起少量查询做交叉比对。";

    // ================= tick =================

    private void OnTick()
    {
        try
        {
            _tickCount++;

            while (Config.Changes.TryDequeue(out var ch))
            {
                ConfigHistory.Insert(0, new ConfigChangeRowVM(ch));
                while (ConfigHistory.Count > 200) ConfigHistory.RemoveAt(ConfigHistory.Count - 1);
                AddEvent(EventRowVM.FromAlert(ch.TimeUtc, ch.Serious ? RiskLevel.Medium : RiskLevel.Low,
                    $"[{ch.What}] {ch.Old}  →  {ch.New}"));
                if (ch.Serious) _seriousConfigCount++;
            }

            var logs = new List<NetEvent>();
            if (Paused) Agg.Drain(); else Agg.Tick(!HideLoopback, logs);
            foreach (var le in logs)
                AddEvent(EventRowVM.FromNet(le, Tracker.Get(le.Pid).Name, Dns));

            foreach (var it in Dns.DrainStream())
            {
                DnsStream.Add(DnsRowVM.From(it, Tracker.Get(it.Pid).Name));
                while (DnsStream.Count > 400) DnsStream.RemoveAt(0);
            }
            foreach (var a in Dns.DrainAlerts())
                AddEvent(EventRowVM.FromAlert(a.Time, a.Level, a.Text));

            RebuildConnIndex();
            UpdateRows();
            UpdateDestinations();
            UpdatePorts();
            UpdateConfigCards();
            UpdateDetail();
            UpdateTop();
            UpdateStatus();
            RefreshRecentNames();

            if (_tickCount % 30 == 0)
                Log.Info($"tick: rows={Rows.Count}, conns={_latestConns.Count}, events={Agg.EventCount}, etw={Monitor.Running}, paused={Paused}");
        }
        catch (Exception ex)
        {
            Log.Error("UI Tick 异常", ex);
        }
    }

    private void AddEvent(EventRowVM vm)
    {
        Events.Add(vm);
        while (Events.Count > 3000) Events.RemoveAt(0);
    }

    private void AddSystemEvent(string text) => AddEvent(EventRowVM.FromSystem(text));

    /// 进程名是异步解析的：占位名（PID xxx）出现后，回填最近事件/解析行的名字
    private void RefreshRecentNames()
    {
        for (int i = Events.Count - 1, n = 0; i >= 0 && n < 120; i--, n++)
        {
            var e = Events[i];
            if (e.Pid > 0 && e.Process.StartsWith("PID ", StringComparison.Ordinal))
                e.UpdateName(Tracker.Get(e.Pid).Name);
        }
        for (int i = DnsStream.Count - 1, n = 0; i >= 0 && n < 120; i--, n++)
        {
            var d = DnsStream[i];
            if (d.Pid > 0 && d.Process.StartsWith("PID ", StringComparison.Ordinal))
                d.UpdateName(Tracker.Get(d.Pid).Name);
        }
    }

    private void RebuildConnIndex()
    {
        _connsByPid = _latestConns
            .Where(c => HideLoopback || !c.IsLoopback)
            .GroupBy(c => c.Pid)
            .ToDictionary(g => g.Key, g => g.ToList());
    }

    // ================= 进程表 =================

    private void UpdateRows()
    {
        var active = new HashSet<int>(Agg.Stats.Keys);
        foreach (var pid in _connsByPid.Keys) active.Add(pid);

        foreach (var pid in active)
        {
            var entry = Tracker.Get(pid);

            // PID 复用检测：启动时间变化即重置该 PID 统计
            if (_pidStarts.TryGetValue(pid, out var prev) && prev != null &&
                entry.StartTimeUtc != null && prev != entry.StartTimeUtc)
                Agg.ResetPid(pid);
            _pidStarts[pid] = entry.StartTimeUtc;

            Agg.Stats.TryGetValue(pid, out var stats);

            // 已退出且无连接、60 秒无活动 → 清行
            if (entry.Exited && !_connsByPid.ContainsKey(pid))
            {
                var last = stats?.LastActivityUtc ?? entry.LastActivityUtc;
                if ((DateTime.UtcNow - last).TotalSeconds > 60)
                {
                    if (_rowsByPid.Remove(pid, out var old)) Rows.Remove(old);
                    Agg.ResetPid(pid);
                    _pidStarts.Remove(pid);
                    continue;
                }
            }

            SuspicionAnalyzer.Evaluate(entry, stats, _session.Elapsed);
            entry.FirewallBlocked = entry.Path != null && _blockedPaths.Contains(entry.Path);

            if (!_rowsByPid.TryGetValue(pid, out var row))
            {
                row = new ProcessRowVM();
                _rowsByPid[pid] = row;
                Rows.Add(row);
            }
            row.Update(entry, stats, _connsByPid.TryGetValue(pid, out var cl) ? cl.Count : 0);
        }

        foreach (var kv in _rowsByPid.Where(kv => !active.Contains(kv.Key)).ToList())
        {
            Rows.Remove(kv.Value);
            _rowsByPid.Remove(kv.Key);
        }

        SortRows();
    }

    private void SortRows()
    {
        Comparison<ProcessRowVM> cmp = _sortKey switch
        {
            "Name" => (a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase),
            "Pid" => (a, b) => a.Pid.CompareTo(b.Pid),
            "UpSpeedBytes" => (a, b) => a.UpSpeedBytes.CompareTo(b.UpSpeedBytes),
            "DownSpeedBytes" => (a, b) => a.DownSpeedBytes.CompareTo(b.DownSpeedBytes),
            "UpTotalBytes" => (a, b) => a.UpTotalBytes.CompareTo(b.UpTotalBytes),
            "DownTotalBytes" => (a, b) => a.DownTotalBytes.CompareTo(b.DownTotalBytes),
            "ConnCount" => (a, b) => a.ConnCount.CompareTo(b.ConnCount),
            "Risk" => (a, b) => a.RiskByte != b.RiskByte
                ? a.RiskByte.CompareTo(b.RiskByte)
                : (a.UpTotalBytes + a.DownTotalBytes).CompareTo(b.UpTotalBytes + b.DownTotalBytes),
            _ => (a, b) => (a.UpTotalBytes + a.DownTotalBytes).CompareTo(b.UpTotalBytes + b.DownTotalBytes),
        };
        CollSync.Sort(Rows, cmp, _sortDesc);
    }

    public void ApplySort(string memberPath)
    {
        if (memberPath == _sortKey) _sortDesc = !_sortDesc;
        else
        {
            _sortKey = memberPath;
            _sortDesc = memberPath is "Name" or "Pid";
        }
        SortRows();
    }

    private bool MatchSearch(ProcessRowVM r)
    {
        var q = SearchText;
        if (string.IsNullOrWhiteSpace(q)) return true;
        return r.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.Path.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.Company.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.Pid.ToString().Contains(q, StringComparison.Ordinal);
    }

    // ================= 详情 =================

    private void UpdateDetail()
    {
        var row = _selected;
        if (row == null)
        {
            if (SelectedConns.Count > 0) SelectedConns.Clear();
            if (DetailRisks.Count > 0) DetailRisks.Clear();
            if (DetailDns.Count > 0) DetailDns.Clear();
            return;
        }

        var entry = Tracker.Get(row.Pid);
        DetailName = entry.Name;
        DetailCompany = entry.Description ?? entry.Company ?? "";
        DetailPid = $"PID {entry.Pid} · {(entry.Exited ? "已退出" : "运行中")}" +
                    (entry.StartTimeUtc != null ? $" · 启动于 {entry.StartTimeUtc.Value.ToLocalTime():MM-dd HH:mm:ss}" : "");
        DetailPath = entry.Path ?? "（无法读取路径：受保护进程或权限不足）";
        DetailIcon = entry.Icon;
        (DetailSignature, DetailSignatureBrush) = entry.Signature switch
        {
            SignatureState.Valid => (entry.SignatureSubject == null ? "签名有效" : $"签名有效 · {entry.SignatureSubject}", UiBrushes.Green),
            SignatureState.Unsigned => ("未签名", UiBrushes.Amber),
            SignatureState.Untrusted => ($"签名不受信任{(entry.SignatureSubject == null ? "" : $" · {entry.SignatureSubject}")}（自签名/未知发布者）", UiBrushes.Amber),
            SignatureState.Invalid => ("签名无效——文件可能在签名后被篡改", UiBrushes.Red),
            _ => ("未检测（分析中或路径未知）", UiBrushes.Dim),
        };

        DetailRisks.Clear();
        if (entry.RiskReasons.Count == 0) DetailRisks.Add("未发现可疑点");
        else foreach (var r in entry.RiskReasons) DetailRisks.Add("• " + r);

        DetailDns.Clear();
        var doms = Dns.RecentDomains(entry.Pid);
        if (doms.Count == 0) DetailDns.Add("（无解析记录）");
        else foreach (var d in doms) DetailDns.Add(d);

        SelectedConns.Clear();
        if (_connsByPid.TryGetValue(row.Pid, out var conns))
            foreach (var c in conns) SelectedConns.Add(ConnRowVM.From(c, Dns));

        RaiseAll(nameof(DetailName), nameof(DetailCompany), nameof(DetailPid), nameof(DetailPath),
            nameof(DetailSignature), nameof(DetailSignatureBrush), nameof(DetailIcon));
    }

    // ================= 目的地 / 端口 / 配置 =================

    private void UpdateDestinations()
    {
        if (_tickCount % 10 == 0) Agg.PruneRemotes(TimeSpan.FromMinutes(30));

        var tops = Agg.Remotes.OrderByDescending(kv => kv.Value.Up + kv.Value.Down).Take(400).ToList();

        CollSync.Sync(Destinations, _destByIp,
            tops.Select(kv => kv.Key),
            _ => new RemoteRowVM(),
            (ip, vm) =>
            {
                Agg.Remotes.TryGetValue(ip, out var rs);
                var names = (rs?.Pids.ToList() ?? new List<int>())
                    .Select(p => Tracker.Get(p).Name).Distinct().Take(3);
                vm.Update(ip, rs ?? new RemoteStats(), Dns.LookupDomain(ip), string.Join("、", names));
            });

        CollSync.Sort(Destinations, (a, b) => (a.UpBytes + a.DownBytes).CompareTo(b.UpBytes + b.DownBytes), desc: true);
    }

    private void UpdatePorts()
    {
        var listen = _latestConns
            .Where(c => HideLoopback || !c.IsLoopback)
            .Where(c => c.Proto == NetProto.Udp || c.State == "LISTEN")
            .ToList();

        CollSync.Sync(Ports, _portMap,
            listen.Select(c => $"{(int)c.Proto}:{c.Local}:{c.Pid}"),
            _ => new PortRowVM(),
            (key, vm) =>
            {
                foreach (var c in listen)
                {
                    if ($"{(int)c.Proto}:{c.Local}:{c.Pid}" != key) continue;
                    vm.Update(c, Tracker.Get(c.Pid).Name);
                    break;
                }
            });

        CollSync.Sort(Ports,
            (a, b) => a.Port != b.Port ? a.Port.CompareTo(b.Port) : string.CompareOrdinal(a.ProtoText, b.ProtoText),
            desc: false);
    }

    private void UpdateConfigCards()
    {
        var snap = Config.Snapshot;
        DnsServersText = snap.AllDns.Length == 0 ? "（未配置）" : string.Join("　", snap.AllDns);
        ProxyText = snap.ProxyText;
        WinHttpText = snap.WinHttpText;
        HostsText = $"{snap.Hosts.Count} 条生效映射 · 修改于 {(snap.HostsModified == default ? "未知" : snap.HostsModified.ToString("MM-dd HH:mm"))}";

        CollSync.Sync(Adapters, _adapterMap,
            snap.Adapters.Select(a => a.Name),
            _ => new AdapterRowVM(),
            (name, vm) =>
            {
                foreach (var a in snap.Adapters)
                {
                    if (a.Name != name) continue;
                    vm.Update(a);
                    break;
                }
            });

        DnsAlertCountText = $"DNS/配置告警 {Dns.AlertCount + _seriousConfigCount} 条";
        RaiseAll(nameof(DnsServersText), nameof(ProxyText), nameof(WinHttpText), nameof(HostsText), nameof(DnsAlertCountText));
    }

    private void UpdateTop()
    {
        double upNow = 0, downNow = 0;
        long upAll = 0, downAll = 0;
        foreach (var s in Agg.Stats.Values)
        {
            upNow += s.UpSpeed; downNow += s.DownSpeed;
            upAll += s.UpTotal; downAll += s.DownTotal;
        }
        TotalUpText = Util.FormatSpeed(upNow);
        TotalDownText = Util.FormatSpeed(downNow);
        SessionText = $"↑ {Util.FormatBytes(upAll)}　↓ {Util.FormatBytes(downAll)}";
        TrayText = $"↑ {Util.FormatSpeed(upNow)}   ↓ {Util.FormatSpeed(downNow)}";
        ConnCountText = $"当前连接 {_latestConns.Count(c => HideLoopback || !c.IsLoopback)}";
        BlockedCountText = $"已拦截 {_blockedPaths.Count} 个程序";

        var flagged = 0;
        foreach (var r in Rows) if (r.RiskByte >= 2) flagged++;
        var alerts = Dns.AlertCount + _seriousConfigCount;
        if (flagged > 0 || alerts > 0)
        {
            var parts = new List<string>();
            if (flagged > 0) parts.Add($"{flagged} 个进程行为可疑（总览表已标色）");
            if (alerts > 0) parts.Add($"{alerts} 条 DNS/配置告警（见 DNS 安全页与事件流）");
            BannerText = "⚠ " + string.Join("；", parts);
            BannerVisible = true;
        }
        else BannerVisible = false;

        ChartPush?.Invoke(upNow, downNow);
        RaiseAll(nameof(TotalUpText), nameof(TotalDownText), nameof(SessionText), nameof(TrayText),
            nameof(ConnCountText), nameof(BlockedCountText), nameof(BannerText), nameof(BannerVisible));
    }

    private void UpdateStatus()
    {
        if (Monitor.LastError != null)
        {
            StatusText = $"⚠ 实时监控异常：{Monitor.LastError}（连接表/DNS 配置监控仍可用）";
            StatusBrush = UiBrushes.Red;
        }
        else if (Monitor.Running)
        {
            StatusText = Paused ? "⏸ 已暂停（流量不累计）" : $"● 实时监控中 · 事件 {Agg.EventCount:N0}";
            StatusBrush = Paused ? UiBrushes.Amber : UiBrushes.Green;
        }
        else
        {
            StatusText = "监控启动中…（需要管理员权限）";
            StatusBrush = UiBrushes.Amber;
        }
        RaiseAll(nameof(StatusText), nameof(StatusBrush));
    }

    // ================= 操作 =================

    public void BlockSelected()
    {
        var row = _selected;
        if (row == null) return;
        var entry = Tracker.Get(row.Pid);
        var path = entry.Path;
        if (string.IsNullOrEmpty(path))
        {
            MessageBox.Show("尚未获取到该进程的程序路径（可能还在解析，或进程受系统保护）。", "无法拦截",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var name = Path.GetFileName(path);
        bool sharedHost = string.Equals(path, Path.Combine(Environment.SystemDirectory, "svchost.exe"), StringComparison.OrdinalIgnoreCase);
        string msg = sharedHost
            ? $"⚠ {name} 是共享服务宿主（svchost.exe），拦截会连同影响它承载的全部系统服务（更新、DNS 客户端等），可能导致系统异常。\n\n仍要拦截吗？"
            : $"将创建 Windows 防火墙规则，禁止 {name} 的所有联网（出站 + 入站）。\n\n程序：{path}\n\n可随时在「拦截名单」页恢复。确定拦截？";
        if (MessageBox.Show(msg, "确认拦截", MessageBoxButton.YesNo,
                sharedHost ? MessageBoxImage.Warning : MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;

        try
        {
            Firewall.BlockApp(path!, name);
            RefreshBlocked();
            AddSystemEvent($"已禁止 {name} 联网（防火墙规则已创建）");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"拦截失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    public void UnblockSelectedRow()
    {
        if (_selected == null) return;
        UnblockAppByPath(Tracker.Get(_selected.Pid).Path);
    }

    public void UnblockAppByPath(string? path)
    {
        if (string.IsNullOrEmpty(path)) { MessageBox.Show("无法读取该程序的路径。", "提示"); return; }
        try
        {
            Firewall.UnblockApp(path);
            RefreshBlocked();
            AddSystemEvent($"已恢复 {Path.GetFileName(path)} 的联网");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"恢复失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    public void RefreshBlocked()
    {
        try
        {
            var rules = Firewall.ListRules();
            _blockedPaths = rules.Where(r => r.AppPath.Length > 0)
                                 .Select(r => r.AppPath)
                                 .ToHashSet(StringComparer.OrdinalIgnoreCase);
            BlockedApps.Clear();
            foreach (var g in rules.GroupBy(r => r.AppPath, StringComparer.OrdinalIgnoreCase))
            {
                BlockedApps.Add(new BlockedAppVM
                {
                    DisplayName = g.Key.Length > 0 ? Path.GetFileName(g.Key) : "(未知路径)",
                    Path = g.Key,
                    RulesText = $"{g.Count()} 条规则",
                });
            }
        }
        catch (Exception ex) { Log.Error("读取拦截名单失败", ex); }
    }

    public void CopyDetails()
    {
        var row = _selected;
        if (row == null) return;
        var entry = Tracker.Get(row.Pid);
        var sb = new StringBuilder();
        sb.AppendLine($"进程：{entry.Name} (PID {entry.Pid})");
        sb.AppendLine($"厂商：{entry.Company ?? "未知"}　描述：{entry.Description ?? "未知"}");
        sb.AppendLine($"路径：{entry.Path ?? "未知"}");
        sb.AppendLine($"签名：{DetailSignature}");
        sb.AppendLine($"风险提示：{(entry.RiskReasons.Count == 0 ? "无" : string.Join("；", entry.RiskReasons))}");
        sb.AppendLine($"上传累计：{Util.FormatBytes(row.UpTotalBytes)}　下载累计：{Util.FormatBytes(row.DownTotalBytes)}");
        if (_connsByPid.TryGetValue(row.Pid, out var conns))
        {
            sb.AppendLine("当前连接：");
            foreach (var c in conns)
                sb.AppendLine($"  [{c.Proto}] {c.Local} → {c.Remote}（{c.State}，{Util.ScopeText(c.IsLoopback, c.IsLan)}）");
        }
        try { Clipboard.SetText(sb.ToString()); } catch { }
    }

    public void OpenProcessFolder()
    {
        var path = _selected == null ? null : Tracker.Get(_selected.Pid).Path;
        if (string.IsNullOrEmpty(path))
        {
            MessageBox.Show("无法读取程序路径。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try { Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"")); } catch { }
    }

    public void ExportEvents()
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = "导出事件流",
            Filter = "CSV 文件 (*.csv)|*.csv",
            FileName = $"NetWatch_事件_{DateTime.Now:yyyyMMdd_HHmmss}.csv",
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            using var w = new StreamWriter(dlg.FileName, false, new UTF8Encoding(true));
            w.WriteLine("时间,事件,进程,目标,数据量");
            foreach (var e in Events.ToList())
                w.WriteLine($"\"{e.RawTime:yyyy-MM-dd HH:mm:ss}\",\"{e.RawKind}\",\"{e.Process}\",\"{e.Detail.Replace("\"", "\"\"")}\",\"{e.RawBytes}\"");
            AddSystemEvent($"事件流已导出：{dlg.FileName}");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"导出失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    public void OpenHostsFile()
    {
        try { Process.Start(new ProcessStartInfo("notepad.exe", NetConfigService.HostsPath)); } catch { }
    }

    public async Task RunDnsCheck()
    {
        if (DohRunning) return;
        var domains = DohProbeDomains
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Take(8).ToArray();
        if (domains.Length == 0)
        {
            DohStatusText = "请先填写至少一个探测域名。";
            Raise(nameof(DohStatusText));
            return;
        }

        var url = DnsCheckService.Endpoints[Math.Clamp(DohProviderIndex, 0, DnsCheckService.Endpoints.Length - 1)].Url;
        DohRunning = true;
        DohStatusText = "体检中…";
        RaiseAll(nameof(DohRunning), nameof(DohStatusText));
        try
        {
            var progress = new Progress<string>(s => { DohStatusText = s; Raise(nameof(DohStatusText)); });
            var results = await DnsCheck.RunAsync(domains, url, progress);
            DohResults.Clear();
            foreach (var r in results) DohResults.Add(new DohResultVM(r));
            DohStatusText = "体检完成。注意：结论为提示性——公共域名的 CDN 调度可能合法造成“不一致”，请换参考源复核后再下结论。";
        }
        catch (Exception ex)
        {
            DohStatusText = $"体检失败：{ex.Message}";
        }
        finally
        {
            DohRunning = false;
            RaiseAll(nameof(DohRunning), nameof(DohStatusText));
        }
    }

    public void Dispose()
    {
        _timer.Stop();
        Monitor.Dispose();
        Config.Dispose();
        Tracker.Dispose();
    }
}
