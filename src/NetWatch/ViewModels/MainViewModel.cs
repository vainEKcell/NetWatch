using System.Collections.Concurrent;
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

    /// P1 统一事件库与实体仓库（事实层；P2 证据链、P3 持久化的数据源）
    public EventStore Store { get; } = new();
    public EntityStore Entities { get; } = new();
    public AppSettings Settings { get; } = AppSettings.Load();
    public BaselineStore Baseline { get; }
    public EvidenceWriter Evidence { get; }
    public FirewallAuditWatcher Audit { get; } = new();
    public SysmonWatcher Sysmon { get; } = new();
    private readonly ConcurrentQueue<BlockedConnectionEvent> _blockedEvents = new();
    private readonly ConcurrentDictionary<int, string> _userByPid = new();
    private int _blockedConnCount;
    private readonly HashSet<string> _firstSeenQueried = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<(bool Start, int Pid, int? Parent, string? Image, string? Cmd, DateTime T)> _procEvents = new();

    public string StorageInfo { get; private set; } = "";

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
    private readonly Dictionary<int, Verdict> _verdictsByPid = new();
    private volatile List<ConnectionInfo> _latestConns = new();
    private HashSet<string> _blockedPaths = new(StringComparer.OrdinalIgnoreCase);
    private ListCollectionView? _rowsView;
    private ListCollectionView? _eventsView;
    private string? _sortKey = "Total";
    private bool _sortDesc = true;

    public event Action<double, double>? ChartPush;

    public MainViewModel()
    {
        Baseline = new BaselineStore(Settings);
        Evidence = new EvidenceWriter(Settings);

        Monitor.OnNetEvent += e => { Dns.InspectNetEvent(e); Agg.Enqueue(e); };
        Monitor.OnDnsEvent += d => Dns.OnDns(d);
        Monitor.OnProcessEvent += (start, pid, parent, image, cmd, t) => _procEvents.Enqueue((start, pid, parent, image, cmd, t));

        _rowsView = (ListCollectionView)CollectionViewSource.GetDefaultView(Rows);
        _rowsView.Filter = o => o is ProcessRowVM r && MatchSearch(r) && (!OnlyFlagged || r.RiskByte >= 2);

        _eventsView = (ListCollectionView)CollectionViewSource.GetDefaultView(Events);
        _eventsView.Filter = o => o is EventRowVM ev && (EventsPidFilter == null || ev.Pid == EventsPidFilter.Value);

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
        ShowRelatedEventsCommand = new RelayCommand(ShowRelatedEventsForSelection);
        ClearEventsFilterCommand = new RelayCommand(ClearEventsFilter);
        QueryFileIntelCommand = new RelayCommand(() => _ = QuerySelectedFileIntelAsync());
        InitTrustedList();

        Monitor.Start();
        RefreshBlocked();
        InitAudit();
        InitSysmon();
        AddSystemEvent("监控已开始。说明：本工具只能看到「谁在连谁、传多少」，看不到加密内容；风险提示 ≠ 确诊病毒。");
    }

    // ================= 防火墙拦截审计（5157）与 Sysmon =================

    public string AuditStatusText { get; private set; } = "";
    public string SysmonStatusText { get; private set; } = "";
    public string BlockedConnCountText { get; private set; } = "";
    public string DetailUser { get; private set; } = "—";

    private void InitAudit()
    {
        var (s, f) = FirewallAuditWatcher.QueryAuditState();
        if (s || f) Audit.Start(OnBlockedConnection);
        UpdateAuditStatus();
    }

    private void InitSysmon()
    {
        if (SysmonWatcher.IsChannelPresent())
            Sysmon.Start((pid, user) => _userByPid[pid] = user);
        UpdateAuditStatus();
    }

    private void UpdateAuditStatus()
    {
        var (s, f) = FirewallAuditWatcher.QueryAuditState();
        AuditStatusText = (s || f)
            ? "拦截审计：已启用（被防火墙拦截的连接实时显示于事件流）"
            : "拦截审计：未启用";
        SysmonStatusText = Sysmon.Available
            ? "Sysmon：已检测到（运行用户富化生效）"
            : "Sysmon：未安装（可选增强，不影响功能）";
        RaiseAll(nameof(AuditStatusText), nameof(SysmonStatusText));
    }

    public void EnableFirewallAudit()
    {
        var r = MessageBox.Show(
            "将在系统审核策略中启用「审核筛选平台连接」（auditpol 命令，完全可逆），\n用于实时显示被 Windows 防火墙拦截的连接。继续？",
            "启用拦截审计", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (r != MessageBoxResult.Yes) return;
        if (FirewallAuditWatcher.EnableAudit())
        {
            Audit.Start(OnBlockedConnection);
            UpdateAuditStatus();
            AddSystemEvent("防火墙拦截审计已启用——被拦截的连接将实时出现在事件流");
        }
        else
            MessageBox.Show("启用失败（需要管理员权限）。", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private void OnBlockedConnection(BlockedConnectionEvent b) => _blockedEvents.Enqueue(b);

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
    public RelayCommand ShowRelatedEventsCommand { get; }
    public RelayCommand ClearEventsFilterCommand { get; }
    public RelayCommand QueryFileIntelCommand { get; }

    /// P2 调查联动：UI 订阅后切到事件流页
    public event Action? NavigateToEventsRequested;

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
    public string DetailParent { get; private set; } = "";
    public string DetailCmdLine { get; private set; } = "";
    public string DetailServices { get; private set; } = "";
    public string DetailIdentity { get; private set; } = "";
    public string DetailVerdict { get; private set; } = "";
    public SolidColorBrush DetailVerdictBrush { get; private set; } = UiBrushes.Dim;
    public ObservableCollection<string> DetailEvidence { get; } = new();

    // ---------- 事件流按进程过滤（调查联动） ----------
    private int? _eventsPidFilter;
    public int? EventsPidFilter
    {
        get => _eventsPidFilter;
        set
        {
            _eventsPidFilter = value;
            Raise(nameof(EventsPidFilter));
            Raise(nameof(EventsFilterText));
            Raise(nameof(EventsFilterVisible));
            _eventsView?.Refresh();
        }
    }
    public string EventsFilterText => EventsPidFilter == null ? "" : $"只看 PID {EventsPidFilter} 的相关事件";
    public bool EventsFilterVisible => EventsPidFilter != null;

    public void ShowRelatedEventsForSelection()
    {
        if (_selected == null) return;
        EventsPidFilter = _selected.Pid;
        NavigateToEventsRequested?.Invoke();
    }

    public void ClearEventsFilter() => EventsPidFilter = null;

    public void FilterEventsByPid(int pid)
    {
        EventsPidFilter = pid;
        NavigateToEventsRequested?.Invoke();
    }

    /// 文件哈希缓存（按需计算）：用于“浏览器查询此文件公开情报”
    private static readonly ConcurrentDictionary<string, string?> _fileHashCache = new(StringComparer.OrdinalIgnoreCase);

    public async Task QuerySelectedFileIntelAsync()
    {
        var row = _selected;
        if (row == null) return;
        var path = Tracker.Get(row.Pid).Path;
        if (string.IsNullOrEmpty(path))
        {
            MessageBox.Show("无法读取该程序的路径。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try
        {
            var hash = await Task.Run(() => _fileHashCache.GetOrAdd(path!, p =>
            {
                using var fs = File.OpenRead(p);
                return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fs)).ToLowerInvariant();
            }));
            Process.Start(new ProcessStartInfo
            {
                FileName = $"https://www.virustotal.com/gui/file/{hash}",
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"查询失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

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
            if (Paused) Agg.Drain(); else Agg.Tick(!HideLoopback, logs, OnTrafficObserved);
            foreach (var le in logs)
            {
                var name = Tracker.Get(le.Pid).Name;
                AddEvent(EventRowVM.FromNet(le, name, Dns));
                AddStoreRecord(new EventRecord
                {
                    TimeUtc = le.TimeUtc,
                    Kind = le.Kind switch
                    {
                        EventKind.NewConn => EventKindEx.NewConn,
                        EventKind.Closed => EventKindEx.Closed,
                        _ => EventKindEx.LargeTransfer,
                    },
                    Pid = le.Pid,
                    IdentityKey = Entities.GetProcess(le.Pid)?.IdentityKey,
                    RemoteIp = le.RemoteIp,
                    RemotePort = le.RemotePort,
                    Proto = le.Proto,
                    Bytes = le.Kind == EventKind.Traffic ? le.Bytes : 0,
                });
            }

            foreach (var it in Dns.DrainStream())
            {
                DnsStream.Add(DnsRowVM.From(it, Tracker.Get(it.Pid).Name));
                while (DnsStream.Count > 400) DnsStream.RemoveAt(0);
                AddStoreRecord(new EventRecord
                {
                    TimeUtc = it.TimeUtc, Kind = EventKindEx.DnsResolve, Pid = it.Pid,
                    IdentityKey = Entities.GetProcess(it.Pid)?.IdentityKey, Domain = it.Domain, Text = it.AlertText,
                });
            }
            foreach (var a in Dns.DrainAlerts())
            {
                AddEvent(EventRowVM.FromAlert(a.Time, a.Level, a.Text));
                AddStoreRecord(new EventRecord { TimeUtc = a.Time, Kind = EventKindEx.Alert, Text = a.Text, Level = a.Level });
            }

            // 进程生命周期事件（内核 rundown/启动/退出）→ 实体库 + 事件库
            while (_procEvents.TryDequeue(out var pe))
            {
                Entities.ApplyKernelProcessEvent(pe.Start, pe.Pid, pe.Parent, pe.Image, pe.Cmd, pe.T);
                AddStoreRecord(new EventRecord
                {
                    TimeUtc = pe.T,
                    Kind = pe.Start ? EventKindEx.ProcessStart : EventKindEx.ProcessStop,
                    Pid = pe.Pid,
                    Text = pe.Start ? $"{pe.Image ?? ""} {pe.Cmd ?? ""}".Trim() : pe.Image,
                });
            }

            // 防火墙拦截审计事件（5157）
            while (_blockedEvents.TryDequeue(out var b))
            {
                _blockedConnCount++;
                var bname = b.Pid > 0 ? Tracker.Get(b.Pid).Name : "未知进程";
                AddEvent(EventRowVM.FromBlocked(b, bname));
                AddStoreRecord(new EventRecord
                {
                    TimeUtc = b.TimeUtc,
                    Kind = EventKindEx.Alert,
                    Pid = b.Pid,
                    IdentityKey = Entities.GetProcess(b.Pid)?.IdentityKey,
                    RemoteIp = b.RemoteIp,
                    RemotePort = b.RemotePort,
                    Text = $"防火墙拦截：{b.AppPath ?? bname} → {b.RemoteIp}:{b.RemotePort} ({b.Protocol})",
                    Level = RiskLevel.Medium,
                });
            }

            // P3 持久化：证据流落盘 + 基线批量刷写 + 周期清理
            Evidence.FlushIfDue();
            if (_tickCount % 8 == 0) FlushBaseline();
            if (_tickCount % 1800 == 500) _ = Task.Run(() => RunRetentionCleanup(false));
            if (_tickCount % 30 == 10) UpdateStorageInfo();
            if (_blockedConnCount > 0)
            {
                BlockedConnCountText = $"防火墙拦截 {_blockedConnCount} 条";
                Raise(nameof(BlockedConnCountText));
            }

            RebuildConnIndex();
            UpdateRows();
            UpdateDestinations();
            UpdatePorts();
            UpdateConfigCards();
            UpdateDetail();
            UpdateTop();
            UpdateStatus();
            RefreshRecentNames();

            if (_tickCount % 30 == 1) _ = Task.Run(() => Entities.RefreshServices());

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

    // ================= P3 持久化 =================

    private void AddStoreRecord(EventRecord rec)
    {
        Store.Add(rec);
        Evidence.Enqueue(rec);
    }

    /// 流量事件 → (身份, 目的地) 关系记账（域名优先；未解析身份与回环不计）
    private void OnTrafficObserved(NetEvent e)
    {
        if (e.RemoteIp == null || e.IsLoopback || e.Pid <= 0) return;
        var domain = Dns.LookupDomain(e.RemoteIp);
        Entities.NoteDestination(domain, e.RemoteIp, e.TimeUtc);
        var identityKey = Entities.GetProcess(e.Pid)?.IdentityKey;
        if (string.IsNullOrEmpty(identityKey) || identityKey!.StartsWith("unk:", StringComparison.Ordinal)) return;
        var destKey = string.IsNullOrEmpty(domain) ? $"ip:{e.RemoteIp}" : $"d:{domain.ToLowerInvariant()}";
        Entities.NoteIdentityDestTraffic(identityKey, destKey, e.IsSend, e.Bytes, e.TimeUtc);
    }

    private DateTime _lastFlushUtc = DateTime.UtcNow;

    private void FlushBaseline()
    {
        if (Settings.BaselinePaused) return;
        try
        {
            var cutoff = _lastFlushUtc;
            _lastFlushUtc = DateTime.UtcNow;
            var ids = Entities.Identities.Values
                .Where(i => i.LastSeenUtc >= cutoff && !i.Key.StartsWith("unk:", StringComparison.Ordinal)).ToList();
            var dests = Entities.Destinations.Values.Where(d => d.LastSeenUtc >= cutoff).ToList();
            var relations = Entities.DrainRelationDeltas();
            if (ids.Count == 0 && dests.Count == 0 && relations.Count == 0) return;
            Baseline.Flush(ids, dests, relations);
        }
        catch (Exception ex) { Log.Error("基线刷写调度失败", ex); }
    }

    public void RunRetentionCleanup(bool manual)
    {
        try
        {
            var cutoff = Settings.BaselineRetentionDays > 0
                ? DateTime.UtcNow.AddDays(-Settings.BaselineRetentionDays)
                : DateTime.MinValue;
            int removed = Baseline.Cleanup(cutoff);
            Evidence.Cleanup();
            UpdateStorageInfo();
            if (manual)
                MessageBox.Show($"清理完成：基线删除 {removed} 行。\n证据流保留 {Settings.EvidenceRetentionDays} 天 / 容量上限 {Settings.EvidenceMaxSizeMB} MB。",
                    "NetWatch", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { Log.Error("保留策略清理失败", ex); }
    }

    private void UpdateStorageInfo()
    {
        var (eb, ef) = Evidence.Stats();
        StorageInfo = $"基线库 {Util.FormatBytes(BaselineStore.DbSizeBytes)} · 证据 {Util.FormatBytes(eb)}（{ef} 个文件）" +
                      (Settings.BaselinePaused ? " · 基线学习已暂停" : "");
        Raise(nameof(StorageInfo));
    }

    public void SetBaselineRetention(int days) { Settings.BaselineRetentionDays = days; Settings.Save(); UpdateStorageInfo(); }
    public void SetEvidenceRetention(int days) { Settings.EvidenceRetentionDays = days; Settings.Save(); Evidence.Cleanup(); }
    public void SetEvidenceCap(int mb) { Settings.EvidenceMaxSizeMB = mb; Settings.Save(); Evidence.Cleanup(); }
    public void SetBaselinePaused(bool paused) { Settings.BaselinePaused = paused; Settings.Save(); UpdateStorageInfo(); }

    // ================= P5 处置增强：允许名单 =================

    public class TrustedAppVM
    {
        public required string Key { get; init; }
        public required string DisplayName { get; init; }
        public string Display => $"{DisplayName}   ·   {Key}";
    }

    public ObservableCollection<TrustedAppVM> TrustedApps { get; } = new();
    public TrustedAppVM? SelectedTrustedApp { get; set; }
    public bool SelectedTrusted { get; private set; }
    public RelayCommand ToggleTrustCommand { get; private set; } = null!;
    public RelayCommand RemoveTrustedCommand { get; private set; } = null!;

    public bool IsIdentityTrusted(string? key) =>
        !string.IsNullOrEmpty(key) && Settings.TrustedIdentityKeys.Contains(key);

    private void InitTrustedList()
    {
        ToggleTrustCommand = new RelayCommand(ToggleTrustForSelection);
        RemoveTrustedCommand = new RelayCommand(() =>
        {
            if (SelectedTrustedApp == null) return;
            Settings.TrustedIdentityKeys.Remove(SelectedTrustedApp.Key);
            Settings.TrustedIdentityNames.Remove(SelectedTrustedApp.Key);
            Settings.Save();
            AddSystemEvent($"已将 {SelectedTrustedApp.DisplayName} 移出允许名单");
            RefreshTrustedApps();
        });
        RefreshTrustedApps();
    }

    private void RefreshTrustedApps()
    {
        TrustedApps.Clear();
        foreach (var k in Settings.TrustedIdentityKeys)
            TrustedApps.Add(new TrustedAppVM
            {
                Key = k,
                DisplayName = Settings.TrustedIdentityNames.TryGetValue(k, out var n) ? n : k,
            });
    }

    public void ToggleTrustForSelection()
    {
        var row = _selected;
        if (row == null) return;
        var key = Entities.GetProcess(row.Pid)?.IdentityKey;
        if (string.IsNullOrEmpty(key) || key.StartsWith("unk:", StringComparison.Ordinal))
        {
            MessageBox.Show("该进程尚无稳定身份（路径未解析），无法加入允许名单。", "提示",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var name = Entities.GetIdentity(key)?.DisplayName ?? Tracker.Get(row.Pid).Name;
        if (IsIdentityTrusted(key))
        {
            Settings.TrustedIdentityKeys.Remove(key);
            Settings.TrustedIdentityNames.Remove(key);
            Settings.Save();
            AddSystemEvent($"已将 {name} 移出允许名单（恢复引擎判定）");
        }
        else
        {
            Settings.TrustedIdentityKeys.Add(key);
            Settings.TrustedIdentityNames[key] = name;
            Settings.Save();
            AddSystemEvent($"已将 {name} 加入允许名单——判定将显示为正常，可随时撤销");
        }
        RefreshTrustedApps();
        UpdateDetail();
    }

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

            Entities.ApplyProcessEntry(entry);   // 实体库登记（身份/实例）

            // 跨会话“首见于”回填（每个身份只查一次库）
            var identityKey = Entities.GetProcess(pid)?.IdentityKey;
            if (!string.IsNullOrEmpty(identityKey) && !identityKey.StartsWith("unk:", StringComparison.Ordinal)
                && _firstSeenQueried.Add(identityKey))
            {
                var id = Entities.GetIdentity(identityKey);
                if (id != null) _ = Task.Run(() => Baseline.BackfillIdentity(id));
            }

            var verdict = AnalysisEngine.Evaluate(entry, stats, _session.Elapsed,
                userTrusted: IsIdentityTrusted(identityKey));
            entry.FirewallBlocked = entry.Path != null && _blockedPaths.Contains(entry.Path);
            _verdictsByPid[pid] = verdict;

            if (!_rowsByPid.TryGetValue(pid, out var row))
            {
                row = new ProcessRowVM();
                _rowsByPid[pid] = row;
                Rows.Add(row);
            }
            row.Update(entry, stats, _connsByPid.TryGetValue(pid, out var cl) ? cl.Count : 0, verdict);
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

        // P1 关联信息：父进程 / 命令行 / 所属服务 / 软件身份
        var inst = Entities.GetProcess(entry.Pid);
        DetailParent = inst?.ParentPid is { } pp
            ? $"PID {pp}" + (Entities.GetProcess(pp)?.Name is { } pn ? $" · {pn}" : "")
            : "未知（内核 rundown 未覆盖该进程时不可得）";
        DetailCmdLine = inst?.CommandLine ?? "（未采集到）";
        DetailUser = _userByPid.TryGetValue(entry.Pid, out var u) ? u
            : (Sysmon.Available ? "（暂无 Sysmon 网络事件记录）" : "（需安装 Sysmon 后可用）");
        var svcs = Entities.ServicesOf(entry.Pid);
        DetailServices = svcs.Count == 0
            ? "（非服务宿主，或服务枚举尚未完成）"
            : string.Join("、", svcs.Select(s => s.DisplayName == s.Name ? s.Name : $"{s.Name} ({s.DisplayName})"));
        var id = Entities.GetIdentity(inst?.IdentityKey);
        DetailIdentity = id == null
            ? "未知"
            : $"{id.Kind switch { IdentityKind.Signed => "签名身份", IdentityKind.PathOnly => "路径身份", IdentityKind.SystemReserved => "系统保留", IdentityKind.Packaged => "打包应用", _ => "未知" }} · {id.DisplayName}" +
              (id.Kind == IdentityKind.Signed && id.CertSubject != null ? $" · {id.CertSubject}" : "") +
              (id.Kind != IdentityKind.SystemReserved ? $" · 首见于 {id.FirstSeenUtc.ToLocalTime():MM-dd HH:mm}" : "");

        (DetailSignature, DetailSignatureBrush) = entry.Signature switch
        {
            SignatureState.Valid => (entry.SignatureSubject == null ? "签名有效" : $"签名有效 · {entry.SignatureSubject}", UiBrushes.Green),
            SignatureState.Unsigned => ("未签名", UiBrushes.Amber),
            SignatureState.Untrusted => ($"签名不受信任{(entry.SignatureSubject == null ? "" : $" · {entry.SignatureSubject}")}（自签名/未知发布者）", UiBrushes.Amber),
            SignatureState.Invalid => ("签名无效——文件可能在签名后被篡改", UiBrushes.Red),
            _ => ("未检测（分析中或路径未知）", UiBrushes.Dim),
        };

        DetailRisks.Clear();
        var verdict = _verdictsByPid.TryGetValue(row.Pid, out var vv) ? vv : null;
        if (verdict == null)
        {
            DetailVerdict = "分析中…";
            DetailVerdictBrush = UiBrushes.Dim;
            DetailRisks.Add("（分析尚未完成）");
        }
        else
        {
            DetailVerdict = $"[{verdict.Status switch { VerdictStatus.HighRisk => "高风险", VerdictStatus.Attention => "值得关注", VerdictStatus.Unknown => "未知", _ => "正常" }}] {verdict.Summary}";
            DetailVerdictBrush = verdict.Status switch
            {
                VerdictStatus.HighRisk => UiBrushes.Red,
                VerdictStatus.Attention => UiBrushes.Amber,
                VerdictStatus.Unknown => UiBrushes.Dim,
                _ => UiBrushes.Green,
            };
            if (verdict.Evidence.Count == 0) DetailRisks.Add("无独立证据项。判定依据：签名与位置信息（见上方签名/路径）");
            else foreach (var ev in verdict.Evidence)
            {
                DetailRisks.Add($"• {ev.Statement}" +
                    (ev.Basis != null ? $"\n   依据：{ev.Basis}" : "") +
                    (ev.Caveat != null ? $"\n   误报可能/说明：{ev.Caveat}" : ""));
            }
        }

        DetailDns.Clear();
        var doms = Dns.RecentDomains(entry.Pid);
        if (doms.Count == 0) DetailDns.Add("（无解析记录）");
        else foreach (var d in doms) DetailDns.Add(d);

        SelectedConns.Clear();
        if (_connsByPid.TryGetValue(row.Pid, out var conns))
            foreach (var c in conns) SelectedConns.Add(ConnRowVM.From(c, Dns));

        SelectedTrusted = IsIdentityTrusted(inst?.IdentityKey);
        Raise(nameof(SelectedTrusted));

        RaiseAll(nameof(DetailName), nameof(DetailCompany), nameof(DetailPid), nameof(DetailPath),
            nameof(DetailSignature), nameof(DetailSignatureBrush), nameof(DetailIcon),
            nameof(DetailParent), nameof(DetailCmdLine), nameof(DetailServices), nameof(DetailIdentity),
            nameof(DetailVerdict), nameof(DetailVerdictBrush), nameof(DetailUser));
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
            if (flagged > 0) parts.Add($"{flagged} 个进程存在值得关注的行为（详见总览标色与详情面板，提示 ≠ 确诊）");
            if (alerts > 0) parts.Add($"{alerts} 条 DNS/配置提示（见 DNS 安全页与事件流）");
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
        FlushBaseline();
        Evidence.FlushIfDue();
        Audit.Dispose();
        Sysmon.Dispose();
        Monitor.Dispose();
        Config.Dispose();
        Tracker.Dispose();
    }
}
