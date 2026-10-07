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

    // ---------- 本地化：DataGrid 列头绑定用索引器 ----------
    public string this[string key] => L10n.T(key);

    /// 语言切换后通知所有 [key] 绑定刷新，并重算非 tick 驱动的状态文本
    public void OnLanguageChanged()
    {
        Raise("Item[]");
        UpdateAuditStatus();
        UpdateStorageInfo();
    }

    public string Language
    {
        get => Settings.Language;
        set
        {
            if (Settings.Language == value) return;
            Settings.Language = value;
            Settings.Save();
            L10n.Apply(value);
            OnLanguageChanged();
        }
    }

    public string AppVersion =>
        "NetWatch v" + (System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1.1");

    public string Theme
    {
        get => Settings.Theme;
        set
        {
            if (Settings.Theme == value) return;
            Settings.Theme = value;
            Settings.Save();
            ThemeService.Apply(value);
        }
    }

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
        KillCommand = new RelayCommand(KillSelectedProcess);
        TaskMgrCommand = new RelayCommand(OpenTaskManager);
        CopyPidCommand = new RelayCommand(CopySelectedPid);
        StopServicesCommand = new RelayCommand(StopSelectedServices);
        DisableServicesCommand = new RelayCommand(DisableSelectedServices);

        Monitor.Start();
        RefreshBlocked();
        InitAudit();
        InitSysmon();
        DohStatusText = L10n.T("doh.idle");
        Raise(nameof(DohStatusText));
        AddSystemEvent(L10n.T("sys.started"));
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
        AuditStatusText = (s || f) ? L10n.T("cfg.auditOn") : L10n.T("cfg.auditOff");
        SysmonStatusText = Sysmon.Available ? L10n.T("cfg.sysmonOn") : L10n.T("cfg.sysmonOff");
        RaiseAll(nameof(AuditStatusText), nameof(SysmonStatusText));
    }

    public void EnableFirewallAudit()
    {
        var r = MessageBox.Show(L10n.T("msg.confirmAudit"), "NetWatch",
            MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (r != MessageBoxResult.Yes) return;
        if (FirewallAuditWatcher.EnableAudit())
        {
            Audit.Start(OnBlockedConnection);
            UpdateAuditStatus();
            AddSystemEvent(L10n.T("sys.auditOn"));
        }
        else
            MessageBox.Show(L10n.T("msg.auditFail"), "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error);
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
    public RelayCommand KillCommand { get; private set; } = null!;
    public RelayCommand TaskMgrCommand { get; private set; } = null!;
    public RelayCommand CopyPidCommand { get; private set; } = null!;
    public RelayCommand StopServicesCommand { get; private set; } = null!;
    public RelayCommand DisableServicesCommand { get; private set; } = null!;

    /// P2 调查联动：UI 订阅后切到事件流页
    public event Action? NavigateToEventsRequested;

    public void TogglePause()
    {
        Paused = !Paused;
        Raise(nameof(Paused));
        AddSystemEvent(Paused ? L10n.T("sys.paused") : L10n.T("sys.resumed"));
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
    public string TrayText { get; private set; } = "NetWatch";
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
            MessageBox.Show(L10n.T("msg.intelFail", ex.Message), "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error);
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
    public string DohStatusText { get; private set; } = "";

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
                    Text = $"{L10n.T("kind.fwBlock")}: {b.AppPath ?? bname} → {Util.FormatEndpoint(b.RemoteIp, b.RemotePort)} ({b.Protocol})",
                    Level = RiskLevel.Medium,
                });
            }

            // P3 持久化：证据流落盘 + 基线批量刷写 + 周期清理
            Evidence.FlushIfDue();
            if (_tickCount % 8 == 0) FlushBaseline();
            if (_tickCount % 1800 == 500) _ = Task.Run(() => RunRetentionCleanup(false));
            if (_tickCount % 30 == 10) UpdateStorageInfo();
            if (_tickCount % 30 == 20 && Settings.Theme == "auto") ThemeService.Apply("auto"); // 跟随系统主题的周期校准
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
                MessageBox.Show(L10n.T("msg.cleanupDone", removed, Settings.EvidenceRetentionDays, Settings.EvidenceMaxSizeMB),
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
            MessageBox.Show(L10n.T("msg.noIdentity"), "NetWatch",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var name = Entities.GetIdentity(key)?.DisplayName ?? Tracker.Get(row.Pid).Name;
        if (IsIdentityTrusted(key))
        {
            Settings.TrustedIdentityKeys.Remove(key);
            Settings.TrustedIdentityNames.Remove(key);
            Settings.Save();
            AddSystemEvent(L10n.T("sys.untrusted", name));
        }
        else
        {
            Settings.TrustedIdentityKeys.Add(key);
            Settings.TrustedIdentityNames[key] = name;
            Settings.Save();
            AddSystemEvent(L10n.T("sys.trusted", name));
        }
        RefreshTrustedApps();
        UpdateDetail();
    }

    // ================= 进程处置：结束进程 / 任务管理器 / 服务 =================

    public void KillSelectedProcess()
    {
        var row = _selected;
        if (row == null) return;
        var entry = Tracker.Get(row.Pid);
        if (MessageBox.Show(L10n.T("msg.confirmKill", entry.Name, entry.Pid), "NetWatch",
                MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        try
        {
            using var p = Process.GetProcessById(row.Pid);
            p.Kill();
            p.WaitForExit(3000);
            AddSystemEvent(L10n.T("sys.processKilled", entry.Name, entry.Pid));
        }
        catch (Exception ex)
        {
            MessageBox.Show(L10n.T("msg.killFail", ex.Message), "NetWatch",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    public void OpenTaskManager()
    {
        try { Process.Start(new ProcessStartInfo("taskmgr.exe") { UseShellExecute = true }); }
        catch (Exception ex) { MessageBox.Show(ex.Message, "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    public void CopySelectedPid()
    {
        if (_selected == null) return;
        try { Clipboard.SetText(_selected.Pid.ToString()); } catch { }
    }

    public void StopSelectedServices()
    {
        var row = _selected;
        if (row == null) return;
        var svcs = Entities.ServicesOf(row.Pid);
        if (svcs.Count == 0)
        {
            MessageBox.Show(L10n.T("msg.noServices"), "NetWatch", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var list = string.Join("\n", svcs.Select(s => $"{s.Name} ({s.DisplayName})"));
        if (MessageBox.Show(L10n.T("msg.confirmStopServices", list), "NetWatch",
                MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        var stopped = new List<string>();
        foreach (var s in svcs)
        {
            var (ok, _) = RunSc($"stop \"{s.Name}\"");
            if (ok) stopped.Add(s.Name);
            AddSystemEvent(L10n.T("sys.serviceStopped", s.Name));
        }
        if (stopped.Count > 0)
            MessageBox.Show(L10n.T("sys.serviceStopped", string.Join(", ", stopped)), "NetWatch",
                MessageBoxButton.OK, MessageBoxImage.Information);
    }

    public void DisableSelectedServices()
    {
        var row = _selected;
        if (row == null) return;
        var svcs = Entities.ServicesOf(row.Pid);
        if (svcs.Count == 0)
        {
            MessageBox.Show(L10n.T("msg.noServices"), "NetWatch", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var list = string.Join("\n", svcs.Select(s => $"{s.Name} ({s.DisplayName})"));
        if (MessageBox.Show(L10n.T("msg.confirmDisableServices", list), "NetWatch",
                MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        foreach (var s in svcs)
        {
            RunSc($"config \"{s.Name}\" start= disabled");
            AddSystemEvent(L10n.T("sys.serviceDisabled", s.Name));
        }
    }

    private static (bool Ok, string Output) RunSc(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("sc.exe", args)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true,
            };
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(10000);
            return (p.ExitCode == 0, output);
        }
        catch (Exception ex) { Log.Error("sc.exe 执行失败", ex); return (false, ""); }
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
        DetailPid = $"PID {entry.Pid} · {(entry.Exited ? L10n.T("common.exitedShort") : L10n.T("common.running"))}" +
                    (entry.StartTimeUtc != null ? $" · {L10n.T("common.started", entry.StartTimeUtc.Value.ToLocalTime().ToString("MM-dd HH:mm:ss"))}" : "");
        DetailPath = entry.Path ?? L10n.T("d.pathUnavailable");
        DetailIcon = entry.Icon;

        // P1 关联信息：父进程 / 命令行 / 所属服务 / 软件身份
        var inst = Entities.GetProcess(entry.Pid);
        DetailParent = inst?.ParentPid is { } pp
            ? $"PID {pp}" + (Entities.GetProcess(pp)?.Name is { } pn ? $" · {pn}" : "")
            : L10n.T("d.parentUnknown");
        DetailCmdLine = inst?.CommandLine ?? L10n.T("d.cmdNone");
        DetailUser = _userByPid.TryGetValue(entry.Pid, out var u) ? u
            : (Sysmon.Available ? L10n.T("d.userNoRecord") : L10n.T("d.userNeedSysmon"));
        var svcs = Entities.ServicesOf(entry.Pid);
        DetailServices = svcs.Count == 0
            ? L10n.T("d.noServices")
            : string.Join("、", svcs.Select(s => s.DisplayName == s.Name ? s.Name : $"{s.Name} ({s.DisplayName})"));
        var id = Entities.GetIdentity(inst?.IdentityKey);
        DetailIdentity = id == null
            ? L10n.T("common.unknown")
            : $"{L10n.T(id.Kind switch { IdentityKind.Signed => "id.signed", IdentityKind.PathOnly => "id.pathOnly", IdentityKind.SystemReserved => "id.sysReserved", IdentityKind.Packaged => "id.packaged", _ => "common.unknown" })} · {id.DisplayName}" +
              (id.Kind == IdentityKind.Signed && id.CertSubject != null ? $" · {id.CertSubject}" : "") +
              (id.Kind != IdentityKind.SystemReserved ? $" · {L10n.T("common.firstSeen", id.FirstSeenUtc.ToLocalTime().ToString("MM-dd HH:mm"))}" : "");

        (DetailSignature, DetailSignatureBrush) = entry.Signature switch
        {
            SignatureState.Valid => (entry.SignatureSubject == null ? L10n.T("sig.valid") : $"{L10n.T("sig.valid")} · {entry.SignatureSubject}", UiBrushes.Green),
            SignatureState.Unsigned => (L10n.T("sig.unsigned"), UiBrushes.Amber),
            SignatureState.Untrusted => ($"{L10n.T("sig.untrusted")}{(entry.SignatureSubject == null ? "" : $" · {entry.SignatureSubject}")} {L10n.T("sig.untrustedSuffix")}", UiBrushes.Amber),
            SignatureState.Invalid => (L10n.T("sig.invalid"), UiBrushes.Red),
            _ => (L10n.T("sig.unknown"), UiBrushes.Dim),
        };

        DetailRisks.Clear();
        var verdict = _verdictsByPid.TryGetValue(row.Pid, out var vv) ? vv : null;
        if (verdict == null)
        {
            DetailVerdict = L10n.T("d.analyzing");
            DetailVerdictBrush = UiBrushes.Dim;
            DetailRisks.Add(L10n.T("d.analyzing"));
        }
        else
        {
            DetailVerdict = $"[{L10n.T(verdict.Status switch { VerdictStatus.HighRisk => "verdict.highrisk", VerdictStatus.Attention => "verdict.attention", VerdictStatus.Unknown => "verdict.unknown", _ => "verdict.normal" })}] {verdict.Summary}";
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
        DnsServersText = snap.AllDns.Length == 0 ? L10n.T("cfg.none") : string.Join("　", snap.AllDns);
        ProxyText = snap.ProxyText;
        WinHttpText = snap.WinHttpText;
        HostsText = L10n.T("cfg.entries", snap.Hosts.Count,
            snap.HostsModified == default ? "—" : snap.HostsModified.ToString("MM-dd HH:mm"));

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

        DnsAlertCountText = L10n.T("st.dnsAlerts", Dns.AlertCount + _seriousConfigCount);
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
        ConnCountText = L10n.T("st.connCount", _latestConns.Count(c => HideLoopback || !c.IsLoopback));
        BlockedCountText = L10n.T("st.blockedCount", _blockedPaths.Count);

        var flagged = 0;
        foreach (var r in Rows) if (r.RiskByte >= 2) flagged++;
        var alerts = Dns.AlertCount + _seriousConfigCount;
        if (flagged > 0 || alerts > 0)
        {
            var parts = new List<string>();
            if (flagged > 0) parts.Add(L10n.T(flagged == 1 ? "banner.flagged1" : "banner.flagged", flagged));
            if (alerts > 0) parts.Add(L10n.T(alerts == 1 ? "banner.dns1" : "banner.dns", alerts));
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
            StatusText = L10n.T("st.error", Monitor.LastError);
            StatusBrush = UiBrushes.Red;
        }
        else if (Monitor.Running)
        {
            StatusText = Paused ? L10n.T("st.paused") : L10n.T("st.running", Agg.EventCount);
            StatusBrush = Paused ? UiBrushes.Amber : UiBrushes.Green;
        }
        else
        {
            StatusText = L10n.T("st.starting");
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
            MessageBox.Show(L10n.T("msg.noPath"), "NetWatch",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var name = Path.GetFileName(path);
        bool sharedHost = string.Equals(path, Path.Combine(Environment.SystemDirectory, "svchost.exe"), StringComparison.OrdinalIgnoreCase);
        string msg = sharedHost
            ? L10n.T("msg.confirmBlockShared", name)
            : L10n.T("msg.confirmBlock", name, path);
        if (MessageBox.Show(msg, "NetWatch", MessageBoxButton.YesNo,
                sharedHost ? MessageBoxImage.Warning : MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;

        try
        {
            Firewall.BlockApp(path!, name);
            RefreshBlocked();
            AddSystemEvent(L10n.T("sys.blockedApp", name));
        }
        catch (Exception ex)
        {
            MessageBox.Show(L10n.T("msg.blockFail", ex.Message), "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    public void UnblockSelectedRow()
    {
        if (_selected == null) return;
        UnblockAppByPath(Tracker.Get(_selected.Pid).Path);
    }

    public void UnblockAppByPath(string? path)
    {
        if (string.IsNullOrEmpty(path)) { MessageBox.Show(L10n.T("msg.noPathShort"), "NetWatch"); return; }
        try
        {
            Firewall.UnblockApp(path);
            RefreshBlocked();
            AddSystemEvent(L10n.T("sys.unblockedApp", Path.GetFileName(path)));
        }
        catch (Exception ex)
        {
            MessageBox.Show(L10n.T("msg.unblockFail", ex.Message), "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error);
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
                    RulesText = L10n.T("rules.count", g.Count()),
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
        var verdict = _verdictsByPid.TryGetValue(row.Pid, out var vv) ? vv : null;
        var sb = new StringBuilder();
        sb.AppendLine($"{L10n.T("cd.process")}: {entry.Name} (PID {entry.Pid})");
        sb.AppendLine($"{L10n.T("cd.vendor")}: {entry.Company ?? L10n.T("common.unknown")}   {L10n.T("cd.desc")}: {entry.Description ?? L10n.T("common.unknown")}");
        sb.AppendLine($"{L10n.T("cd.path")}: {entry.Path ?? L10n.T("common.unknown")}");
        sb.AppendLine($"{L10n.T("cd.signature")}: {DetailSignature}");
        sb.AppendLine($"{L10n.T("cd.risk")}: {(verdict == null ? L10n.T("d.analyzing") : verdict.Summary)}");
        sb.AppendLine($"{L10n.T("cd.up")}: {Util.FormatBytes(row.UpTotalBytes)}   {L10n.T("cd.down")}: {Util.FormatBytes(row.DownTotalBytes)}");
        if (_connsByPid.TryGetValue(row.Pid, out var conns))
        {
            sb.AppendLine(L10n.T("cd.conns") + ":");
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
            MessageBox.Show(L10n.T("msg.noPathShort"), "NetWatch", MessageBoxButton.OK, MessageBoxImage.Information);
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
            AddSystemEvent(L10n.T("sys.exported", dlg.FileName));
        }
        catch (Exception ex)
        {
            MessageBox.Show(L10n.T("msg.exportFail", ex.Message), "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error);
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
        DohStatusText = L10n.T("doh.running");
        RaiseAll(nameof(DohRunning), nameof(DohStatusText));
        try
        {
            var progress = new Progress<string>(s => { DohStatusText = s; Raise(nameof(DohStatusText)); });
            var results = await DnsCheck.RunAsync(domains, url, progress);
            DohResults.Clear();
            foreach (var r in results) DohResults.Add(new DohResultVM(r));
            DohStatusText = L10n.T("doh.done");
        }
        catch (Exception ex)
        {
            DohStatusText = L10n.T("msg.exportFail", ex.Message);
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
