using System.Collections.ObjectModel;
using System.Windows.Input;

namespace NetWatch.ViewModels;

public sealed class RelayCommand : ICommand
{
    private readonly Action _exec;
    private readonly Func<bool>? _canExec;

    public RelayCommand(Action exec, Func<bool>? canExec = null)
    {
        _exec = exec;
        _canExec = canExec;
    }

    public bool CanExecute(object? parameter) => _canExec?.Invoke() ?? true;
    public void Execute(object? parameter) => _exec();
    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}

/// 把“每秒快照”同步进 ObservableCollection：新增/删除/更新，不整表重建，保留选中态
public static class CollSync
{
    public static void Sync<TKey, TVm>(
        ObservableCollection<TVm> coll,
        Dictionary<TKey, TVm> map,
        IEnumerable<TKey> keys,
        Func<TKey, TVm> create,
        Action<TKey, TVm> fill)
        where TKey : notnull
        where TVm : class
    {
        var seen = new HashSet<TKey>();
        foreach (var k in keys)
        {
            seen.Add(k);
            if (!map.TryGetValue(k, out var vm))
            {
                vm = create(k);
                map[k] = vm;
                coll.Add(vm);
            }
            fill(k, vm);
        }
        foreach (var kv in map.Where(x => !seen.Contains(x.Key)).ToList())
        {
            coll.Remove(kv.Value);
            map.Remove(kv.Key);
        }
    }

    /// 基于 Move 的排序：不重建元素，尽量保留选中与虚拟化
    public static void Sort<T>(ObservableCollection<T> coll, Comparison<T> cmp, bool desc)
    {
        var sorted = coll.ToList();
        sorted.Sort(cmp);
        if (desc) sorted.Reverse();
        for (int i = 0; i < sorted.Count; i++)
        {
            int cur = coll.IndexOf(sorted[i]);
            if (cur != i) coll.Move(cur, i);
        }
    }
}
