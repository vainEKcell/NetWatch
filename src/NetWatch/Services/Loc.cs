using System.ComponentModel;

namespace NetWatch.Services;

/// 供 DataGridColumn 等不在可视树中的元素绑定本地化字符串（列头）。
/// 用法：Header="{Binding [col.process], Source={StaticResource Loc}}"
public sealed class Loc : INotifyPropertyChanged
{
    public static Loc Instance { get; } = new();
    private Loc() { }

    public string this[string key] => L10n.T(key);

    public event PropertyChangedEventHandler? PropertyChanged;

    public void Refresh() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
}
