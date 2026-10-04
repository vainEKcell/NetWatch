using System.Globalization;
using System.Windows;
using System.Windows.Media;
using NetWatch.Services;

namespace NetWatch;

/// 120 秒上/下行速率迷你走势图（自绘，零第三方依赖）
public sealed class TrafficChart : FrameworkElement
{
    private const int N = 120;
    private readonly double[] _up = new double[N];
    private readonly double[] _down = new double[N];

    private static readonly Pen GridPen = MakePen(new SolidColorBrush(Color.FromRgb(0x22, 0x2B, 0x3A)), 1);
    private static readonly Pen UpPen = MakePen(new SolidColorBrush(Color.FromRgb(0x4C, 0xC8, 0x78)), 1.6);
    private static readonly Pen DownPen = MakePen(new SolidColorBrush(Color.FromRgb(0x46, 0xA0, 0xFF)), 1.6);
    private static readonly Brush FillUp = MakeBrush(Color.FromArgb(0x30, 0x4C, 0xC8, 0x78));
    private static readonly Brush FillDown = MakeBrush(Color.FromArgb(0x30, 0x46, 0xA0, 0xFF));
    private static readonly Brush Bg = MakeBrush(Color.FromRgb(0x0D, 0x11, 0x18));
    private static readonly Brush Label = MakeBrush(Color.FromRgb(0x8B, 0x95, 0xA7));

    public void Push(double up, double down)
    {
        Array.Copy(_up, 1, _up, 0, N - 1); _up[N - 1] = up;
        Array.Copy(_down, 1, _down, 0, N - 1); _down[N - 1] = down;
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        if (w <= 1 || h <= 1 || double.IsNaN(w) || double.IsNaN(h)) return;

        dc.DrawRectangle(Bg, null, new Rect(0, 0, w, h));
        dc.DrawLine(GridPen, new Point(0, h / 2), new Point(w, h / 2));

        double max = 1024;
        foreach (var v in _up) max = Math.Max(max, v);
        foreach (var v in _down) max = Math.Max(max, v);
        max *= 1.15;

        DrawSeries(dc, _down, w, h, max, DownPen, FillDown);
        DrawSeries(dc, _up, w, h, max, UpPen, FillUp);

        var ft = new FormattedText(
            $"峰值 {Util.FormatSpeed(max / 1.15)}",
            CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
            new Typeface("Microsoft YaHei UI"), 9, Label, 1.25);
        dc.DrawText(ft, new Point(4, 1));
    }

    private static void DrawSeries(DrawingContext dc, double[] data, double w, double h, double max, Pen pen, Brush fill)
    {
        double top = 3, bottom = h - 3;
        var line = new StreamGeometry();
        var area = new StreamGeometry();

        using (var lc = line.Open())
        using (var ac = area.Open())
        {
            bool first = true;
            for (int i = 0; i < N; i++)
            {
                double x = i * w / (N - 1);
                double y = bottom - (data[i] / max) * (bottom - top);
                if (first) { lc.BeginFigure(new Point(x, y), false, false); ac.BeginFigure(new Point(x, bottom), true, true); first = false; }
                else { lc.LineTo(new Point(x, y), true, false); ac.LineTo(new Point(x, y), true, false); }
            }
            ac.LineTo(new Point(w, bottom), true, false);
            ac.LineTo(new Point(0, bottom), true, false);
        }
        line.Freeze();
        area.Freeze();
        dc.DrawGeometry(fill, null, area);
        dc.DrawGeometry(null, pen, line);
    }

    private static Pen MakePen(Brush b, double t)
    {
        b.Freeze();
        var p = new Pen(b, t);
        p.Freeze();
        return p;
    }

    private static Brush MakeBrush(Color c)
    {
        var b = new SolidColorBrush(c);
        b.Freeze();
        return b;
    }
}
