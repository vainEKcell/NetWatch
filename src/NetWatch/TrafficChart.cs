using System.Globalization;
using System.Windows;
using System.Windows.Media;
using NetWatch.Services;

namespace NetWatch;

/// 120 秒上/下行速率迷你走势图（自绘，颜色随主题）
public sealed class TrafficChart : FrameworkElement
{
    private const int N = 120;
    private readonly double[] _up = new double[N];
    private readonly double[] _down = new double[N];

    public void Push(double up, double down)
    {
        Array.Copy(_up, 1, _up, 0, N - 1); _up[N - 1] = up;
        Array.Copy(_down, 1, _down, 0, N - 1); _down[N - 1] = down;
        InvalidateVisual();
    }

    private static SolidColorBrush Res(string key) =>
        Application.Current?.TryFindResource(key) as SolidColorBrush ?? new SolidColorBrush(Colors.Gray);

    private static Pen MakePen(Brush b, double t) => new(b, t) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        if (w <= 1 || h <= 1 || double.IsNaN(w) || double.IsNaN(h)) return;

        var bg = Res("BgBrush");
        var label = Res("DimBrush");
        var gridBrush = Res("LineBrush");
        var upBrush = Res("GreenBrush");
        var downBrush = Res("BlueBrush");

        var gridPen = MakePen(gridBrush, 1);
        var upPen = MakePen(upBrush, 1.6);
        var downPen = MakePen(downBrush, 1.6);
        var fillUp = new SolidColorBrush(Color.FromArgb(0x30, upBrush.Color.R, upBrush.Color.G, upBrush.Color.B));
        var fillDown = new SolidColorBrush(Color.FromArgb(0x30, downBrush.Color.R, downBrush.Color.G, downBrush.Color.B));

        dc.DrawRectangle(bg, null, new Rect(0, 0, w, h));
        dc.DrawLine(gridPen, new Point(0, h / 2), new Point(w, h / 2));

        double max = 1024;
        foreach (var v in _up) max = Math.Max(max, v);
        foreach (var v in _down) max = Math.Max(max, v);
        max *= 1.15;

        DrawSeries(dc, _down, w, h, max, downPen, fillDown);
        DrawSeries(dc, _up, w, h, max, upPen, fillUp);

        var ft = new FormattedText(
            L10n.T("chart.peak", Util.FormatSpeed(max / 1.15)),
            CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
            new Typeface("Microsoft YaHei UI"), 9, label, 1.25);
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
}
