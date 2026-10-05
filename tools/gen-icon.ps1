# 生成应用图标 Assets\app.ico
# 设计：深空渐变圆角底 + 金属蓝盾牌 + 流量脉冲线（ECG 风格），256px 绘制，含 256/48/32/16 四档
# 用法: powershell -ExecutionPolicy Bypass -File tools\gen-icon.ps1
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$outFile = Join-Path $PSScriptRoot '..\src\NetWatch\Assets\app.ico'
New-Item -ItemType Directory -Force -Path (Split-Path $outFile) | Out-Null

$S = 256
$bmp = New-Object System.Drawing.Bitmap $S, $S
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = 'AntiAlias'
$g.PixelOffsetMode = 'HighQuality'

function New-RoundedRectPath([float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $r * 2
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    return $p
}

# ---- 1. 背景：深空纵向渐变圆角方 ----
$bgPath = New-RoundedRectPath 8 8 240 240 56
$bgRect = New-Object System.Drawing.Rectangle 0, 0, 256, 256
$bgBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    $bgRect,
    [System.Drawing.Color]::FromArgb(255, 30, 42, 68),
    [System.Drawing.Color]::FromArgb(255, 10, 14, 22),
    [System.Drawing.Drawing2D.LinearGradientMode]::Vertical)
$g.FillPath($bgBrush, $bgPath)
$borderPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 72, 96, 140)), 4
$g.DrawPath($borderPen, $bgPath)

# ---- 2. 盾牌：蓝灰渐变 + 亮蓝描边 ----
$shield = New-Object System.Drawing.Drawing2D.GraphicsPath
$shield.AddLines([System.Drawing.PointF[]]@(
    (New-Object System.Drawing.PointF 58, 52),
    (New-Object System.Drawing.PointF 198, 52),
    (New-Object System.Drawing.PointF 198, 116)
))
$shield.AddBezier(
    (New-Object System.Drawing.PointF 198, 116),
    (New-Object System.Drawing.PointF 196, 166),
    (New-Object System.Drawing.PointF 170, 198),
    (New-Object System.Drawing.PointF 128, 214))
$shield.AddBezier(
    (New-Object System.Drawing.PointF 128, 214),
    (New-Object System.Drawing.PointF 86, 198),
    (New-Object System.Drawing.PointF 60, 166),
    (New-Object System.Drawing.PointF 58, 116))
$shield.CloseFigure()

$shRect = New-Object System.Drawing.Rectangle 0, 40, 256, 190
$shBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    $shRect,
    [System.Drawing.Color]::FromArgb(255, 52, 74, 116),
    [System.Drawing.Color]::FromArgb(255, 20, 30, 48),
    [System.Drawing.Drawing2D.LinearGradientMode]::Vertical)
$g.FillPath($shBrush, $shield)
$shieldPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 122, 176, 255)), 6
$shieldPen.LineJoin = 'Round'
$g.DrawPath($shieldPen, $shield)

# 内衬细描边（层次感）
$innerPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(70, 160, 200, 255)), 2
$g.DrawPath($innerPen, $shield)

# ---- 3. 流量脉冲线（青绿 ECG，先辉光后亮线） ----
$pts = [System.Drawing.PointF[]]@(
    (New-Object System.Drawing.PointF 76, 138),
    (New-Object System.Drawing.PointF 106, 138),
    (New-Object System.Drawing.PointF 121, 104),
    (New-Object System.Drawing.PointF 140, 172),
    (New-Object System.Drawing.PointF 155, 138),
    (New-Object System.Drawing.PointF 184, 138)
)
$glow = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(70, 76, 232, 160)), 12
$glow.LineJoin = 'Round'; $glow.StartCap = 'Round'; $glow.EndCap = 'Round'
$g.DrawLines($glow, $pts)
$line = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 96, 244, 168)), 5
$line.LineJoin = 'Round'; $line.StartCap = 'Round'; $line.EndCap = 'Round'
$g.DrawLines($line, $pts)

# ---- 4. 顶部小信号点（雷达扫描感） ----
$dot = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 122, 176, 255))
$g.FillEllipse($dot, 118, 66, 20, 20)
$halo = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(90, 122, 176, 255)), 3
$g.DrawEllipse($halo, 112, 60, 32, 32)

# ---- 5. 多尺寸输出（256/48/32/16） ----
$sizes = @(256, 48, 32, 16)
$pngs = @()
foreach ($sz in $sizes) {
    if ($sz -eq 256) { $src = $bmp } else {
        $src = New-Object System.Drawing.Bitmap $sz, $sz
        $gs = [System.Drawing.Graphics]::FromImage($src)
        $gs.InterpolationMode = 'HighQualityBicubic'
        $gs.DrawImage($bmp, 0, 0, $sz, $sz)
        $gs.Dispose()
    }
    $ms = New-Object System.IO.MemoryStream
    $src.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngs += , @{ Size = $sz; Data = $ms.ToArray() }
    if ($sz -ne 256) { $src.Dispose() }
}

$fs = [System.IO.File]::Create($outFile)
$bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$pngs.Count)
$offset = 6 + 16 * $pngs.Count
foreach ($e in $pngs) {
    $szByte = if ($e.Size -eq 256) { 0 } else { $e.Size }
    $bw.Write([byte]$szByte); $bw.Write([byte]$szByte)
    $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32)
    $bw.Write([uint32]$e.Data.Length); $bw.Write([uint32]$offset)
    $offset += $e.Data.Length
}
foreach ($e in $pngs) { $bw.Write($e.Data) }
$bw.Close(); $fs.Close()

Write-Output "图标已生成: $outFile（256/48/32/16 四档）"
