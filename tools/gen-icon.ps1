# 生成应用图标 Assets\app.ico（深色圆角底 + 上传/下载箭头）
# 用法: powershell -ExecutionPolicy Bypass -File tools\gen-icon.ps1
# 兼容 PowerShell 5.1（不使用三元运算符）
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$outFile = Join-Path $PSScriptRoot '..\src\NetWatch\Assets\app.ico'
New-Item -ItemType Directory -Force -Path (Split-Path $outFile) | Out-Null

$size = 64
$bmp = New-Object System.Drawing.Bitmap $size, $size
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = 'AntiAlias'

# 深色圆角底
$path = New-Object System.Drawing.Drawing2D.GraphicsPath
$r = 14
$path.AddArc(0, 0, $r, $r, 180, 90)
$path.AddArc($size - $r, 0, $r, $r, 270, 90)
$path.AddArc($size - $r, $size - $r, $r, $r, 0, 90)
$path.AddArc(0, $size - $r, $r, $r, 90, 90)
$path.CloseFigure()
$bg = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 22, 28, 40))
$g.FillPath($bg, $path)
$pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 80, 96, 128)), 2
$g.DrawPath($pen, $path)

function Draw-Arrow($gr, $cx, $top, $bottom, $color, $up) {
    $w = 12; $head = 12
    $brush = New-Object System.Drawing.SolidBrush $color
    $stemH = $bottom - $top - $head
    if ($up) { $stemY = $top + $head } else { $stemY = $top }
    $stem = New-Object System.Drawing.Rectangle (($cx - 2), $stemY, 4, $stemH)
    $gr.FillRectangle($brush, $stem)

    if ($up) {
        $p1 = New-Object System.Drawing.PointF (($cx - $w / 2), ($top + $head))
        $p2 = New-Object System.Drawing.PointF (($cx + $w / 2), ($top + $head))
        $p3 = New-Object System.Drawing.PointF $cx, $top
    } else {
        $p1 = New-Object System.Drawing.PointF (($cx - $w / 2), ($bottom - $head))
        $p2 = New-Object System.Drawing.PointF (($cx + $w / 2), ($bottom - $head))
        $p3 = New-Object System.Drawing.PointF $cx, $bottom
    }
    $pts = [System.Drawing.PointF[]]@($p1, $p2, $p3)
    $gr.FillPolygon($brush, $pts)
}

# 上箭头（绿，左） 下箭头（蓝，右）
Draw-Arrow $g 22 12 52 ([System.Drawing.Color]::FromArgb(255, 76, 200, 120)) $true
Draw-Arrow $g 42 12 52 ([System.Drawing.Color]::FromArgb(255, 70, 160, 255)) $false

# 缩成 32x32 PNG，再包成 ICO 容器（Vista+ 支持 PNG 条目）
$ico32 = New-Object System.Drawing.Bitmap 32, 32
$g2 = [System.Drawing.Graphics]::FromImage($ico32)
$g2.InterpolationMode = 'HighQualityBicubic'
$g2.DrawImage($bmp, 0, 0, 32, 32)

$ms = New-Object System.IO.MemoryStream
$ico32.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
$png = $ms.ToArray()

$fs = [System.IO.File]::Create($outFile)
$bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([uint16]0)      # reserved
$bw.Write([uint16]1)      # type = icon
$bw.Write([uint16]1)      # count
$bw.Write([byte]32)       # width
$bw.Write([byte]32)       # height
$bw.Write([byte]0)        # colors
$bw.Write([byte]0)        # reserved
$bw.Write([uint16]1)      # planes
$bw.Write([uint16]32)     # bitcount
$bw.Write([uint32]$png.Length)
$bw.Write([uint32]22)     # offset = 6 + 16
$bw.Write($png)
$bw.Close(); $fs.Close()

Write-Output "图标已生成: $outFile"
