param([string]$Root = (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)))

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$assetDir = Join-Path $Root 'src\assets'
New-Item -ItemType Directory -Force -Path $assetDir | Out-Null

function New-LogoBitmap([int]$size) {
    $bitmap = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.Clear([System.Drawing.Color]::Transparent)
    $scale = $size / 1024.0

    function Points([float[]]$values) {
        $result = New-Object 'System.Drawing.PointF[]' ($values.Length / 2)
        for ($i = 0; $i -lt $values.Length; $i += 2) {
            $result[$i / 2] = [System.Drawing.PointF]::new([single]($values[$i] * $scale), [single]($values[$i + 1] * $scale))
        }
        return $result
    }

    $panel = New-Object System.Drawing.Drawing2D.GraphicsPath
    $r = 204 * $scale; $x = 72 * $scale; $y = 72 * $scale; $w = 880 * $scale
    $panel.AddArc($x, $y, 2*$r, 2*$r, 180, 90); $panel.AddArc($x+$w-2*$r, $y, 2*$r, 2*$r, 270, 90)
    $panel.AddArc($x+$w-2*$r, $y+$w-2*$r, 2*$r, 2*$r, 0, 90); $panel.AddArc($x, $y+$w-2*$r, 2*$r, 2*$r, 90, 90); $panel.CloseFigure()
    $panelStart = [System.Drawing.PointF]::new([single](160*$scale), [single](120*$scale))
    $panelEnd = [System.Drawing.PointF]::new([single](864*$scale), [single](904*$scale))
    $panelBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($panelStart, $panelEnd, ([System.Drawing.ColorTranslator]::FromHtml('#0D252C')), ([System.Drawing.ColorTranslator]::FromHtml('#050C11')))
    $graphics.FillPath($panelBrush, $panel)
    $panelPen = New-Object System.Drawing.Pen(([System.Drawing.ColorTranslator]::FromHtml('#24424A')), ([Math]::Max(1,20*$scale)))
    $graphics.DrawPath($panelPen, $panel)

    $shield = New-Object System.Drawing.Drawing2D.GraphicsPath
    $shield.AddPolygon((Points @(512,177,748,264,748,467,740,548,716,630,676,705,624,768,570,814,512,852,454,814,400,768,348,705,308,630,284,548,276,467,276,264)))
    $shieldStart = [System.Drawing.PointF]::new([single](278*$scale), [single](194*$scale))
    $shieldEnd = [System.Drawing.PointF]::new([single](742*$scale), [single](844*$scale))
    $shieldBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($shieldStart, $shieldEnd, ([System.Drawing.ColorTranslator]::FromHtml('#173D45')), ([System.Drawing.ColorTranslator]::FromHtml('#0B1B22')))
    $graphics.FillPath($shieldBrush, $shield)
    $shieldPen = New-Object System.Drawing.Pen(([System.Drawing.ColorTranslator]::FromHtml('#35D9D0')), ([Math]::Max(1.5,38*$scale)))
    $shieldPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $graphics.DrawPath($shieldPen, $shield)

    $pulse = Points @(210,524,358,524,424,392,512,658,594,464,642,524,814,524)
    $shadowPen = New-Object System.Drawing.Pen(([System.Drawing.Color]::FromArgb(220,6,16,20)), ([Math]::Max(2,62*$scale)))
    $shadowPen.StartCap = $shadowPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round; $shadowPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $graphics.DrawLines($shadowPen, $pulse)
    $pulseStart = [System.Drawing.PointF]::new([single](210*$scale), [single](524*$scale))
    $pulseEnd = [System.Drawing.PointF]::new([single](814*$scale), [single](524*$scale))
    $pulseBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($pulseStart, $pulseEnd, ([System.Drawing.ColorTranslator]::FromHtml('#35D9D0')), ([System.Drawing.ColorTranslator]::FromHtml('#F2A62B')))
    $pulsePen = New-Object System.Drawing.Pen($pulseBrush, ([Math]::Max(1.5,34*$scale)))
    $pulsePen.StartCap = $pulsePen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round; $pulsePen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $graphics.DrawLines($pulsePen, $pulse)
    $dotBrush = New-Object System.Drawing.SolidBrush(([System.Drawing.ColorTranslator]::FromHtml('#F2A62B')))
    $graphics.FillEllipse($dotBrush, (792*$scale), (502*$scale), (44*$scale), (44*$scale))

    $dotBrush.Dispose(); $pulsePen.Dispose(); $pulseBrush.Dispose(); $shadowPen.Dispose(); $shieldPen.Dispose(); $shieldBrush.Dispose(); $shield.Dispose()
    $panelPen.Dispose(); $panelBrush.Dispose(); $panel.Dispose(); $graphics.Dispose()
    return $bitmap
}

$pngPath = Join-Path $assetDir 'PulseGuard-logo.png'
$master = New-LogoBitmap 1024
$master.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)
$master.Dispose()

$sizes = @(16, 24, 32, 48, 64, 128, 256)
$images = @()
foreach ($size in $sizes) {
    $bitmap = New-LogoBitmap $size
    $stream = New-Object System.IO.MemoryStream
    $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
    $images += ,@($size, $stream.ToArray())
    $stream.Dispose(); $bitmap.Dispose()
}

$icoPath = Join-Path $assetDir 'PulseGuard.ico'
$file = [System.IO.File]::Create($icoPath)
$writer = New-Object System.IO.BinaryWriter($file)
$writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$images.Count)
$offset = 6 + 16 * $images.Count
foreach ($image in $images) {
    $size = [int]$image[0]; $bytes = [byte[]]$image[1]
    $iconSize = if ($size -eq 256) { 0 } else { $size }
    $writer.Write([byte]$iconSize); $writer.Write([byte]$iconSize); $writer.Write([byte]0); $writer.Write([byte]0)
    $writer.Write([uint16]1); $writer.Write([uint16]32); $writer.Write([uint32]$bytes.Length); $writer.Write([uint32]$offset)
    $offset += $bytes.Length
}
foreach ($image in $images) { $writer.Write([byte[]]$image[1]) }
$writer.Dispose(); $file.Dispose()

Write-Host "Generated: $pngPath"
Write-Host "Generated: $icoPath"
