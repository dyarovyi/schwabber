# Regenerates windows/Schwabber/Schwabber.ico from Assets/Schwabber-icon.png with PNG-compressed entries.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$windowsDir = Split-Path -Parent $PSScriptRoot
$source = Join-Path (Split-Path -Parent $windowsDir) 'Assets\Schwabber-icon.png'
$target = Join-Path $windowsDir 'Schwabber\Schwabber.ico'
$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256

$image = [System.Drawing.Image]::FromFile($source)
try {
    $entries = foreach ($size in $sizes) {
        $bitmap = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $graphics.DrawImage($image, 0, 0, $size, $size)
        $graphics.Dispose()
        $stream = New-Object System.IO.MemoryStream
        $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
        $bitmap.Dispose()
        [pscustomobject]@{ Size = $size; Bytes = $stream.ToArray() }
    }
} finally { $image.Dispose() }

$out = New-Object System.IO.MemoryStream
$writer = New-Object System.IO.BinaryWriter $out
$writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$entries.Count)
$offset = 6 + 16 * $entries.Count
foreach ($entry in $entries) {
    $dimension = if ($entry.Size -ge 256) { 0 } else { $entry.Size }
    $writer.Write([byte]$dimension); $writer.Write([byte]$dimension)
    $writer.Write([byte]0); $writer.Write([byte]0)
    $writer.Write([uint16]1); $writer.Write([uint16]32)
    $writer.Write([uint32]$entry.Bytes.Length); $writer.Write([uint32]$offset)
    $offset += $entry.Bytes.Length
}
foreach ($entry in $entries) { $writer.Write($entry.Bytes) }
$writer.Flush()
[System.IO.File]::WriteAllBytes($target, $out.ToArray())
Write-Host "Wrote $target"
