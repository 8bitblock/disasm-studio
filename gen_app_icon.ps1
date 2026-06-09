# gen_app_icon.ps1
# Generates src\app.ico — a multi-resolution Windows icon for DisasmStudio.
# Motif: a dark rounded tile showing a disassembly listing with an accent-blue
# "current instruction" row (the classic ▶ debugger arrow), matching the app's
# Midnight theme (accent = 66,150,250). Each size is rendered natively (not just
# downscaled) for crispness, PNG-encoded, and packed into a Vista+ PNG .ico.
#
# Run:  powershell -NoProfile -ExecutionPolicy Bypass -File gen_app_icon.ps1

Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'

$root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$icoPath   = Join-Path $root 'src\app.ico'
$pngPath   = Join-Path $root 'app_icon_preview.png'

# --- palette (ARGB) ---------------------------------------------------------
$cTileTop  = [System.Drawing.Color]::FromArgb(255, 30, 35, 48)   # tile gradient top
$cTileBot  = [System.Drawing.Color]::FromArgb(255, 16, 19, 27)   # tile gradient bottom
$cBorder   = [System.Drawing.Color]::FromArgb(150, 66, 150, 250) # subtle accent border
$cGutter   = [System.Drawing.Color]::FromArgb(70, 120, 134, 165) # vertical gutter line
$cAddr     = [System.Drawing.Color]::FromArgb(255, 96, 106, 130) # address column (muted)
$cInstr    = [System.Drawing.Color]::FromArgb(255, 205, 211, 224)# instruction bars (text)
$cAccent   = [System.Drawing.Color]::FromArgb(255, 66, 150, 250) # current row + arrow
$cHilite   = [System.Drawing.Color]::FromArgb(60, 66, 150, 250)  # current-row band

function New-RoundedPath([float]$x,[float]$y,[float]$w,[float]$h,[float]$r){
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    if ($r -le 0.0) { $p.AddRectangle((New-Object System.Drawing.RectangleF($x,$y,$w,$h))); $p.CloseFigure(); return $p }
    $d = $r * 2.0
    $p.AddArc($x,        $y,        $d, $d, 180, 90)
    $p.AddArc($x+$w-$d,  $y,        $d, $d, 270, 90)
    $p.AddArc($x+$w-$d,  $y+$h-$d,  $d, $d,   0, 90)
    $p.AddArc($x,        $y+$h-$d,  $d, $d,  90, 90)
    $p.CloseFigure()
    return $p
}

function Add-Bar([System.Drawing.Graphics]$g,[System.Drawing.Brush]$b,[float]$x,[float]$cy,[float]$w,[float]$h){
    $r = $h / 2.0
    $path = New-RoundedPath $x ($cy - $h/2.0) $w $h $r
    $g.FillPath($b, $path)
    $path.Dispose()
}

function Render-Size([int]$S){
    $bmp = New-Object System.Drawing.Bitmap($S, $S, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g   = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode     = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode   = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::FromArgb(0,0,0,0))

    $sf = [float]$S
    $m  = $sf * 0.055
    $tx = $m; $ty = $m; $tw = $sf - 2*$m; $th = $sf - 2*$m
    $rad = $sf * 0.20

    # tile (vertical gradient) + subtle border
    $tile = New-RoundedPath $tx $ty $tw $th $rad
    $rect = New-Object System.Drawing.RectangleF($tx, $ty, $tw, $th)
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $cTileTop, $cTileBot, 90.0)
    $g.FillPath($grad, $tile)
    $penW = [Math]::Max(1.0, $sf * 0.014)
    $pen  = New-Object System.Drawing.Pen($cBorder, $penW)
    $g.DrawPath($pen, $tile)

    # column geometry
    $arrowX  = $tx + $tw * 0.075
    $addrX1  = $tx + $tw * 0.155
    $addrW   = $tw * 0.135
    $gutterX = $tx + $tw * 0.37
    $instrX1 = $tx + $tw * 0.44
    $rights  = @(0.84, 0.90, 0.68)   # instruction-bar right fraction, per row
    $selRow  = 1                       # middle row is the "current instruction"

    $cyTop = $ty + $th * 0.31
    $cyMid = $ty + $th * 0.50
    $cyBot = $ty + $th * 0.69
    $cys   = @($cyTop, $cyMid, $cyBot)
    $barH  = $th * 0.10

    # gutter line
    $gpen = New-Object System.Drawing.Pen($cGutter, [Math]::Max(1.0, $sf*0.012))
    $g.DrawLine($gpen, $gutterX, ($cyTop - $barH), $gutterX, ($cyBot + $barH))

    $brAddr   = New-Object System.Drawing.SolidBrush($cAddr)
    $brInstr  = New-Object System.Drawing.SolidBrush($cInstr)
    $brAccent = New-Object System.Drawing.SolidBrush($cAccent)
    $brHilite = New-Object System.Drawing.SolidBrush($cHilite)

    for ($i = 0; $i -lt 3; $i++){
        $cy = $cys[$i]
        $instrX2 = $tx + $tw * $rights[$i]
        $instrW  = $instrX2 - $instrX1

        if ($i -eq $selRow){
            # current-instruction highlight band
            $band = New-RoundedPath ($tx + $tw*0.03) ($cy - $barH*0.95) ($tw*0.94) ($barH*1.9) ($barH*0.6)
            $g.FillPath($brHilite, $band); $band.Dispose()
            # ▶ arrow in the left gutter
            $aw = $tw * 0.07; $ah = $barH * 1.15
            $pts = @(
                (New-Object System.Drawing.PointF($arrowX,        ($cy - $ah))),
                (New-Object System.Drawing.PointF($arrowX,        ($cy + $ah))),
                (New-Object System.Drawing.PointF(($arrowX + $aw), $cy))
            )
            $g.FillPolygon($brAccent, $pts)
            Add-Bar $g $brAccent $addrX1 $cy $addrW $barH
            Add-Bar $g $brAccent $instrX1 $cy $instrW $barH
        } else {
            Add-Bar $g $brAddr  $addrX1 $cy $addrW $barH
            Add-Bar $g $brInstr $instrX1 $cy $instrW $barH
        }
    }

    $grad.Dispose(); $pen.Dispose(); $gpen.Dispose(); $tile.Dispose()
    $brAddr.Dispose(); $brInstr.Dispose(); $brAccent.Dispose(); $brHilite.Dispose()
    $g.Dispose()
    return $bmp
}

# --- render every size, PNG-encode -----------------------------------------
$sizes = @(256,128,64,48,32,24,16)
$pngs  = @{}
foreach ($s in $sizes){
    $bmp = Render-Size $s
    $ms  = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngs[$s] = $ms.ToArray()
    $ms.Dispose()
    if ($s -eq 256){ $bmp.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png) }
    $bmp.Dispose()
}

# --- assemble the .ico container (PNG-in-ICO) ------------------------------
$out = New-Object System.IO.MemoryStream
$bw  = New-Object System.IO.BinaryWriter($out)
$bw.Write([UInt16]0)             # idReserved
$bw.Write([UInt16]1)             # idType = icon
$bw.Write([UInt16]$sizes.Count)  # idCount

$offset = 6 + (16 * $sizes.Count)
foreach ($s in $sizes){
    $len = $pngs[$s].Length
    $b = if ($s -ge 256) { [byte]0 } else { [byte]$s }
    $bw.Write([byte]$b)          # width  (0 => 256)
    $bw.Write([byte]$b)          # height (0 => 256)
    $bw.Write([byte]0)           # color count
    $bw.Write([byte]0)           # reserved
    $bw.Write([UInt16]1)         # planes
    $bw.Write([UInt16]32)        # bit count
    $bw.Write([UInt32]$len)      # bytes in resource
    $bw.Write([UInt32]$offset)   # image offset
    $offset += $len
}
foreach ($s in $sizes){ $bw.Write($pngs[$s]) }
$bw.Flush()
[System.IO.File]::WriteAllBytes($icoPath, $out.ToArray())
$bw.Dispose(); $out.Dispose()

Write-Output ("Wrote {0} ({1} bytes, {2} images)" -f $icoPath, (Get-Item $icoPath).Length, $sizes.Count)
Write-Output ("Preview: {0}" -f $pngPath)
