<#
.SYNOPSIS
    Load / unload the HvDbg AMD-V (SVM) kernel driver via the Service Control
    Manager, with an honest preflight about whether your machine will accept it.

.DESCRIPTION
    Mirrors what src/Hv/HvDbgLoader does, but from the command line:
      * status  - report elevation, Secure Boot, test-signing, driver signature,
                  and the current service state. (read-only)
      * load    - sc create (kernel/demand) + sc start, then drops the service
                  registration so nothing persists (one-shot). The driver stays
                  resident until 'unload' or reboot; re-run 'load' each session.
                  Pass -KeepService to leave a demand-start entry registered instead
                  (still never auto-starts at boot). Reports CI rejections clearly.
      * unload  - sc stop (waits for STOPPED) + sc delete.
      * sign    - create a self-signed test cert, trust it (LocalMachine Root +
                  TrustedPublisher), and embed-sign HvDbg.sys. Only useful AFTER
                  test-signing is enabled.

    IMPORTANT: A kernel driver only loads if Code Integrity accepts its signature.
    With Secure Boot ON and test-signing OFF, an unsigned/self-signed HvDbg.sys is
    rejected (StartService error 577 / ERROR_INVALID_IMAGE_HASH). To develop with a
    self-signed driver you must disable Secure Boot in firmware, then
    `bcdedit /set testsigning on`, reboot, and `sign` the driver. This script does
    NOT and will not bypass Secure Boot / Driver Signature Enforcement.

.PARAMETER Action
    load (default) | unload | status | sign

.PARAMETER SysPath
    Path to HvDbg.sys. If omitted, common build-output locations are searched.

.PARAMETER ServiceName
    Kernel service name. Default 'HvDbg' (matches HvDbgLoader / the \\.\HvDbg device).

.PARAMETER CertName
    Subject CN for the self-signed test cert used by `sign`.

.PARAMETER NoElevate
    Do not auto-relaunch elevated; just run (and likely fail the privileged parts).

.EXAMPLE
    .\load-driver.ps1 status
.EXAMPLE
    .\load-driver.ps1 load
.EXAMPLE
    .\load-driver.ps1 sign      # after Secure Boot off + testsigning on + reboot
.EXAMPLE
    .\load-driver.ps1 unload
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('load', 'unload', 'status', 'sign')] [string] $Action = 'load',
    [string] $SysPath,
    [string] $ServiceName = 'HvDbg',
    [string] $CertName = 'DisasmStudio HvDbg Test Cert',
    [switch] $KeepService,
    [switch] $NoElevate
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
}

# --- Self-elevate (every action touches bcdedit / SCM / cert stores) -----------
if (-not (Test-Admin) -and -not $NoElevate) {
    Write-Host "Not elevated - relaunching with admin rights (UAC prompt)..." -ForegroundColor Yellow
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Action', $Action)
    if ($SysPath)                  { $a += @('-SysPath', "`"$SysPath`"") }
    if ($ServiceName -ne 'HvDbg')  { $a += @('-ServiceName', $ServiceName) }
    if ($CertName -ne 'DisasmStudio HvDbg Test Cert') { $a += @('-CertName', "`"$CertName`"") }
    if ($KeepService)              { $a += '-KeepService' }
    try { Start-Process powershell.exe -Verb RunAs -ArgumentList $a } catch {
        Write-Host "Elevation cancelled. Re-run from an elevated PowerShell, or pass -NoElevate." -ForegroundColor Red
    }
    return
}

# --- Locate the driver ---------------------------------------------------------
function Resolve-SysPath {
    if ($SysPath) {
        if (Test-Path $SysPath) { return (Resolve-Path $SysPath).Path }
        throw "SysPath not found: $SysPath"
    }
    $candidates = @(
        (Join-Path $root 'HvDbg.sys'),
        (Join-Path $root 'build\x64\Release\HvDbg.sys'),
        (Join-Path $root 'build\x64\Debug\HvDbg.sys'),
        (Join-Path $root 'driver\x64\Release\HvDbg.sys'),
        (Join-Path $root 'driver\x64\Debug\HvDbg.sys')
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return (Resolve-Path $c).Path } }
    return $null
}

# --- Environment probes --------------------------------------------------------
function Get-SecureBoot {
    try { return [bool](Confirm-SecureBootUEFI) }
    catch { return $null }   # legacy BIOS / not supported
}
function Get-TestSigning {
    try {
        $out = & bcdedit /enum '{current}' 2>$null | Out-String
        if ($out -match '(?im)^\s*testsigning\s+Yes\s*$') { return $true }
        return $false
    } catch { return $null }
}
function Get-ServiceState {
    $q = & sc.exe query $ServiceName 2>&1 | Out-String
    if ($q -match 'STATE\s*:\s*\d+\s+(\w+)') { return $Matches[1] }   # RUNNING / STOPPED / ...
    if ($q -match '1060') { return 'NotInstalled' }
    return 'Unknown'
}

function Show-Status {
    $sb   = Get-SecureBoot
    $ts   = Get-TestSigning
    $sys  = Resolve-SysPath
    $sig  = if ($sys) { (Get-AuthenticodeSignature $sys).Status } else { 'N/A' }
    $svc  = Get-ServiceState

    $sbTxt = if ($null -eq $sb) { 'unknown (legacy BIOS?)' } elseif ($sb) { 'ON' } else { 'off' }
    $tsTxt = if ($null -eq $ts) { 'unknown' } elseif ($ts) { 'ON' } else { 'off' }

    Write-Host "`n=== HvDbg driver status ===" -ForegroundColor Cyan
    Write-Host ("  Elevated      : {0}" -f (Test-Admin))
    Write-Host ("  Secure Boot   : {0}" -f $sbTxt)
    Write-Host ("  Test-signing  : {0}" -f $tsTxt)
    Write-Host ("  Driver (.sys) : {0}" -f ($(if ($sys) { $sys } else { 'NOT FOUND (build it / pass -SysPath)' })))
    Write-Host ("  Signature     : {0}" -f $sig)
    Write-Host ("  Service       : {0}" -f $svc)

    # The decisive verdict for *this* machine.
    if ($sys) {
        $willLoad = ($sig -eq 'Valid') -or ($ts -eq $true -and $sig -ne 'NotSigned')
        if ($willLoad) {
            Write-Host "`n  Verdict: Code Integrity should ACCEPT this driver." -ForegroundColor Green
        } elseif ($sb -eq $true -and $ts -ne $true) {
            Write-Host "`n  Verdict: WILL BE REJECTED. Secure Boot is ON and test-signing is off," -ForegroundColor Red
            Write-Host "  so a self-signed/unsigned driver fails the load (error 577)." -ForegroundColor Red
            Write-Host "  Fix: disable Secure Boot in firmware, then run (elevated):" -ForegroundColor Yellow
            Write-Host "       bcdedit /set testsigning on   ; reboot   ; .\load-driver.ps1 sign" -ForegroundColor Yellow
            Write-Host "  Or have HvDbg.sys production (attestation) signed to load under Secure Boot." -ForegroundColor Yellow
        } else {
            Write-Host "`n  Verdict: driver is not signed. Run '.\load-driver.ps1 sign' (test-signing must be on)." -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

# --- Map common sc.exe / Win32 load failures to actionable text ----------------
function Explain-LoadError([int]$code, [string]$raw) {
    switch ($code) {
        577  { return "error 577: image hash invalid - HvDbg.sys is not signed by a cert Code Integrity trusts (enable test-signing + sign, or production-sign)." }
        1275 { return "error 1275: driver blocked by Code Integrity / blocklist policy." }
        654  { return "error 654: a previous HvDbg instance is still unloading - wait a moment and retry." }
        5    { return "error 5: access denied - run elevated." }
        1072 { return "error 1072: service marked for delete - wait a moment (or reboot) and retry." }
        2    { return "error 2: the system cannot find the driver file." }
        default { return ("sc.exe failed (code {0}):`n{1}" -f $code, $raw.Trim()) }
    }
}

function Invoke-Load {
    $sys = Resolve-SysPath
    if (-not $sys) { Write-Host "HvDbg.sys not found. Build the driver or pass -SysPath." -ForegroundColor Red; exit 1 }

    # Already resident? (a transient load leaves the service queryable as RUNNING
    # until it's stopped). Don't try to re-load on top of it.
    if ((Get-ServiceState) -eq 'RUNNING') {
        Write-Host "HvDbg is already loaded - \\.\HvDbg is live. Run '.\load-driver.ps1 unload' to remove it." -ForegroundColor Green
        return
    }

    Show-Status

    # Register the kernel service (idempotent: 1073 = already exists is fine).
    Write-Host "Registering service '$ServiceName' -> $sys"
    $create = & sc.exe create $ServiceName type= kernel start= demand binPath= "$sys" 2>&1 | Out-String
    $cc = $LASTEXITCODE
    if ($cc -ne 0 -and $create -notmatch '1073') {
        # 1072 (marked for delete) can linger briefly after an unload; brief retry.
        if ($create -match '1072') {
            Start-Sleep -Milliseconds 800
            $create = & sc.exe create $ServiceName type= kernel start= demand binPath= "$sys" 2>&1 | Out-String
            $cc = $LASTEXITCODE
        }
        if ($cc -ne 0 -and $create -notmatch '1073') {
            Write-Host ("CreateService failed: {0}" -f $create.Trim()) -ForegroundColor Red; exit 1
        }
    }

    # Start it -> runs DriverEntry, which creates \\.\HvDbg.
    Write-Host "Starting driver..."
    $start = & sc.exe start $ServiceName 2>&1 | Out-String
    $sc = $LASTEXITCODE
    if ($sc -eq 0 -or $start -match '1056') {     # 1056 = already running
        if (-not $KeepService) {
            # One-shot load: drop the persistent SCM registration now. The running
            # driver keeps the record alive (and \\.\HvDbg up) until it's stopped,
            # so nothing is left in the service database and nothing can autostart.
            & sc.exe delete $ServiceName 2>&1 | Out-Null
            Write-Host "`nDriver loaded (one-shot: no persistent service entry)." -ForegroundColor Green
            Write-Host "It stays resident until '.\load-driver.ps1 unload' or a reboot; re-run 'load' each session." -ForegroundColor DarkGray
        } else {
            Write-Host "`nDriver loaded. Service '$ServiceName' kept as demand-start (never auto-starts at boot)." -ForegroundColor Green
        }
        Write-Host "\\.\HvDbg is live - open DisasmStudio > Communications and click Connect." -ForegroundColor Green
    } else {
        Write-Host ("`nStartService failed: {0}" -f (Explain-LoadError $sc $start)) -ForegroundColor Red
        # Don't leave a dead registration behind from a failed start.
        & sc.exe delete $ServiceName 2>&1 | Out-Null
        exit $sc
    }
}

function Invoke-Unload {
    $state = Get-ServiceState
    if ($state -eq 'NotInstalled') { Write-Host "Service '$ServiceName' is not installed - nothing to do."; return }

    if ($state -ne 'STOPPED') {
        Write-Host "Stopping driver..."
        & sc.exe stop $ServiceName 2>&1 | Out-Null
        # Wait for the async stop (DriverUnload) to actually finish before delete,
        # so the record isn't left marked-for-delete.
        for ($i = 0; $i -lt 50; $i++) {
            if ((Get-ServiceState) -eq 'STOPPED') { break }
            Start-Sleep -Milliseconds 100
        }
    }

    Write-Host "Deleting service '$ServiceName'..."
    $del = & sc.exe delete $ServiceName 2>&1 | Out-String
    # 1072 = already marked for delete; 1060 = already gone (one-shot load drops
    # its own record when the driver stops). Both mean "deregistered".
    if ($LASTEXITCODE -eq 0 -or $del -match '1072' -or $del -match '1060') {
        Write-Host "Driver stopped and deregistered." -ForegroundColor Green
    } else {
        Write-Host ("DeleteService failed: {0}" -f $del.Trim()) -ForegroundColor Red; exit 1
    }
}

function Find-SignTool {
    $base = 'C:\Program Files (x86)\Windows Kits\10\bin'
    if (-not (Test-Path $base)) { return $null }
    Get-ChildItem $base -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } |
        Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}

function Invoke-Sign {
    $sys = Resolve-SysPath
    if (-not $sys) { Write-Host "HvDbg.sys not found. Build the driver or pass -SysPath." -ForegroundColor Red; exit 1 }
    $signtool = Find-SignTool
    if (-not $signtool) {
        Write-Host "signtool.exe not found (install the Windows 10/11 SDK)." -ForegroundColor Red
        Write-Host "Manual path: create a code-signing cert, trust it in LocalMachine Root + TrustedPublisher, then" -ForegroundColor Yellow
        Write-Host "  signtool sign /v /fd SHA256 /n `"$CertName`" /s My `"$sys`"" -ForegroundColor Yellow
        exit 1
    }

    Write-Host "Creating self-signed code-signing cert 'CN=$CertName'..."
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$CertName" `
        -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3') -KeyExportPolicy Exportable

    # Trust it for kernel-mode test signing: machine Root + TrustedPublisher.
    $cer = Join-Path $env:TEMP 'hvdbg_test.cer'
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root          | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
    Remove-Item $cer -ErrorAction SilentlyContinue

    Write-Host "Signing $sys ..."
    & $signtool sign /v /fd SHA256 /sha1 $cert.Thumbprint /s My "$sys"
    if ($LASTEXITCODE -ne 0) { Write-Host "signtool failed." -ForegroundColor Red; exit 1 }

    $ts = Get-TestSigning
    Write-Host "`nSigned. Signature: $((Get-AuthenticodeSignature $sys).Status)" -ForegroundColor Green
    if ($ts -ne $true) {
        Write-Host "NOTE: test-signing is currently OFF. Enable it (Secure Boot must be off first):" -ForegroundColor Yellow
        Write-Host "  bcdedit /set testsigning on   ; then reboot." -ForegroundColor Yellow
    } else {
        Write-Host "Test-signing is on - you can now run '.\load-driver.ps1 load'." -ForegroundColor Green
    }
}

switch ($Action) {
    'status' { Show-Status; exit 0 }
    'load'   { Invoke-Load;   exit 0 }
    'unload' { Invoke-Unload; exit 0 }
    'sign'   { Invoke-Sign;   exit 0 }
}
