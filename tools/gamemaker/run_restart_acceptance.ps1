param(
    [Parameter(Mandatory=$true)][int]$PreviousPid,
    [Parameter(Mandatory=$true)][string]$PreviousStart,
    [int]$Runs=3,
    [int]$FirstLogNumber=2
)
$ErrorActionPreference='Stop'
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
Set-Location -LiteralPath $projectRoot
$gameDirectory="C:\Program Files (x86)\Steam\steamapps\common\Nubby's Number Factory"
$gameExecutable=Join-Path $gameDirectory 'NNF_FULLVERSION.exe'
$intentPath=Join-Path $projectRoot 'build\gamemaker-live-test\restart-intent.json'
$intentDigest=(Get-FileHash -LiteralPath $intentPath -Algorithm SHA256).Hash
$ownedPid=$PreviousPid
$ownedStart=$PreviousStart
$records=@()
for($run=0;$run -lt $Runs;$run++) {
    $prior=Get-CimInstance Win32_Process -Filter "ProcessId=$ownedPid"
    if(!$prior -or $prior.ExecutablePath -ne $gameExecutable -or $prior.CreationDate.ToString('o') -ne $ownedStart) {
        throw 'The prior test-owned process identity changed; refusing to terminate another process.'
    }
    Stop-Process -Id $ownedPid -Force
    $until=[datetime]::UtcNow.AddSeconds(10)
    while((Get-CimInstance Win32_Process -Filter "ProcessId=$ownedPid") -and [datetime]::UtcNow -lt $until){Start-Sleep -Milliseconds 100}
    if(Get-CimInstance Win32_Process -Filter "Name='NNF_FULLVERSION.exe'"){throw 'An unrelated game process remains; restart acceptance stopped.'}
    $launchedAt=[datetime]::Now.AddSeconds(-1)
    $launcher=Start-Process -FilePath $gameExecutable -WorkingDirectory $gameDirectory -WindowStyle Hidden -PassThru
    # Steam may replace the direct launch with a different PID. Admit only one
    # exact-path process created by this launch interval, then keep its identity.
    Start-Sleep -Seconds 3
    $until=[datetime]::UtcNow.AddSeconds(30)
    $candidate=$null
    while([datetime]::UtcNow -lt $until) {
        $matching=@(Get-CimInstance Win32_Process -Filter "Name='NNF_FULLVERSION.exe'" | Where-Object {$_.ExecutablePath -eq $gameExecutable -and $_.CreationDate -ge $launchedAt})
        if($matching.Count -gt 1){throw 'Ambiguous restarted game processes.'}
        if($matching.Count -eq 1){$candidate=$matching[0];break}
        Start-Sleep -Milliseconds 200
    }
    if(!$candidate){throw 'Steam did not start the game within the bounded launch interval.'}
    $ownedPid=$candidate.ProcessId
    $ownedStart=$candidate.CreationDate.ToString('o')
    # Keep startup/menu state comparable before sampling CPU time and cycles.
    Start-Sleep -Seconds 8
    if((Get-FileHash -LiteralPath $intentPath -Algorithm SHA256).Hash -ne $intentDigest){throw 'The saved intent file changed between restarts.'}
    $number=$FirstLogNumber+$run
    $log=Join-Path $projectRoot "build\gamemaker-live-restart-$number.log"
    & (Join-Path $projectRoot 'build\gamemaker-live-test\live_debugger_test.exe') $ownedPid > $log 2>&1
    $result=$LASTEXITCODE
    Get-Content -LiteralPath $log | Where-Object {$_ -match 'REBIND|BENCH|FAIL|PASSED|DETACH|WATCH'}
    $records+=[pscustomobject]@{run=$number;pid=$ownedPid;started=$ownedStart;exitCode=$result;intentSha256=$intentDigest;log=$log}
    $records | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $projectRoot 'build\gamemaker-restart-acceptance.json')
    if($result -ne 0){throw "Restart acceptance failed for test-owned PID $ownedPid. See $log"}
}
Write-Output "Final test-owned PID=$ownedPid start=$ownedStart"
