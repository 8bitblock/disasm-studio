param(
    [Parameter(Mandatory = $true)][string] $Executable,
    [Parameter(Mandatory = $true)][string] $HelperDll
)

$ErrorActionPreference = 'Stop'
$imagePath = (Resolve-Path -LiteralPath $Executable).Path
$helperPath = (Resolve-Path -LiteralPath $HelperDll).Path
$maximumHelperBytes = 32MB
$helperInfo = Get-Item -LiteralPath $helperPath
if ($helperInfo.Length -lt 512 -or $helperInfo.Length -gt $maximumHelperBytes) {
    throw "GameMaker helper has an invalid resource size: $($helperInfo.Length)"
}

if (-not ('DisasmStudioHelperResource.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace DisasmStudioHelperResource {
    public static class Native {
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern IntPtr LoadLibraryExW(string path, IntPtr file, uint flags);
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool FreeLibrary(IntPtr module);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern IntPtr FindResourceW(IntPtr module, IntPtr name, IntPtr type);
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern uint SizeofResource(IntPtr module, IntPtr resource);
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr LoadResource(IntPtr module, IntPtr resource);
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr LockResource(IntPtr resource);
    }
}
'@
}

# Read the executable as a resource image. This never executes its entry point.
$module = [DisasmStudioHelperResource.Native]::LoadLibraryExW($imagePath, [IntPtr]::Zero, 0x22)
if ($module -eq [IntPtr]::Zero) { throw "Cannot inspect application resources: $imagePath" }
try {
    $resource = [DisasmStudioHelperResource.Native]::FindResourceW($module, [IntPtr]30101, [IntPtr]10)
    if ($resource -eq [IntPtr]::Zero) { throw 'DisasmStudio is missing its embedded GameMaker helper (RCDATA 30101).' }
    $length = [DisasmStudioHelperResource.Native]::SizeofResource($module, $resource)
    if ($length -lt 512 -or $length -gt $maximumHelperBytes -or $length -ne $helperInfo.Length) {
        throw "Embedded GameMaker helper size is stale or invalid: embedded $length, current DLL $($helperInfo.Length)."
    }
    $loaded = [DisasmStudioHelperResource.Native]::LoadResource($module, $resource)
    $pointer = [DisasmStudioHelperResource.Native]::LockResource($loaded)
    if ($pointer -eq [IntPtr]::Zero) { throw 'Cannot read embedded GameMaker helper bytes.' }
    $embeddedBytes = [byte[]]::new($length)
    [Runtime.InteropServices.Marshal]::Copy($pointer, $embeddedBytes, 0, $length)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $embeddedHash = [BitConverter]::ToString($sha.ComputeHash($embeddedBytes)).Replace('-', '')
        $helperStream = [IO.File]::OpenRead($helperPath)
        try {
            $currentHash = [BitConverter]::ToString($sha.ComputeHash($helperStream)).Replace('-', '')
        } finally { $helperStream.Dispose() }
    } finally { $sha.Dispose() }
    if ($embeddedHash -ne $currentHash) {
        throw "Embedded GameMaker helper is stale: embedded SHA256 $embeddedHash, current DLL SHA256 $currentHash."
    }
    Write-Host "GameMaker helper resource verified: $length bytes, SHA256 $currentHash"
} finally {
    [void][DisasmStudioHelperResource.Native]::FreeLibrary($module)
}
