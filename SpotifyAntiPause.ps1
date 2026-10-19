#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Install','Uninstall','Launch','Status')][string]$Action='Install',
    [string]$SpotifyPath,
    [string]$LaunchArgumentsBase64,
    [string]$Uri
)
$ErrorActionPreference='Stop'
$Version='2.0.1'
$root=Join-Path $env:LOCALAPPDATA 'SpotifyAntiPause'
if($Action -eq 'Launch' -or ((Split-Path -Leaf $PSScriptRoot) -ieq 'SpotifyAntiPause' -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'config.json')))){$root=$PSScriptRoot}
elseif(-not (Test-Path -LiteralPath (Join-Path $root 'config.json'))) {
    $knownLinks=@((Join-Path ([Environment]::GetFolderPath('Desktop')) 'Spotify.lnk'),(Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Spotify.lnk'))
    $lookup=New-Object -ComObject WScript.Shell
    foreach($path in $knownLinks){
        if(-not (Test-Path -LiteralPath $path)){continue}
        $link=$lookup.CreateShortcut($path)
        if($link.Arguments -match '-File "([^"]*\\SpotifyAntiPause\.ps1)"' -and (Test-Path -LiteralPath $Matches[1])) {
            $candidate=Split-Path -Parent $Matches[1]
            if(Test-Path -LiteralPath (Join-Path $candidate 'config.json')){$root=$candidate;break}
        }
    }
}
$installedScript=Join-Path $root 'SpotifyAntiPause.ps1'
$backupPath=Join-Path $root 'backup.json'
$configPath=Join-Path $root 'config.json'
$runKey='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$protocolKey='HKCU:\Software\Classes\spotify\shell\open\command'
$powerShell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Read-Value([string]$Path,[string]$Name) {
    $item=Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if($item){$property=$item.PSObject.Properties[$Name];if($property){return $property.Value}}
    return $null
}
function Write-Value([string]$Path,[string]$Name,[object]$Value) {
    if($null -eq $Value){Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue}
    else {
        if(-not (Test-Path -LiteralPath $Path)){New-Item -Path $Path -Force | Out-Null}
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null
    }
}
function Save-Json([string]$Path,[object]$Data) {
    [IO.File]::WriteAllText($Path,(ConvertTo-Json -InputObject $Data -Depth 8),(New-Object Text.UTF8Encoding($false)))
}
function Launch-Command([string]$Arguments) {
    $command='-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+$installedScript+'" -Action Launch -SpotifyPath "'+$SpotifyPath+'"'
    if($Arguments){$command+=' -LaunchArgumentsBase64 '+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Arguments))}
    return $command
}
function Load-NativePatch {
    if('SpotifyNativePatch' -as [type]){return}
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public static class SpotifyNativePatch {
    const long Entry = 0x16061f4;
    const string Hash = "4F8A965AA4492C6CBFA304956EA8428F10538C74DFAE5EAADF54BE08572A897A";
    static readonly byte[] Original = {0x48,0x89,0x5c,0x24,0x08};
    static readonly byte[] Magic = Encoding.ASCII.GetBytes("SPAP2000");
    // x64 Windows ABI: compare the 39-byte MSVC string at capture+0x70,
    // then construct success, invoke completion+0x38 (vtable slot 0x10),
    // destroy success, and increment the counter. Other senders replay the
    // original five-byte instruction and jump back. MakeCode relocates the
    // four absolute addresses; the matched branch has registered unwind data.
    const string Template = "4883b980000000270f85e10000004883b988000000270f82d30000004881b988000000001000000f83c20000004c8b51704d85d20f84b500000049bb7765626170692d304d391a0f85a200000049bb66373866343733364d395a080f858e00000049bb30613734386630394d395a10757e49bb61363662626662344d395a18756e41817a203030636175646641817a246661755b41807a263075544983793800744d534883ec60498b5938488d4c242048b82222222211111111ffd04889d9488b01488d542420ff5010488d4c242048b84444444433333333ffd048b86666666655555555f048ff004883c4605bc348895c240849bb888888887777777741ffe3";
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint rights,bool inherit,int pid);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadProcessMemory(IntPtr process,IntPtr address,byte[] bytes,UIntPtr size,out UIntPtr read);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool WriteProcessMemory(IntPtr process,IntPtr address,byte[] bytes,UIntPtr size,out UIntPtr written);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr VirtualAllocEx(IntPtr process,IntPtr address,UIntPtr size,uint allocation,uint protection);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool VirtualFreeEx(IntPtr process,IntPtr address,UIntPtr size,uint kind);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool VirtualProtectEx(IntPtr process,IntPtr address,UIntPtr size,uint protection,out uint old);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool FlushInstructionCache(IntPtr process,IntPtr address,UIntPtr size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenThread(uint rights,bool inherit,uint tid);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint SuspendThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateRemoteThread(IntPtr process,IntPtr attributes,UIntPtr stack,IntPtr start,IntPtr parameter,uint flags,IntPtr id);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeThread(IntPtr thread,out uint code);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll",CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr module,string name);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(IntPtr file,StringBuilder path,uint length,uint flags);

    public static string RealPath(string path) {
        using(FileStream file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)) {
            StringBuilder result=new StringBuilder(32768);
            uint length=GetFinalPathNameByHandle(file.SafeFileHandle.DangerousGetHandle(),result,(uint)result.Capacity,0);
            if(length==0 || length>=result.Capacity)throw Error("Resolve installed file path");
            string final=result.ToString();
            if(final.StartsWith(@"\\?\UNC\",StringComparison.OrdinalIgnoreCase))return @"\\"+final.Substring(8);
            return final.StartsWith(@"\\?\",StringComparison.Ordinal)?final.Substring(4):final;
        }
    }

    static Exception Error(string action) { return new Win32Exception(Marshal.GetLastWin32Error(),action); }
    static byte[] Read(IntPtr p,long address,int length) {
        byte[] result=new byte[length]; UIntPtr done;
        if(!ReadProcessMemory(p,new IntPtr(address),result,(UIntPtr)length,out done)||done.ToUInt64()!=(ulong)length) throw Error("Read Spotify memory");
        return result;
    }
    static void Write(IntPtr p,long address,byte[] bytes) {
        UIntPtr done;
        if(!WriteProcessMemory(p,new IntPtr(address),bytes,(UIntPtr)bytes.Length,out done)||done.ToUInt64()!=(ulong)bytes.Length) throw Error("Write Spotify memory");
    }
    static bool Equal(byte[] a,byte[] b) {
        if(a.Length!=b.Length)return false;
        for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false;
        return true;
    }
    static ProcessModule Module(Process p,string name) {
        foreach(ProcessModule module in p.Modules)if(String.Equals(module.ModuleName,name,StringComparison.OrdinalIgnoreCase))return module;
        throw new InvalidOperationException(name+" is not loaded");
    }
    public static byte[] MakeCode(long construct,long destroy,long counter,long resume) {
        byte[] code=new byte[Template.Length/2];
        for(int i=0;i<code.Length;i++)code[i]=Convert.ToByte(Template.Substring(i*2,2),16);
        int[] offsets={178,209,221,246}; long[] addresses={construct,destroy,counter,resume};
        for(int i=0;i<offsets.Length;i++)Buffer.BlockCopy(BitConverter.GetBytes(addresses[i]),0,code,offsets[i],8);
        return code;
    }
    static long Existing(IntPtr p,long target) {
        byte[] entry=Read(p,target,5);
        if(entry[0]!=0xe9)return 0;
        long page=target+5+BitConverter.ToInt32(entry,1)-0x1000;
        if(page<=0 || (page&0xffff)!=0)return 0;
        try{return Equal(Read(p,page,8),Magic)?page:0;}catch(Win32Exception){return 0;}
    }
    public static long Blocked(int pid) {
        using(Process process=Process.GetProcessById(pid)) {
            long target=Module(process,"Spotify.dll").BaseAddress.ToInt64()+Entry;
            IntPtr handle=OpenProcess(0x410,false,pid);
            if(handle==IntPtr.Zero)throw Error("Open Spotify");
            try{long page=Existing(handle,target);return page==0?-1:BitConverter.ToInt64(Read(handle,page+8,8),0);}
            finally{CloseHandle(handle);}
        }
    }
    static long AllocateNear(IntPtr p,long target) {
        long aligned=target&~0xffffL;
        for(long distance=0;distance<0x7fff0000L;distance+=0x10000) {
            foreach(long candidate in new long[]{aligned+distance,aligned-distance}) {
                if(candidate<0x10000)continue;
                IntPtr page=VirtualAllocEx(p,new IntPtr(candidate),(UIntPtr)0x2000,0x3000,0x04);
                if(page==IntPtr.Zero)continue;
                long displacement=page.ToInt64()+0x1000-target-5;
                if(displacement>=Int32.MinValue && displacement<=Int32.MaxValue)return page.ToInt64();
                VirtualFreeEx(p,page,UIntPtr.Zero,0x8000);
            }
        }
        throw new InvalidOperationException("No nearby memory available for the hook");
    }
    static uint RemoteCall(IntPtr process,long function,long argument) {
        IntPtr thread=CreateRemoteThread(process,IntPtr.Zero,UIntPtr.Zero,new IntPtr(function),new IntPtr(argument),0,IntPtr.Zero);
        if(thread==IntPtr.Zero)throw Error("Initialize native unwind table");
        try {
            if(WaitForSingleObject(thread,10000)!=0)throw new TimeoutException("Native initialization timed out; restart Spotify");
            uint result;if(!GetExitCodeThread(thread,out result))throw Error("Read native initialization result");return result;
        } finally{CloseHandle(thread);}
    }
    static void Emit64(List<byte> code,params long[] values) { foreach(long value in values)code.AddRange(BitConverter.GetBytes(value)); }
    static byte[] Initializer(long table,long page,long addFunction) {
        List<byte> code=new List<byte>(new byte[]{0x48,0x83,0xec,0x28,0x48,0xb9});Emit64(code,table);
        code.AddRange(new byte[]{0xba,1,0,0,0,0x49,0xb8});Emit64(code,page);
        code.AddRange(new byte[]{0x48,0xb8});Emit64(code,addFunction);
        code.AddRange(new byte[]{0xff,0xd0,0x48,0x83,0xc4,0x28,0xc3});return code.ToArray();
    }
    static List<IntPtr> PauseThreads(Process process) {
        List<IntPtr> handles=new List<IntPtr>(); HashSet<int> seen=new HashSet<int>();
        try {
            for(int pass=0;pass<8;pass++) {
                bool added=false;process.Refresh();
                foreach(ProcessThread thread in process.Threads) {
                    if(seen.Contains(thread.Id))continue;
                    IntPtr handle=OpenThread(2,false,(uint)thread.Id);
                    if(handle==IntPtr.Zero)throw Error("Open Spotify thread");
                    if(SuspendThread(handle)==UInt32.MaxValue){CloseHandle(handle);throw Error("Pause Spotify thread");}
                    handles.Add(handle);seen.Add(thread.Id);added=true;
                }
                if(!added)return handles;
            }
            throw new InvalidOperationException("Spotify threads are still starting; retry shortly");
        }catch{ContinueThreads(handles);throw;}
    }
    static void ContinueThreads(List<IntPtr> handles) {
        for(int i=handles.Count-1;i>=0;i--){ResumeThread(handles[i]);CloseHandle(handles[i]);}
    }
    public static void Apply(int pid) {
        if(IntPtr.Size!=8)throw new InvalidOperationException("Use 64-bit Windows PowerShell");
        using(Process process=Process.GetProcessById(pid)) {
            if(!String.Equals(process.ProcessName,"Spotify",StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Expected Spotify.exe");
            ProcessModule module=Module(process,"Spotify.dll");
            using(SHA256 sha=SHA256.Create())using(FileStream input=File.OpenRead(module.FileName)) {
                if(BitConverter.ToString(sha.ComputeHash(input)).Replace("-","")!=Hash)throw new InvalidOperationException("Unsupported Spotify version (requires 1.3.5.3058 x64)");
            }
            long target=module.BaseAddress.ToInt64()+Entry;
            IntPtr handle=OpenProcess(0x43a,false,pid);
            if(handle==IntPtr.Zero)throw Error("Open Spotify");
            long page=0;bool registered=false,patched=false,initializing=false;
            try {
                if(Existing(handle,target)!=0)return;
                if(!Equal(Read(handle,target,5),Original))throw new InvalidOperationException("Spotify already has a different patch; restart it first");
                page=AllocateNear(handle,target);
                Write(handle,page,Magic);
                byte[] code=MakeCode(module.BaseAddress.ToInt64()+0x15f2190,module.BaseAddress.ToInt64()+0x6c7844,page+8,target+5);
                Write(handle,page+0x1000,code);
                byte[] table=new byte[12];
                Buffer.BlockCopy(BitConverter.GetBytes(0x1000+162),0,table,0,4);
                Buffer.BlockCopy(BitConverter.GetBytes(0x1000+239),0,table,4,4);
                Buffer.BlockCopy(BitConverter.GetBytes(0x120),0,table,8,4);
                Write(handle,page+0x100,table);
                Write(handle,page+0x120,new byte[]{1,5,2,0,5,0xb2,1,0x30});
                long localNtdll=GetModuleHandle("ntdll.dll").ToInt64();
                IntPtr add=GetProcAddress(new IntPtr(localNtdll),"RtlAddFunctionTable");
                if(add==IntPtr.Zero)throw Error("Resolve unwind registration");
                long remoteNtdll=Module(process,"ntdll.dll").BaseAddress.ToInt64();
                Write(handle,page+0x1400,Initializer(page+0x100,page,remoteNtdll+add.ToInt64()-localNtdll));
                uint old;
                if(!VirtualProtectEx(handle,new IntPtr(page+0x1000),(UIntPtr)0x1000,0x20,out old))throw Error("Protect native code");
                if(!FlushInstructionCache(handle,new IntPtr(page+0x1000),(UIntPtr)0x1000))throw Error("Flush native code");
                initializing=true;
                uint result=RemoteCall(handle,page+0x1400,0);
                initializing=false;
                if(result==0)throw new InvalidOperationException("Native unwind registration failed");
                registered=true;
                List<IntPtr> threads=PauseThreads(process);
                try {
                    if(!Equal(Read(handle,target,5),Original))throw new InvalidOperationException("Spotify entry changed during setup");
                    if(!VirtualProtectEx(handle,new IntPtr(target),(UIntPtr)5,0x40,out old))throw Error("Unprotect native entry");
                    try {
                        byte[] jump=new byte[5];jump[0]=0xe9;
                        Buffer.BlockCopy(BitConverter.GetBytes(checked((int)(page+0x1000-target-5))),0,jump,1,4);
                        try {
                            Write(handle,target,jump);
                            if(!FlushInstructionCache(handle,new IntPtr(target),(UIntPtr)5))throw Error("Flush native entry");
                            patched=true;
                        }catch{
                            try{Write(handle,target,Original);FlushInstructionCache(handle,new IntPtr(target),(UIntPtr)5);}
                            catch{patched=true;throw new InvalidOperationException("Entry rollback failed; restart Spotify");}
                            throw;
                        }
                    }finally{uint ignored;if(!VirtualProtectEx(handle,new IntPtr(target),(UIntPtr)5,old,out ignored))throw Error("Restore native entry protection");}
                }finally{ContinueThreads(threads);}
            } finally {
                if(page!=0 && !patched && !initializing) {
                    bool free=!registered;
                    if(registered)try {
                        long local=GetModuleHandle("ntdll.dll").ToInt64();
                        long remove=Module(process,"ntdll.dll").BaseAddress.ToInt64()+GetProcAddress(new IntPtr(local),"RtlDeleteFunctionTable").ToInt64()-local;
                        free=RemoteCall(handle,remove,page+0x100)!=0;
                    }catch{}
                    if(free)VirtualFreeEx(handle,new IntPtr(page),UIntPtr.Zero,0x8000);
                }
                CloseHandle(handle);
            }
        }
    }
}

'@
}
function Find-Spotify([string]$Executable) {
    Get-CimInstance Win32_Process -Filter "name='Spotify.exe'" | Where-Object {
        $_.CommandLine -notmatch '--type=' -and $_.ExecutablePath -ieq $Executable
    } | Sort-Object CreationDate | Select-Object -First 1
}
function Refresh-Protocol([string]$Executable) {
    if(-not (Test-Path -LiteralPath $backupPath)){return}
    $saved=Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
    $current=Read-Value $protocolKey '(default)'
    if($null -ne $saved.protocol -and $current -and
       ($current.StartsWith(('"'+$Executable+'"'),[StringComparison]::OrdinalIgnoreCase) -or $current.Contains($installedScript))) {
        Write-Value $protocolKey '(default)' ('"'+$powerShell+'" '+(Launch-Command '')+' -Uri "%1"')
    }
}
function Restore-Links($Saved,[string]$Owner,[switch]$ExecutableOwner) {
    $shell=New-Object -ComObject WScript.Shell
    foreach($link in $Saved.shortcuts) {
        if(-not (Test-Path -LiteralPath $link.path)){continue}
        $current=$shell.CreateShortcut($link.path)
        $owned=if($ExecutableOwner){$current.TargetPath -eq $Owner}else{$current.Arguments.Contains($Owner)}
        if($owned){
            if($link.backup -and (Test-Path -LiteralPath $link.backup)){Copy-Item -LiteralPath $link.backup -Destination $link.path -Force}
            elseif(-not $ExecutableOwner){Remove-Item -LiteralPath $link.path -Force}
        }
    }
    $protocol=Read-Value $protocolKey '(default)'
    if($protocol -and $protocol.Contains($Owner)){Write-Value $protocolKey '(default)' $Saved.protocol}
    $startup=Read-Value $runKey 'Spotify'
    if($startup -and $startup.Contains($Owner)){Write-Value $runKey 'Spotify' $Saved.spotifyStartup}
}

if([IntPtr]::Size -ne 8){throw 'Run this script in 64-bit Windows PowerShell.'}
if($Action -eq 'Launch') {
    try {
        if(-not $SpotifyPath -and (Test-Path -LiteralPath $configPath)) {
            $config=Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
            $SpotifyPath=$config.spotifyExecutable
        }
        if(-not (Test-Path -LiteralPath $SpotifyPath)){throw 'Spotify.exe moved. Run Install again with -SpotifyPath.'}
        $arguments=if($LaunchArgumentsBase64){[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($LaunchArgumentsBase64))}else{''}
        if($Uri){
            if($Uri -notmatch '^spotify:' -or $Uri.Contains('"')){throw 'Invalid Spotify URI.'}
            $arguments='--protocol-uri="'+$Uri+'"'
        }
        if($arguments){Start-Process -FilePath $SpotifyPath -ArgumentList $arguments}
        else{Start-Process -FilePath $SpotifyPath}
        $mutex=New-Object Threading.Mutex($false,'Local\SpotifyAntiPause-v2')
        $locked=$false
        try {
            try{$locked=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$locked=$true}
            if(-not $locked){return}
            $main=$null
            for($attempt=0;$attempt -lt 40;$attempt++) {
                $main=Find-Spotify $SpotifyPath
                if($main){break}
                Start-Sleep -Milliseconds 100
            }
            if(-not $main){throw 'Spotify did not start.'}
            $process=Get-Process -Id $main.ProcessId -ErrorAction Stop
            $wait=[Math]::Max(0,15000-((Get-Date)-$process.StartTime).TotalMilliseconds)
            if($wait -gt 0 -and $process.WaitForExit([int]$wait)){return}
            Load-NativePatch
            [SpotifyNativePatch]::Apply($main.ProcessId)
            Refresh-Protocol $SpotifyPath
            Save-Json (Join-Path $root 'state.json') @{version=$Version;spotifyPid=$main.ProcessId;startedUtc=$process.StartTime.ToUniversalTime().ToString('o')}
            Remove-Item -LiteralPath (Join-Path $root 'launch-error.txt') -ErrorAction SilentlyContinue
        }finally{if($locked){$mutex.ReleaseMutex()};$mutex.Dispose()}
    }catch {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $root 'launch-error.txt'),($_|Out-String))
        throw
    }
    return
}
if($Action -eq 'Status') {
    $count=-1L;$main=$null
    if(Test-Path -LiteralPath $configPath){
        $config=Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        $main=Find-Spotify $config.spotifyExecutable
        if($main){Load-NativePatch;try{$count=[SpotifyNativePatch]::Blocked($main.ProcessId)}catch{$count=-1L}}
    }
    [pscustomobject]@{Active=($count -ge 0);BlockedPausesThisSession=if($count -ge 0){$count}else{0};SpotifyPid=if($main){$main.ProcessId}else{$null}}
    return
}

New-Item -ItemType Directory -Path $root -Force | Out-Null
$setupMutex=New-Object Threading.Mutex($false,'Local\SpotifyAntiPause-v2')
$setupLocked=$false
try {
    try{$setupLocked=$setupMutex.WaitOne(25000)}catch [Threading.AbandonedMutexException]{$setupLocked=$true}
    if(-not $setupLocked){throw 'Spotify is still starting. Retry shortly.'}
    if($Action -eq 'Install') {
        Load-NativePatch
        if($PSCommandPath -ne $installedScript){Copy-Item -LiteralPath $PSCommandPath -Destination $installedScript -Force}
        $installedScript=[SpotifyNativePatch]::RealPath($installedScript)
        $root=Split-Path -Parent $installedScript
        $backupPath=Join-Path $root 'backup.json'
        $configPath=Join-Path $root 'config.json'
    }
    $backup=if(Test-Path -LiteralPath $backupPath){Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json}else{$null}
    if($backup){
        foreach($entry in $backup.shortcuts){
            if($entry.backup -and -not (Test-Path -LiteralPath $entry.backup)){
                $physicalBackup=Join-Path $root ([IO.Path]::GetFileName($entry.backup))
                if(Test-Path -LiteralPath $physicalBackup){$entry.backup=$physicalBackup}
            }
        }
    }
    if($Action -eq 'Uninstall') {
        if($backup){Restore-Links $backup $installedScript}
        Write-Output 'Uninstalled. Restart Spotify to remove the patch.'
        return
    }

    # Restore launch entries from the earlier packaged installer before backing them up.
    $legacy=Join-Path $env:LOCALAPPDATA 'SpotifyPauseGuard'
    $legacyBackup=Join-Path $legacy 'launcher-backup.json'
    $legacyExe=Join-Path $legacy 'app\SpotifyPauseGuard.exe'
    if(Test-Path -LiteralPath $legacyBackup) {
        Restore-Links (Get-Content -LiteralPath $legacyBackup -Raw | ConvertFrom-Json) $legacyExe -ExecutableOwner
    }
    $legacyProcesses=@(Get-Process SpotifyPauseGuard -ErrorAction SilentlyContinue)
    $legacyProcesses|Stop-Process -Force
    foreach($p in $legacyProcesses){try{$p.WaitForExit(10000)|Out-Null}catch{}}
    Remove-ItemProperty -LiteralPath $runKey -Name SpotifyPauseGuard -ErrorAction SilentlyContinue

    $shell=New-Object -ComObject WScript.Shell
    $roots=@([Environment]::GetFolderPath('Desktop'),[Environment]::GetFolderPath('StartMenu'),(Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar'))
    $links=@(foreach($folder in $roots){
        if(Test-Path -LiteralPath $folder){
            Get-ChildItem -LiteralPath $folder -Filter '*.lnk' -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $s=$shell.CreateShortcut($_.FullName)
                if([IO.Path]::GetFileName($s.TargetPath) -ieq 'Spotify.exe' -or $s.Arguments.Contains($installedScript)) {
                    [pscustomobject]@{path=$_.FullName;shortcut=$s}
                }
            }
        }
    })
    if(-not $SpotifyPath -and (Test-Path -LiteralPath $configPath)){$SpotifyPath=(Get-Content -LiteralPath $configPath -Raw|ConvertFrom-Json).spotifyExecutable}
    if(-not $SpotifyPath){$candidate=$links|Where-Object {[IO.Path]::GetFileName($_.shortcut.TargetPath) -ieq 'Spotify.exe'}|Select-Object -First 1;if($candidate){$SpotifyPath=$candidate.shortcut.TargetPath}}
    if(-not $SpotifyPath){$SpotifyPath=Join-Path $env:APPDATA 'Spotify\Spotify.exe'}
    if(-not (Test-Path -LiteralPath $SpotifyPath) -or [IO.Path]::GetFileName($SpotifyPath) -ine 'Spotify.exe'){throw 'Spotify.exe not found. Supply -SpotifyPath with its full path.'}
    $SpotifyPath=[SpotifyNativePatch]::RealPath($SpotifyPath)
    if(-not $backup){$backup=[pscustomobject]@{protocol=(Read-Value $protocolKey '(default)');spotifyStartup=(Read-Value $runKey 'Spotify');shortcuts=@()}}
    Save-Json $configPath @{spotifyExecutable=$SpotifyPath}
    if(-not $links.Count) {
        $path=Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Programs\Spotify.lnk'
        $links=@([pscustomobject]@{path=$path;shortcut=$shell.CreateShortcut($path)})
    }
    foreach($link in $links) {
        $saved=$backup.shortcuts|Where-Object path -eq $link.path|Select-Object -First 1
        if(-not $saved) {
            $copy=$null
            if(Test-Path -LiteralPath $link.path) {
                $hash=[Security.Cryptography.SHA256]::Create()
                try{$name=[BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($link.path))).Replace('-','')}finally{$hash.Dispose()}
                $copy=Join-Path $root ($name+'.lnk')
                Copy-Item -LiteralPath $link.path -Destination $copy -Force
            }
            $saved=[pscustomobject]@{path=$link.path;backup=$copy;arguments=$link.shortcut.Arguments}
            $backup.shortcuts=@($backup.shortcuts)+$saved
        }
        Save-Json $backupPath $backup
        $link.shortcut.TargetPath=$powerShell
        $link.shortcut.Arguments=Launch-Command $saved.arguments
        $link.shortcut.WorkingDirectory=Split-Path -Parent $SpotifyPath
        $link.shortcut.IconLocation=$SpotifyPath+',0'
        $link.shortcut.WindowStyle=7
        $link.shortcut.Save()
    }
    Save-Json $backupPath $backup
    Refresh-Protocol $SpotifyPath
    $startup=Read-Value $runKey 'Spotify'
    if($startup -and $startup -match '^"[^"]*Spotify\.exe"(.*)$') {
        Write-Value $runKey 'Spotify' ('"'+$powerShell+'" '+(Launch-Command $Matches[1]))
    }
    Write-Output 'Installed. Restart Spotify using your usual shortcut.'
}finally{if($setupLocked){$setupMutex.ReleaseMutex()};$setupMutex.Dispose()}
