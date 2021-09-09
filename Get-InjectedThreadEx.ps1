function Get-InjectedThreadEx
{
    <# 
    
    .SYNOPSIS 
    
    Looks for threads that were created as a result of code injection.
    
    .DESCRIPTION
    
    Memory resident malware (fileless malware) often uses a form of memory injection to get code execution. Get-InjectedThread looks at each running thread to determine if it is the result of memory injection.
    
    Common memory injection techniques that *can* be caught using this method include:
    - Classic Injection (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
    - Reflective DLL Injection
    - Memory Module

    NOTE: Nothing in security is a silver bullet. An attacker could modify their tactics to avoid detection using this methodology.
    
    .NOTES

    Authors - Jared Atkinson (@jaredcatkinson)
            - Joe Desimone (@dez_)
            - John Uhlmann (@jdu2600)


    .EXAMPLE 
    
    PS > Get-InjectedThreadEx

    ProcessName                  : ThreadStart.exe
    ProcessId                    : 7784
    Wow64                        : False
    Path                         : C:\Users\tester\Desktop\ThreadStart.exe
    KernelPath                   : C:\Users\tester\Desktop\ThreadStart.exe
    CommandLine                  : "C:\Users\tester\Desktop\ThreadStart.exe"
    PathMismatch                 : False
    ProcessIntegrity             : MEDIUM_MANDATORY_LEVEL
    ProcessPrivilege             : SeChangeNotifyPrivilege
    ProcessLogonId               : 999
    ProcessSecurityIdentifier    : S-1-5-21-386661145-2656271985-3844047388-1001
    ProcessUserName              : DESKTOP-HMTGQ0R\SYSTEM
    ProcessLogonSessionStartTime : 3/15/2017 5:45:38 PM
    ProcessLogonType             : System
    ProcessAuthenticationPackage : NTLM
    ThreadId                     : 14512
    BasePriority                 : 8
    IsUniqueThreadToken          : False
    ThreadIntegrity              :
    ThreadPrivilege              :
    AdditionalThreadPrivilege    :
    ThreadLogonId                :
    ThreadSecurityIdentifier     :
    ThreadUserName               : \
    ThreadLogonSessionStartTime  :
    ThreadLogonType              :
    ThreadAuthenticationPackage  :
    AllocatedMemoryProtection    : PAGE_EXECUTE_READWRITE
    MemoryProtection             : PAGE_EXECUTE_READWRITE
    MemoryState                  : MEM_COMMIT
    MemoryType                   : MEM_PRIVATE
    Win32StartAddress            : 430000
    Win32StartAddressModule      :
    Win32StartAddressPrivate     : True
    Size                         : 4096
    TailBytes                    : 90909090909090909090909090909090
    StartBytes                   : 558bec5356578b7d086a008b5f1083671000ff15c4c9595a8bf085f6780f8bcfe82f85f5ff8bf0ff15c8c9595a5653ff
    Detections                   : {MEM_PRIVATE}
    
    #>

    [CmdletBinding()]
    param
    (
        [Parameter()]
        [Switch]$Aggressive
    )

    $WindowsVersion = [Int]((Get-WmiObject Win32_OperatingSystem).version -split '\.')[0]
    foreach($proc in (Get-Process))
    {
        if($proc.Id -eq 0 -or $proc.Id -eq 4)
        {
            continue # skip Idle and System
        }

        $hProcess = OpenProcess -ProcessId $proc.Id -DesiredAccess PROCESS_ALL_ACCESS -InheritHandle $false
        if($hProcess -eq 0)
        {
            continue # skip process - Access is Denied
        }

        Write-Verbose -Message "Checking $($proc.Name) [$($proc.Id)] for injection"
        $IsWow64Process = IsWow64Process -ProcessHandle $hProcess

        $hProcessToken = OpenProcessToken -ProcessHandle $hProcess -DesiredAccess TOKEN_QUERY
        if($hProcessToken -ne 0)
        {
            $ProcessSID = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 1
            $ProcessPrivs = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 3
            $ProcessLogonSession = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 17
            $ProcessIntegrity = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 25
        }

        foreach ($thread in $proc.Threads)
        {
            $hThread = OpenThread -ThreadId $thread.Id -DesiredAccess THREAD_ALL_ACCESS
            if ($hThread -eq 0)
            {
                continue # skip thread - Access is Denied
            }
            Write-Verbose -Message "Thread Id: [$($thread.Id)]"

            # check if thread has unique token
            $IsUniqueThreadToken = $false
            $ThreadSID = ""
            $ThreadPrivs = ""
            $ThreadLogonSession = ""
            $ThreadIntegrity = ""
            $NewPrivileges = ""
            try
            {
                $hThreadToken = OpenThreadToken -ThreadHandle $hThread -DesiredAccess TOKEN_QUERY

                if ($hThreadToken -ne 0)
                {
                    $ThreadSID = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 1
                    $ThreadPrivs = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 3
                    $ThreadLogonSession = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 17
                    $ThreadIntegrity = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 25
                    $IsUniqueThreadToken = $true
                }
            }
            catch {}

            # Win32StartAddress memory information
            $Win32StartAddress = NtQueryInformationThread_Win32StartAddress -ThreadHandle $hThread
            $memory_basic_info = VirtualQueryEx -ProcessHandle $hProcess -BaseAddress $Win32StartAddress
            $AllocatedMemoryProtection = $memory_basic_info.AllocationProtect -as $MemProtection
            $MemoryProtection = $memory_basic_info.Protect -as $MemProtection
            $MemoryState = $memory_basic_info.State -as $MemState
            $MemoryType = $memory_basic_info.Type -as $MemType
               
            if ($MemoryState -eq $MemState::MEM_COMMIT)
            {
                $StartBytesLength = [math]::Min(48, [UInt64]$memory_basic_info.BaseAddress + [UInt64]$memory_basic_info.RegionSize - [Int64]$Win32StartAddress)
                $buf = ReadProcessMemory -ProcessHandle $hProcess -BaseAddress $Win32StartAddress -Size $StartBytesLength
                $StartBytes = New-Object -TypeName System.Text.StringBuilder($StartBytesLength)
                ForEach ($byte in $buf) { $StartBytes.AppendFormat("{0:x2}", $byte) | Out-Null }
                $StartBytes = $StartBytes.ToString()

                $TailBytesLength = [math]::Min(16, [Int64]$Win32StartAddress - [UInt64]$memory_basic_info.BaseAddress)
                $buf = ReadProcessMemory -ProcessHandle $hProcess -BaseAddress ([Int64]$Win32StartAddress - $TailBytesLength) -Size $TailBytesLength
                $TailBytes = New-Object -TypeName System.Text.StringBuilder($TailBytesLength)
                ForEach ($byte in $buf) { $TailBytes.AppendFormat("{0:x2}", $byte) | Out-Null }
                $TailBytes = $TailBytes.ToString()

                $StartAddressModule = GetMappedFileName -ProcessHandle $hProcess -Address $Win32StartAddress
                $WindowsRegex = '^\\Device\\HarddiskVolume\d+\\Windows\\'

                # Suspicious thread heuristics
                # original
                #  - not MEM_IMAGE
                # new
                #  - MEM_IMAGE and x64 and Win32StartAddress is not 16-byte aligned
                #  - MEM_IMAGE and x64 and Win32StartAddress is unexpected prolog
                #  - MEM_IMAGE and Win32StartAddress is preceded by unexpected byte
                #  - MEM_IMAGE and Win32StartAddress is on a private (modified) page
                #  - MEM_IMAGE and Win32StartAddress is in a suspicious module
                #  - Thread has a higher integrity level than process
                #  - Thread has additional unexpected privileges
                $Detections = @()

                # All threads not starting in a MEM_IMAGE region are suspicious
                if ($MemoryType -ne $MemType::MEM_IMAGE)
                {
                    $Detections += $MemoryType
                }

                # Modern CPUs load instructions in 16-byte lines. So, for performance, compilers want to ensure
                # that the maximum number of useful bytes will be loaded. This is either 16 or the number
                # of bytes modulo 16 until the end of the first call (or absolute jmp) instruction.
                # Any start address not aligned as such is a potential MEM_IMAGE trampoline gadget such
                # as 'jmp rcx'
                # https://blog.xpnsec.com/undersanding-and-evading-get-injectedthread/

                $EarlyCallRegex = '^(..)*?e8'
                $ImmediateJumpRegex = '^(e9|(48)?ff25)'
                # Only check Windows components by default - other compilers may behave differently.
                if ((($StartAddressModule -match $WindowsRegex) -or $Aggressive) -and
                    (([Int64]$Win32StartAddress -band 0xF) -ne 0) -and
                    # If < Windows 10 then also allow 4-byte alignments
                    (($WindowsVersion -ge 10) -or (([Int64]$Win32StartAddress -band 3) -ne 0)))
                {
                    if ($StartBytes -match $EarlyCallRegex)
                    {
                        # Calulate the distance to the end of the call modulo 16
                        # This calculation isn't perfect - we did a rough regex match, not an exact decompilation...
                        $BytesNeeded = (($matches[0].Length / 2) -band 0xF) + 4
                        $BytesLoaded = 16 - ([Int64]$Win32StartAddress -band 0xF)
                        if ($BytesLoaded -lt $BytesNeeded)
                        {
                            $Detections += 'alignment'
                        }
                    }
                    elseif ($StartBytes -notmatch $ImmediateJumpRegex)
                    {
                        $Detections += 'alignment'
                    }
                }
                        
                # Any x64 threads not starting with a valid Windows x64 ABI prolog are suspicious
                # In lieu of a dissassembler in PowerShell we approximate with a regex :-(
                $x64PrologRegex = '^(' +
                '(488d0[5d]........)?' + # lea rax,[rip+nnnn]
                '(eb0.(90){3,14})?' + # hot patch space
                '(488bc4|4c8bdc)?' + # stack pointer - rax|r11
                '(4[8-9c]89(....|[3-7][4c]24..))*' + # save registers in shadow space
                '((5|fff|4(0|1)5)[0-7])*' + # push registers
                '(488bec|4889e5)?' + # stack pointer - rbp
                '(488d6c24..)?' + # lea rbp,[rsp+n]
                '(488dac24........)?' + # lea rbp,[rsp+nnnn]
                '(488d68..)?' + # lea rbp,[rax+n]
                '(488da8........)?' + # lea rbp,[rax+nnnn]
                '(498d6b..)?' + # lea rbp,[r11+n]
                '(498dab........)?' + # lea rbp,[r11+nnnn]
                '(488(1|3)ec' + # sub rsp,n
                '|b8........e8........482be0)' + # mov rax; call; sub rsp, rax
                '|4885c90f8[4-5]........(e9........cc|b8........c3)' + # test rcx,rcx; j[n]e nnnn; [jmp nnnn | mov eax, ret]
                '|(488d0[5d]........)?(488b..(..)?)*(e9|(48)?ff25)' + # (mov ... ) jmp
                '|4d5a90000300000004000000ffff0000b8000000000000004000000000000000' + # PE Header -> CLR Assembly with AddressOfEntryPoint=0
                ')'
                # TODO(jdu) - update with more variants? Or is the approach simply too unreliable? Move to -Aggressive perhaps?
                if ((-not $IsWow64Process) -and
                    ($StartBytes -notmatch $x64PrologRegex))
                {
                    $Detections += 'prolog'
                }

                $x86PrologRegex = '^(' +
                '(8bff)?55(8bec|89e5)' + # stack pointer
                '|(6a..|(68|b8)........)*e8' + # call
                '|e9|ff25' + # jmp
                '|4d5a90000300000004000000ffff0000b8000000000000004000000000000000' + # CLR Assembly
                ')'
                if ($IsWow64Process -and
                    ($StartBytes -notmatch $x86PrologRegex))
                {
                    $Detections += 'prolog'
                }

                # The byte preceding a function prolog is typically a return, or filler byte.
                # False positives can occur if data was included in a code section. This was
                # common in older compilers.
                $x64EpilogFillerRegex = '(00|90|c3|cc|(e8|e9|ff25)........|^)$'
                if ($TailBytes -notmatch $x64EpilogFillerRegex)
                {
                    $Detections += 'tail'
                }

                # Has our MEM_IMAGE Win32StartAddress been (naively) hooked?
                # https://blog.redbluepurple.io/offensive-research/bypassing-injection-detection#creating-the-thread
                # TODO(jdu) if false positives, check against bytes on disk?
                # Detection gap - the hook could easily be deeper, potentially even in a subsequent call. :-(
                # Microsoft-Windows-Threat-Intelligence ETW events should detect this more robustly.
                #
                # Only check Windows components by default.
                $PrivatePage = IsWorkingSetPage -ProcessHandle $hProcess -Address $Win32StartAddress
                if ((($StartAddressModule -match $WindowsRegex) -or $Aggressive) -and
                    ($MemoryType -eq $MemType::MEM_IMAGE) -and
                    $PrivatePage)
                {
                    $Detections += 'modified'
                }

                # Suspicious start modules
                # https://www.trustedsec.com/blog/avoiding-get-injectedthread-for-internal-thread-creation/
                $crt = '^\\Device\\HarddiskVolume\d+\\Windows\\System32\\(msvcr[t0-9]+|ucrtbase)d?\.dll$'
                # https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/beginthread-beginthreadex
                # crt!_startthread[ex] - the CRT wrapper around CreateThread
                # This will *false positive* on legitimate CRT applications...
                # If we were in a kernel CreateThreadNotifyRoutine then we could inspect the function's
                # parameter to determine the real Win32StartAddress.
                # Instead we walk the thread's stack bottom up to find an approximate Win32StartAddress
                # so we can eliminate the FPs.
                if ($StartAddressModule -match $crt)
                {
                    if (-not $IsWow64Process)
                    {
                        $Suspicious = SuspiciousCrtThreadStartReturnAddress -ProcessHandle $hProcess -ThreadHandle $hThread
                        if ($Suspicious)
                        {
                            $Detections += 'crt'
                        }
                    }
                    else
                    {
                        $Detections += 'crt_x86_TODO'  # Handle x86 FPs...
                    }
                }

                if ($IsUniqueThreadToken)
                {
                    if ($ProcessIntegrity -ne 'SYSTEM_MANDATORY_LEVEL')
                    {
                        if ($ThreadIntegrity -eq 'SYSTEM_MANDATORY_LEVEL')
                        {
                            $Detections += 'SystemToken'
                        }

                        if (($ProcessIntegrity -ne 'HIGH_MANDATORY_LEVEL') -and
                            ($ThreadIntegrity -eq 'HIGH_MANDATORY_LEVEL'))
                        {
                            $Detections += 'AdminToken'
                        }
                    }

                    $NewPrivileges = @()
                    foreach ($Privilege in $ThreadPrivs -split ', ')
                    {
                        if ($ProcessPrivs -notmatch $Privilege)
                        {
                            $NewPrivileges += $Privilege
                        }
                    }
                    $NewPrivileges = $NewPrivileges -join ', '

                    # Known additional privileges
                    # SysMain (sechost.dll) -> SeTakeOwnership
                    $SysMainService = '\\Device\\HarddiskVolume\d+\\Windows\\System32\\sechost.dll'

                    if (($NewPrivileges.Length -ne 0) -and
                        -not ($StartAddressModule -match $SysMainService -and $NewPrivileges -eq 'SeTakeOwnershipPrivilege'))
                    {
                        $Detections += $NewPrivileges
                    }

                }

                if ($Detections.Length -ne 0)
                {
                    $WmiProcess = Get-WmiObject Win32_Process -Filter "ProcessId = '$($proc.Id)'"
                    $KernelPath = QueryFullProcessImageName -ProcessHandle $hProcess
                    $PathMismatch = $proc.Path.ToLower() -ne $KernelPath.ToLower()

                    $ThreadDetail = New-Object PSObject
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessName -Value $WmiProcess.Name
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessId -Value $WmiProcess.ProcessId
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name Wow64 -Value $IsWow64Process
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name Path -Value $WmiProcess.Path
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name KernelPath -Value $KernelPath
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name CommandLine -Value $WmiProcess.CommandLine
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name PathMismatch -Value $PathMismatch
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessIntegrity -Value $ProcessIntegrity
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessPrivilege -Value $ProcessPrivs
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessLogonId -Value $ProcessLogonSession.LogonId
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessSecurityIdentifier -Value $ProcessSID
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessUserName -Value "$($ProcessLogonSession.Domain)\$($ProcessLogonSession.UserName)"
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessLogonSessionStartTime -Value $ProcessLogonSession.StartTime
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessLogonType -Value $ProcessLogonSession.LogonType
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessAuthenticationPackage -Value $ProcessLogonSession.AuthenticationPackage
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ThreadId -Value $thread.Id
                    $ThreadDetail | Add-Member -MemberType NoteProperty -Name ThreadStartTime -Value $thread.StartTime
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name BasePriority -Value $thread.BasePriority
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name IsUniqueThreadToken -Value $IsUniqueThreadToken
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ThreadIntegrity -Value $ThreadIntegrity
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ThreadPrivilege -Value $ThreadPrivs
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name AdditionalThreadPrivilege -Value $NewPrivileges
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ThreadLogonId -Value $ThreadLogonSession.LogonId
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ThreadSecurityIdentifier -Value $ThreadSID
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ThreadUserName -Value "$($ThreadLogonSession.Domain)\$($ThreadLogonSession.UserName)"
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ThreadLogonSessionStartTime -Value $ThreadLogonSession.StartTime
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ThreadLogonType -Value $ThreadLogonSession.LogonType
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name ThreadAuthenticationPackage -Value $ThreadLogonSession.AuthenticationPackage
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name AllocatedMemoryProtection -Value $AllocatedMemoryProtection
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name MemoryProtection -Value $MemoryProtection
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name MemoryState -Value $MemoryState
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name MemoryType -Value $MemoryType
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name Win32StartAddress -Value $Win32StartAddress.ToString('X')
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name Win32StartAddressModule -Value $StartAddressModule
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name Win32StartAddressPrivate -Value $PrivatePage
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name Size -Value $memory_basic_info.RegionSize
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name TailBytes -Value $TailBytes
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name StartBytes -Value $StartBytes
                    $ThreadDetail | Add-Member -MemberType Noteproperty -Name Detections -Value $Detections
                    Write-Output $ThreadDetail
                }
            }
        }
        CloseHandle($hThread)
    }
    CloseHandle($hProcess)
}

function SuspiciousCrtThreadStartReturnAddress {
    <#
    .SYNOPSIS

    Checks the return address into the module that called crt!_beginthread[ex] for suspicious characteristics.

    .DESCRIPTION

    .PARAMETER ThreadHandle

    .NOTES

    Author - John Uhlmann (@jdu2600)

    .LINK

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,

        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ThreadHandle
    )

    <#
    (func ntdll NtQueryInformationThread ([UInt32]) @(
        [IntPtr],                                   #_In_      HANDLE          ThreadHandle,
        [Int32],                                    #_In_      THREADINFOCLASS ThreadInformationClass,
        [THREAD_BASIC_INFORMATION].MakeByRefType(), #_Inout_   PVOID           ThreadInformation,
        [Int32],                                    #_In_      ULONG           ThreadInformationLength,
        [IntPtr]                                    #_Out_opt_ PULONG          ReturnLength
    ))
    #>

    # TODO(jdu) handle 32-bit ...

    # 1. Query the THREAD_BASIC_INFORMATION to determine the location of the Thread Environment Block (TEB)
    $thread_basic_info = [Activator]::CreateInstance($THREAD_BASIC_INFORMATION)
    $NtStatus = $Ntdll::NtQueryInformationThread($ThreadHandle, 0, [Ref]$thread_basic_info, $THREAD_BASIC_INFORMATION::GetSize(), [IntPtr]::Zero)
    if ($NtStatus -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "NtQueryInformationThread Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    # 2. The TIB is the first elemenet of the TEB. Read the TIB to determine the stack limits.
    # TODO(jdu) Urgh. Powershell help needed... there must be a neater way...
    $buf = ReadProcessMemory -ProcessHandle $ProcessHandle -BaseAddress $thread_basic_info.TebBaseAddress -Size $TIB64::GetSize()
    $TibPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TIB64::GetSize())
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $TibPtr, $TIB64::GetSize())
    $Tib = $TibPtr -as $TIB64

    # 3. Read the (partial) stack contents
    $StackReadLength = [math]::Min(0x3000, [Int64]$Tib.StackBase - [Int64]$Tib.StackLimit)
    $StackBuffer = ReadProcessMemory -ProcessHandle $ProcessHandle -BaseAddress ([Int64]$Tib.StackBase - $StackReadLength) -Size $StackReadLength

    # 4. Search the stack bottom up for the return address immediately after the CRT wrapper.
    # ntdll!RtlUserThreadStart -> kernel32!BaseThreadInitThunk -> CRT!_beginthread[ex] -> actual user start address
    $RspBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
    $Rsp = 0
    $NtdllFound = $false
    $Kernel32Found = $false
    $CrtFound = $false
    $NonImageFound = $false
    $NtdllRegex = '^\\Device\\HarddiskVolume\d+\\Windows\\System32\\ntdll\.dll$'
    $Kernel32Regex = '^\\Device\\HarddiskVolume\d+\\Windows\\System32\\kernel32\.dll$'
    $CrtRegex = '^\\Device\\HarddiskVolume\d+\\Windows\\System32\\(msvcr[t0-9]+|ucrtbase)d?\.dll$'
    for ($i = 8; $Rsp -eq 0 -and $i -lt $StackReadLength; $i += 8) {
        [System.Runtime.InteropServices.Marshal]::Copy($StackBuffer, ($StackReadLength - $i), $RspBuffer, [IntPtr]::Size)
        $CandidateRsp = [System.Runtime.InteropServices.Marshal]::ReadInt64($RspBuffer)
        if ($CandidateRsp -ne 0) {
            $memory_basic_info = VirtualQueryEx -ProcessHandle $ProcessHandle -BaseAddress $CandidateRsp
            if ($memory_basic_info.State -eq $MemState::MEM_COMMIT -and
                ($memory_basic_info.Protect -eq $MemProtection::PAGE_EXECUTE -or
                    $memory_basic_info.Protect -eq $MemProtection::PAGE_EXECUTE_READ -or
                    $memory_basic_info.Protect -eq $MemProtection::PAGE_EXECUTE_READWRITE -or
                    $memory_basic_info.Protect -eq $MemProtection::PAGE_EXECUTE_WRITECOPY)) {
                # 5. Is this the 4th return address on the stack?
                # Note - at this stack depth it is unlikely, but not impossible, that we encounter a
                # false positive return address on the stack.
                $NonImageFound = $NonImageFound -or ($memory_basic_info.Type -ne $MemType::MEM_IMAGE)
                $CandidateRspModule = GetMappedFileName -ProcessHandle $hProcess -Address $CandidateRsp
                if ($CrtFound -and ($CandidateRspModule -notmatch $CrtRegex)) {
                    $Rsp = $CandidateRsp
                }
                else {
                    $NtdllFound = $NtdllFound -or ($CandidateRspModule -match $NtdllRegex)
                    $Kernel32Found = $Kernel32Found -or ($NtdllFound -and ($CandidateRspModule -match $Kernel32Regex))
                    $CrtFound = $CrtFound -or ($Kernel32Found -and ($CandidateRspModule -match $CrtRegex))
                }
            }
        }
    }

    # 6. Is our return address either not MEM_IMAGE or modified MEM_IMAGE?
    $Suspicious = $false
    if ($Rsp -ne 0) {
        $PrivatePage = IsWorkingSetPage -ProcessHandle $hProcess -Address $Rsp
        $Suspicious = $NonImageFound -or $PrivatePage
    }

    Write-Output $Suspicious
}

function Get-LogonSession
{
    <#
    .NOTES

    Author: Lee Christensen (@tifkin_)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    #>
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $LogonId
    )
    
    $LogonMap = @{}
    Get-WmiObject Win32_LoggedOnUser  | %{
    
        $Identity = $_.Antecedent | Select-String 'Domain="(.*)",Name="(.*)"'
        $LogonSession = $_.Dependent | Select-String 'LogonId="(\d+)"'

        $LogonMap[$LogonSession.Matches[0].Groups[1].Value] = New-Object PSObject -Property @{
            Domain = $Identity.Matches[0].Groups[1].Value
            UserName = $Identity.Matches[0].Groups[2].Value
        }
    }

    Get-WmiObject Win32_LogonSession -Filter "LogonId = `"$($LogonId)`"" | %{
        $LogonType = $Null
        switch($_.LogonType) {
            $null {$LogonType = 'None'}
            0 { $LogonType = 'System' }
            2 { $LogonType = 'Interactive' }
            3 { $LogonType = 'Network' }
            4 { $LogonType = 'Batch' }
            5 { $LogonType = 'Service' }
            6 { $LogonType = 'Proxy' }
            7 { $LogonType = 'Unlock' }
            8 { $LogonType = 'NetworkCleartext' }
            9 { $LogonType = 'NewCredentials' }
            10 { $LogonType = 'RemoteInteractive' }
            11 { $LogonType = 'CachedInteractive' }
            12 { $LogonType = 'CachedRemoteInteractive' }
            13 { $LogonType = 'CachedUnlock' }
            default { $LogonType = $_.LogonType}
        }

        New-Object PSObject -Property @{
            UserName = $LogonMap[$_.LogonId].UserName
            Domain = $LogonMap[$_.LogonId].Domain
            LogonId = $_.LogonId
            LogonType = $LogonType
            AuthenticationPackage = $_.AuthenticationPackage
            Caption = $_.Caption
            Description = $_.Description
            InstallDate = $_.InstallDate
            Name = $_.Name
            StartTime = $_.ConvertToDateTime($_.StartTime)
        }
    }
}

#region PSReflect

function New-InMemoryModule
{
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}

function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func
 
.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

function psenum
{
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}

# A helper function used to reduce typing while defining struct
# fields.
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
 
.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

#endregion PSReflect

#region PSReflect Definitions (Thread)

$Module = New-InMemoryModule -ModuleName GetInjectedThread

#region Constants
$UNTRUSTED_MANDATORY_LEVEL = "S-1-16-0"
$LOW_MANDATORY_LEVEL = "S-1-16-4096"
$MEDIUM_MANDATORY_LEVEL = "S-1-16-8192"
$MEDIUM_PLUS_MANDATORY_LEVEL = "S-1-16-8448"
$HIGH_MANDATORY_LEVEL = "S-1-16-12288"
$SYSTEM_MANDATORY_LEVEL = "S-1-16-16384"
$PROTECTED_PROCESS_MANDATORY_LEVEL = "S-1-16-20480"
$SECURE_PROCESS_MANDATORY_LEVEL = "S-1-16-28672"
#endregion Constants

#region Enums
$LuidAttributes = psenum $Module LuidAttributes UInt32 @{
    DISABLED                            =   '0x00000000'
    SE_PRIVILEGE_ENABLED_BY_DEFAULT     =   '0x00000001'
    SE_PRIVILEGE_ENABLED                =   '0x00000002'
    SE_PRIVILEGE_REMOVED                =   '0x00000004'
    SE_PRIVILEGE_USED_FOR_ACCESS        =   '0x80000000'
} -Bitfield

$MemProtection = psenum $Module MemProtection UInt32 @{
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_TARGETS_INVALID = 0x40000000
    PAGE_TARGETS_NO_UPDATE = 0x40000000
    PAGE_GUARD = 0x100
    PAGE_NOCACHE = 0x200
    PAGE_WRITECOMBINE = 0x400
} -Bitfield

$MemState = psenum $Module MemState UInt32 @{
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_FREE = 0x10000
}

$MemType = psenum $Module MemType UInt32 @{
    MEM_PRIVATE = 0x20000
    MEM_MAPPED = 0x40000
    MEM_IMAGE = 0x1000000
}

$PROCESS_ACCESS = psenum $Module PROCESS_ACCESS UInt32 @{
    PROCESS_TERMINATE                 = 0x00000001
    PROCESS_CREATE_THREAD             = 0x00000002
    PROCESS_VM_OPERATION              = 0x00000008
    PROCESS_VM_READ                   = 0x00000010
    PROCESS_VM_WRITE                  = 0x00000020
    PROCESS_DUP_HANDLE                = 0x00000040
    PROCESS_CREATE_PROCESS            = 0x00000080
    PROCESS_SET_QUOTA                 = 0x00000100
    PROCESS_SET_INFORMATION           = 0x00000200
    PROCESS_QUERY_INFORMATION         = 0x00000400
    PROCESS_SUSPEND_RESUME            = 0x00000800
    PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
    DELETE                            = 0x00010000
    READ_CONTROL                      = 0x00020000
    WRITE_DAC                         = 0x00040000
    WRITE_OWNER                       = 0x00080000
    SYNCHRONIZE                       = 0x00100000
    PROCESS_ALL_ACCESS                = 0x001f1ffb
} -Bitfield

$SecurityEntity = psenum $Module SecurityEntity UInt32 @{
    SeCreateTokenPrivilege              =   1
    SeAssignPrimaryTokenPrivilege       =   2
    SeLockMemoryPrivilege               =   3
    SeIncreaseQuotaPrivilege            =   4
    SeUnsolicitedInputPrivilege         =   5
    SeMachineAccountPrivilege           =   6
    SeTcbPrivilege                      =   7
    SeSecurityPrivilege                 =   8
    SeTakeOwnershipPrivilege            =   9
    SeLoadDriverPrivilege               =   10
    SeSystemProfilePrivilege            =   11
    SeSystemtimePrivilege               =   12
    SeProfileSingleProcessPrivilege     =   13
    SeIncreaseBasePriorityPrivilege     =   14
    SeCreatePagefilePrivilege           =   15
    SeCreatePermanentPrivilege          =   16
    SeBackupPrivilege                   =   17
    SeRestorePrivilege                  =   18
    SeShutdownPrivilege                 =   19
    SeDebugPrivilege                    =   20
    SeAuditPrivilege                    =   21
    SeSystemEnvironmentPrivilege        =   22
    SeChangeNotifyPrivilege             =   23
    SeRemoteShutdownPrivilege           =   24
    SeUndockPrivilege                   =   25
    SeSyncAgentPrivilege                =   26
    SeEnableDelegationPrivilege         =   27
    SeManageVolumePrivilege             =   28
    SeImpersonatePrivilege              =   29
    SeCreateGlobalPrivilege             =   30
    SeTrustedCredManAccessPrivilege     =   31
    SeRelabelPrivilege                  =   32
    SeIncreaseWorkingSetPrivilege       =   33
    SeTimeZonePrivilege                 =   34
    SeCreateSymbolicLinkPrivilege       =   35
}

$SidNameUser = psenum $Module SID_NAME_USE UInt32 @{
  SidTypeUser                            = 1
  SidTypeGroup                           = 2
  SidTypeDomain                          = 3
  SidTypeAlias                           = 4
  SidTypeWellKnownGroup                  = 5
  SidTypeDeletedAccount                  = 6
  SidTypeInvalid                         = 7
  SidTypeUnknown                         = 8
  SidTypeComputer                        = 9
}

$THREAD_ACCESS = psenum $Module THREAD_ACCESS UInt32 @{
    THREAD_TERMINATE                 = 0x00000001
    THREAD_SUSPEND_RESUME            = 0x00000002
    THREAD_GET_CONTEXT               = 0x00000008
    THREAD_SET_CONTEXT               = 0x00000010
    THREAD_SET_INFORMATION           = 0x00000020
    THREAD_QUERY_INFORMATION         = 0x00000040
    THREAD_SET_THREAD_TOKEN          = 0x00000080
    THREAD_IMPERSONATE               = 0x00000100
    THREAD_DIRECT_IMPERSONATION      = 0x00000200
    THREAD_SET_LIMITED_INFORMATION   = 0x00000400
    THREAD_QUERY_LIMITED_INFORMATION = 0x00000800
    DELETE                           = 0x00010000
    READ_CONTROL                     = 0x00020000
    WRITE_DAC                        = 0x00040000
    WRITE_OWNER                      = 0x00080000
    SYNCHRONIZE                      = 0x00100000
    THREAD_ALL_ACCESS                = 0x001f0ffb
} -Bitfield

$TOKEN_ACCESS = psenum $Module TOKEN_ACCESS UInt32 @{
    TOKEN_DUPLICATE          = 0x00000002
    TOKEN_IMPERSONATE        = 0x00000004
    TOKEN_QUERY              = 0x00000008
    TOKEN_QUERY_SOURCE       = 0x00000010
    TOKEN_ADJUST_PRIVILEGES  = 0x00000020
    TOKEN_ADJUST_GROUPS      = 0x00000040
    TOKEN_ADJUST_DEFAULT     = 0x00000080
    TOKEN_ADJUST_SESSIONID   = 0x00000100
    DELETE                   = 0x00010000
    READ_CONTROL             = 0x00020000
    WRITE_DAC                = 0x00040000
    WRITE_OWNER              = 0x00080000
    SYNCHRONIZE              = 0x00100000
    STANDARD_RIGHTS_REQUIRED = 0x000F0000
    TOKEN_ALL_ACCESS         = 0x001f01ff
} -Bitfield

$TokenInformationClass = psenum $Module TOKEN_INFORMATION_CLASS UInt16 @{ 
  TokenUser                             = 1
  TokenGroups                           = 2
  TokenPrivileges                       = 3
  TokenOwner                            = 4
  TokenPrimaryGroup                     = 5
  TokenDefaultDacl                      = 6
  TokenSource                           = 7
  TokenType                             = 8
  TokenImpersonationLevel               = 9
  TokenStatistics                       = 10
  TokenRestrictedSids                   = 11
  TokenSessionId                        = 12
  TokenGroupsAndPrivileges              = 13
  TokenSessionReference                 = 14
  TokenSandBoxInert                     = 15
  TokenAuditPolicy                      = 16
  TokenOrigin                           = 17
  TokenElevationType                    = 18
  TokenLinkedToken                      = 19
  TokenElevation                        = 20
  TokenHasRestrictions                  = 21
  TokenAccessInformation                = 22
  TokenVirtualizationAllowed            = 23
  TokenVirtualizationEnabled            = 24
  TokenIntegrityLevel                   = 25
  TokenUIAccess                         = 26
  TokenMandatoryPolicy                  = 27
  TokenLogonSid                         = 28
  TokenIsAppContainer                   = 29
  TokenCapabilities                     = 30
  TokenAppContainerSid                  = 31
  TokenAppContainerNumber               = 32
  TokenUserClaimAttributes              = 33
  TokenDeviceClaimAttributes            = 34
  TokenRestrictedUserClaimAttributes    = 35
  TokenRestrictedDeviceClaimAttributes  = 36
  TokenDeviceGroups                     = 37
  TokenRestrictedDeviceGroups           = 38
  TokenSecurityAttributes               = 39
  TokenIsRestricted                     = 40
  MaxTokenInfoClass                     = 41
}
#endregion Enums

#region Structs
$LUID = struct $Module Luid @{
    LowPart         =   field 0 $SecurityEntity
    HighPart        =   field 1 Int32
}

$LUID_AND_ATTRIBUTES = struct $Module LuidAndAttributes @{
    Luid            =   field 0 $LUID
    Attributes      =   field 1 UInt32
}

$MEMORYBASICINFORMATION = struct $Module MEMORY_BASIC_INFORMATION @{
  BaseAddress       = field 0 UIntPtr
  AllocationBase    = field 1 UIntPtr
  AllocationProtect = field 2 UInt32
  RegionSize        = field 3 UIntPtr
  State             = field 4 UInt32
  Protect           = field 5 UInt32
  Type              = field 6 UInt32
}

$SID_AND_ATTRIBUTES = struct $Module SidAndAttributes @{
    Sid             =   field 0 IntPtr
    Attributes      =   field 1 UInt32
}

$TOKEN_MANDATORY_LABEL = struct $Module TokenMandatoryLabel @{
    Label           = field 0 $SID_AND_ATTRIBUTES;
}

$TOKEN_ORIGIN = struct $Module TokenOrigin @{
  OriginatingLogonSession = field 0 UInt64
}

$TOKEN_PRIVILEGES = struct $Module TokenPrivileges @{
    PrivilegeCount  = field 0 UInt32
    Privileges      = field 1 $LUID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 50)
}

$TOKEN_USER = struct $Module TOKEN_USER @{
    User            = field 0 $SID_AND_ATTRIBUTES
}

$WORKING_SET_EX_INFORMATION = struct $Module  WorkingSetExInformation @{
    VirtualAddress    = field 0 IntPtr
    VirtualAttributes = field 1 IntPtr
}

$THREAD_BASIC_INFORMATION = struct $Module THREAD_BASIC_INFORMATION @{
    ExitStatus     = field 0 Int32
    TebBaseAddress = field 1 IntPtr
    UniqueProcess  = field 2 IntPtr
    UniqueThread   = field 3 IntPtr
    AffinityMask   = field 4 IntPtr
    Priority       = field 5 Int32
    BasePriority   = field 6 Int32
}

$TIB64 = struct $Module NT_TIB64 @{
    ExceptionList        = field 0 IntPtr
    StackBase            = field 1 IntPtr
    StackLimit           = field 2 IntPtr
    SubSystemTib         = field 3 IntPtr
    FiberData            = field 4 IntPtr
    ArbitraryUserPointer = field 5 IntPtr
    Self                 = field 6 IntPtr
}
#endregion Structs

#region Function Definitions
$FunctionDefinitions = @(
    (func kernel32 CloseHandle ([bool]) @(
        [IntPtr]                                  #_In_ HANDLE hObject
    ) -SetLastError),
    
    (func advapi32 ConvertSidToStringSid ([bool]) @(
        [IntPtr]                                  #_In_  PSID   Sid,
        [IntPtr].MakeByRefType()                  #_Out_ LPTSTR *StringSid
    ) -SetLastError),
    
    (func advapi32 GetTokenInformation ([bool]) @(
      [IntPtr],                                   #_In_      HANDLE                  TokenHandle
      [Int32],                                    #_In_      TOKEN_INFORMATION_CLASS TokenInformationClass
      [IntPtr],                                   #_Out_opt_ LPVOID                  TokenInformation
      [UInt32],                                   #_In_      DWORD                   TokenInformationLength
      [UInt32].MakeByRefType()                    #_Out_     PDWORD                  ReturnLength
    ) -SetLastError),

    (func ntdll NtQueryInformationThread ([UInt32]) @(
        [IntPtr],                                 #_In_      HANDLE          ThreadHandle,
        [Int32],                                  #_In_      THREADINFOCLASS ThreadInformationClass,
        [IntPtr],                                 #_Inout_   PVOID           ThreadInformation,
        [Int32],                                  #_In_      ULONG           ThreadInformationLength,
        [IntPtr]                                  #_Out_opt_ PULONG          ReturnLength
    )),

    (func ntdll NtQueryInformationThread ([UInt32]) @(
        [IntPtr],                                  #_In_      HANDLE          ThreadHandle,
        [Int32],                                   #_In_      THREADINFOCLASS ThreadInformationClass,
        $THREAD_BASIC_INFORMATION.MakeByRefType(), #_Inout_   PVOID           ThreadInformation,
        [Int32],                                   #_In_      ULONG           ThreadInformationLength,
        [IntPtr]                                   #_Out_opt_ PULONG          ReturnLength
    )),

    (func kernel32 OpenProcess ([IntPtr]) @(
        [UInt32],                                 #_In_ DWORD dwDesiredAccess,
        [bool],                                   #_In_ BOOL  bInheritHandle,
        [UInt32]                                  #_In_ DWORD dwProcessId
    ) -SetLastError),
    
    (func advapi32 OpenProcessToken ([bool]) @(
      [IntPtr],                                   #_In_  HANDLE  ProcessHandle
      [UInt32],                                   #_In_  DWORD   DesiredAccess
      [IntPtr].MakeByRefType()                    #_Out_ PHANDLE TokenHandle
    ) -SetLastError),

    (func kernel32 OpenThread ([IntPtr]) @(
        [UInt32],                                  #_In_ DWORD dwDesiredAccess,
        [bool],                                    #_In_ BOOL  bInheritHandle,
        [UInt32]                                   #_In_ DWORD dwThreadId
    ) -SetLastError),
    
    (func advapi32 OpenThreadToken ([bool]) @(
      [IntPtr],                                    #_In_  HANDLE  ThreadHandle
      [UInt32],                                    #_In_  DWORD   DesiredAccess
      [bool],                                      #_In_  BOOL    OpenAsSelf
      [IntPtr].MakeByRefType()                     #_Out_ PHANDLE TokenHandle
    ) -SetLastError),
    
    (func kernel32 QueryFullProcessImageName ([bool]) @(
      [IntPtr]                                     #_In_    HANDLE hProcess
      [UInt32]                                     #_In_    DWORD  dwFlags,
      [System.Text.StringBuilder]                  #_Out_   LPTSTR lpExeName,
      [UInt32].MakeByRefType()                     #_Inout_ PDWORD lpdwSize
    ) -SetLastError),
    
    (func kernel32 ReadProcessMemory ([Bool]) @(
        [IntPtr],                                  # _In_ HANDLE hProcess
        [IntPtr],                                  # _In_ LPCVOID lpBaseAddress
        [Byte[]],                                  # _Out_ LPVOID  lpBuffer
        [Int],                                     # _In_ SIZE_T nSize
        [Int].MakeByRefType()                      # _Out_ SIZE_T *lpNumberOfBytesRead
    ) -SetLastError),
    
    (func kernel32 VirtualQueryEx ([Int32]) @(
        [IntPtr],                                  #_In_     HANDLE                    hProcess,
        [IntPtr],                                  #_In_opt_ LPCVOID                   lpAddress,
        $MEMORYBASICINFORMATION.MakeByRefType(),   #_Out_    PMEMORY_BASIC_INFORMATION lpBuffer,
        [UInt32]                                   #_In_     SIZE_T                    dwLength
    ) -SetLastError),

    (func kernel32 IsWow64Process ([Bool]) @(
		[IntPtr],                                    #_In_  HANDLE hProcess,
		[Bool].MakeByRefType()                       #_Out_ PBOOL  Wow64Process
	) -SetLastError),

    (func kernel32 K32GetMappedFileName ([Int32]) @(
		[IntPtr]                                     #_In_  HANDLE hProcess,
		[IntPtr]                                     #_In_  LPVOID lpv,
		[System.Text.StringBuilder]                  #_Out_ LPTSTR lpFilename,
		[Int32]                                      #_In_  DWORD nSize
	) -SetLastError),

    (func kernel32 K32QueryWorkingSetEx ([Bool]) @(
		[IntPtr]                                     #_In_  HANDLE hProcess,
		$WORKING_SET_EX_INFORMATION.MakeByRefType(), #_In_  PVOID pv,
		[Int32]                                      #_In_  DWORD cb
	) -SetLastError)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'Win32SysInfo'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Advapi32 = $Types['advapi32']
#endregion Function Definitions

#endregion PSReflect Definitions (Thread)

#region Win32 API Abstractions

function CloseHandle
{
    <#
    .SYNOPSIS

    Closes an open object handle.

    .DESCRIPTION

    The CloseHandle function closes handles to the following objects:
    - Access token
    - Communications device
    - Console input
    - Console screen buffer
    - Event
    - File
    - File mapping
    - I/O completion port
    - Job
    - Mailslot
    - Memory resource notification
    - Mutex
    - Named pipe
    - Pipe
    - Process
    - Semaphore
    - Thread
    - Transaction
    - Waitable timer
    
    The documentation for the functions that create these objects indicates that CloseHandle should be used when you are finished with the object, and what happens to pending operations on the object after the handle is closed. In general, CloseHandle invalidates the specified object handle, decrements the object's handle count, and performs object retention checks. After the last handle to an object is closed, the object is removed from the system. 

    .PARAMETER Handle

    A valid handle to an open object.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $Handle    
    )
    
    <#
    (func kernel32 CloseHandle ([bool]) @(
        [IntPtr]                                  #_In_ HANDLE hObject
    ) -SetLastError)
    #>
    
    $Success = $Kernel32::CloseHandle($Handle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "Close Handle Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

function ConvertSidToStringSid
{
    <#
    .SYNOPSIS

    The ConvertSidToStringSid function converts a security identifier (SID) to a string format suitable for display, storage, or transmission.

    .DESCRIPTION

    The ConvertSidToStringSid function uses the standard S-R-I-S-S… format for SID strings.
    
    .PARAMETER SidPointer

    A pointer to the SID structure to be converted.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa376399(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $SidPointer    
    )
    
    <#
    (func advapi32 ConvertSidToStringSid ([bool]) @(
        [IntPtr]                                  #_In_  PSID   Sid,
        [IntPtr].MakeByRefType()                  #_Out_ LPTSTR *StringSid
    ) -SetLastError)
    #>
    
    $StringPtr = [IntPtr]::Zero
    $Success = $Advapi32::ConvertSidToStringSid($SidPointer, [ref]$StringPtr); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "ConvertSidToStringSid Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($StringPtr))
}

function GetTokenInformation
{
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER TokenHandle

    .PARAMETER TokenInformationClass

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)
    
    .LINK

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $TokenHandle,
        
        [Parameter(Mandatory = $true)]
        $TokenInformationClass 
    )
    
    <# 
    (func advapi32 GetTokenInformation ([bool]) @(
      [IntPtr],                                   #_In_      HANDLE                  TokenHandle
      [Int32],                                    #_In_      TOKEN_INFORMATION_CLASS TokenInformationClass
      [IntPtr],                                   #_Out_opt_ LPVOID                  TokenInformation
      [UInt32],                                   #_In_      DWORD                   TokenInformationLength
      [UInt32].MakeByRefType()                    #_Out_     PDWORD                  ReturnLength
    ) -SetLastError)
    #>
    
    # initial query to determine the necessary buffer size
    $TokenPtrSize = 0
    $Success = $Advapi32::GetTokenInformation($TokenHandle, $TokenInformationClass, 0, $TokenPtrSize, [ref]$TokenPtrSize)
    [IntPtr]$TokenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPtrSize)
    
    if($TokenPtrSize -ne 0)
    {
        [IntPtr]$TokenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPtrSize)
        # retrieve the proper buffer value
        $Success = $Advapi32::GetTokenInformation($TokenHandle, $TokenInformationClass, $TokenPtr, $TokenPtrSize, [ref]$TokenPtrSize); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }
    
    if($Success)
    {
        switch($TokenInformationClass)
        {
            1 # TokenUser
            {    
                $TokenUser = $TokenPtr -as $TOKEN_USER
                ConvertSidToStringSid -SidPointer $TokenUser.User.Sid
            }
            3 # TokenPrivilege
            {
                # query the process token with the TOKEN_INFORMATION_CLASS = 3 enum to retrieve a TOKEN_PRIVILEGES structure
                $TokenPrivileges = $TokenPtr -as $TOKEN_PRIVILEGES
                
                $sb = New-Object System.Text.StringBuilder
                
                for($i=0; $i -lt $TokenPrivileges.PrivilegeCount; $i++) 
                {
                    if((($TokenPrivileges.Privileges[$i].Attributes -as $LuidAttributes) -band $LuidAttributes::SE_PRIVILEGE_ENABLED) -eq $LuidAttributes::SE_PRIVILEGE_ENABLED)
                    {
                       $sb.Append(", $($TokenPrivileges.Privileges[$i].Luid.LowPart.ToString())") | Out-Null  
                    }
                }
                Write-Output $sb.ToString().TrimStart(', ')
            }
            17 # TokenOrigin
            {
                $TokenOrigin = $TokenPtr -as $LUID
                Write-Output (Get-LogonSession -LogonId $TokenOrigin.LowPart)
            }
            22 # TokenAccessInformation
            {
            
            }
            25 # TokenIntegrityLevel
            {
                $TokenIntegrity = $TokenPtr -as $TOKEN_MANDATORY_LABEL
                switch(ConvertSidToStringSid -SidPointer $TokenIntegrity.Label.Sid)
                {
                    $UNTRUSTED_MANDATORY_LEVEL
                    {
                        Write-Output "UNTRUSTED_MANDATORY_LEVEL"
                    }
                    $LOW_MANDATORY_LEVEL
                    {
                        Write-Output "LOW_MANDATORY_LEVEL"
                    }
                    $MEDIUM_MANDATORY_LEVEL
                    {
                        Write-Output "MEDIUM_MANDATORY_LEVEL"
                    }
                    $MEDIUM_PLUS_MANDATORY_LEVEL
                    {
                        Write-Output "MEDIUM_PLUS_MANDATORY_LEVEL"
                    }
                    $HIGH_MANDATORY_LEVEL
                    {
                        Write-Output "HIGH_MANDATORY_LEVEL"
                    }
                    $SYSTEM_MANDATORY_LEVEL
                    {
                        Write-Output "SYSTEM_MANDATORY_LEVEL"
                    }
                    $PROTECTED_PROCESS_MANDATORY_LEVEL
                    {
                        Write-Output "PROTECTED_PROCESS_MANDATORY_LEVEL"
                    }
                    $SECURE_PROCESS_MANDATORY_LEVEL
                    {
                        Write-Output "SECURE_PROCESS_MANDATORY_LEVEL"
                    }
                }
            }
        }
    }
    else
    {
        Write-Debug "GetTokenInformation Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }        
    try
    {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPtr)
    }
    catch
    {
    
    }
}

function NtQueryInformationThread_Win32StartAddress
{
    <#
    .SYNOPSIS

    Retrieves information about the specified thread.

    .DESCRIPTION

    .PARAMETER ThreadHandle

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)
    
    .LINK

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ThreadHandle  
    )
    
    <#
    (func ntdll NtQueryInformationThread ([Int32]) @(
        [IntPtr],                                 #_In_      HANDLE          ThreadHandle,
        [Int32],                                  #_In_      THREADINFOCLASS ThreadInformationClass,
        [IntPtr],                                 #_Inout_   PVOID           ThreadInformation,
        [Int32],                                  #_In_      ULONG           ThreadInformationLength,
        [IntPtr]                                  #_Out_opt_ PULONG          ReturnLength
    ))
    #>
    
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)

    $NtStatus = $Ntdll::NtQueryInformationThread($ThreadHandle, 9, $buf, [IntPtr]::Size, [IntPtr]::Zero); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($NtStatus -ne 0)
    {
        Write-Debug "NtQueryInformationThread Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output ([System.Runtime.InteropServices.Marshal]::ReadIntPtr($buf))
}

function OpenProcess
{
    <#
    .SYNOPSIS

    Opens an existing local process object.

    .DESCRIPTION

    To open a handle to another local process and obtain full access rights, you must enable the SeDebugPrivilege privilege.
    The handle returned by the OpenProcess function can be used in any function that requires a handle to a process, such as the wait functions, provided the appropriate access rights were requested.
    When you are finished with the handle, be sure to close it using the CloseHandle function.

    .PARAMETER ProcessId

    The identifier of the local process to be opened.
    If the specified process is the System Process (0x00000000), the function fails and the last error code is ERROR_INVALID_PARAMETER. If the specified process is the Idle process or one of the CSRSS processes, this function fails and the last error code is ERROR_ACCESS_DENIED because their access restrictions prevent user-level code from opening them.

    .PARAMETER DesiredAccess

    The access to the process object. This access right is checked against the security descriptor for the process. This parameter can be one or more of the process access rights.
    If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.

    .PARAMETER InheritHandle

    If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: PROCESS_ACCESS

    (func kernel32 OpenProcess ([IntPtr]) @(
        [UInt32], #_In_ DWORD dwDesiredAccess
        [bool],   #_In_ BOOL  bInheritHandle
        [UInt32]  #_In_ DWORD dwProcessId
    ) -EntryPoint OpenProcess -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880(v=vs.85).aspx

    .EXAMPLE
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $ProcessId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('PROCESS_TERMINATE','PROCESS_CREATE_THREAD','PROCESS_VM_OPERATION','PROCESS_VM_READ','PROCESS_VM_WRITE','PROCESS_DUP_HANDLE','PROCESS_CREATE_PROCESS','PROCESS_SET_QUOTA','PROCESS_SET_INFORMATION','PROCESS_QUERY_INFORMATION','PROCESS_SUSPEND_RESUME','PROCESS_QUERY_LIMITED_INFORMATION','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','PROCESS_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $InheritHandle = $false
    )

    # Calculate Desired Access Value
    $dwDesiredAccess = 0

    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $PROCESS_ACCESS::$val
    }

    $hProcess = $Kernel32::OpenProcess($dwDesiredAccess, $InheritHandle, $ProcessId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($hProcess -eq 0) 
    {
        #throw "OpenProcess Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hProcess
}

function OpenProcessToken
{ 
    <#
    .SYNOPSIS

    The OpenProcessToken function opens the access token associated with a process.

    .PARAMETER ProcessHandle

    A handle to the process whose access token is opened. The process must have the PROCESS_QUERY_INFORMATION access permission.

    .PARAMETER DesiredAccess

    Specifies an access mask that specifies the requested types of access to the access token. These requested access types are compared with the discretionary access control list (DACL) of the token to determine which accesses are granted or denied.
    For a list of access rights for access tokens, see Access Rights for Access-Token Objects.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: TOKEN_ACCESS (Enumeration)

    (func advapi32 OpenProcessToken ([bool]) @(
        [IntPtr],                #_In_  HANDLE  ProcessHandle
        [UInt32],                #_In_  DWORD   DesiredAccess
        [IntPtr].MakeByRefType() #_Out_ PHANDLE TokenHandle
    ) -EntryPoint OpenProcessToken -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa379295(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa374905(v=vs.85).aspx

    .EXAMPLE
    #>

    [OutputType([IntPtr])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('TOKEN_ASSIGN_PRIMARY','TOKEN_DUPLICATE','TOKEN_IMPERSONATE','TOKEN_QUERY','TOKEN_QUERY_SOURCE','TOKEN_ADJUST_PRIVILEGES','TOKEN_ADJUST_GROUPS','TOKEN_ADJUST_DEFAULT','TOKEN_ADJUST_SESSIONID','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','STANDARD_RIGHTS_REQUIRED','TOKEN_ALL_ACCESS')]
        [string[]]
        $DesiredAccess  
    )
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0

    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $TOKEN_ACCESS::$val
    }

    $hToken = [IntPtr]::Zero
    $Success = $Advapi32::OpenProcessToken($ProcessHandle, $dwDesiredAccess, [ref]$hToken); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        throw "OpenProcessToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hToken
}

function OpenThread
{
    <#
    .SYNOPSIS

    Opens an existing thread object.

    .DESCRIPTION

    The handle returned by OpenThread can be used in any function that requires a handle to a thread, such as the wait functions, provided you requested the appropriate access rights. The handle is granted access to the thread object only to the extent it was specified in the dwDesiredAccess parameter.
    When you are finished with the handle, be sure to close it by using the CloseHandle function.

    .PARAMETER ThreadId

    The identifier of the thread to be opened.

    .PARAMETER DesiredAccess

    The access to the thread object. This access right is checked against the security descriptor for the thread. This parameter can be one or more of the thread access rights.
    If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.

    .PARAMETER InheritHandle

    If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.
    
    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: THREAD_ACCESS (Enumeration)

    (func kernel32 OpenThread ([IntPtr]) @(
        [UInt32], #_In_ DWORD dwDesiredAccess
        [bool],   #_In_ BOOL  bInheritHandle
        [UInt32]  #_In_ DWORD dwThreadId
    ) -EntryPoint OpenThread -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684335(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms686769(v=vs.85).aspx

    .EXAMPLE
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $ThreadId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('THREAD_TERMINATE','THREAD_SUSPEND_RESUME','THREAD_GET_CONTEXT','THREAD_SET_CONTEXT','THREAD_SET_INFORMATION','THREAD_QUERY_INFORMATION','THREAD_SET_THREAD_TOKEN','THREAD_IMPERSONATE','THREAD_DIRECT_IMPERSONATION','THREAD_SET_LIMITED_INFORMATION','THREAD_QUERY_LIMITED_INFORMATION','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','THREAD_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $InheritHandle = $false
    )
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0
    
    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $THREAD_ACCESS::$val
    }

    $hThread = $Kernel32::OpenThread($dwDesiredAccess, $InheritHandle, $ThreadId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($hThread -eq 0) 
    {
        #throw "OpenThread Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hThread
}

function OpenThreadToken
{
    <#
    .SYNOPSIS

    The OpenThreadToken function opens the access token associated with a thread

    .DESCRIPTION

    Tokens with the anonymous impersonation level cannot be opened.
    Close the access token handle returned through the Handle parameter by calling CloseHandle.

    .PARAMETER ThreadHandle

    A handle to the thread whose access token is opened.

    .PARAMETER DesiredAccess

    Specifies an access mask that specifies the requested types of access to the access token. These requested access types are reconciled against the token's discretionary access control list (DACL) to determine which accesses are granted or denied.

    .PARAMETER OpenAsSelf

    TRUE if the access check is to be made against the process-level security context.
    FALSE if the access check is to be made against the current security context of the thread calling the OpenThreadToken function.
    The OpenAsSelf parameter allows the caller of this function to open the access token of a specified thread when the caller is impersonating a token at SecurityIdentification level. Without this parameter, the calling thread cannot open the access token on the specified thread because it is impossible to open executive-level objects by using the SecurityIdentification impersonation level.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: $TOKEN_ACCESS (Enumeration)

    (func advapi32 OpenThreadToken ([bool]) @(
      [IntPtr],                #_In_  HANDLE  ThreadHandle
      [UInt32],                #_In_  DWORD   DesiredAccess
      [bool],                  #_In_  BOOL    OpenAsSelf
      [IntPtr].MakeByRefType() #_Out_ PHANDLE TokenHandle
    ) -EntryPoint OpenThreadToken -SetLastError)
        
    .LINK
    
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa379296(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa374905(v=vs.85).aspx

    .EXAMPLE
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ThreadHandle,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('TOKEN_ASSIGN_PRIMARY','TOKEN_DUPLICATE','TOKEN_IMPERSONATE','TOKEN_QUERY','TOKEN_QUERY_SOURCE','TOKEN_ADJUST_PRIVILEGES','TOKEN_ADJUST_GROUPS','TOKEN_ADJUST_DEFAULT','TOKEN_ADJUST_SESSIONID','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','STANDARD_RIGHTS_REQUIRED','TOKEN_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $OpenAsSelf = $false   
    )
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0

    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $TOKEN_ACCESS::$val
    }

    $hToken = [IntPtr]::Zero
    $Success = $Advapi32::OpenThreadToken($ThreadHandle, $dwDesiredAccess, $OpenAsSelf, [ref]$hToken); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        throw "OpenThreadToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hToken
}

function QueryFullProcessImageName
{
    <#
    .SYNOPSIS

    Retrieves the full name of the executable image for the specified process.

    .PARAMETER ProcessHandle

    A handle to the process. This handle must be created with the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right.

    .PARAMETER Flags

    This parameter can be one of the following values.
    0x00 - The name should use the Win32 path format.
    0x01 - The name should use the native system path format.

    .NOTES
    
    Author - Jared Atkinson (@jaredcatkinson)
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684919(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter()]
        [UInt32]
        $Flags = 0
    )
    
    $capacity = 2048
    $sb = New-Object -TypeName System.Text.StringBuilder($capacity)

    $Success = $Kernel32::QueryFullProcessImageName($ProcessHandle, $Flags, $sb, [ref]$capacity); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "QueryFullProcessImageName Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $sb.ToString()
}

function ReadProcessMemory
{
    <#
    .SYNOPSIS

    Reads data from an area of memory in a specified process. The entire area to be read must be accessible or the operation fails.

    .DESCRIPTION

    ReadProcessMemory copies the data in the specified address range from the address space of the specified process into the specified buffer of the current process. Any process that has a handle with PROCESS_VM_READ access can call the function.

    The entire area to be read must be accessible, and if it is not accessible, the function fails.

    .PARAMETER ProcessHandle

    A handle to the process with memory that is being read. The handle must have PROCESS_VM_READ access to the process.

    .PARAMETER BaseAddress

    The base address in the specified process from which to read. Before any data transfer occurs, the system verifies that all data in the base address and memory of the specified size is accessible for read access, and if it is not accessible the function fails.

    .PARAMETER Size

    The number of bytes to be read from the specified process.

    .NOTES
    
    Author - Jared Atkinson (@jaredcatkinson)
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553(v=vs.85).aspx
    
    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $BaseAddress,
        
        [Parameter(Mandatory = $true)]
        [Int]
        $Size    
    )
    
    <#
    (func kernel32 ReadProcessMemory ([Bool]) @(
        [IntPtr],                                  # _In_ HANDLE hProcess
        [IntPtr],                                  # _In_ LPCVOID lpBaseAddress
        [Byte[]],                                  # _Out_ LPVOID  lpBuffer
        [Int],                                     # _In_ SIZE_T nSize
        [Int].MakeByRefType()                      # _Out_ SIZE_T *lpNumberOfBytesRead
    ) -SetLastError) # MSDN states to call GetLastError if the return value is false. 
    #>
    
    $buf = New-Object byte[]($Size)
    [Int32]$NumberOfBytesRead = 0
    
    $Success = $Kernel32::ReadProcessMemory($ProcessHandle, $BaseAddress, $buf, $buf.Length, [ref]$NumberOfBytesRead); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "ReadProcessMemory Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $buf
}

function VirtualQueryEx
{
    <#
    .SYNOPSIS

    Retrieves information about a range of pages within the virtual address space of a specified process.

    .PARAMETER ProcessHandle

    A handle to the process whose memory information is queried. The handle must have been opened with the PROCESS_QUERY_INFORMATION access right, which enables using the handle to read information from the process object.

    .PARAMETER BaseAddress

    The base address of the region of pages to be queried. This value is rounded down to the next page boundary.
    
    .NOTES
    
    Author - Jared Atkinson (@jaredcatkinson)
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa366907(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $BaseAddress
    )
    
    <#  
    (func kernel32 VirtualQueryEx ([Int32]) @(
        [IntPtr],                                  #_In_     HANDLE                    hProcess,
        [IntPtr],                                  #_In_opt_ LPCVOID                   lpAddress,
        $MEMORYBASICINFORMATION.MakeByRefType(),   #_Out_    PMEMORY_BASIC_INFORMATION lpBuffer,
        [UInt32]                                   #_In_     SIZE_T                    dwLength
    ) -SetLastError)
    #>
    
    $memory_basic_info = [Activator]::CreateInstance($MEMORYBASICINFORMATION)
    $BytesWritten = $Kernel32::VirtualQueryEx($ProcessHandle, $BaseAddress, [Ref]$memory_basic_info, $MEMORYBASICINFORMATION::GetSize()); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($BytesWritten -eq 0)
    {
        Write-Debug "VirtualQueryEx Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $memory_basic_info
}

function IsWow64Process
{
    <#
    .SYNOPSIS

    Determines whether the specified process is running under WOW64 on an x64 processor.

    .PARAMETER ProcessHandle

    A handle to the process. The handle must have the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right.

    .NOTES

    Author - John Uhlmann (@jdu2600)

    .LINK

    https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle
    )

    <#
     (func kernel32 IsWow64Process ([Bool]) @(
        [IntPtr],                                  #_In_  HANDLE hProcess,
        [Bool].MakeByRefType()                     #_Out_ PBOOL  Wow64Process
    ) -SetLastError)
    #>

    $Wow64Process = $false
    $Success = $Kernel32::IsWow64Process($ProcessHandle, [ref]$Wow64Process);

    if (-not $Success)
    {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Debug "IsWow64Process Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output $Wow64Process
}

function GetMappedFileName
{
    <#
    .SYNOPSIS

    Checks whether the specified address is within a memory-mapped file in the address space of the specified process. If so, the function returns the name of the memory-mapped file.

    .PARAMETER ProcessHandle

    A handle to the process. This handle must be created with the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right.

    .PARAMETER Address

    The address to be verified.

    .NOTES

    Author - John Uhlmann (@jdu2600)

    .LINK

    https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamea

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,

        [Parameter(Mandatory = $true)]
        [IntPtr]
        $Address
    )
    <#
     (func kernel32 K32GetMappedFileName ([Int32]) @(
        [IntPtr]                                     #_In_  HANDLE hProcess
        [IntPtr]                                     #_In_  LPVOID lpv,
        [System.Text.StringBuilder]                  #_Out_ LPTSTR lpFilename,
        [UInt32]                                     #_In_  DWORD nSize
    ) -SetLastError)
    #>

    $capacity = 2048
    $sb = New-Object -TypeName System.Text.StringBuilder($capacity)

    $BytesCopied = $Kernel32::K32GetMappedFileName($ProcessHandle, $Address, $sb, $capacity);

    if ($BytesCopied -eq 0)
    {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Debug "GetMappedFileName Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output $sb.ToString()
}


function IsWorkingSetPage
{
    <#
        .SYNOPSIS

        Checks whether the specified address is within the working set of the specified process.
        For MEM_IMAGE pages, this indicates that it has been locally modified.

        .PARAMETER ProcessHandle

        A handle to the process. This handle must be created with the PROCESS_QUERY_INFORMATION access right.

        .PARAMETER Address

        The address to be checked.

        .NOTES

        Author - John Uhlmann (@jdu2600)

        .LINK

        https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-queryworkingsetex

        .EXAMPLE
        #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,

        [Parameter(Mandatory = $true)]
        [IntPtr]
        $Address
    )
    <#
         (func kernel32 K32QueryWorkingSetEx ([Bool]) @(
            [IntPtr]                                     #_In_  HANDLE hProcess,
            [IntPtr]                                     #_In_  PVOID pv,
            [Int32]                                      #_In_  DWORD cb
        ) -SetLastError)
        #>

    $working_set_info = [Activator]::CreateInstance($WORKING_SET_EX_INFORMATION)
    $working_set_info.VirtualAddress = $Address
    $Success = $Kernel32::K32QueryWorkingSetEx($ProcessHandle, [Ref]$working_set_info, $WORKING_SET_EX_INFORMATION::GetSize());

    if (-not $Success)
    {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Debug "QueryWorkingSetEx Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    $IsPrivate = ($working_set_info.VirtualAttributes.ToInt64() -band $WORKING_SET_EX_BLOCK::Valid) -eq $WORKING_SET_EX_BLOCK::Valid -and
    ($working_set_info.VirtualAttributes.ToInt64() -band $WORKING_SET_EX_BLOCK::Shared) -ne $WORKING_SET_EX_BLOCK::Shared
    Write-Output $IsPrivate
}

#endregion Win32 API Abstractions