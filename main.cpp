#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <thread>
#include <tlhelp32.h>
#include <psapi.h> // For memory info
#include <nlohmann/json.hpp>

using json = nlohmann::json;

typedef LONG(NTAPI* pNtSuspendProcess)(HANDLE ProcessHandle);
typedef LONG(NTAPI* pNtResumeProcess)(HANDLE ProcessHandle);
pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtSuspendProcess");
pNtResumeProcess NtResumeProcess = (pNtResumeProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtResumeProcess");

// --- UTILS ---
DWORD GetPID(const char* procName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
        if (Process32First(snapshot, &pe)) {
            do { if (_stricmp(pe.szExeFile, procName) == 0) { pid = pe.th32ProcessID; break; } } while (Process32Next(snapshot, &pe));
        }
        CloseHandle(snapshot);
    }
    return pid;
}

size_t GetMemoryUsage(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) return 0;
    PROCESS_MEMORY_COUNTERS pmc;
    size_t mem = 0;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        mem = pmc.WorkingSetSize;
    }
    CloseHandle(hProcess);
    return mem;
}

uintptr_t GetModuleBase(DWORD pid, const char* name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    uintptr_t base = 0;
    if (Module32First(snapshot, &me)) {
        do { if (_stricmp(me.szModule, name) == 0) { base = (uintptr_t)me.modBaseAddr; break; } } while (Module32Next(snapshot, &me));
    }
    CloseHandle(snapshot);
    return base;
}

uintptr_t FindPattern(HANDLE hProc, uintptr_t base, const char* pattern, const char* mask) {
    size_t size = 0x5000000; // 80MB
    std::vector<uint8_t> data(size);
    SIZE_T read;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, data.data(), size, &read)) return 0;
    size_t patternLen = strlen(mask);
    for (size_t i = 0; i < read - patternLen; i++) {
        bool found = true;
        for (size_t j = 0; j < patternLen; j++) {
            if (mask[j] != '?' && (uint8_t)pattern[j] != data[i + j]) { found = false; break; }
        }
        if (found) return base + i;
    }
    return 0;
}

int main() {
    std::cout << "[*] GHOST SNIPER v7: Waiting for Roblox..." << std::endl;
    
    DWORD pid = 0;
    while (!(pid = GetPID("RobloxPlayerBeta.exe"))) { std::this_thread::sleep_for(std::chrono::milliseconds(5)); }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        std::cout << "[-] Failed to open handle (Admin needed?)" << std::endl;
        return 1;
    }

    std::cout << "[!] Process Detected. Waiting for memory to map..." << std::endl;

    // SAFETY GUARD: Wait until Roblox hits 20MB usage
    // This ensures the game code is actually in RAM and readable
    while (GetMemoryUsage(pid) < (20 * 1024 * 1024)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    std::cout << "[!] Catching wave..." << std::endl;
    NtSuspendProcess(hProc); 

    uintptr_t base = GetModuleBase(pid, "RobloxPlayerBeta.exe");
    if (!base) {
        std::cout << "[-] Base not found. Resuming..." << std::endl;
        NtResumeProcess(hProc);
        return 1;
    }

    uintptr_t sig = FindPattern(hProc, base, "\x48\x83\xEC\x38\x48\x8B\x0D", "xxxxxxx");
    if (!sig) {
        std::cout << "[-] Signature not found. Incompatible version?" << std::endl;
        NtResumeProcess(hProc);
        return 1;
    }

    uintptr_t instr = sig + 4;
    int32_t disp;
    ReadProcessMemory(hProc, (LPCVOID)(instr + 3), &disp, 4, NULL);
    uintptr_t singleton_ptr_addr = instr + 7 + disp;

    std::cout << "[*] Signature Found. Pulsing until Flag Map initializes..." << std::endl;

    uintptr_t singleton = 0;
    int pulses = 0;
    while (pulses < 1000) {
        if (!ReadProcessMemory(hProc, (LPCVOID)singleton_ptr_addr, &singleton, 8, NULL)) break;
        
        if (singleton > 0x1000) {
            uint64_t mask_val = 0;
            // Map Map starts at singleton + 0x8. Mask is at Map + 0x28
            if (ReadProcessMemory(hProc, (LPCVOID)(singleton + 0x8 + 0x28), &mask_val, 8, NULL)) {
                if (mask_val > 0) {
                    std::cout << "[+] WAVE DETECTED. Pulse: " << pulses << std::endl;
                    break;
                }
            }
        }

        NtResumeProcess(hProc);
        std::this_thread::sleep_for(std::chrono::milliseconds(2)); // 2ms pulses
        NtSuspendProcess(hProc);
        pulses++;
    }

    if (singleton > 0x1000) {
        std::cout << "[!] Injecting flags..." << std::endl;
        std::ifstream file("fflags.json");
        if (file.is_open()) {
            json config; file >> config;
            uintptr_t map_root = singleton + 0x8;
            uintptr_t buckets; ReadProcessMemory(hProc, (LPCVOID)(map_root + 0x10), &buckets, 8, NULL);
            uint64_t map_mask; ReadProcessMemory(hProc, (LPCVOID)(map_root + 0x28), &map_mask, 8, NULL);

            for (auto& it : config.items()) {
                std::string name = it.key();
                uint64_t hash = 0xcbf29ce484222325;
                for (char c : name) { hash ^= (uint64_t)c; hash *= 0x100000001b3; }
                
                uintptr_t bucket_addr = buckets + ((hash & map_mask) * 16);
                uintptr_t node; ReadProcessMemory(hProc, (LPCVOID)(bucket_addr + 0x8), &node, 8, NULL);

                int safety = 0;
                while (node != 0 && safety < 100) {
                    uintptr_t name_ptr = node + 0x10;
                    uint64_t s_size; ReadProcessMemory(hProc, (LPCVOID)(name_ptr + 0x10), &s_size, 8, NULL);
                    if (s_size >= 16) ReadProcessMemory(hProc, (LPCVOID)name_ptr, &name_ptr, 8, NULL);
                    
                    char buf[128] = {0};
                    ReadProcessMemory(hProc, (LPCVOID)name_ptr, buf, (s_size > 127 ? 127 : s_size), NULL);

                    if (name == buf) {
                        uintptr_t val_root; ReadProcessMemory(hProc, (LPCVOID)(node + 0x30), &val_root, 8, NULL);
                        uintptr_t real_val_ptr; ReadProcessMemory(hProc, (LPCVOID)(val_root + 0xC0), &real_val_ptr, 8, NULL);
                        
                        int val = (it.value() == "True" || it.value() == true) ? 1 : 0;
                        if (it.value().is_number()) val = it.value().get<int>();

                        WriteProcessMemory(hProc, (LPVOID)real_val_ptr, &val, sizeof(int), NULL);
                        std::cout << "  [+] " << name << std::endl;
                        break;
                    }
                    ReadProcessMemory(hProc, (LPCVOID)node, &node, 8, NULL);
                    safety++;
                }
            }
        }
    }

    std::cout << "[!] Done. Resuming Roblox." << std::endl;
    NtResumeProcess(hProc);
    CloseHandle(hProc);
    return 0;
}
