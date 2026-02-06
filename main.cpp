#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <thread>
#include <tlhelp32.h>
#include <psapi.h>
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

bool SafeRead(HANDLE hProc, uintptr_t addr, void* buffer, size_t size) {
    SIZE_T read;
    return ReadProcessMemory(hProc, (LPCVOID)addr, buffer, size, &read) && read == size;
}

uintptr_t FindPattern(HANDLE hProc, uintptr_t base, const char* pattern, const char* mask) {
    size_t size = 0x5000000; 
    std::vector<uint8_t> data(size);
    if (!SafeRead(hProc, base, data.data(), size)) return 0;
    
    size_t patternLen = strlen(mask);
    for (size_t i = 0; i < size - patternLen; i++) {
        bool found = true;
        for (size_t j = 0; j < patternLen; j++) {
            if (mask[j] != '?' && (uint8_t)pattern[j] != data[i + j]) { found = false; break; }
        }
        if (found) return base + i;
    }
    return 0;
}

int main() {
    std::cout << "[*] CHILL SNIPER v9: Waiting for Roblox..." << std::endl;
    
    DWORD pid = 0;
    while (!(pid = GetPID("RobloxPlayerBeta.exe"))) { std::this_thread::sleep_for(std::chrono::milliseconds(10)); }

    // MINIMUM PERMISSIONS (Avoids Anti-Cheat triggers)
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) { std::cout << "[-] Failed to open handle." << std::endl; return 1; }

    std::cout << "[!] Process Found. Waiting for 20MB..." << std::endl;
    
    PROCESS_MEMORY_COUNTERS pmc;
    while (true) {
        if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
            if (pmc.WorkingSetSize > 20 * 1024 * 1024) break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::cout << "[!] Threshold reached. Starting 25ms Pulses..." << std::endl;

    uintptr_t base = 0;
    uintptr_t sig = 0;
    
    // LOOP
    for (int i = 0; i < 500; i++) {
        NtSuspendProcess(hProc);
        
        base = GetModuleBase(pid, "RobloxPlayerBeta.exe");
        if (base) {
            if (!sig) sig = FindPattern(hProc, base, "\x48\x83\xEC\x38\x48\x8B\x0D", "xxxxxxx");
            
            if (sig) {
                uintptr_t instr = sig + 4;
                int32_t disp;
                if (SafeRead(hProc, instr + 3, &disp, 4)) {
                    uintptr_t ptr = instr + 7 + disp;
                    uintptr_t singleton;
                    if (SafeRead(hProc, ptr, &singleton, 8)) {
                        if (singleton > 0x1000) {
                            uint64_t mask = 0;
                            // Check if map is populated (mask > 0)
                            if (SafeRead(hProc, singleton + 0x30, &mask, 8) && mask > 0) {
                                std::cout << "[+] WAVE 2 CAUGHT! (Step " << i << ")" << std::endl;
                                goto inject;
                            }
                        }
                    }
                }
            }
        }

        NtResumeProcess(hProc);
        // CRITICAL: 25ms sleep matches Python timing. Prevents Crash.
        std::this_thread::sleep_for(std::chrono::milliseconds(25)); 
    }
    
    std::cout << "[-] Timed out." << std::endl;
    NtResumeProcess(hProc);
    return 0;

inject:
    std::cout << "[*] Injecting..." << std::endl;
    std::ifstream file("fflags.json");
    if (file.is_open()) {
        json config; file >> config;
        
        // RE-READ POINTERS (Just in case)
        uintptr_t singleton; 
        int32_t disp;
        ReadProcessMemory(hProc, (LPCVOID)(sig + 7), &disp, 4, NULL);
        ReadProcessMemory(hProc, (LPCVOID)(sig + 11 + disp), &singleton, 8, NULL);
        
        uintptr_t buckets; SafeRead(hProc, singleton + 0x18, &buckets, 8);
        uint64_t map_mask; SafeRead(hProc, singleton + 0x30, &map_mask, 8);

        for (auto& it : config.items()) {
            std::string name = it.key();
            uint64_t hash = 0xcbf29ce484222325;
            for (char c : name) { hash ^= (uint64_t)c; hash *= 0x100000001b3; }
            
            uintptr_t bucket_addr = buckets + ((hash & map_mask) * 16);
            uintptr_t node; SafeRead(hProc, bucket_addr + 0x8, &node, 8);

            int safety = 0;
            while (node != 0 && safety < 50) {
                uintptr_t name_ptr = node + 0x10;
                uint64_t s_size; SafeRead(hProc, name_ptr + 0x10, &s_size, 8);
                if (s_size >= 16) SafeRead(hProc, name_ptr, &name_ptr, 8);
                
                char buf[128] = {0};
                SafeRead(hProc, name_ptr, buf, (s_size > 127 ? 127 : s_size));

                if (name == buf) {
                    uintptr_t val_root; SafeRead(hProc, node + 0x30, &val_root, 8);
                    uintptr_t real_val_ptr; SafeRead(hProc, val_root + 0xC0, &real_val_ptr, 8);
                    
                    int val = (it.value() == "True" || it.value() == true) ? 1 : 0;
                    if (it.value().is_number()) val = it.value().get<int>();

                    WriteProcessMemory(hProc, (LPVOID)real_val_ptr, &val, sizeof(int), NULL);
                    std::cout << "  [+] Set " << name << " = " << val << std::endl;
                    break;
                }
                SafeRead(hProc, node, &node, 8);
                safety++;
            }
        }
    }

    std::cout << "[!] Done. Resuming." << std::endl;
    NtResumeProcess(hProc);
    return 0;
}
