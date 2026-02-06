#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <thread>
#include <tlhelp32.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

typedef LONG(NTAPI* pNtSuspendProcess)(HANDLE ProcessHandle);
typedef LONG(NTAPI* pNtResumeProcess)(HANDLE ProcessHandle);
pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtSuspendProcess");
pNtResumeProcess NtResumeProcess = (pNtResumeProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtResumeProcess");

// --- GET PID ---
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

// --- MODULE BASE (FAST) ---
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

// --- PATTERN SCAN (ONCE) ---
uintptr_t FindPattern(HANDLE hProc, uintptr_t base, const char* pattern, const char* mask) {
    size_t size = 0x5000000; 
    std::vector<uint8_t> data(size);
    if (!ReadProcessMemory(hProc, (LPCVOID)base, data.data(), size, NULL)) return 0;
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
    std::cout << "[*] SNIPER v6: Waiting for Roblox..." << std::endl;
    
    DWORD pid = 0;
    while (!(pid = GetPID("RobloxPlayerBeta.exe"))) { std::this_thread::sleep_for(std::chrono::milliseconds(5)); }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    NtSuspendProcess(hProc); // Catch it at 0.1MB
    std::cout << "[!] Process Caught. Locating static entry point..." << std::endl;

    uintptr_t base = 0;
    while (!(base = GetModuleBase(pid, "RobloxPlayerBeta.exe"))) {
        NtResumeProcess(hProc);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        NtSuspendProcess(hProc);
    }

    // FIND THE SIG ONCE
    uintptr_t sig = FindPattern(hProc, base, "\x48\x83\xEC\x38\x48\x8B\x0D", "xxxxxxx");
    if (!sig) {
        std::cout << "[-] Failed to find signature. Are you using an outdated Roblox?" << std::endl;
        NtResumeProcess(hProc);
        return 0;
    }

    // Resolve the pointer address once
    uintptr_t instr = sig + 4;
    int32_t disp;
    ReadProcessMemory(hProc, (LPCVOID)(instr + 3), &disp, 4, NULL);
    uintptr_t singleton_ptr_addr = instr + 7 + disp;

    std::cout << "[*] Entry point locked. Pulsing until Map is ready..." << std::endl;

    uintptr_t singleton = 0;
    int pulses = 0;
    while (pulses < 1000) {
        ReadProcessMemory(hProc, (LPCVOID)singleton_ptr_addr, &singleton, 8, NULL);
        
        if (singleton > 0x1000) {
            uint64_t mask_val = 0;
            ReadProcessMemory(hProc, (LPCVOID)(singleton + 0x30), &mask_val, 8, NULL); // OFF_MAP_MASK (0x28 + 0x8 alignment)
            
            if (mask_val > 0) {
                std::cout << "[+] WAVE DETECTED. Map initialized at Pulse " << pulses << std::endl;
                break;
            }
        }

        // MICRO-PULSE: Just 1ms of execution
        NtResumeProcess(hProc);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        NtSuspendProcess(hProc);
        pulses++;
    }

    if (singleton > 0x1000) {
        std::cout << "[!] Injecting FFlags..." << std::endl;
        std::ifstream file("fflags.json");
        if (file.is_open()) {
            json config; file >> config;
            uintptr_t buckets; ReadProcessMemory(hProc, (LPCVOID)(singleton + 0x18), &buckets, 8, NULL); // OFF_MAP_LIST
            uint64_t map_mask; ReadProcessMemory(hProc, (LPCVOID)(singleton + 0x30), &map_mask, 8, NULL); // OFF_MAP_MASK

            for (auto& it : config.items()) {
                std::string name = it.key();
                // FNV-1a
                uint64_t hash = 0xcbf29ce484222325;
                for (char c : name) { hash ^= (uint64_t)c; hash *= 0x100000001b3; }
                
                uintptr_t bucket_addr = buckets + ((hash & map_mask) * 16);
                uintptr_t node; ReadProcessMemory(hProc, (LPCVOID)(bucket_addr + 0x8), &node, 8, NULL);

                int safety = 0;
                while (node != 0 && safety < 50) {
                    uintptr_t name_ptr = node + 0x10;
                    uint64_t s_size; ReadProcessMemory(hProc, (LPCVOID)(name_ptr + 0x10), &s_size, 8, NULL);
                    if (s_size >= 16) ReadProcessMemory(hProc, (LPCVOID)name_ptr, &name_ptr, 8, NULL);
                    
                    char buf[128] = {0};
                    ReadProcessMemory(hProc, (LPCVOID)name_ptr, buf, (s_size > 127 ? 127 : s_size), NULL);

                    if (name == buf) {
                        uintptr_t val_root; ReadProcessMemory(hProc, (LPCVOID)(node + 0x30), &val_root, 8, NULL);
                        uintptr_t real_val_ptr; ReadProcessMemory(hProc, (LPCVOID)(val_root + 0xC0), &real_val_ptr, 8, NULL);
                        
                        int val = (it.value() == "True" || it.value() == true) ? 1 : it.value().get<int>();
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

    std::cout << "[!] Done. Resuming process permanently." << std::endl;
    NtResumeProcess(hProc);
    return 0;
}
