#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <thread>
#include <tlhelp32.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// --- NTAPI FOR SPEED ---
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
    if (Module32First(snapshot, &me)) {
        do { if (_stricmp(me.szModule, name) == 0) break; } while (Module32Next(snapshot, &me));
    }
    CloseHandle(snapshot);
    return (uintptr_t)me.modBaseAddr;
}

// --- FNV1A HASHING ---
uint64_t fnv1a(const std::string& str) {
    uint64_t hash = 0xcbf29ce484222325;
    for (char c : str) { hash ^= (uint64_t)c; hash *= 0x100000001b3; }
    return hash;
}

// --- SCANNER ---
uintptr_t FindPattern(HANDLE hProc, uintptr_t base, const char* pattern, const char* mask) {
    size_t size = 0x5000000; // Scan first 80MB
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
    std::cout << "[*] SNIPER START: Waiting for RobloxPlayerBeta.exe..." << std::endl;
    
    DWORD pid = 0;
    while (!(pid = GetPID("RobloxPlayerBeta.exe"))) { std::this_thread::sleep_for(std::chrono::milliseconds(10)); }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    std::cout << "[!] Caught Process. Suspending immediately!" << std::endl;
    NtSuspendProcess(hProc);

    uintptr_t base = 0;
    while (!(base = GetModuleBase(pid, "RobloxPlayerBeta.exe"))) { std::this_thread::sleep_for(std::chrono::milliseconds(10)); }

    // THE PATTERN SCAN
    uintptr_t sig = FindPattern(hProc, base, "\x48\x83\xEC\x38\x48\x8B\x0D", "xxxxxxx");
    if (!sig) {
        std::cout << "[-] Failed to find signature. Resuming..." << std::endl;
        NtResumeProcess(hProc);
        return 1;
    }

    // RESOLVE SINGLETON
    uintptr_t instr = sig + 4;
    int32_t disp;
    ReadProcessMemory(hProc, (LPCVOID)(instr + 3), &disp, 4, NULL);
    uintptr_t ptr = instr + 7 + disp;
    uintptr_t singleton;
    ReadProcessMemory(hProc, (LPCVOID)ptr, &singleton, 8, NULL);

    if (singleton < 0x1000) {
        std::cout << "[-] Map Singleton not initialized. You might need to step forward." << std::endl;
    } else {
        std::cout << "[+] Map Found at: " << std::hex << singleton << std::endl;
        
        // --- INJECTION LOGIC ---
        std::ifstream file("fflags.json");
        if (file.is_open()) {
            json config; file >> config;
            
            uintptr_t map_ptr = singleton + 0x8;
            uintptr_t buckets; ReadProcessMemory(hProc, (LPCVOID)(map_ptr + 0x10), &buckets, 8, NULL);
            uint64_t mask; ReadProcessMemory(hProc, (LPCVOID)(map_ptr + 0x28), &mask, 8, NULL);

            for (auto& it : config.items()) {
                std::string name = it.key();
                uint64_t hash = fnv1a(name);
                uintptr_t bucket_addr = buckets + ((hash & mask) * 16);
                uintptr_t node; ReadProcessMemory(hProc, (LPCVOID)(bucket_addr + 0x8), &node, 8, NULL);

                int safety = 0;
                while (node != 0 && safety < 50) {
                    // Read Node Name
                    uintptr_t name_ptr = node + 0x10;
                    uint64_t s_size; ReadProcessMemory(hProc, (LPCVOID)(name_ptr + 0x10), &s_size, 8, NULL);
                    if (s_size >= 16) ReadProcessMemory(hProc, (LPCVOID)name_ptr, &name_ptr, 8, NULL);
                    
                    char buf[256] = {0};
                    ReadProcessMemory(hProc, (LPCVOID)name_ptr, buf, (s_size > 255 ? 255 : s_size), NULL);

                    if (std::string(buf) == name) {
                        uintptr_t val_root; ReadProcessMemory(hProc, (LPCVOID)(node + 0x30), &val_root, 8, NULL);
                        uintptr_t real_val_ptr; ReadProcessMemory(hProc, (LPCVOID)(val_root + 0xC0), &real_val_ptr, 8, NULL);
                        
                        int val = (it.value() == "True" || it.value() == true) ? 1 : 0;
                        if (it.value().is_number()) val = it.value().get<int>();

                        WriteProcessMemory(hProc, (LPVOID)real_val_ptr, &val, sizeof(int), NULL);
                        std::cout << "[+] Injected: " << name << " -> " << val << std::endl;
                        break;
                    }
                    ReadProcessMemory(hProc, (LPCVOID)node, &node, 8, NULL); // Next node
                    safety++;
                }
            }
        }
    }

    std::cout << "[!] Done. Resuming Roblox..." << std::endl;
    NtResumeProcess(hProc);
    return 0;
}
