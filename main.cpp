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

// --- NTAPI ---
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

// --- SAFE MEMORY READ ---
// This function asks Windows if the memory is readable before touching it.
// Prevents the "Instant Crash".
bool SafeRead(HANDLE hProc, uintptr_t addr, void* buffer, size_t size) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        // Check if memory is Committed (Active) and Readable
        if (mbi.State == MEM_COMMIT && 
           (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            return ReadProcessMemory(hProc, (LPCVOID)addr, buffer, size, NULL);
        }
    }
    return false;
}

// --- SAFE SCANNER ---
uintptr_t FindPatternSafe(HANDLE hProc, uintptr_t start, size_t range, const char* pattern, const char* mask) {
    size_t chunkSize = 4096; // Scan in 4KB pages
    std::vector<uint8_t> buffer(chunkSize);
    size_t patternLen = strlen(mask);

    for (size_t i = 0; i < range; i += chunkSize) {
        if (SafeRead(hProc, start + i, buffer.data(), chunkSize)) {
            for (size_t j = 0; j < chunkSize - patternLen; j++) {
                bool found = true;
                for (size_t k = 0; k < patternLen; k++) {
                    if (mask[k] != '?' && (uint8_t)pattern[k] != buffer[j + k]) {
                        found = false;
                        break;
                    }
                }
                if (found) return start + i + j;
            }
        }
    }
    return 0;
}

int main() {
    std::cout << "[*] STABLE SNIPER v8: Waiting for Roblox..." << std::endl;
    
    DWORD pid = 0;
    while (!(pid = GetPID("RobloxPlayerBeta.exe"))) { std::this_thread::sleep_for(std::chrono::milliseconds(10)); }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // SAFETY: Wait for 15MB RAM usage. 
    // This ensures the game executable is actually loaded.
    std::cout << "[!] Process Found. Waiting for initialization..." << std::endl;
    PROCESS_MEMORY_COUNTERS pmc;
    while (true) {
        if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
            if (pmc.WorkingSetSize > 15 * 1024 * 1024) break; // Wait for 15MB
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::cout << "[!] Target Ready. Engaging Stutter-Step..." << std::endl;

    uintptr_t base = 0;
    uintptr_t sig = 0;
    uintptr_t singleton = 0;

    // Try for 500 steps (approx 5 seconds)
    for (int step = 0; step < 500; step++) {
        NtSuspendProcess(hProc);
        
        base = GetModuleBase(pid, "RobloxPlayerBeta.exe");
        if (base) {
            // SAFE SCAN
            sig = FindPatternSafe(hProc, base, 0x5000000, "\x48\x83\xEC\x38\x48\x8B\x0D", "xxxxxxx");
            
            if (sig) {
                uintptr_t instr = sig + 4;
                int32_t disp;
                if (SafeRead(hProc, instr + 3, &disp, 4)) {
                    uintptr_t ptr = instr + 7 + disp;
                    SafeRead(hProc, ptr, &singleton, 8);
                    
                    if (singleton > 0x1000) {
                        uint64_t mask_val = 0;
                        if (SafeRead(hProc, singleton + 0x30, &mask_val, 8)) {
                            if (mask_val > 0) {
                                std::cout << "[+] MAP FOUND AT STEP " << step << std::endl;
                                goto inject; // Jump to injection
                            }
                        }
                    }
                }
            }
        }
        
        NtResumeProcess(hProc);
        // 15ms Sleep matches Python's timing (prevents crash, allows loading)
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }

    std::cout << "[-] Timed out finding map." << std::endl;
    NtResumeProcess(hProc);
    return 0;

inject:
    std::cout << "[*] Injecting..." << std::endl;
    std::ifstream file("fflags.json");
    if (file.is_open()) {
        json config; file >> config;
        uintptr_t buckets; SafeRead(hProc, singleton + 0x18, &buckets, 8);
        uint64_t map_mask; SafeRead(hProc, singleton + 0x30, &map_mask, 8);

        for (auto& it : config.items()) {
            std::string name = it.key();
            uint64_t hash = 0xcbf29ce484222325;
            for (char c : name) { hash ^= (uint64_t)c; hash *= 0x100000001b3; }
            
            uintptr_t bucket_addr = buckets + ((hash & map_mask) * 16);
            uintptr_t node; SafeRead(hProc, bucket_addr + 0x8, &node, 8);

            int safety = 0;
            while (node != 0 && safety < 100) {
                uintptr_t name_ptr = node + 0x10;
                uint64_t s_size; SafeRead(hProc, name_ptr + 0x10, &s_size, 8);
                if (s_size >= 16) SafeRead(hProc, name_ptr, &name_ptr, 8);
                
                char buf[128] = {0};
                SafeRead(hProc, name_ptr, buf, (s_size > 127 ? 127 : s_size));

                if (name == buf) {
                    uintptr_t val_root; SafeRead(hProc, node + 0x30, &val_root, 8);
                    uintptr_t real_val_ptr; SafeRead(hProc, val_root + 0xC0, &real_val_ptr, 8);
                    
                    int val = (it.value() == "True" || it.value() == true) ? 1 : it.value().get<int>();
                    WriteProcessMemory(hProc, (LPVOID)real_val_ptr, &val, sizeof(int), NULL);
                    std::cout << "  [+] " << name << std::endl;
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
