#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <thread>
#include <tlhelp32.h>
#include <psapi.h>
#include <conio.h> // For _kbhit
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// --- NTAPI ---
typedef LONG(NTAPI* pNtSuspendProcess)(HANDLE ProcessHandle);
typedef LONG(NTAPI* pNtResumeProcess)(HANDLE ProcessHandle);
pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtSuspendProcess");
pNtResumeProcess NtResumeProcess = (pNtResumeProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtResumeProcess");

const std::vector<std::string> PREFIXES = {
    "FFlag", "DFFlag", "SFFlag", "FInt", "DFInt", "SFInt", "SInt", "FLog", "DFLog", "FString", "DFString", ""
};

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

bool GetModuleInfo(DWORD pid, const char* name, uintptr_t& base, DWORD& size) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    bool found = false;
    if (Module32First(snapshot, &me)) {
        do { if (_stricmp(me.szModule, name) == 0) { base = (uintptr_t)me.modBaseAddr; size = me.modBaseSize; found = true; break; } } while (Module32Next(snapshot, &me));
    }
    CloseHandle(snapshot);
    return found;
}

uintptr_t FindPattern(HANDLE hProc, uintptr_t start, size_t size, const char* pattern, const char* mask) {
    size_t chunkSize = 4096 * 32; 
    std::vector<uint8_t> buffer(chunkSize);
    size_t patternLen = strlen(mask);
    for (size_t i = 0; i < size; i += chunkSize) {
        SIZE_T read;
        if (ReadProcessMemory(hProc, (LPCVOID)(start + i), buffer.data(), chunkSize, &read)) {
            for (size_t j = 0; j < read - patternLen; j++) {
                bool found = true;
                for (size_t k = 0; k < patternLen; k++) {
                    if (mask[k] != '?' && (uint8_t)pattern[k] != buffer[j + k]) { found = false; break; }
                }
                if (found) return start + i + j;
            }
        }
    }
    return 0;
}

uint64_t fnv1a(const std::string& str) {
    uint64_t hash = 0xcbf29ce484222325;
    for (char c : str) { hash ^= (uint64_t)c; hash *= 0x100000001b3; }
    return hash;
}

std::string StripPrefix(const std::string& name) {
    for (const auto& p : PREFIXES) {
        if (name.rfind(p, 0) == 0 && !p.empty()) return name.substr(p.length());
    }
    return name;
}

// --- CORE INJECTOR ---
int InjectFlags(HANDLE hProc, uintptr_t singleton_val) {
    std::ifstream file("fflags.json");
    if (!file.good()) {
        std::cout << "[ERROR] fflags.json missing!" << std::endl;
        return 0;
    }

    json config; file >> config;
    uintptr_t map_ptr = singleton_val + 0x8;
    uintptr_t buckets; ReadProcessMemory(hProc, (LPCVOID)(map_ptr + 0x10), &buckets, 8, NULL);
    uint64_t mask; ReadProcessMemory(hProc, (LPCVOID)(map_ptr + 0x28), &mask, 8, NULL);
    
    // Safety check for rehashed map
    if (mask == 0) return 0;

    int hits = 0;
    for (auto& it : config.items()) {
        std::string originalName = it.key();
        std::string cleanName = StripPrefix(originalName);
        bool injected = false;

        int val = 0;
        if (it.value().is_string()) {
            std::string s = it.value();
            if (s == "True" || s == "true") val = 1;
        } else if (it.value().is_boolean()) {
            val = it.value() ? 1 : 0;
        } else if (it.value().is_number()) {
            val = it.value().get<int>();
        }

        for (const auto& prefix : PREFIXES) {
            std::string testName = prefix + cleanName;
            uint64_t hash = fnv1a(testName);
            uintptr_t bucket_addr = buckets + ((hash & mask) * 16);
            uintptr_t node; ReadProcessMemory(hProc, (LPCVOID)(bucket_addr + 0x8), &node, 8, NULL);

            int safety = 0;
            while (node != 0 && safety < 100) {
                uintptr_t name_ptr = node + 0x10;
                uint64_t s_size; ReadProcessMemory(hProc, (LPCVOID)(name_ptr + 0x10), &s_size, 8, NULL);
                if (s_size >= 16) ReadProcessMemory(hProc, (LPCVOID)name_ptr, &name_ptr, 8, NULL);
                
                char buf[128] = {0};
                ReadProcessMemory(hProc, (LPCVOID)name_ptr, buf, (s_size > 127 ? 127 : s_size), NULL);

                if (testName == buf) {
                    uintptr_t val_root; ReadProcessMemory(hProc, (LPCVOID)(node + 0x30), &val_root, 8, NULL);
                    uintptr_t real_val_ptr; ReadProcessMemory(hProc, (LPCVOID)(val_root + 0xC0), &real_val_ptr, 8, NULL);
                    WriteProcessMemory(hProc, (LPVOID)real_val_ptr, &val, sizeof(int), NULL);
                    hits++;
                    injected = true;
                    break;
                }
                ReadProcessMemory(hProc, (LPCVOID)node, &node, 8, NULL);
                safety++;
            }
            if (injected) break;
        }
    }
    return hits;
}

// --- MAIN LOOP ---
int main() {
    SetConsoleTitleA("ROBLOX INFINITY INJECTOR v13");
    
    while (true) {
        system("cls");
        std::cout << "--- WAITING FOR ROBLOX ---" << std::endl;
        
        DWORD pid = 0;
        while (!(pid = GetPID("RobloxPlayerBeta.exe"))) { std::this_thread::sleep_for(std::chrono::milliseconds(100)); }

        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        
        std::cout << "[!] Process Detected (PID: " << pid << "). Waiting for Init..." << std::endl;
        
        // BOOT PHASE
        PROCESS_MEMORY_COUNTERS pmc;
        while (true) {
            if (!GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) goto reset; // Process died
            if (pmc.WorkingSetSize > 20 * 1024 * 1024) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        uintptr_t base = 0, sig = 0, singleton_ptr = 0;
        DWORD modSize = 0;
        bool boot_injected = false;

        // Try Boot Inject (Timeout 5s)
        for (int i = 0; i < 200; i++) {
            NtSuspendProcess(hProc);
            
            if (GetModuleInfo(pid, "RobloxPlayerBeta.exe", base, modSize)) {
                if (!sig) sig = FindPattern(hProc, base, modSize, "\x48\x83\xEC\x38\x48\x8B\x0D", "xxxxxxx");
                if (sig) {
                    uintptr_t instr = sig + 4;
                    int32_t disp;
                    ReadProcessMemory(hProc, (LPCVOID)(instr + 3), &disp, 4, NULL);
                    singleton_ptr = instr + 7 + disp;
                    
                    uintptr_t singleton_val = 0;
                    ReadProcessMemory(hProc, (LPCVOID)singleton_ptr, &singleton_val, 8, NULL);
                    if (singleton_val > 0x1000) {
                        uint64_t mask = 0;
                        ReadProcessMemory(hProc, (LPCVOID)(singleton_val + 0x30), &mask, 8, NULL);
                        if (mask > 0) {
                            std::cout << "[+] BOOT MAP FOUND! Injecting..." << std::endl;
                            int hits = InjectFlags(hProc, singleton_val);
                            std::cout << "[+] Boot Injection: " << hits << " flags set." << std::endl;
                            boot_injected = true;
                            NtResumeProcess(hProc);
                            break;
                        }
                    }
                }
            }
            NtResumeProcess(hProc);
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }

        if (!boot_injected) std::cout << "[-] Missed Boot Phase (Game loaded too fast)." << std::endl;

        // RUNTIME PHASE
        std::cout << "\n--- GAME RUNNING ---" << std::endl;
        std::cout << "Press [ENTER] to inject Runtime Flags." << std::endl;
        std::cout << "Close Roblox to reset." << std::endl;

        // Clear input buffer
        while (_kbhit()) _getch();

        while (true) {
            // Check if process is dead
            DWORD exitCode;
            if (!GetExitCodeProcess(hProc, &exitCode) || exitCode != STILL_ACTIVE) {
                std::cout << "\n[!] Roblox Closed. Resetting..." << std::endl;
                CloseHandle(hProc);
                std::this_thread::sleep_for(std::chrono::seconds(1));
                goto reset;
            }

            // Check for User Input (Enter Key)
            if (_kbhit()) {
                char ch = _getch();
                if (ch == 13) { // Enter key
                    std::cout << "\n[>] Injecting Runtime Flags..." << std::endl;
                    NtSuspendProcess(hProc);
                    
                    // RE-READ SINGLETON (Map might have moved)
                    uintptr_t current_singleton_val = 0;
                    if (ReadProcessMemory(hProc, (LPCVOID)singleton_ptr, &current_singleton_val, 8, NULL)) {
                        int hits = InjectFlags(hProc, current_singleton_val);
                        std::cout << "[+] Runtime Injection: " << hits << " flags set." << std::endl;
                    } else {
                        std::cout << "[-] Failed to read memory. Game crashing?" << std::endl;
                    }

                    NtResumeProcess(hProc);
                    std::cout << "[!] Done. Press [ENTER] again to re-inject." << std::endl;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        reset:;
    }
    return 0;
}
