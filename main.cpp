#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <thread>
#include <tlhelp32.h>
#include <psapi.h>
#include <conio.h>
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

// --- SAFE MEMORY HELPERS ---
bool IsMemorySafe(HANDLE hProc, uintptr_t addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        return (mbi.State == MEM_COMMIT && 
               (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)));
    }
    return false;
}

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
    size_t chunkSize = 4096 * 64; 
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

// Helper to find the pointer address (Does not return the value, but the location of the pointer)
uintptr_t ScanForSingletonPtr(HANDLE hProc, DWORD pid) {
    uintptr_t base = 0;
    DWORD size = 0;
    if (!GetModuleInfo(pid, "RobloxPlayerBeta.exe", base, size)) return 0;
    
    uintptr_t sig = FindPattern(hProc, base, size, "\x48\x83\xEC\x38\x48\x8B\x0D", "xxxxxxx");
    if (!sig) return 0;

    uintptr_t instr = sig + 4;
    int32_t disp;
    if (ReadProcessMemory(hProc, (LPCVOID)(instr + 3), &disp, 4, NULL)) {
        return instr + 7 + disp; // Return address of the singleton pointer
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
    if (!file.good()) return 0;

    json config; file >> config;
    uintptr_t map_ptr = singleton_val + 0x8;
    
    if (!IsMemorySafe(hProc, map_ptr)) return 0;

    uintptr_t buckets; ReadProcessMemory(hProc, (LPCVOID)(map_ptr + 0x10), &buckets, 8, NULL);
    uint64_t mask; ReadProcessMemory(hProc, (LPCVOID)(map_ptr + 0x28), &mask, 8, NULL);
    
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
        } else if (it.value().is_boolean()) val = it.value() ? 1 : 0;
        else if (it.value().is_number()) val = it.value().get<int>();

        for (const auto& prefix : PREFIXES) {
            std::string testName = prefix + cleanName;
            uint64_t hash = fnv1a(testName);
            uintptr_t bucket_addr = buckets + ((hash & mask) * 16);
            uintptr_t node; 
            
            if (!ReadProcessMemory(hProc, (LPCVOID)(bucket_addr + 0x8), &node, 8, NULL)) break;

            int safety = 0;
            while (node != 0 && safety < 100) {
                uintptr_t name_ptr = node + 0x10;
                uint64_t s_size; 
                ReadProcessMemory(hProc, (LPCVOID)(name_ptr + 0x10), &s_size, 8, NULL);
                if (s_size >= 16) ReadProcessMemory(hProc, (LPCVOID)name_ptr, &name_ptr, 8, NULL);
                
                char buf[128] = {0};
                ReadProcessMemory(hProc, (LPCVOID)name_ptr, buf, (s_size > 127 ? 127 : s_size), NULL);

                if (testName == buf) {
                    uintptr_t val_root; ReadProcessMemory(hProc, (LPCVOID)(node + 0x30), &val_root, 8, NULL);
                    uintptr_t real_val_ptr; ReadProcessMemory(hProc, (LPCVOID)(val_root + 0xC0), &real_val_ptr, 8, NULL);
                    
                    if (IsMemorySafe(hProc, real_val_ptr)) {
                        WriteProcessMemory(hProc, (LPVOID)real_val_ptr, &val, sizeof(int), NULL);
                        hits++;
                        injected = true;
                    }
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

int main() {
    SetConsoleTitleA("ROBLOX PERSISTENT INJECTOR v15");
    
    int user_delay = 0;
    std::cout << "--- CONFIGURATION ---" << std::endl;
    std::cout << "Enter Boot Delay (ms) [Default: 0]: ";
    if (std::cin.peek() == '\n') user_delay = 0;
    else std::cin >> user_delay;
    std::cin.ignore();

    while (true) {
        system("cls");
        std::cout << "[*] Waiting for Roblox..." << std::endl;
        
        DWORD pid = 0;
        while (!(pid = GetPID("RobloxPlayerBeta.exe"))) { std::this_thread::sleep_for(std::chrono::milliseconds(100)); }

        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        std::cout << "[!] Process Detected (PID: " << pid << "). Waiting for 20MB..." << std::endl;
        
        PROCESS_MEMORY_COUNTERS pmc;
        while (true) {
            if (!GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) goto reset;
            if (pmc.WorkingSetSize > 20 * 1024 * 1024) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        if (user_delay > 0) std::this_thread::sleep_for(std::chrono::milliseconds(user_delay));

        // --- BOOT PHASE ---
        std::cout << "[*] Starting Boot Pulse..." << std::endl;
        uintptr_t singleton_ptr_addr = 0;
        bool boot_success = false;

        for (int i = 0; i < 200; i++) {
            NtSuspendProcess(hProc);
            
            // Lazy scan: Only scan if we haven't found the address yet
            if (singleton_ptr_addr == 0) {
                singleton_ptr_addr = ScanForSingletonPtr(hProc, pid);
            }

            if (singleton_ptr_addr != 0) {
                uintptr_t singleton_val = 0;
                ReadProcessMemory(hProc, (LPCVOID)singleton_ptr_addr, &singleton_val, 8, NULL);
                
                if (singleton_val > 0x1000) {
                    uint64_t mask = 0;
                    ReadProcessMemory(hProc, (LPCVOID)(singleton_val + 0x30), &mask, 8, NULL);
                    
                    if (mask > 0) {
                        int hits = InjectFlags(hProc, singleton_val);
                        if (hits > 0) {
                            std::cout << "[+] BOOT INJECTION: " << hits << " flags set." << std::endl;
                            boot_success = true;
                            NtResumeProcess(hProc);
                            break; 
                        }
                    }
                }
            }
            NtResumeProcess(hProc);
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }

        if (!boot_success) std::cout << "[-] Boot Phase timed out (Game loaded too fast)." << std::endl;

        // --- RUNTIME PHASE ---
        std::cout << "\n--- GAME RUNNING ---" << std::endl;
        std::cout << "Press [ENTER] to Inject. (No Freeze)" << std::endl;

        while (_kbhit()) _getch(); // Clear buffer

        while (true) {
            DWORD exitCode;
            if (!GetExitCodeProcess(hProc, &exitCode) || exitCode != STILL_ACTIVE) {
                std::cout << "\n[!] Roblox Closed." << std::endl;
                CloseHandle(hProc);
                std::this_thread::sleep_for(std::chrono::seconds(1));
                goto reset;
            }

            if (_kbhit()) {
                char ch = _getch();
                if (ch == 13) {
                    std::cout << "\n[>] Injecting Runtime..." << std::endl;
                    
                    uintptr_t current_singleton_val = 0;
                    bool read_ok = false;

                    // 1. Try old pointer
                    if (singleton_ptr_addr != 0) {
                        ReadProcessMemory(hProc, (LPCVOID)singleton_ptr_addr, &current_singleton_val, 8, NULL);
                        if (current_singleton_val > 0x1000) read_ok = true;
                    }

                    // 2. If invalid, RE-SCAN (Rehash recovery)
                    if (!read_ok) {
                        std::cout << "[*] Pointer invalid/moved. Re-scanning..." << std::endl;
                        singleton_ptr_addr = ScanForSingletonPtr(hProc, pid);
                        if (singleton_ptr_addr != 0) {
                            ReadProcessMemory(hProc, (LPCVOID)singleton_ptr_addr, &current_singleton_val, 8, NULL);
                            read_ok = true;
                        }
                    }

                    // 3. Inject
                    if (read_ok) {
                        int hits = InjectFlags(hProc, current_singleton_val);
                        std::cout << "[+] Result: " << hits << " flags set." << std::endl;
                    } else {
                        std::cout << "[-] Could not find Flag Map." << std::endl;
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        reset:;
    }
    return 0;
}
