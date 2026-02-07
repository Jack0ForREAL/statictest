#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <thread>
#include <tlhelp32.h>
#include <psapi.h> // Linked via build.yml
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

// Get the exact base and size of the module to prevent bad scans
bool GetModuleInfo(DWORD pid, const char* name, uintptr_t& base, DWORD& size) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    bool found = false;
    if (Module32First(snapshot, &me)) {
        do { 
            if (_stricmp(me.szModule, name) == 0) { 
                base = (uintptr_t)me.modBaseAddr; 
                size = me.modBaseSize;
                found = true;
                break; 
            } 
        } while (Module32Next(snapshot, &me));
    }
    CloseHandle(snapshot);
    return found;
}

// Scan exact memory range
uintptr_t FindPattern(HANDLE hProc, uintptr_t start, size_t size, const char* pattern, const char* mask) {
    size_t chunkSize = 4096 * 16; // 64KB chunks
    std::vector<uint8_t> buffer(chunkSize);
    size_t patternLen = strlen(mask);

    for (size_t i = 0; i < size; i += chunkSize) {
        SIZE_T read;
        if (ReadProcessMemory(hProc, (LPCVOID)(start + i), buffer.data(), chunkSize, &read)) {
            for (size_t j = 0; j < read - patternLen; j++) {
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
    std::cout << "[*] SNIPER v10 DEBUG: Waiting for Roblox..." << std::endl;
    
    DWORD pid = 0;
    while (!(pid = GetPID("RobloxPlayerBeta.exe"))) { std::this_thread::sleep_for(std::chrono::milliseconds(10)); }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // WAIT FOR 20MB (Safety)
    std::cout << "[!] Found PID: " << pid << ". Waiting for 20MB RAM..." << std::endl;
    PROCESS_MEMORY_COUNTERS pmc;
    while (true) {
        GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc));
        if (pmc.WorkingSetSize > 20 * 1024 * 1024) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::cout << "[!] Memory Threshold Reached. Starting Scan Loop..." << std::endl;

    uintptr_t base = 0;
    DWORD modSize = 0;
    uintptr_t sig = 0;

    // TRY FOR 5 SECONDS
    for (int i = 0; i < 500; i++) {
        NtSuspendProcess(hProc);
        
        if (GetModuleInfo(pid, "RobloxPlayerBeta.exe", base, modSize)) {
            // SCAN ONLY ONCE IF FOUND
            if (!sig) {
                sig = FindPattern(hProc, base, modSize, "\x48\x83\xEC\x38\x48\x8B\x0D", "xxxxxxx");
                if (sig) std::cout << "[DEBUG] Sig Found at: " << std::hex << sig << std::endl;
            }

            if (sig) {
                uintptr_t instr = sig + 4;
                int32_t disp;
                ReadProcessMemory(hProc, (LPCVOID)(instr + 3), &disp, 4, NULL);
                uintptr_t singleton_ptr = instr + 7 + disp;
                
                uintptr_t singleton_val = 0;
                ReadProcessMemory(hProc, (LPCVOID)singleton_ptr, &singleton_val, 8, NULL);

                if (singleton_val > 0x1000) {
                    uint64_t mask = 0;
                    ReadProcessMemory(hProc, (LPCVOID)(singleton_val + 0x30), &mask, 8, NULL);
                    
                    // ONLY BREAK IF MAP IS POPULATED
                    if (mask > 0) {
                        std::cout << "[+] MAP READY! Mask: " << mask << std::endl;
                        
                        // INJECT HERE
                        std::ifstream file("fflags.json");
                        if (file.is_open()) {
                            json config; file >> config;
                            uintptr_t buckets; ReadProcessMemory(hProc, (LPCVOID)(singleton_val + 0x18), &buckets, 8, NULL);
                            
                            std::cout << "[*] Injecting " << config.size() << " flags..." << std::endl;

                            for (auto& it : config.items()) {
                                std::string name = it.key();
                                uint64_t hash = 0xcbf29ce484222325;
                                for (char c : name) { hash ^= (uint64_t)c; hash *= 0x100000001b3; }
                                
                                uintptr_t bucket_addr = buckets + ((hash & mask) * 16);
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
                                        std::cout << "  [+] " << name << " -> " << val << std::endl;
                                        break;
                                    }
                                    ReadProcessMemory(hProc, (LPCVOID)node, &node, 8, NULL);
                                    safety++;
                                }
                            }
                        }
                        
                        NtResumeProcess(hProc);
                        return 0; // EXIT SUCCESS
                    }
                }
            }
        }

        NtResumeProcess(hProc);
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }

    std::cout << "[-] TIMEOUT: Sig Found? " << (sig ? "YES" : "NO") << std::endl;
    NtResumeProcess(hProc);
    return 0;
}
