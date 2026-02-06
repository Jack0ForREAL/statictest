#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <thread>
#include <tlhelp32.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// --- NTAPI FOR FREEZING ---
typedef LONG(NTAPI* pNtSuspendProcess)(HANDLE ProcessHandle);
typedef LONG(NTAPI* pNtResumeProcess)(HANDLE ProcessHandle);
pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtSuspendProcess");
pNtResumeProcess NtResumeProcess = (pNtResumeProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtResumeProcess");

// --- UTILS ---
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

// --- SCANNER ---
uintptr_t FindPattern(HANDLE hProcess, uintptr_t start, size_t size, const char* pattern, const char* mask) {
    std::vector<char> buffer(size);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPCVOID)start, buffer.data(), size, &bytesRead)) return 0;

    size_t patternLen = strlen(mask);
    for (size_t i = 0; i < size - patternLen; i++) {
        bool found = true;
        for (size_t j = 0; j < patternLen; j++) {
            if (mask[j] != '?' && pattern[j] != buffer[i + j]) {
                found = false;
                break;
            }
        }
        if (found) return start + i;
    }
    return 0;
}

int main() {
    std::cout << "--- ROBLOX C++ SNIPER [STANDALONE] ---" << std::endl;
    
    while (true) {
        HWND hwnd = FindWindowA(NULL, "Roblox");
        if (hwnd) {
            DWORD pid; GetWindowThreadProcessId(hwnd, &pid);
            HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            uintptr_t base = GetModuleBase(pid, "RobloxPlayerBeta.exe");

            if (hProc && base) {
                std::cout << "[+] Found Roblox. Suspending..." << std::endl;
                NtSuspendProcess(hProc);

                // Pattern for FFlag Singleton
                const char* pattern = "\x48\x83\xEC\x38\x48\x8B\x0D";
                const char* mask = "xxxxxxx";
                
                uintptr_t sig = FindPattern(hProc, base, 0x5000000, pattern, mask);
                if (sig) {
                    uintptr_t instr = sig + 4;
                    int32_t disp;
                    ReadProcessMemory(hProc, (LPCVOID)(instr + 3), &disp, 4, NULL);
                    uintptr_t ptr = instr + 7 + disp;
                    uintptr_t singleton;
                    ReadProcessMemory(hProc, (LPCVOID)ptr, &singleton, 8, NULL);

                    if (singleton > 0x1000) {
                        std::cout << "[+] Map Found. Loading fflags.json..." << std::endl;
                        
                        std::ifstream file("fflags.json");
                        if (file.is_open()) {
                            json j; file >> j;
                            
                            // Note: For a single-file sniper, we iterate the map logic here
                            // Or simpler: If you know the names, we can use your old FNV1a hash logic
                            // For now, let's assume we use the address-writing logic.
                            std::cout << "[!] Injecting " << j.size() << " flags..." << std::endl;
                            
                            // (Simplified Injection Logic)
                            // In a real sniper, you'd walk the map here. 
                            // This code assumes standard offsets 0x8 (Map), 0x10 (List), etc.
                        }
                    }
                }

                std::cout << "[+] Resuming Game." << std::endl;
                NtResumeProcess(hProc);
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return 0;
}
