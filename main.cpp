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

// --- FNV1A HASHING (How Roblox finds flags) ---
uint64_t fnv1a(const std::string& str) {
    uint64_t hash = 0xcbf29ce484222325;
    for (char c : str) {
        hash ^= (uint64_t)c;
        hash *= 0x100000001b3;
    }
    return hash;
}

// --- MEMORY HELPERS ---
template <typename T>
T Read(HANDLE hProc, uintptr_t addr) {
    T val;
    ReadProcessMemory(hProc, (LPCVOID)addr, &val, sizeof(T), NULL);
    return val;
}

std::string ReadString(HANDLE hProc, uintptr_t addr) {
    uint64_t size = Read<uint64_t>(hProc, addr + 0x10);
    if (size == 0 || size > 200) return "";
    uintptr_t data_addr = (size >= 16) ? Read<uintptr_t>(hProc, addr) : addr;
    std::vector<char> buffer(size);
    ReadProcessMemory(hProc, (LPCVOID)data_addr, buffer.data(), size, NULL);
    return std::string(buffer.begin(), buffer.end());
}

// --- THE INJECTOR ---
void Inject(HANDLE hProc, uintptr_t singleton, const json& config) {
    uintptr_t map_ptr = singleton + 0x8;
    uintptr_t buckets = Read<uintptr_t>(hProc, map_ptr + 0x10);
    uint64_t mask = Read<uint64_t>(hProc, map_ptr + 0x28);

    int count = 0;
    for (auto& it : config.items()) {
        std::string name = it.key();
        uint64_t hash = fnv1a(name);
        uintptr_t bucket = buckets + ((hash & mask) * 16);
        uintptr_t node = Read<uintptr_t>(hProc, bucket + 0x8);

        int safety = 0;
        while (node != 0 && safety < 100) {
            if (ReadString(hProc, node + 0x10) == name) {
                uintptr_t val_ptr = Read<uintptr_t>(hProc, Read<uintptr_t>(hProc, node + 0x30) + 0xC0);
                
                // Write value (assume int/bool for now)
                int val = (it.value().is_string() && it.value() == "True") ? 1 : 0;
                if (it.value().is_number()) val = it.value().get<int>();

                WriteProcessMemory(hProc, (LPVOID)val_ptr, &val, sizeof(int), NULL);
                std::cout << "[+] Injected: " << name << std::endl;
                count++;
                break;
            }
            node = Read<uintptr_t>(hProc, node + 0x8);
            safety++;
        }
    }
    std::cout << "[!] Total Successfully Injected: " << count << std::endl;
}

int main() {
    std::cout << "Waiting for Roblox..." << std::endl;
    while (true) {
        HWND hwnd = FindWindowA(NULL, "Roblox");
        if (hwnd) {
            DWORD pid; GetWindowThreadProcessId(hwnd, &pid);
            HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if (!hProc) continue;

            // FREEZE IMMEDIATELY
            NtSuspendProcess(hProc);
            std::cout << "[!] Caught & Frozen. Scanning..." << std::endl;

            // Find Map (Wait for init)
            uintptr_t singleton = 0;
            for (int i = 0; i < 50; i++) {
                // Pattern scanning logic here (Simplified for standalone)
                // In production, we scan 'RobloxPlayerBeta.exe' memory for SIG_PATTERN
                // ... (Logic from previous sessions) ...
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }

            // Load fflags.json and Inject
            std::ifstream file("fflags.json");
            if (file.is_open()) {
                json config; file >> config;
                // Inject(hProc, singleton, config);
            }

            NtResumeProcess(hProc);
            std::cout << "[+] Resumed. Sniper shutting down." << std::endl;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return 0;
}
