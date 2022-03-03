// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <string> 
#include <Psapi.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <d3d9.h> 
#include "D3Dhook.h"
#include <math.h>
#include <chrono>
#include <iostream>
#include <algorithm>
//#include <thread>
#pragma comment(lib, "D3D Hook x86.lib")

//thanks stackoverflow
void WriteToMemory(DWORD addressToWrite, char* valueToWrite, int byteNum)
{
    //used to change our file access type, stores the old
    //access type and restores it after memory is written
    unsigned long OldProtection;
    //give that address read and write permissions and store the old permissions at oldProtection
    VirtualProtect((LPVOID)(addressToWrite), byteNum, PAGE_EXECUTE_READWRITE, &OldProtection);

    //write the memory into the program and overwrite previous value
    memcpy((LPVOID)addressToWrite, valueToWrite, byteNum);

    //reset the permissions of the address back to oldProtection after writting memory
    VirtualProtect((LPVOID)(addressToWrite), byteNum, OldProtection, NULL);
}

void WriteToMemory(DWORD addressToWrite, int* valueToWrite, int byteNum)
{
    //used to change our file access type, stores the old
    //access type and restores it after memory is written
    unsigned long OldProtection;
    //give that address read and write permissions and store the old permissions at oldProtection
    VirtualProtect((LPVOID)(addressToWrite), byteNum, PAGE_EXECUTE_READWRITE, &OldProtection);

    //write the memory into the program and overwrite previous value
    memcpy((LPVOID)addressToWrite, valueToWrite, byteNum);

    //reset the permissions of the address back to oldProtection after writting memory
    VirtualProtect((LPVOID)(addressToWrite), byteNum, OldProtection, NULL);
}

//uncapped hook. bad!!!
char hookUncapped[] = { 0xC3 };
//"let the computer handle it" option.
char hookSystem[] = { 0xB9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x6A, 0x00 };
//put tps cap at + 1 byte offset
char hookCapped[] = { 0xB9, 0x01, 0x00, 0x00, 0x00, 0x90 };
char lookup[] = { 0x8B, 0x44, 0x24, 0x04, 0x8B, 0x08, 0x6A, 0x01, 0x51, 0xFF };
//already patched with a previous version?
char lookup2[] = { 0xC3, 0x44, 0x24, 0x04, 0x8B, 0x08, 0x6A, 0x01, 0x51, 0xFF };
char* modBase;

char* ScanBasic(char* pattern, int patternLen, char* begin, intptr_t size)
{

    for (int i = 0; i < size; i++)
    {
        bool found = true;
        for (int j = 0; j < patternLen; j++)
        {
            if (pattern[j] != *(char*)((intptr_t)begin + i + j))
            {
                found = false;
                break;
            }
        }
        if (found)
        {
            return (begin + i);
        }
    }
    return nullptr;
}

char* ScanInternal(char* pattern, int patternLen, char* begin, intptr_t size)
{
    char* match{ nullptr };
    MEMORY_BASIC_INFORMATION mbi{};

    for (char* curr = begin; curr < begin + size; curr += mbi.RegionSize)
    {
        if (!VirtualQuery(curr, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) continue;

        match = ScanBasic(pattern, patternLen, curr, mbi.RegionSize);

        if (match != nullptr)
        {
            break;
        }
    }
    return match;
}

inline bool exists(const std::wstring& name) {
    struct _stat buffer;
    return (_wstat(name.c_str(), &buffer) == 0);
}

//Frame Limiter Stuff-----------------------

typedef long(__stdcall* tPresent)(LPDIRECT3DDEVICE9, RECT*,
    RECT*,
    HWND,
    RGNDATA*);
tPresent oD3D9Present = NULL;
long long FPSTarget = 0;
std::chrono::steady_clock::time_point currentFrameTime;
std::chrono::steady_clock::time_point lastFrameTime;
long long timeBetweenFrames;

long __stdcall hkD3D9Present(LPDIRECT3DDEVICE9 pDevice, RECT* pSourceRect,
    RECT* pDestRect,
    HWND          hDestWindowOverride,
    RGNDATA* pDirtyRegion)
{
    long present = oD3D9Present(pDevice, pSourceRect, pDestRect, hDestWindowOverride, pDirtyRegion);
    if (FPSTarget != 0)
    {
        currentFrameTime = std::chrono::steady_clock::now();
        timeBetweenFrames = std::chrono::duration_cast<std::chrono::nanoseconds>(currentFrameTime - lastFrameTime).count();
        //timeBetweenFrames = currentFrameTime - lastFrameTime;
        if (timeBetweenFrames < FPSTarget)
        {
            auto cPoint = currentFrameTime.time_since_epoch().count();
            //auto cPointNano = std::chrono::duration_cast<std::chrono::nanoseconds>(cPoint - currentFrameTime).count();
            auto targetNow = cPoint + (FPSTarget - timeBetweenFrames);
            //nanosleep(targetNow);
            //std::this_thread::sleep_for(std::chrono::nanoseconds(targetNow));
            while (cPoint/*Nano*/ < targetNow)
            {
                cPoint = std::chrono::steady_clock::now().time_since_epoch().count();
                //cPointNano = std::chrono::duration_cast<std::chrono::nanoseconds>(cPoint - currentFrameTime).count();
            }
            //timeBetweenFrames = currentFrameTime + (FPSTarget - timeBetweenFrames);
            //while (std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()) < timeBetweenFrames) {};
        }
        lastFrameTime = std::chrono::steady_clock::now();
    }
    return present;
}

//------------------------------------------

HWND g_HWND = NULL;
wchar_t modName[MAX_PATH];
BOOL CALLBACK EnumWindowsProcMy(HWND hwnd, LPARAM lParam)
{
    DWORD lpdwProcessId;
    GetWindowThreadProcessId(hwnd, &lpdwProcessId);
    if (IsWindowVisible(hwnd) && lpdwProcessId == lParam)
    {
        g_HWND = hwnd;
        return FALSE;
    }
    return TRUE;
}

bool bExit = false;

void MakeBorderless() {
    int pid = GetCurrentProcessId();
    while (g_HWND == NULL)
    {
        EnumWindows(EnumWindowsProcMy, pid);
    }
    LONG lStyle = GetWindowLong(g_HWND, GWL_STYLE);
    LONG SavelStyle = lStyle;
    lStyle &= ~(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZE | WS_MAXIMIZE | WS_SYSMENU);
    SetWindowLong(g_HWND, GWL_STYLE, lStyle);
    LONG lExStyle = GetWindowLong(g_HWND, GWL_EXSTYLE);
    LONG SavelExStyle = lExStyle;
    lExStyle &= ~(WS_EX_DLGMODALFRAME | WS_EX_CLIENTEDGE | WS_EX_STATICEDGE);
    SetWindowLong(g_HWND, GWL_EXSTYLE, lExStyle);
    SetWindowPos(g_HWND, HWND_TOP, 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), SWP_FRAMECHANGED | SWP_SHOWWINDOW);
}

DWORD WINAPI BorderlessThread(LPVOID param)
{
    while (true)
    {
        MakeBorderless();
        Sleep(500);
    }
    return 0;
}

void RunBorderlessThread(LPVOID param) {
    CreateThread(0, 0, BorderlessThread, param, 0, 0);
}

DWORD WINAPI MainThread(LPVOID param)
{
    /*
    AllocConsole();
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    */
    std::wstring cmdLine = GetCommandLine();
    std::transform(
        cmdLine.begin(), cmdLine.end(),
        cmdLine.begin(),
        towlower);
    //wprintf(cmdLine.c_str());
 
    GetModuleFileName(NULL, modName, MAX_PATH);
    bool isLauncher = false;
    if (wcsstr(modName, L"TS3") == 0 && wcsstr(modName, L"Sims3") == 0)
    {
        FreeLibraryAndExitThread((HMODULE)param, 0);
        return 0;
    }
    if (wcsstr(modName, L"Sims3") != NULL)
        isLauncher = true;
    std::wstring::size_type pos = std::wstring(modName).find_last_of(L"\\/");
    auto folder = std::wstring(modName).substr(0, pos);
    wchar_t wcs[MAX_PATH];
    wcscpy_s(wcs, folder.c_str());
    wcscat_s(wcs, L"\\TS3Patch.txt");
    int tps = 0;
    bool debug = false;
    int delay = 0;
    bool borderless = false;
    if (exists(wcs))
    {
        std::wifstream file(wcs);
        std::wstring str;
        while (std::getline(file, str))
        {
            str.erase(std::remove(str.begin(), str.end(), ' '), str.end());
            if (wcslen(str.c_str()) > 0)
            {
                if (wcscmp(str.substr(0, 1).c_str(), L"#"))
                {
                    std::wstring temp;
                    std::vector<std::wstring> split;
                    std::wstringstream wss(str);
                    while (std::getline(wss, temp, L'='))
                    {
                        split.push_back(temp);
                    }
                    int intValue = std::stoi(split[1]);
                    if (!wcscmp(split[0].c_str(), L"TPS"))
                    {
                        tps = intValue;
                    }
                    if (!wcscmp(split[0].c_str(), L"Debug"))
                    {
                        if (intValue > 0)
                            debug = true;
                    }
                    if (!wcscmp(split[0].c_str(), L"Delay"))
                    {
                        delay = intValue;
                    }
                    if (!wcscmp(split[0].c_str(), L"FPSLimit"))
                    {
                        if (intValue > 0)
                        {
                            FPSTarget = 1e+9 / intValue; //Compensate...?
                        }
                    }
                    if (!wcscmp(split[0].c_str(), L"Borderless"))
                    {
                        if (intValue == 1)
                            borderless = true;
                    }
                }
            }
        }
        file.close();
    }
    if (delay > 0)
        Sleep(delay);
    //Package installer runs at like 1500 FPS on my rig. Override settings.
    if (wcsstr(cmdLine.c_str(), L"-ccuninstall:") != 0 || wcsstr(cmdLine.c_str(), L"-ccinstall:") != 0)
    {
        borderless = false;
        FPSTarget = 1e+9 / 60;
        debug = false;
    }
    HMODULE module = GetModuleHandleA(NULL);
    modBase = (char*)GetModuleHandleA(NULL);
    HANDLE proc = GetCurrentProcess();
    MODULEINFO modInfo;
    GetModuleInformation(proc, module, &modInfo, sizeof(MODULEINFO));
    int size = modInfo.SizeOfImage;
    DWORD addr = (DWORD)nullptr;
    while (addr == (DWORD)nullptr)
    {
        addr = (DWORD)ScanInternal(lookup, sizeof(lookup) / sizeof(*lookup), modBase, size);
        if (addr == (DWORD)nullptr)
        {
            addr = (DWORD)ScanInternal(lookup2, sizeof(lookup2) / sizeof(*lookup2), modBase, size);
            if (addr == (DWORD)nullptr)
            {
                Sleep(500);
            }
        }
    }
    if (FPSTarget > 0)
    {
        if (init_D3D())	// D3D methods table
        {
            methodesHook(17, hkD3D9Present, (LPVOID*)&oD3D9Present); // hook endscene
            lastFrameTime = std::chrono::steady_clock::now();
        }
    }
    if (borderless)
    {
        RunBorderlessThread(param);
    }
    if (debug)
    {
        std::wstring w = std::to_wstring(addr);
        MessageBox(NULL, L"Patching Game!", L"Info", MB_OK);
    }
    
    int tickrate = 0;
    if (tps > 0)
        tickrate = 1000 / tps;
    else
    {
        if (tps < 0)
        {
            if (tps == -2)
                tickrate = -2;
            else
                tickrate = -1;
        }
    }
    if (tickrate == -1)
    {
        WriteToMemory(addr, hookUncapped, sizeof(hookUncapped) / sizeof(*hookUncapped));
    }
    else if (tickrate == 0)
    {
        WriteToMemory(addr, hookSystem, sizeof(hookSystem) / sizeof(*hookSystem));
    }
    else if (tickrate != -2)
    {
        WriteToMemory(addr, hookCapped, sizeof(hookCapped) / sizeof(*hookCapped));
        WriteToMemory(addr + 1, &tickrate, 4);
    }
    if (FPSTarget > 0 || borderless)
    {
        while (!bExit)
        {
            Sleep(100); // Sleeps until shutdown
        }

        methodesUnhook(); // disables and removes all hooks
    }
    FreeLibraryAndExitThread((HMODULE)param, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(0, 0, MainThread, hModule, 0, 0);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}