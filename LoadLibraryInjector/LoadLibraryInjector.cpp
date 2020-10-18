// LoadLibraryInjector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>

#define print(str) std::cout << str << std::endl
#define printW(str) std::wcout << str << std::endl
#define input(str) std::wcin >> str
#define inputA(str) std::cin >> str

DWORD FindProcID(const wchar_t* procName);
bool InjectDll(const char* dllPath, DWORD procID);


int main()
{
    using std::wstring;
    using std::string;
    print("Enter Process Name: ");
    wstring in;
    input(in);
    
    DWORD procID = FindProcID(in.c_str());
    
    if (!procID)
    {
        print("Failed to find PID");
        return 0;
    }
    std::cout << "Successfully Found PID: " << std::hex << procID << std::endl;
    print("Enter Dll Path: ");
    string dllPath;
    inputA(dllPath);

    print("Starting Injection...");

    if (!InjectDll(dllPath.c_str(), procID))
    {
        print("Injection Failed!");
        return 0;
    }
    print("Successfully Injected! Congratulations");

    std::cin.get();
}

DWORD FindProcID(const wchar_t* procName)
{
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;
    if (!Process32First(hSnap, &pe))
        return 0;
    do
    {
        if (!wcscmp(procName, pe.szExeFile))
        {
            CloseHandle(hSnap);
            return pe.th32ProcessID;
        }
        

    } while (Process32Next(hSnap, &pe));

    CloseHandle(hSnap);
    return 0;
}

bool InjectDll(const char* dllPath, DWORD procID)
{
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, procID);
    LPVOID allocAddy = VirtualAllocEx(hProc, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocAddy == NULL)
    {
        print("VirtualAllocEx Failed");
        CloseHandle(hProc);
        return false;
    }
    if (!WriteProcessMemory(hProc, allocAddy, dllPath, strlen(dllPath), nullptr))
    {
        print("WriteProcessMemory Failed");
        CloseHandle(hProc);
        return false;
    }
    LPVOID pLoadLibrary = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (pLoadLibrary == NULL)
    {
        print("GetProcAddress Failed");
        CloseHandle(hProc);
        return false;
    }
    HANDLE hThread = CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibrary, allocAddy, NULL, NULL);
    if (hThread == NULL)
    {
        DWORD error = GetLastError();
        std::cout << "CreateRemoteThread Failed. Error code: " << std::hex << error << std::endl;
        CloseHandle(hProc);
        return false;
    }

    CloseHandle(hProc);
    return true;

   
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
