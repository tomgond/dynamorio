#include <string>
#include <vector>
#include <cwchar>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <windows.h>
#include <winternl.h>
#include <map>
#include <string>
#include <sstream>
#include <iostream>
#include <algorithm>

using std::size_t;
using std::string;
using std::vector;
using std::wstring;

// define process_t type
typedef DWORD process_t;

// #define instead of typedef to override
#define RTL_DRIVE_LETTER_CURDIR \
    struct {                    \
        WORD Flags;             \
        WORD Length;            \
        ULONG TimeStamp;        \
        STRING DosPath;         \
    }

// #define instead of typedef to override
#define RTL_USER_PROCESS_PARAMETERS                     \
    struct {                                            \
        ULONG MaximumLength;                            \
        ULONG Length;                                   \
        ULONG Flags;                                    \
        ULONG DebugFlags;                               \
        PVOID ConsoleHandle;                            \
        ULONG ConsoleFlags;                             \
        PVOID StdInputHandle;                           \
        PVOID StdOutputHandle;                          \
        PVOID StdErrorHandle;                           \
        UNICODE_STRING CurrentDirectoryPath;            \
        PVOID CurrentDirectoryHandle;                   \
        UNICODE_STRING DllPath;                         \
        UNICODE_STRING ImagePathName;                   \
        UNICODE_STRING CommandLine;                     \
        PVOID Environment;                              \
        ULONG StartingPositionLeft;                     \
        ULONG StartingPositionTop;                      \
        ULONG Width;                                    \
        ULONG Height;                                   \
        ULONG CharWidth;                                \
        ULONG CharHeight;                               \
        ULONG ConsoleTextAttributes;                    \
        ULONG WindowFlags;                              \
        ULONG ShowWindowFlags;                          \
        UNICODE_STRING WindowTitle;                     \
        UNICODE_STRING DesktopName;                     \
        UNICODE_STRING ShellInfo;                       \
        UNICODE_STRING RuntimeData;                     \
        RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[32]; \
        ULONG EnvironmentSize;                          \
    }

DWORD
FindProcessId(const WCHAR *processname)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD result = NULL;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap)
        return (FALSE);

    pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap); // clean the snapshot object
        printf("!!! Failed to gather information on system processes! \n");
        return (NULL);
    }

    do {
        // printf("Checking process %ls\n", pe32.szExeFile);
        if (0 == wcscmp(processname, pe32.szExeFile)) {
            result = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    printf("Target process name is: %s", processname);
    return result;
}



// shortens a wide string to a narrow string
static inline string
shorten(wstring wstr)
{
    int nbytes = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), NULL,
                                     0, NULL, NULL);
    vector<char> buf(nbytes);
    return string{ buf.data(),
                   (size_t)WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(),
                                               (int)wstr.length(), buf.data(), nbytes,
                                               NULL, NULL) };
}

// replace all occurrences of substring found in string with specified new string
static inline string
string_replace_all(string str, string substr, string nstr)
{
    size_t pos = 0;
    while ((pos = str.find(substr, pos)) != string::npos) {
        str.replace(pos, substr.length(), nstr);
        pos += nstr.length();
    }
    return str;
}

// func that splits string by first occurrence of equals sign
vector<string>
string_split_by_first_equalssign(string str)
{
    size_t pos = 0;
    vector<string> vec;
    if ((pos = str.find_first_of("=")) != string::npos) {
        vec.push_back(str.substr(0, pos));
        vec.push_back(str.substr(pos + 1));
    }
    return vec;
}

// checks whether process handle is 32-bit or not
static inline bool
IsX86Process(HANDLE process)
{
    BOOL isWow = true;
    SYSTEM_INFO systemInfo = { 0 };
    GetNativeSystemInfo(&systemInfo);
    if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
        return isWow;
    IsWow64Process(process, &isWow);
    return isWow;
}

// helper to open processes based on pid with full debug privileges
static inline HANDLE
OpenProcessWithDebugPrivilege(process_t pid)
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);
    CloseHandle(hToken);
    return OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
}

// get wide character string of pids environ based on handle
static inline wchar_t *
GetEnvironmentStringsW(HANDLE proc)
{
    PEB peb;
    SIZE_T nRead;
    ULONG res_len = 0;
    PROCESS_BASIC_INFORMATION pbi;
    RTL_USER_PROCESS_PARAMETERS upp;
    HMODULE p_ntdll = GetModuleHandleW(L"ntdll.dll");
    typedef NTSTATUS(__stdcall * tfn_qip)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    tfn_qip pfn_qip = tfn_qip(GetProcAddress(p_ntdll, "NtQueryInformationProcess"));
    NTSTATUS status = pfn_qip(proc, ProcessBasicInformation, &pbi, sizeof(pbi), &res_len);
    if (status) {
        return NULL;
    }
    ReadProcessMemory(proc, pbi.PebBaseAddress, &peb, sizeof(peb), &nRead);
    if (!nRead) {
        return NULL;
    }
    ReadProcessMemory(proc, peb.ProcessParameters, &upp, sizeof(upp), &nRead);
    if (!nRead) {
        return NULL;
    }
    PVOID buffer = upp.Environment;
    ULONG length = upp.EnvironmentSize;
    wchar_t *res = new wchar_t[length / 2 + 1];
    ReadProcessMemory(proc, buffer, res, length, &nRead);
    if (!nRead) {
        return NULL;
    }
    res[length / 2] = 0;
    return res;
}

// get env of pid as a narrow string
string
env_from_pid(process_t pid)
{
    string envs;
    HANDLE proc = OpenProcessWithDebugPrivilege(pid);
    wchar_t *wenvs = NULL;
    if (IsX86Process(GetCurrentProcess())) {
        if (IsX86Process(proc)) {
            wenvs = GetEnvironmentStringsW(proc);
        }
    } else {
        if (!IsX86Process(proc)) {
            wenvs = GetEnvironmentStringsW(proc);
        }
    }
    string arg;
    if (wenvs == NULL) {
        return "";
    } else {
        arg = shorten(wenvs);
    }
    size_t i = 0;
    do {
        size_t j = 0;
        vector<string> envVec = string_split_by_first_equalssign(arg);
        for (const string &env : envVec) {
            if (j == 0) {
                if (env.find_first_of("%<>^&|:") != string::npos) {
                    continue;
                }
                if (env.empty()) {
                    continue;
                }
                envs += env;
            } else {
                envs += "=\"" + string_replace_all(env, "\"", "\\\"") + "\"\n";
            }
            j++;
        }
        i += wcslen(wenvs + i) + 1;
        arg = shorten(wenvs + i);
    } while (wenvs[i] != L'\0');
    if (envs.back() == '\n') {
        envs.pop_back();
    }
    if (wenvs != NULL) {
        delete[] wenvs;
    }
    CloseHandle(proc);
    return envs;
}

std::map<std::string, unsigned int>
env_to_values(std::string const &s)
{
    std::map<std::string, unsigned int> m;

    std::string key, val, tmp, tmp2;
    std::istringstream iss(s);
    string dr_global_data("dr_global_data");
    string dr_global_data_value;
    string dr_module_table("dr_module_table");
    string dr_module_table_value;
    std::stringstream ss; 

	
    
    while (std::getline(iss, tmp)) {
        printf("Line is :%s\n", tmp.c_str());
        if (tmp.find(dr_global_data) != string::npos ) {
            printf("global data is here: %s\n", tmp.c_str());
            ss << tmp;
			std::getline(ss, tmp2, '=');
			std::getline(ss, dr_global_data_value);
			dr_global_data_value.erase(std::remove(dr_global_data_value.begin(), dr_global_data_value.end(), '"'), dr_global_data_value.end());
			printf("Only value : %s\n", dr_global_data_value.c_str());
			m[dr_global_data] =  std::stoul(dr_global_data_value, nullptr, 16);
		}
        if (tmp.find(dr_module_table) != string::npos) {
            printf("Module table is here: %s\n", tmp.c_str());
            ss.clear();
            ss.str(std::string());
			ss << tmp;
			std::getline(ss, tmp2, '=');
            printf("tmp2 is : %s\n", tmp2.c_str());
            std::getline(ss, dr_module_table_value);
            dr_module_table_value.erase(std::remove(dr_module_table_value.begin(), dr_module_table_value.end(), '"'), dr_module_table_value.end());
            printf("Only value : %s\n", dr_module_table_value.c_str());
            m[dr_module_table] = std::stoul(dr_module_table_value, nullptr, 16);
        }
        
	}

    //while (std::getline(std::getline(iss, key, ':') >> std::ws, val))
    //    m[key] = val;

    return m;
}

// test function (can be omitted)
int
main(int argc, char **argv)
{
    argc = 2;
    if (argc == 2) {
        string s = env_from_pid(FindProcessId(L"notepad.exe"));
		//printf("%s", s.c_str());
        printf("===================\n");
		std::map<std::string, unsigned int> m = env_to_values(s);
        for (const auto &x : m) {
            std::cout << x.first << ": " << x.second << "\n";
        }

        printf("%s", "\r\n");
    } else {
        printf("%s", env_from_pid(GetCurrentProcessId()).c_str());
        printf("%s", "\r\n");
    }
    return 0;
}
