#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

static SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
static SERVICE_STATUS g_status{};
static HANDLE g_stopEvent = nullptr;
static std::wstring g_serviceName;

static fs::path ModulePath() {
    std::wstring path(32768, L'\0');
    DWORD size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    path.resize(size);
    return path;
}

static void Report(DWORD state, DWORD error = NO_ERROR, DWORD hint = 0) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = error;
    g_status.dwServiceSpecificExitCode = error == ERROR_SERVICE_SPECIFIC_ERROR ? 1 : 0;
    g_status.dwWaitHint = hint;
    g_status.dwControlsAccepted = state == SERVICE_START_PENDING ? 0 : SERVICE_ACCEPT_STOP;
    static DWORD checkpoint = 1;
    g_status.dwCheckPoint = (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) ? checkpoint++ : 0;
    if (g_statusHandle) SetServiceStatus(g_statusHandle, &g_status);
}

static void WriteResult(DWORD exitCode, DWORD error, const std::wstring& message) {
    const fs::path finalPath = ModulePath().parent_path() / L"result.txt";
    const fs::path temporary = finalPath.wstring() + L".tmp";
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    output << "exitCode=" << exitCode << "\r\nerror=" << error << "\r\n";
    if (!message.empty()) {
        int bytes = WideCharToMultiByte(CP_UTF8, 0, message.data(), static_cast<int>(message.size()), nullptr, 0, nullptr, nullptr);
        std::string utf8(static_cast<size_t>(bytes), '\0');
        if (bytes) WideCharToMultiByte(CP_UTF8, 0, message.data(), static_cast<int>(message.size()), utf8.data(), bytes, nullptr, nullptr);
        output << "message=" << utf8 << "\r\n";
    }
    output.close();
    MoveFileExW(temporary.c_str(), finalPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
}

static DWORD RunInstaller() {
    const fs::path agent = ModulePath().parent_path() / L"MeshAgent.exe";
    if (!fs::exists(agent)) {
        WriteResult(ERROR_FILE_NOT_FOUND, ERROR_FILE_NOT_FOUND, L"MeshAgent.exe was not found beside the runner.");
        return ERROR_FILE_NOT_FOUND;
    }

    std::wstring command = L"\"" + agent.wstring() + L"\" -fullinstall";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(agent.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, agent.parent_path().c_str(), &startup, &process)) {
        DWORD error = GetLastError();
        WriteResult(error, error, L"CreateProcessW failed.");
        return error;
    }

    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
        AssignProcessToJobObject(job, process.hProcess);
    }

    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exitCode = ERROR_GEN_FAILURE;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (job) CloseHandle(job);
    WriteResult(exitCode, NO_ERROR, exitCode == 0 ? L"MeshAgent -fullinstall completed." : L"MeshAgent -fullinstall returned a failure code.");
    return exitCode;
}

static DWORD WINAPI Handler(DWORD control, DWORD, LPVOID, LPVOID) {
    if (control == SERVICE_CONTROL_STOP) {
        Report(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        if (g_stopEvent) SetEvent(g_stopEvent);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(g_serviceName.c_str(), Handler, nullptr);
    if (!g_statusHandle) return;
    Report(SERVICE_START_PENDING, NO_ERROR, 10000);
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Report(SERVICE_RUNNING);
    DWORD result = RunInstaller();
    Report(SERVICE_STOPPED, result == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
    if (g_stopEvent) CloseHandle(g_stopEvent);
}

int wmain(int argc, wchar_t** argv) {
    bool once = false;
    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--run-once") == 0) once = true;
        else if (_wcsicmp(argv[i], L"--service-name") == 0 && i + 1 < argc) g_serviceName = argv[++i];
    }
    if (once) return static_cast<int>(RunInstaller());
    if (g_serviceName.empty()) return ERROR_INVALID_PARAMETER;
    SERVICE_TABLE_ENTRYW table[] = {{g_serviceName.data(), ServiceMain}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) return static_cast<int>(GetLastError());
    return 0;
}
