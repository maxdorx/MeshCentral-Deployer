#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace mcd {

inline constexpr wchar_t kServiceName[] = L"MeshCentralDeployer";
inline constexpr wchar_t kDisplayName[] = L"MeshCentral Deployer";

struct Config {
    std::wstring domainController;
    std::vector<std::wstring> searchBases;
    std::filesystem::path meshAgentPath;
    std::filesystem::path remoteRunnerPath;
    std::filesystem::path databasePath;
    std::filesystem::path logPath;
    std::vector<std::wstring> meshServiceNames{L"Mesh Agent"};
    unsigned discoveryMinutes = 15;
    unsigned installedRecheckHours = 24;
    unsigned staleDays = 7;
    unsigned workerCount = 4;
    unsigned connectTimeoutSeconds = 3;
    unsigned installTimeoutSeconds = 180;
    unsigned retryBaseSeconds = 60;
    unsigned retryMaximumSeconds = 21600;
};

class Error : public std::runtime_error {
public:
    explicit Error(const std::string& message) : std::runtime_error(message) {}
};

std::filesystem::path ModulePath();
std::filesystem::path ModuleDirectory();
std::filesystem::path ProgramDataDirectory();
std::string Utf8(const std::wstring& value);
std::wstring Wide(const std::string& value);
std::wstring Win32Message(DWORD error);
std::wstring Trim(std::wstring value);
std::vector<std::wstring> Split(const std::wstring& value, wchar_t delimiter);
long long UnixNow();
unsigned BackoffSeconds(unsigned attempts, unsigned baseSeconds, unsigned maximumSeconds, const std::wstring& key);
Config LoadConfig(const std::filesystem::path& iniPath);
void WriteConfig(const std::filesystem::path& iniPath, const Config& config);
void ThrowLastError(const char* operation, DWORD error = GetLastError());

} // namespace mcd
