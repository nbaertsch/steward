#include <windows.h>
#include <userenv.h>
#include <wtsapi32.h>
#include <string>
#include <vector>

#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "wtsapi32.lib")

namespace
{
    std::wstring Quote(const std::wstring& value)
    {
        std::wstring result = L"\"";
        size_t slashes = 0;
        for (const auto character : value)
        {
            if (character == L'\\')
            {
                ++slashes;
                continue;
            }
            if (character == L'"')
            {
                result.append(slashes * 2 + 1, L'\\');
                result.push_back(character);
                slashes = 0;
                continue;
            }
            result.append(slashes, L'\\');
            slashes = 0;
            result.push_back(character);
        }
        result.append(slashes * 2, L'\\');
        result.push_back(L'"');
        return result;
    }

    DWORD FindActiveSession()
    {
        PWTS_SESSION_INFOW sessions = nullptr;
        DWORD count = 0;
        if (!WTSEnumerateSessionsW(
                WTS_CURRENT_SERVER_HANDLE,
                0,
                1,
                &sessions,
                &count))
            return MAXDWORD;
        DWORD selected = MAXDWORD;
        for (DWORD index = 0; index < count; ++index)
        {
            if (sessions[index].State == WTSActive &&
                sessions[index].SessionId != 0)
            {
                selected = sessions[index].SessionId;
                break;
            }
        }
        WTSFreeMemory(sessions);
        return selected;
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2)
        return ERROR_INVALID_PARAMETER;

    const auto deadline = GetTickCount64() + 90ULL * 1000ULL;
    DWORD sessionId = MAXDWORD;
    while (sessionId == MAXDWORD && GetTickCount64() < deadline)
    {
        sessionId = FindActiveSession();
        if (sessionId == MAXDWORD)
            Sleep(2000);
    }
    if (sessionId == MAXDWORD)
        return ERROR_CTX_WINSTATION_NOT_FOUND;

    HANDLE token = nullptr;
    if (!WTSQueryUserToken(sessionId, &token))
        return static_cast<int>(GetLastError());
    LPVOID environment = nullptr;
    if (!CreateEnvironmentBlock(&environment, token, FALSE))
    {
        const auto error = GetLastError();
        CloseHandle(token);
        return static_cast<int>(error);
    }

    std::wstring command;
    for (int index = 1; index < argc; ++index)
    {
        if (!command.empty())
            command.push_back(L' ');
        command += Quote(argv[index]);
    }
    std::vector<wchar_t> mutableCommand(
        command.begin(),
        command.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.lpDesktop = const_cast<wchar_t*>(L"winsta0\\default");
    PROCESS_INFORMATION process{};
    const auto created = CreateProcessAsUserW(
        token,
        argv[1],
        mutableCommand.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT,
        environment,
        nullptr,
        &startup,
        &process);
    const auto createError = GetLastError();
    DestroyEnvironmentBlock(environment);
    CloseHandle(token);
    if (!created)
        return static_cast<int>(createError);

    CloseHandle(process.hThread);
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hProcess);
    return static_cast<int>(exitCode);
}
