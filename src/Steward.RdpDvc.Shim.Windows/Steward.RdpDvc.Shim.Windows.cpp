#include <windows.h>
#include <cchannel.h>
#include <tsvirtualchannels.h>
#include <cwchar>
#include <iterator>

namespace
{
    IUnknown* pluginInstance = nullptr;

    void Record(const wchar_t* stage)
    {
        wchar_t path[32768]{};
        auto length = GetEnvironmentVariableW(
            L"STEWARD_RDCORE_SHIM_EVIDENCE_PATH",
            path,
            static_cast<DWORD>(std::size(path)));
        if (length == 0 || length >= std::size(path))
            return;
        auto file = CreateFileW(
            path,
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return;
        DWORD written = 0;
        WriteFile(
            file,
            stage,
            static_cast<DWORD>(wcslen(stage) * sizeof(wchar_t)),
            &written,
            nullptr);
        CloseHandle(file);
    }
}

extern "C" __declspec(dllexport) void VCAPITYPE
StewardSetPluginInstance(IUnknown* instance)
{
    if (instance != nullptr)
        instance->AddRef();
    auto previous = static_cast<IUnknown*>(
        InterlockedExchangePointer(
            reinterpret_cast<void* volatile*>(&pluginInstance),
            instance));
    if (previous != nullptr)
        previous->Release();
    Record(L"instance-set\r\n");
}

extern "C" __declspec(dllexport) HRESULT VCAPITYPE
VirtualChannelGetInstance(
    REFIID interfaceId,
    ULONG* objectCount,
    void** objects)
{
    Record(objects == nullptr ? L"query\r\n" : L"create\r\n");
    if (objectCount == nullptr)
        return E_POINTER;
    if (interfaceId != __uuidof(IWTSPlugin))
        return E_NOINTERFACE;
    if (objects == nullptr)
    {
        *objectCount = 1;
        return S_OK;
    }
    if (*objectCount < 1)
    {
        *objectCount = 1;
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }

    objects[0] = nullptr;
    auto current = pluginInstance;
    if (current == nullptr)
        return CO_E_NOTINITIALIZED;
    current->AddRef();
    auto result = current->QueryInterface(interfaceId, &objects[0]);
    current->Release();
    Record(SUCCEEDED(result) ? L"instance-ok\r\n" : L"instance-failed\r\n");
    *objectCount = SUCCEEDED(result) ? 1UL : 0UL;
    return result;
}
