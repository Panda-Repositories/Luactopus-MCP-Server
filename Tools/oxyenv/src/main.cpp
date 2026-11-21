#include <lua.h>
#include <lualib.h>
#include <luacode.h>
#include <nlohmann/json.hpp>
#include <zstd.h>
#include <zstd_errors.h>

#include <algorithm>
#include <bit>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#include <wininet.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")
#endif

namespace fsys = std::filesystem;

namespace radium
{
    constexpr const char* kExecutorName = "Madium";
    constexpr const char* kExecutorVersion = "2.0.0";

    static std::string readFile(const std::string& path)
    {
        std::ifstream file(path, std::ios::binary);
        if (!file)
            throw std::runtime_error("could not open file: " + path);

        std::ostringstream stream;
        stream << file.rdbuf();
        return stream.str();
    }

    static bool writeFile(const std::string& path, const std::string& content)
    {
        std::ofstream file(path, std::ios::binary);
        if (!file)
            return false;

        file.write(content.data(), static_cast<std::streamsize>(content.size()));
        return bool(file);
    }

    static void setGlobalCFunction(lua_State* L, const char* name, lua_CFunction fn)
    {
        lua_pushcfunction(L, fn, name);
        lua_setglobal(L, name);
    }

    static void setFieldCFunction(lua_State* L, int index, const char* name, lua_CFunction fn)
    {
        if (index < 0)
            index = lua_gettop(L) + index + 1;

        lua_pushcfunction(L, fn, name);
        lua_setfield(L, index, name);
    }

    static int c_identifyexecutor(lua_State* L)
    {
        lua_pushstring(L, kExecutorName);
        lua_pushstring(L, kExecutorVersion);
        return 2;
    }

    static int c_getexecutorname(lua_State* L)
    {
        lua_pushstring(L, kExecutorName);
        return 1;
    }

    static int c_warn(lua_State* L)
    {
        const int count = lua_gettop(L);
        std::cerr << "[warn] ";

        for (int i = 1; i <= count; ++i)
        {
            if (i > 1)
                std::cerr << '\t';

            const char* value = lua_tostring(L, i);
            if (value)
                std::cerr << value;
            else
                std::cerr << luaL_typename(L, i);
        }

        std::cerr << '\n';
        return 0;
    }

    // ---------------------------------------------------------------------
    // Native C-forwarder
    //
    // L3 passes a Lua implementation to __RADIUM_HOST.native.bind().
    // The returned value is a real C closure that forwards to that function.
    // This keeps L3's actual behavior while making native identity truthful.
    // ---------------------------------------------------------------------

    static const char* nativeDebugName(const char* requested)
    {
        if (!requested) return "radium";
        if (std::strcmp(requested, "new") == 0) return "new";
        if (std::strcmp(requested, "spawn") == 0) return "spawn";
        if (std::strcmp(requested, "defer") == 0) return "defer";
        if (std::strcmp(requested, "delay") == 0) return "delay";
        if (std::strcmp(requested, "wait") == 0) return "wait";
        if (std::strcmp(requested, "cancel") == 0) return "cancel";
        if (std::strcmp(requested, "IsStudio") == 0) return "IsStudio";
        if (std::strcmp(requested, "IsClient") == 0) return "IsClient";
        if (std::strcmp(requested, "IsServer") == 0) return "IsServer";
        if (std::strcmp(requested, "FromName") == 0) return "FromName";
        if (std::strcmp(requested, "FromValue") == 0) return "FromValue";
        if (std::strcmp(requested, "IsA") == 0) return "IsA";
        if (std::strcmp(requested, "Destroy") == 0) return "Destroy";
        if (std::strcmp(requested, "GetChildren") == 0) return "GetChildren";
        if (std::strcmp(requested, "GetService") == 0) return "GetService";
        if (std::strcmp(requested, "GetPhysicsStepId") == 0) return "GetPhysicsStepId";
        if (std::strcmp(requested, "rawget") == 0) return "rawget";
        if (std::strcmp(requested, "rawset") == 0) return "rawset";
        if (std::strcmp(requested, "getfenv") == 0) return "getfenv";
        if (std::strcmp(requested, "setfenv") == 0) return "setfenv";
        if (std::strcmp(requested, "getgenv") == 0) return "getgenv";
        if (std::strcmp(requested, "getrenv") == 0) return "getrenv";
        if (std::strcmp(requested, "getreg") == 0) return "getreg";
        if (std::strcmp(requested, "getgc") == 0) return "getgc";
        if (std::strcmp(requested, "getinstances") == 0) return "getinstances";
        if (std::strcmp(requested, "getnilinstances") == 0) return "getnilinstances";
        if (std::strcmp(requested, "getcustomasset") == 0) return "getcustomasset";
        if (std::strcmp(requested, "writefile") == 0) return "writefile";
        if (std::strcmp(requested, "appendfile") == 0) return "appendfile";
        if (std::strcmp(requested, "readfile") == 0) return "readfile";
        if (std::strcmp(requested, "isfile") == 0) return "isfile";
        if (std::strcmp(requested, "isfolder") == 0) return "isfolder";
        if (std::strcmp(requested, "makefolder") == 0) return "makefolder";
        if (std::strcmp(requested, "listfiles") == 0) return "listfiles";
        if (std::strcmp(requested, "delfile") == 0) return "delfile";
        if (std::strcmp(requested, "delfolder") == 0) return "delfolder";
        if (std::strcmp(requested, "loadstring") == 0) return "loadstring";
        if (std::strcmp(requested, "HttpGet") == 0) return "HttpGet";
        if (std::strcmp(requested, "GetAsync") == 0) return "GetAsync";
        if (std::strcmp(requested, "PostAsync") == 0) return "PostAsync";
        if (std::strcmp(requested, "RequestAsync") == 0) return "RequestAsync";
        if (std::strcmp(requested, "type") == 0) return "type";
        if (std::strcmp(requested, "tostring") == 0) return "tostring";
        if (std::strcmp(requested, "GetMouseLocation") == 0) return "GetMouseLocation";
        return "radium";
    }

    static int c_native_forward(lua_State* L)
    {
        const int argc = lua_gettop(L);

        lua_pushvalue(L, lua_upvalueindex(1));
        lua_insert(L, 1);

        lua_call(L, argc, LUA_MULTRET);
        return lua_gettop(L);
    }


    static int c_native_iscclosure(lua_State* L)
    {
        if (!lua_isfunction(L, 1))
        {
            lua_pushboolean(L, false);
            return 1;
        }

        lua_pushboolean(L, lua_iscfunction(L, 1));
        return 1;
    }

    static int c_native_isfunctionhooked(lua_State* L)
    {
        luaL_checktype(L, 1, LUA_TFUNCTION);

        // Project Radium v0.9 does not install or conceal function hooks.
        // Therefore every currently callable function is truthfully unhooked.
        lua_pushboolean(L, false);
        return 1;
    }

    static int c_native_checkcaller(lua_State* L)
    {
        // Target scripts execute as target code, not as privileged host calls.
        lua_pushboolean(L, false);
        return 1;
    }

    static int c_native_newcclosure(lua_State* L)
    {
        luaL_checktype(L, 1, LUA_TFUNCTION);
        lua_pushvalue(L, 1);
        lua_pushcclosure(L, c_native_forward, "newcclosure", 1);
        return 1;
    }

    static int c_native_clonefunction(lua_State* L)
    {
        luaL_checktype(L, 1, LUA_TFUNCTION);

        // Return an independently callable native forwarding closure.
        // It does not mutate or replace the original function.
        lua_pushvalue(L, 1);
        lua_pushcclosure(L, c_native_forward, "clonefunction", 1);
        return 1;
    }

    static int c_native_bind(lua_State* L)
    {
        const char* requested = luaL_checkstring(L, 1);
        luaL_checktype(L, 2, LUA_TFUNCTION);

        lua_pushvalue(L, 2);
        lua_pushcclosure(L, c_native_forward, nativeDebugName(requested), 1);
        return 1;
    }

    // ---------------------------------------------------------------------
    // L3 host: process
    // ---------------------------------------------------------------------

    static void pushProcess(lua_State* L, int argc, char** argv, int firstArg)
    {
        lua_createtable(L, 0, 1);

        const int count = std::max(0, argc - firstArg);
        lua_createtable(L, count, 0);

        for (int i = 0; i < count; ++i)
        {
            lua_pushstring(L, argv[firstArg + i]);
            lua_rawseti(L, -2, i + 1);
        }

        lua_setfield(L, -2, "args");
    }

    // ---------------------------------------------------------------------
    // L3 host: filesystem
    // ---------------------------------------------------------------------

    static int c_fs_readFile(lua_State* L)
    {
        const char* path = luaL_checkstring(L, 1);

        try
        {
            const std::string content = readFile(path);
            lua_pushlstring(L, content.data(), content.size());
            return 1;
        }
        catch (const std::exception& ex)
        {
            luaL_error(L, "%s", ex.what());
            return 0;
        }
    }

    static int c_fs_writeFile(lua_State* L)
    {
        const char* path = luaL_checkstring(L, 1);
        size_t size = 0;
        const char* content = luaL_checklstring(L, 2, &size);

        if (!writeFile(path, std::string(content, size)))
        {
            luaL_error(L, "could not write file: %s", path);
            return 0;
        }

        return 0;
    }

    static int c_fs_isFile(lua_State* L)
    {
        const char* path = luaL_checkstring(L, 1);
        std::error_code ec;
        lua_pushboolean(L, fsys::is_regular_file(path, ec));
        return 1;
    }

    static int c_fs_isDir(lua_State* L)
    {
        const char* path = luaL_checkstring(L, 1);
        std::error_code ec;
        lua_pushboolean(L, fsys::is_directory(path, ec));
        return 1;
    }

    static int c_fs_writeDir(lua_State* L)
    {
        const char* path = luaL_checkstring(L, 1);

        std::error_code checkEc;
        if (fsys::is_directory(path, checkEc) && !checkEc)
            return 0;

        std::error_code createEc;
        fsys::create_directories(path, createEc);

        // Another Radium process may have created the same directory between
        // the check above and create_directories(). Existing directory = success.
        std::error_code verifyEc;
        if (fsys::is_directory(path, verifyEc) && !verifyEc)
            return 0;

        if (createEc)
        {
            luaL_error(
                L,
                "could not create directory: %s (%s)",
                path,
                createEc.message().c_str()
            );
            return 0;
        }

        luaL_error(L, "could not create directory: %s", path);
        return 0;
    }

    static int c_fs_readDir(lua_State* L)
    {
        const char* path = luaL_checkstring(L, 1);
        std::error_code ec;

        lua_createtable(L, 0, 0);
        int index = 1;

        for (const auto& entry : fsys::directory_iterator(path, ec))
        {
            if (ec)
                break;

            const std::string value = entry.path().string();
            lua_pushlstring(L, value.data(), value.size());
            lua_rawseti(L, -2, index++);
        }

        if (ec)
        {
            lua_pop(L, 1);
            luaL_error(L, "could not read directory: %s", path);
            return 0;
        }

        return 1;
    }

    static int c_fs_removeFile(lua_State* L)
    {
        const char* path = luaL_checkstring(L, 1);
        std::error_code ec;
        fsys::remove(path, ec);

        if (ec)
        {
            luaL_error(L, "could not remove file: %s", path);
            return 0;
        }

        return 0;
    }

    static int c_fs_removeDir(lua_State* L)
    {
        const char* path = luaL_checkstring(L, 1);
        std::error_code ec;
        fsys::remove_all(path, ec);

        if (ec)
        {
            luaL_error(L, "could not remove directory: %s", path);
            return 0;
        }

        return 0;
    }

    static void pushFs(lua_State* L)
    {
        lua_createtable(L, 0, 7);
        setFieldCFunction(L, -1, "readFile", c_fs_readFile);
        setFieldCFunction(L, -1, "writeFile", c_fs_writeFile);
        setFieldCFunction(L, -1, "isFile", c_fs_isFile);
        setFieldCFunction(L, -1, "isDir", c_fs_isDir);
        setFieldCFunction(L, -1, "writeDir", c_fs_writeDir);
        setFieldCFunction(L, -1, "readDir", c_fs_readDir);
        setFieldCFunction(L, -1, "removeFile", c_fs_removeFile);
        setFieldCFunction(L, -1, "removeDir", c_fs_removeDir);
    }

    // ---------------------------------------------------------------------
    // L3 host: luau.load
    // ---------------------------------------------------------------------

    static int c_luau_load(lua_State* L)
    {
        size_t sourceSize = 0;
        const char* source = luaL_checklstring(L, 1, &sourceSize);

        const char* chunkName = "=ProjectRadiumNative";
        int envIndex = 0;

        if (lua_istable(L, 2))
        {
            lua_getfield(L, 2, "chunkName");
            if (lua_isstring(L, -1))
                chunkName = lua_tostring(L, -1);
            lua_pop(L, 1);

            lua_getfield(L, 2, "environment");
            if (lua_istable(L, -1))
                envIndex = lua_gettop(L);
            else
                lua_pop(L, 1);
        }

        size_t bytecodeSize = 0;
        char* bytecode =
            luau_compile(source, sourceSize, nullptr, &bytecodeSize);

        if (!bytecode)
        {
            lua_pushnil(L);
            lua_pushstring(L, "luau_compile failed");
            return 2;
        }

        const int status =
            luau_load(L, chunkName, bytecode, bytecodeSize, envIndex);

        std::free(bytecode);

        if (status != 0)
        {
            const char* errorText = lua_tostring(L, -1);
            std::string copied = errorText ? errorText : "luau_load failed";
            lua_pop(L, 1);

            lua_pushnil(L);
            lua_pushlstring(L, copied.data(), copied.size());
            return 2;
        }

        return 1;
    }

    static void pushLuau(lua_State* L)
    {
        lua_createtable(L, 0, 1);
        setFieldCFunction(L, -1, "load", c_luau_load);
    }

    // ---------------------------------------------------------------------
    // L3 host: network / JSON serde.
    // ---------------------------------------------------------------------

#ifdef _WIN32
    static bool winInetGetFallback(
        const std::wstring& url,
        const std::vector<std::pair<std::string, std::string>>& headers,
        DWORD& status,
        std::string& responseBody,
        DWORD& errorCode)
    {
        HINTERNET session = InternetOpenW(
            L"OxyEnv/3.50",
            INTERNET_OPEN_TYPE_PRECONFIG,
            nullptr,
            nullptr,
            0);
        if (!session)
        {
            errorCode = GetLastError();
            return false;
        }

        std::wstring headerText;
        for (const auto& [k, v] : headers)
        {
            auto widenLocal = [](const std::string& in) -> std::wstring
            {
                if (in.empty()) return {};
                int count = MultiByteToWideChar(CP_UTF8, 0, in.data(), static_cast<int>(in.size()), nullptr, 0);
                if (count <= 0) return {};
                std::wstring out(static_cast<size_t>(count), L'\0');
                MultiByteToWideChar(CP_UTF8, 0, in.data(), static_cast<int>(in.size()), out.data(), count);
                return out;
            };
            headerText += widenLocal(k + ": " + v + "\r\n");
        }

        DWORD flags = INTERNET_FLAG_RELOAD
            | INTERNET_FLAG_NO_CACHE_WRITE
            | INTERNET_FLAG_NO_UI
            | INTERNET_FLAG_KEEP_CONNECTION;
        if (url.rfind(L"https://", 0) == 0)
            flags |= INTERNET_FLAG_SECURE;

        HINTERNET request = InternetOpenUrlW(
            session,
            url.c_str(),
            headerText.empty() ? nullptr : headerText.c_str(),
            headerText.empty() ? 0 : static_cast<DWORD>(-1),
            flags,
            0);
        if (!request)
        {
            errorCode = GetLastError();
            InternetCloseHandle(session);
            return false;
        }

        DWORD statusSize = sizeof(status);
        status = 0;
        if (!HttpQueryInfoW(
                request,
                HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                &status,
                &statusSize,
                nullptr))
        {
            status = 200;
        }

        responseBody.clear();
        char buffer[16384];
        for (;;)
        {
            DWORD read = 0;
            if (!InternetReadFile(request, buffer, sizeof(buffer), &read))
            {
                errorCode = GetLastError();
                InternetCloseHandle(request);
                InternetCloseHandle(session);
                return false;
            }
            if (read == 0) break;
            responseBody.append(buffer, read);
            if (responseBody.size() > 64u * 1024u * 1024u)
            {
                errorCode = ERROR_FILE_TOO_LARGE;
                InternetCloseHandle(request);
                InternetCloseHandle(session);
                return false;
            }
        }

        InternetCloseHandle(request);
        InternetCloseHandle(session);
        errorCode = ERROR_SUCCESS;
        return true;
    }
#endif

    static int c_net_request(lua_State* L)
    {
#ifdef _WIN32
        std::string url;
        std::string method = "GET";
        std::string body;
        std::vector<std::pair<std::string, std::string>> headers;

        if (lua_istable(L, 1))
        {
            lua_getfield(L, 1, "url");
            if (!lua_isstring(L, -1))
            {
                lua_pop(L, 1);
                lua_getfield(L, 1, "Url");
            }
            if (lua_isstring(L, -1)) url = lua_tostring(L, -1);
            lua_pop(L, 1);

            lua_getfield(L, 1, "method");
            if (!lua_isstring(L, -1))
            {
                lua_pop(L, 1);
                lua_getfield(L, 1, "Method");
            }
            if (lua_isstring(L, -1)) method = lua_tostring(L, -1);
            lua_pop(L, 1);

            lua_getfield(L, 1, "body");
            if (!lua_isstring(L, -1))
            {
                lua_pop(L, 1);
                lua_getfield(L, 1, "Body");
            }
            if (lua_isstring(L, -1))
            {
                size_t n = 0;
                const char* p = lua_tolstring(L, -1, &n);
                if (p) body.assign(p, n);
            }
            lua_pop(L, 1);

            lua_getfield(L, 1, "headers");
            if (!lua_istable(L, -1))
            {
                lua_pop(L, 1);
                lua_getfield(L, 1, "Headers");
            }
            if (lua_istable(L, -1))
            {
                lua_pushnil(L);
                while (lua_next(L, -2) != 0)
                {
                    const char* k = lua_tostring(L, -2);
                    const char* v = lua_tostring(L, -1);
                    if (k && v) headers.emplace_back(k, v);
                    lua_pop(L, 1);
                }
            }
            lua_pop(L, 1);
        }
        else if (lua_isstring(L, 1))
        {
            url = lua_tostring(L, 1);
        }
        else
        {
            luaL_error(L, "request expects a URL string or request table");
            return 0;
        }

        if (url.empty()) { luaL_error(L, "request URL is empty"); return 0; }

        auto widen = [](const std::string& in) -> std::wstring
        {
            if (in.empty()) return {};
            int count = MultiByteToWideChar(CP_UTF8, 0, in.data(), static_cast<int>(in.size()), nullptr, 0);
            if (count <= 0) return {};
            std::wstring out(static_cast<size_t>(count), L'\0');
            MultiByteToWideChar(CP_UTF8, 0, in.data(), static_cast<int>(in.size()), out.data(), count);
            return out;
        };

        std::wstring wurl = widen(url);

        // GET requests are the dominant Roblox HttpGet/GetAsync path.
        // WinINet follows the current user's Windows proxy/TLS configuration more
        // closely than service-oriented WinHTTP, so prefer it and keep WinHTTP as
        // the fallback for systems where WinINet is unavailable.
        if (_stricmp(method.c_str(), "GET") == 0)
        {
            DWORD internetStatus = 0;
            DWORD internetError = 0;
            std::string internetBody;
            if (winInetGetFallback(wurl, headers, internetStatus, internetBody, internetError))
            {
                lua_createtable(L, 0, 6);
                lua_pushnumber(L, static_cast<double>(internetStatus));
                lua_setfield(L, -2, "statusCode");
                lua_pushnumber(L, static_cast<double>(internetStatus));
                lua_setfield(L, -2, "StatusCode");
                lua_pushboolean(L, internetStatus >= 200 && internetStatus < 400);
                lua_setfield(L, -2, "success");
                lua_pushlstring(L, internetBody.data(), internetBody.size());
                lua_setfield(L, -2, "body");
                lua_pushlstring(L, internetBody.data(), internetBody.size());
                lua_setfield(L, -2, "Body");
                lua_pushstring(L, "wininet");
                lua_setfield(L, -2, "backend");
                return 1;
            }
        }

        URL_COMPONENTS parts{};
        parts.dwStructSize = sizeof(parts);
        parts.dwSchemeLength = static_cast<DWORD>(-1);
        parts.dwHostNameLength = static_cast<DWORD>(-1);
        parts.dwUrlPathLength = static_cast<DWORD>(-1);
        parts.dwExtraInfoLength = static_cast<DWORD>(-1);
        if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &parts))
        {
            luaL_error(L, "invalid HTTP URL");
            return 0;
        }

        std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
        std::wstring path(parts.lpszUrlPath, parts.dwUrlPathLength);
        if (parts.dwExtraInfoLength)
            path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
        if (path.empty()) path = L"/";

        HINTERNET session = WinHttpOpen(L"OxyEnv/3.50", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session) { luaL_error(L, "WinHttpOpen failed"); return 0; }
        WinHttpSetTimeouts(session, 10000, 10000, 15000, 30000);

        HINTERNET connection = WinHttpConnect(session, host.c_str(), parts.nPort, 0);
        if (!connection)
        {
            WinHttpCloseHandle(session);
            luaL_error(L, "WinHttpConnect failed");
            return 0;
        }

        std::wstring wmethod = widen(method);
        DWORD flags = parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET request = WinHttpOpenRequest(connection, wmethod.c_str(), path.c_str(), nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!request)
        {
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            luaL_error(L, "WinHttpOpenRequest failed");
            return 0;
        }

#ifdef WINHTTP_OPTION_DECOMPRESSION
        DWORD decompressionFlags = WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
        WinHttpSetOption(request, WINHTTP_OPTION_DECOMPRESSION, &decompressionFlags, sizeof(decompressionFlags));
#endif

        for (const auto& [k, v] : headers)
        {
            std::wstring line = widen(k + ": " + v);
            WinHttpAddRequestHeaders(request, line.c_str(), static_cast<DWORD>(-1),
                WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
        }

        BOOL sent = WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
            static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0);
        if (!sent || !WinHttpReceiveResponse(request, nullptr))
        {
            const DWORD winHttpError = GetLastError();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);

            if (_stricmp(method.c_str(), "GET") == 0)
            {
                DWORD fallbackStatus = 0;
                DWORD fallbackError = 0;
                std::string fallbackBody;
                if (winInetGetFallback(wurl, headers, fallbackStatus, fallbackBody, fallbackError))
                {
                    lua_createtable(L, 0, 6);
                    lua_pushnumber(L, static_cast<double>(fallbackStatus));
                    lua_setfield(L, -2, "statusCode");
                    lua_pushnumber(L, static_cast<double>(fallbackStatus));
                    lua_setfield(L, -2, "StatusCode");
                    lua_pushboolean(L, fallbackStatus >= 200 && fallbackStatus < 400);
                    lua_setfield(L, -2, "success");
                    lua_pushlstring(L, fallbackBody.data(), fallbackBody.size());
                    lua_setfield(L, -2, "body");
                    lua_pushlstring(L, fallbackBody.data(), fallbackBody.size());
                    lua_setfield(L, -2, "Body");
                    lua_pushstring(L, "wininet-fallback");
                    lua_setfield(L, -2, "backend");
                    return 1;
                }
                luaL_error(L, "HTTP request failed (WinHTTP %lu, WinINet %lu)",
                    static_cast<unsigned long>(winHttpError),
                    static_cast<unsigned long>(fallbackError));
                return 0;
            }

            luaL_error(L, "HTTP request failed (WinHTTP error %lu)",
                static_cast<unsigned long>(winHttpError));
            return 0;
        }

        DWORD status = 0;
        DWORD statusSize = sizeof(status);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);

        std::string responseBody;
        for (;;)
        {
            DWORD available = 0;
            if (!WinHttpQueryDataAvailable(request, &available) || available == 0) break;
            size_t old = responseBody.size();
            responseBody.resize(old + available);
            DWORD read = 0;
            if (!WinHttpReadData(request, responseBody.data() + old, available, &read)) break;
            responseBody.resize(old + read);
            if (responseBody.size() > 64u * 1024u * 1024u)
            {
                WinHttpCloseHandle(request);
                WinHttpCloseHandle(connection);
                WinHttpCloseHandle(session);
                luaL_error(L, "HTTP response exceeded 64 MiB limit");
                return 0;
            }
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);

        lua_createtable(L, 0, 5);
        lua_pushnumber(L, static_cast<double>(status));
        lua_setfield(L, -2, "statusCode");
        lua_pushnumber(L, static_cast<double>(status));
        lua_setfield(L, -2, "StatusCode");
        lua_pushboolean(L, status >= 200 && status < 400);
        lua_setfield(L, -2, "success");
        lua_pushlstring(L, responseBody.data(), responseBody.size());
        lua_setfield(L, -2, "body");
        lua_pushlstring(L, responseBody.data(), responseBody.size());
        lua_setfield(L, -2, "Body");
        return 1;
#else
        (void)L;
        luaL_error(L, "native HTTP adapter is only implemented on Windows in this build");
        return 0;
#endif
    }

    static void pushJsonValue(lua_State* L, const nlohmann::json& value)
    {
        if (value.is_null())
            lua_pushnil(L);
        else if (value.is_boolean())
            lua_pushboolean(L, value.get<bool>());
        else if (value.is_number_integer())
            lua_pushnumber(L, static_cast<double>(value.get<std::int64_t>()));
        else if (value.is_number_unsigned())
            lua_pushnumber(L, static_cast<double>(value.get<std::uint64_t>()));
        else if (value.is_number_float())
            lua_pushnumber(L, value.get<double>());
        else if (value.is_string())
        {
            const std::string& s = value.get_ref<const std::string&>();
            lua_pushlstring(L, s.data(), s.size());
        }
        else if (value.is_array())
        {
            lua_createtable(L, static_cast<int>(value.size()), 0);
            int index = 1;
            for (const auto& item : value)
            {
                pushJsonValue(L, item);
                lua_rawseti(L, -2, index++);
            }
        }
        else if (value.is_object())
        {
            lua_createtable(L, 0, static_cast<int>(value.size()));
            for (auto it = value.begin(); it != value.end(); ++it)
            {
                pushJsonValue(L, it.value());
                lua_setfield(L, -2, it.key().c_str());
            }
        }
        else
            lua_pushnil(L);
    }

    static bool luaTableLooksArray(lua_State* L, int index, int& lengthOut)
    {
        if (index < 0)
            index = lua_gettop(L) + index + 1;

        int count = 0;
        int maxIndex = 0;
        bool onlyPositiveIntegerKeys = true;

        lua_pushnil(L);
        while (lua_next(L, index) != 0)
        {
            ++count;

            if (lua_type(L, -2) == LUA_TNUMBER)
            {
                const double key = lua_tonumber(L, -2);
                const int integerKey = static_cast<int>(key);
                if (key < 1 || key != static_cast<double>(integerKey))
                    onlyPositiveIntegerKeys = false;
                else
                    maxIndex = std::max(maxIndex, integerKey);
            }
            else
                onlyPositiveIntegerKeys = false;

            lua_pop(L, 1);
        }

        lengthOut = maxIndex;
        return onlyPositiveIntegerKeys && count == maxIndex;
    }

    static nlohmann::json luaValueToJson(lua_State* L, int index, int depth = 0)
    {
        if (depth > 64)
            throw std::runtime_error("JSONEncode nesting limit exceeded");

        if (index < 0)
            index = lua_gettop(L) + index + 1;

        switch (lua_type(L, index))
        {
        case LUA_TNIL:
            return nullptr;

        case LUA_TBOOLEAN:
            return lua_toboolean(L, index) != 0;

        case LUA_TNUMBER:
            return lua_tonumber(L, index);

        case LUA_TSTRING:
        {
            size_t size = 0;
            const char* data = lua_tolstring(L, index, &size);
            return std::string(data ? data : "", size);
        }

        case LUA_TTABLE:
        {
            int arrayLength = 0;

            if (luaTableLooksArray(L, index, arrayLength))
            {
                nlohmann::json result = nlohmann::json::array();
                for (int i = 1; i <= arrayLength; ++i)
                {
                    lua_rawgeti(L, index, i);
                    result.push_back(luaValueToJson(L, -1, depth + 1));
                    lua_pop(L, 1);
                }
                return result;
            }

            nlohmann::json result = nlohmann::json::object();

            lua_pushnil(L);
            while (lua_next(L, index) != 0)
            {
                if (lua_type(L, -2) != LUA_TSTRING)
                {
                    lua_pop(L, 2);
                    throw std::runtime_error("JSONEncode object keys must be strings");
                }

                size_t keySize = 0;
                const char* keyData = lua_tolstring(L, -2, &keySize);
                const std::string key(keyData ? keyData : "", keySize);

                result[key] = luaValueToJson(L, -1, depth + 1);
                lua_pop(L, 1);
            }

            return result;
        }

        default:
            throw std::runtime_error(
                std::string("JSONEncode unsupported Lua type: ") + luaL_typename(L, index)
            );
        }
    }

    static int c_serde_decode(lua_State* L)
    {
        const char* format = luaL_checkstring(L, 1);
        size_t sourceSize = 0;
        const char* source = luaL_checklstring(L, 2, &sourceSize);

        if (std::strcmp(format, "json") != 0)
        {
            luaL_error(L, "unsupported serde format '%s'", format);
            return 0;
        }

        try
        {
            const nlohmann::json parsed = nlohmann::json::parse(source, source + sourceSize);
            pushJsonValue(L, parsed);
            return 1;
        }
        catch (const std::exception& ex)
        {
            luaL_error(L, "JSONDecode error: %s", ex.what());
            return 0;
        }
    }

    static int c_serde_encode(lua_State* L)
    {
        const char* format = luaL_checkstring(L, 1);

        if (std::strcmp(format, "json") != 0)
        {
            luaL_error(L, "unsupported serde format '%s'", format);
            return 0;
        }

        try
        {
            const nlohmann::json encoded = luaValueToJson(L, 2);
            const std::string output = encoded.dump();
            lua_pushlstring(L, output.data(), output.size());
            return 1;
        }
        catch (const std::exception& ex)
        {
            luaL_error(L, "JSONEncode error: %s", ex.what());
            return 0;
        }
    }


    static bool isZstdName(const char* algorithm)
    {
        if (!algorithm)
            return true;

        return std::strcmp(algorithm, "Zstd") == 0
            || std::strcmp(algorithm, "ZSTD") == 0
            || std::strcmp(algorithm, "zstd") == 0;
    }

    static int c_serde_compress(lua_State* L)
    {
        const char* algorithm = luaL_checkstring(L, 1);

        size_t sourceSize = 0;
        const char* source = luaL_checklstring(L, 2, &sourceSize);

        if (!isZstdName(algorithm))
        {
            luaL_error(L, "unsupported compression algorithm '%s'", algorithm);
            return 0;
        }

        int level = 3;
        if (!lua_isnoneornil(L, 3))
            level = static_cast<int>(luaL_checkinteger(L, 3));

        const size_t bound = ZSTD_compressBound(sourceSize);
        std::string output;
        output.resize(bound);

        const size_t written =
            ZSTD_compress(output.data(), output.size(), source, sourceSize, level);

        if (ZSTD_isError(written))
        {
            luaL_error(
                L,
                "Zstd compression failed: %s",
                ZSTD_getErrorName(written)
            );
            return 0;
        }

        output.resize(written);
        lua_pushlstring(L, output.data(), output.size());
        return 1;
    }

    static int c_serde_decompress(lua_State* L)
    {
        const char* algorithm = luaL_checkstring(L, 1);

        size_t sourceSize = 0;
        const char* source = luaL_checklstring(L, 2, &sourceSize);

        if (!isZstdName(algorithm))
        {
            luaL_error(L, "unsupported compression algorithm '%s'", algorithm);
            return 0;
        }

        if (sourceSize == 0)
        {
            lua_pushliteral(L, "");
            return 1;
        }

        const unsigned long long announced =
            ZSTD_getFrameContentSize(source, sourceSize);

        if (announced == ZSTD_CONTENTSIZE_ERROR)
        {
            luaL_error(L, "Zstd decompression failed: invalid frame");
            return 0;
        }

        constexpr size_t kMaxDecompressedSize = 256ull * 1024ull * 1024ull;

        size_t capacity = 0;

        if (announced != ZSTD_CONTENTSIZE_UNKNOWN)
        {
            if (announced > kMaxDecompressedSize)
            {
                luaL_error(L, "Zstd decompressed payload exceeds Radium limit");
                return 0;
            }

            capacity = static_cast<size_t>(announced);
        }
        else
        {
            capacity = std::max<size_t>(sourceSize * 8, 64 * 1024);
            capacity = std::min(capacity, kMaxDecompressedSize);
        }

        if (capacity == 0)
            capacity = 1;

        for (;;)
        {
            std::string output;
            output.resize(capacity);

            const size_t written =
                ZSTD_decompress(output.data(), output.size(), source, sourceSize);

            if (!ZSTD_isError(written))
            {
                output.resize(written);
                lua_pushlstring(L, output.data(), output.size());
                return 1;
            }

            const ZSTD_ErrorCode errorCode = ZSTD_getErrorCode(written);

            if (errorCode != ZSTD_error_dstSize_tooSmall || capacity >= kMaxDecompressedSize)
            {
                luaL_error(
                    L,
                    "Zstd decompression failed: %s",
                    ZSTD_getErrorName(written)
                );
                return 0;
            }

            const size_t nextCapacity =
                std::min(capacity * 2, kMaxDecompressedSize);

            if (nextCapacity <= capacity)
            {
                luaL_error(L, "Zstd decompression exceeded Radium limit");
                return 0;
            }

            capacity = nextCapacity;
        }
    }

    static void pushNet(lua_State* L)
    {
        lua_createtable(L, 0, 1);
        setFieldCFunction(L, -1, "request", c_net_request);
    }

    static void pushSerde(lua_State* L)
    {
        lua_createtable(L, 0, 4);
        setFieldCFunction(L, -1, "decode", c_serde_decode);
        setFieldCFunction(L, -1, "encode", c_serde_encode);
        setFieldCFunction(L, -1, "compress", c_serde_compress);
        setFieldCFunction(L, -1, "decompress", c_serde_decompress);
    }

    static void pushNative(lua_State* L)
    {
        lua_createtable(L, 0, 6);
        setFieldCFunction(L, -1, "bind", c_native_bind);
        setFieldCFunction(L, -1, "iscclosure", c_native_iscclosure);
        setFieldCFunction(L, -1, "isfunctionhooked", c_native_isfunctionhooked);
        setFieldCFunction(L, -1, "checkcaller", c_native_checkcaller);
        setFieldCFunction(L, -1, "newcclosure", c_native_newcclosure);
        setFieldCFunction(L, -1, "clonefunction", c_native_clonefunction);
    }

    static void installRadiumHost(lua_State* L, int argc, char** argv, int firstProcessArg)
    {
        lua_createtable(L, 0, 6);

        pushProcess(L, argc, argv, firstProcessArg);
        lua_setfield(L, -2, "process");

        pushFs(L);
        lua_setfield(L, -2, "fs");

        pushNet(L);
        lua_setfield(L, -2, "net");

        pushSerde(L);
        lua_setfield(L, -2, "serde");

        pushLuau(L);
        lua_setfield(L, -2, "luau");

        pushNative(L);
        lua_setfield(L, -2, "native");

        lua_setglobal(L, "__RADIUM_HOST");
    }

    static bool runSource(lua_State* L, const std::string& source, const char* chunkName)
    {
        size_t bytecodeSize = 0;
        char* bytecode =
            luau_compile(source.data(), source.size(), nullptr, &bytecodeSize);

        if (!bytecode)
        {
            std::cerr << "luau_compile failed\n";
            return false;
        }

        const int loadStatus =
            luau_load(L, chunkName, bytecode, bytecodeSize, 0);

        std::free(bytecode);

        if (loadStatus != 0)
        {
            std::cerr << "load error: " << lua_tostring(L, -1) << "\n";
            lua_pop(L, 1);
            return false;
        }

        const int callStatus = lua_pcall(L, 0, 0, 0);
        if (callStatus != 0)
        {
            std::cerr << "runtime error: " << lua_tostring(L, -1) << "\n";
            lua_pop(L, 1);
            return false;
        }

        return true;
    }

    static void registerBaseGlobals(lua_State* L)
    {
        setGlobalCFunction(L, "identifyexecutor", c_identifyexecutor);
        setGlobalCFunction(L, "getexecutorname", c_getexecutorname);
        setGlobalCFunction(L, "warn", c_warn);
    }
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        std::cerr
            << "Oxygen OxyEnv native host v0.31\n"
            << "usage:\n"
            << "  radium-host <l3.lua> <input.lua> [output.lua] [l3 options]\n";
        return 2;
    }

    lua_State* L = luaL_newstate();
    if (!L)
    {
        std::cerr << "failed to create Luau state\n";
        return 1;
    }

    luaL_openlibs(L);
    radium::registerBaseGlobals(L);

    // l3.lua sees process.args beginning with input.lua, exactly like run_l3.lua.
    radium::installRadiumHost(L, argc, argv, 2);

    try
    {
        const std::string l3Source = radium::readFile(argv[1]);
        const bool ok = radium::runSource(L, l3Source, "=OxyEnvNative");
        lua_close(L);
        return ok ? 0 : 1;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "fatal: " << ex.what() << "\n";
        lua_close(L);
        return 1;
    }
}
