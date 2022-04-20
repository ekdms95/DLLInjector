#pragma once
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>

#pragma warning(disable: 4201) //unnamed union (nt structures)
#pragma warning(disable: 4324) //structure member alignment resulting in additional bytes being added as padding
#pragma warning(disable: 6001) //uninitialized memory & handles (false positive in for loops with continue statements)
#pragma warning(disable: 6258) //TerminateThread warning
#pragma warning(disable: 28159) //I want to use GetTickCount, suck it Bill

#define ALIGN_64 __declspec(align(8))
#define ALIGN_86 __declspec(align(4))

#ifdef _WIN64
#define ALIGN ALIGN_64
#else
#define ALIGN ALIGN_86
#endif