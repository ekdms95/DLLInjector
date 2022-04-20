#pragma once
#include "../pch.h"

struct handle_data
{
	DWORD	OwnerPID;
	WORD	hValue;
	DWORD	Access;
};

std::vector<handle_data> FindProcessHandles(DWORD TargetPID, DWORD WantedHandleAccess);