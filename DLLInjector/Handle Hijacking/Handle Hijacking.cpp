#include "Handle Hijacking.h"
#include "../NT Header.h"

typedef NTSTATUS(WINAPI* tNtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

HMODULE Ntdll = nullptr;
NTSTATUS EnumHandles(char* pBuffer, ULONG Size, ULONG* SizeOut, UINT& Count)
{
	if (!Ntdll) // Ntdll �� nullptr �Ͻÿ�
		LoadLibraryA("ntdll.dll"); // ntdll.dll ���̺귯�� �ҷ���.

	tNtQuerySystemInformation fpQuerySystemInformation = (tNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"); //  NtQuerySystemInformation ã�Ƽ� ����
	NTSTATUS ntRet = fpQuerySystemInformation(static_cast<ULONG>(SYSTEM_INFORMATION_CLASS::SystemHandleInformation), pBuffer, Size, SizeOut); // NtQuerySystemInformation ���.

	if (NT_FAIL(ntRet))
	{
		//printf("[YUME] -> �ڵ� ����Ʈ�� �������µ� �����߽��ϴ�. �����ڵ� %08X\n", ntRet);
		return ntRet;
	}

	auto* pHandleInfo = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(pBuffer);
	Count = pHandleInfo->NumberOfHandles;

	//printf("[YUME] -> %d���� �ڵ� ����Ʈ�� �߰��߽��ϴ�.\n", Count);

	return ntRet;
}

std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> EnumProcessHandles()
{
	std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> Ret;
	UINT Count = 0;
	ULONG Size = 0x10000;
	char* pBuffer = new(std::nothrow) char[Size]();

	if (pBuffer == nullptr)
	{
		return Ret;
	}

	NTSTATUS ntRet = EnumHandles(pBuffer, Size, &Size, Count);

	if (NT_FAIL(ntRet))
	{
		while (ntRet == STATUS_INFO_LENGTH_MISMATCH)
		{
			delete[] pBuffer;
			pBuffer = new(std::nothrow) char[Size];

			if (pBuffer == nullptr)
			{
				return Ret;
			}

			ntRet = EnumHandles(pBuffer, Size, &Size, Count);
		}

		if (NT_FAIL(ntRet))
		{
			delete[] pBuffer;
			return Ret;
		}
	}

	auto* pEntry = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(pBuffer)->Handles;
	for (UINT i = 0; i != Count; ++i)
	{
		if ((OBJECT_TYPE_NUMBER)pEntry[i].ObjectTypeIndex == OBJECT_TYPE_NUMBER::Process)
		{
			Ret.push_back(pEntry[i]);
		}
	}

	delete[] pBuffer;

	return Ret;
}

std::vector<handle_data> FindProcessHandles(DWORD TargetPID, DWORD WantedHandleAccess)
{
	std::vector<handle_data> Ret;
	DWORD OwnPID = GetCurrentProcessId();
	DWORD Mask = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
	auto handles = EnumProcessHandles();

	//printf("[YUME] -> %d���� �ڵ��� �߰��߽��ϴ�.\n", (DWORD)handles.size());

	auto current_process = GetCurrentProcess();
	for (const auto& i : handles)
	{
		DWORD CurrentPID = i.UniqueProcessId;
		if (CurrentPID == OwnPID || CurrentPID == TargetPID)
		{
			continue;
		}

		HANDLE hCurrentProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, CurrentPID);
		if (!hCurrentProc)
		{
			continue;
		}

		if ((i.GrantedAccess & WantedHandleAccess) != WantedHandleAccess)
		{
			continue;
		}

		HANDLE hDup = nullptr;
		HANDLE hOrig = reinterpret_cast<HANDLE>(i.HandleValue);

		if (DuplicateHandle(hCurrentProc, hOrig, current_process, &hDup, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, NULL))
		{
			if (GetProcessId(hDup) == TargetPID)
			{
				Ret.push_back(handle_data{ CurrentPID, i.HandleValue, i.GrantedAccess });
			}

			CloseHandle(hDup);
		}

		CloseHandle(hCurrentProc);
	}

	//printf("[YUME] -> %d���� ���μ���Ÿ�� �ڵ��� �߰��߽��ϴ�.\n", (DWORD)Ret.size());

	return Ret;
}