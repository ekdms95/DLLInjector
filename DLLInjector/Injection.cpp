#include "Injection.h"
#include "Handle Hijacking/Handle Hijacking.h"
#include <fstream>

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

bool IsNativeProcess(HANDLE hTargetProc)
{
	BOOL bWOW64 = FALSE;
	IsWow64Process(hTargetProc, &bWOW64);

	return (bWOW64 == FALSE);
}

bool IsElevatedProcess(HANDLE hTargetProc)
{
	HANDLE hToken = nullptr;
	if (!OpenProcessToken(hTargetProc, TOKEN_QUERY, &hToken))
	{
		return false;
	}

	TOKEN_ELEVATION te{ 0 };
	DWORD SizeOut = 0;
	GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &SizeOut);

	CloseHandle(hToken);

	return (te.TokenIsElevated != 0);
}

extern "C" __declspec(dllexport) void Inject(const char* dllpath, DWORD processid)
{
	auto path = dllpath;
	auto pid = processid;
	if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
		//printf("[YUME] -> Dll ������ ��ο� �����ϴ�.\n");
		//system("PAUSE");
		return;
	}
	std::ifstream File(path, std::ios::binary | std::ios::ate);
	if (File.fail()) {
		//printf("[YUME] -> ������ ���µ� �����߽��ϴ�. -> %X\n", (DWORD)File.rdstate());
		File.close();
		//system("PAUSE");
		return;
	}
	auto FileSize = File.tellg();
	if (FileSize < 0x1000) {
		//printf("[YUME] -> ���� ����� ���� �ʽ��ϴ�.\n");
		File.close();
		//system("PAUSE");
		return;
	}
	BYTE* pSrcData = new BYTE[(UINT_PTR)FileSize];
	if (!pSrcData) {
		//printf("[YUME] -> Dll ������ �Ҵ��ϴµ� �����߽��ϴ�.\n");
		File.close();
		//system("PAUSE");
		return;
	}
	File.seekg(0, std::ios::beg);
	File.read((char*)(pSrcData), FileSize);
	File.close();

	/* pSrcData / FileSize */
	//printf("[YUME] -> �ڵ� ������ŷ�� �����ҰԿ�\n");
	DWORD accessMask = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
	accessMask |= PROCESS_CREATE_THREAD; // NtCreateThread
	auto handles = FindProcessHandles(pid, accessMask);
	if (handles.empty()) {
		//printf("[YUME] -> �ڵ��� �����\n");
		return;
	}

	HANDLE hHijackProc = nullptr;
	//printf("[YUME] -> ������ŷ �Ϸ� ����Ʈ�� ���� ���� ����\n");
	for (const auto& i : handles)
	{
		hHijackProc = OpenProcess(accessMask | PROCESS_CREATE_THREAD, FALSE, i.OwnerPID);
		if (!hHijackProc) {
			CloseHandle(hHijackProc);
			//printf("[YUME] -> �������μ����� �����߽��ϴ�. %06X\n", i.OwnerPID);
			continue;
		}

		//printf("[YUME] -> �������μ����� �����߽��ϴ�. %06X\n", i.OwnerPID);
		if (!IsElevatedProcess(hHijackProc) || !IsNativeProcess(hHijackProc)) {
			//printf("[YUME] -> IsNativeProcess �Ǵ� IsElevatedProcess�� �����ʾ� �����߻�.\n");
			CloseHandle(hHijackProc);
			continue;
		}

		/* ���� ���� �����մϴ�. */
		IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
		IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
		IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
		BYTE* pTargetBase = nullptr;

		if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) { //"MZ"
			//printf("[YUME] -> ��ȿ�������� ���� PE��� ����\n");
			CloseHandle(hHijackProc);
			return;
		}

		pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
		pOldOptHeader = &pOldNtHeader->OptionalHeader;
		pOldFileHeader = &pOldNtHeader->FileHeader;

		if (pOldFileHeader->Machine != CURRENT_ARCH) {
			CloseHandle(hHijackProc);
			//printf("[YUME] -> �������� �÷����Դϴ�. x64 x86 Ȯ�����ּ���.\n");
			return;
		}

		printf("���� OK\n");
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hHijackProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!pTargetBase) {
			CloseHandle(hHijackProc);
			//printf("[YUME] -> Ÿ�ٿ� ���μ��� �޸� �Ҵ� ���� 0x%X\n", GetLastError());
			return;
		}

		DWORD oldp = 0;
		VirtualProtectEx(hHijackProc, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

		//hHijackProc
		MANUAL_MAPPING_DATA data{ 0 };
		data.pLoadLibraryA = LoadLibraryA;
		data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
		data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else 
		SEHExceptionSupport = false;
#endif
		data.pbase = pTargetBase;
		data.fdwReasonParam = DLL_PROCESS_ATTACH;
		data.reservedParam = 0;
		data.SEHSupport = true;

		//File header
		if (!WriteProcessMemory(hHijackProc, pTargetBase, pSrcData, 0x1000, nullptr)) { //only first 0x1000 bytes for the header
			//printf("[YUME] -> ������ ����� ���������ϴ�. 0x%X\n", GetLastError());
			VirtualFreeEx(hHijackProc, pTargetBase, 0, MEM_RELEASE);
			return;
		}

		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->SizeOfRawData) {
				if (!WriteProcessMemory(hHijackProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
					//printf("[YUME] -> ������ �����Ҽ������ϴ�. 0x%x\n", GetLastError());
					VirtualFreeEx(hHijackProc, pTargetBase, 0, MEM_RELEASE);
					return;
				}
			}
		}

		//Mapping params
		BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hHijackProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!MappingDataAlloc) {
			//printf("[YUME] -> Ÿ�� ���μ��� ���� �Ҵ��� �����߽��ϴ�. 0x%X\n", GetLastError());
			VirtualFreeEx(hHijackProc, pTargetBase, 0, MEM_RELEASE);
			return;
		}
		if (!WriteProcessMemory(hHijackProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
			//printf("[YUME] -> ������ ���μ����� ���������ϴ�. 0x%X\n", GetLastError());
			VirtualFreeEx(hHijackProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hHijackProc, MappingDataAlloc, 0, MEM_RELEASE);
			return;
		}
		//Shell code
		void* pShellcode = VirtualAllocEx(hHijackProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pShellcode) {
			//printf("[YUME] -> �޸� ���ڵ� �Ҵ翡 �����߽��ϴ�. 0x%X\n", GetLastError());
			VirtualFreeEx(hHijackProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hHijackProc, MappingDataAlloc, 0, MEM_RELEASE);
			return;
		}
		if (!WriteProcessMemory(hHijackProc, pShellcode, Shellcode, 0x1000, nullptr)) {
			//printf("[YUME] -> ���ڵ带 ���µ� �����߽��ϴ�. 0x%X\n", GetLastError());
			VirtualFreeEx(hHijackProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hHijackProc, MappingDataAlloc, 0, MEM_RELEASE);
			VirtualFreeEx(hHijackProc, pShellcode, 0, MEM_RELEASE);
			return;
		}

		//printf("[YUME] -> DLL�� %p�� ���εǾ����ϴ�.\n", pTargetBase);
		//printf("[YUME] -> DLL���� ������ %p�� �Ҵ�Ǿ����ϴ�.\n", MappingDataAlloc);
		//printf("[YUME] -> ���ڵ尡 %p�� �Ҵ�Ǿ����ϴ�.\n", pShellcode);
		//printf("[YUME] -> �����Ͱ� ���� �Ҵ�Ǿ����ϴ�.\n");

		/* �������� �� */
		/* ������ ���� */

		// NtCreateThreadEx �ּ� �ҷ���
		pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
		if (NtCreateThreadEx == NULL) {
			CloseHandle(hHijackProc);
			//printf("[YUME] -> NtCreateThreadEx�� �ּҸ� �������µ� �����߽��ϴ�.\n");
			return;
		}
		
		HANDLE ThreadHandle = NULL;
		LPVOID LoadLibraryAddress = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
		if (LoadLibraryAddress = NULL) {
			CloseHandle(hHijackProc);
			//printf("[YUME] -> LoadLibraryA�� �ּҸ� �������µ� �����߽��ϴ�.\n");
			return;
		}
		NtCreateThreadEx(&ThreadHandle, 0x1FFFFF, NULL, hHijackProc, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, FALSE, NULL, NULL, NULL, NULL);
		if (ThreadHandle == NULL)
		{
			CloseHandle(hHijackProc);
			//printf("[YUME] -> ������ �ڵ���� �����Դϴ�.\n");
			return;
		}
		if (WaitForSingleObject(ThreadHandle, INFINITE) == WAIT_FAILED)
		{
			//printf("[YUME] -> WaitForSingleObject�� �����߽��ϴ�.\n");
			return;
		}
		CloseHandle(hHijackProc);
		CloseHandle(ThreadHandle);

		/* ���� �𸣰ٴ°� */
		HINSTANCE hCheck = NULL;
		while (!hCheck) {
			DWORD exitcode = 0;
			GetExitCodeProcess(hHijackProc, &exitcode);
			if (exitcode != STILL_ACTIVE) {
				//printf("[YUME] -> ���μ����� �ð���ϴ�. �����ڵ� : %d\n", exitcode);
				return;
			}

			MANUAL_MAPPING_DATA data_checked{ 0 };
			ReadProcessMemory(hHijackProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
			hCheck = data_checked.hMod;

			if (hCheck == (HINSTANCE)0x404040) {
				//printf("[YUME] -> ���� �����Ͱ� �߸��Ǿ����ϴ�.\n");
				VirtualFreeEx(hHijackProc, pTargetBase, 0, MEM_RELEASE);
				VirtualFreeEx(hHijackProc, MappingDataAlloc, 0, MEM_RELEASE);
				VirtualFreeEx(hHijackProc, pShellcode, 0, MEM_RELEASE);
				return;
			}
			else if (hCheck == (HINSTANCE)0x505050) {
				//printf("[YUME] -> ����ó���� �����Ͽ����ϴ�.\n");
			}

			Sleep(10);
		}

		/* PE Header ���� */
		BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
		if (emptyBuffer == nullptr) {
			//printf("[YUME] -> PE Header���Ÿ� ���� �޸� �Ҵ翡 �����Ͽ����ϴ�.\n");
			return;
		}
		memset(emptyBuffer, 0, 1024 * 1024 * 20);

		//CLEAR PE HEAD
		if (1) { // PE Header ����
			if (!WriteProcessMemory(hHijackProc, pTargetBase, emptyBuffer, 0x1000, nullptr)) {
				//printf("[YUME] -> PE Header���ſ� �����Ͽ����ϴ�.\n");
			}
		}
		//END CLEAR PE HEAD

		if (1) { // Clear Non Needed Sections
			pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
			for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
				if (pSectionHeader->Misc.VirtualSize) {
					if ((true ? 0 : strcmp((char*)pSectionHeader->Name, ".pdata") == 0) ||
						strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 ||
						strcmp((char*)pSectionHeader->Name, ".reloc") == 0) {
						//printf("[YUME] -> ���μ��� %s �����Ϸ�.\n", pSectionHeader->Name);
						if (!WriteProcessMemory(hHijackProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr)) {
							//printf("[YUME] -> ������ ������ ���߽��ϴ�. %s : 0x%x\n", pSectionHeader->Name, GetLastError());
						}
					}
				}
			}
		}

		if (1) { // AdjustProtections
			pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
			for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
				if (pSectionHeader->Misc.VirtualSize) {
					DWORD old = 0;
					DWORD newP = PAGE_READONLY;

					if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
						newP = PAGE_READWRITE;
					}
					else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
						newP = PAGE_EXECUTE_READ;
					}
					if (VirtualProtectEx(hHijackProc, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old)) {
						//printf("[YUME] -> ������ %s�� ���������ʾҽ��ϴ�. %lX\n", (char*)pSectionHeader->Name, newP);
					}
					else {
						//printf("[YUME] -> ������ %s�� ���������ʾҽ��ϴ�. %lX\n", (char*)pSectionHeader->Name, newP);
					}
				}
			}
			DWORD old = 0;
			VirtualProtectEx(hHijackProc, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
		}

		if (!WriteProcessMemory(hHijackProc, pShellcode, emptyBuffer, 0x1000, nullptr)) {
			//printf("[YUME] -> ���ڵ带 �������� ���߽��ϴ�.\n");
		}
		if (!VirtualFreeEx(hHijackProc, pShellcode, 0, MEM_RELEASE)) {
			//printf("[YUME] -> ���ڵ� �޸𸮸� ���������� ���߽��ϴ�.\n");
		}
		if (!VirtualFreeEx(hHijackProc, MappingDataAlloc, 0, MEM_RELEASE)) {
			//printf("[YUME] -> ���� ������ �޸𸮸� ���������� ���߽��ϴ�.\n");
		}

	}
}


#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
	if (!pData) {
		pData->hMod = (HINSTANCE)0x404040;
		return;
	}

	BYTE* pBase = pData->pbase;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
	auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	bool ExceptionSupportFailed = false;

#ifdef _WIN64

	if (pData->SEHSupport) {
		auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size) {
			if (!_RtlAddFunctionTable(
				reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
				excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
				ExceptionSupportFailed = true;
			}
		}
	}

#endif

	_DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

	if (ExceptionSupportFailed)
		pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
	else
		pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}
