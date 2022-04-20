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
		//printf("[YUME] -> Dll 파일이 경로에 없습니다.\n");
		//system("PAUSE");
		return;
	}
	std::ifstream File(path, std::ios::binary | std::ios::ate);
	if (File.fail()) {
		//printf("[YUME] -> 파일을 여는데 실패했습니다. -> %X\n", (DWORD)File.rdstate());
		File.close();
		//system("PAUSE");
		return;
	}
	auto FileSize = File.tellg();
	if (FileSize < 0x1000) {
		//printf("[YUME] -> 파일 사이즈가 맞지 않습니다.\n");
		File.close();
		//system("PAUSE");
		return;
	}
	BYTE* pSrcData = new BYTE[(UINT_PTR)FileSize];
	if (!pSrcData) {
		//printf("[YUME] -> Dll 파일을 할당하는데 실패했습니다.\n");
		File.close();
		//system("PAUSE");
		return;
	}
	File.seekg(0, std::ios::beg);
	File.read((char*)(pSrcData), FileSize);
	File.close();

	/* pSrcData / FileSize */
	//printf("[YUME] -> 핸들 하이재킹을 시작할게요\n");
	DWORD accessMask = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
	accessMask |= PROCESS_CREATE_THREAD; // NtCreateThread
	auto handles = FindProcessHandles(pid, accessMask);
	if (handles.empty()) {
		//printf("[YUME] -> 핸들이 없어요\n");
		return;
	}

	HANDLE hHijackProc = nullptr;
	//printf("[YUME] -> 하이재킹 완료 인젝트를 위한 루프 시작\n");
	for (const auto& i : handles)
	{
		hHijackProc = OpenProcess(accessMask | PROCESS_CREATE_THREAD, FALSE, i.OwnerPID);
		if (!hHijackProc) {
			CloseHandle(hHijackProc);
			//printf("[YUME] -> 오픈프로세스에 실패했습니다. %06X\n", i.OwnerPID);
			continue;
		}

		//printf("[YUME] -> 오픈프로세스에 성공했습니다. %06X\n", i.OwnerPID);
		if (!IsElevatedProcess(hHijackProc) || !IsNativeProcess(hHijackProc)) {
			//printf("[YUME] -> IsNativeProcess 또는 IsElevatedProcess가 되지않아 오류발생.\n");
			CloseHandle(hHijackProc);
			continue;
		}

		/* 수동 맵핑 시작합니다. */
		IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
		IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
		IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
		BYTE* pTargetBase = nullptr;

		if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) { //"MZ"
			//printf("[YUME] -> 유효하지않은 파일 PE헤더 깨짐\n");
			CloseHandle(hHijackProc);
			return;
		}

		pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
		pOldOptHeader = &pOldNtHeader->OptionalHeader;
		pOldFileHeader = &pOldNtHeader->FileHeader;

		if (pOldFileHeader->Machine != CURRENT_ARCH) {
			CloseHandle(hHijackProc);
			//printf("[YUME] -> 맞지않은 플랫폼입니다. x64 x86 확인해주세요.\n");
			return;
		}

		printf("파일 OK\n");
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hHijackProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!pTargetBase) {
			CloseHandle(hHijackProc);
			//printf("[YUME] -> 타겟에 프로세스 메모리 할당 실패 0x%X\n", GetLastError());
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
			//printf("[YUME] -> 파일의 헤더를 쓸수없습니다. 0x%X\n", GetLastError());
			VirtualFreeEx(hHijackProc, pTargetBase, 0, MEM_RELEASE);
			return;
		}

		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->SizeOfRawData) {
				if (!WriteProcessMemory(hHijackProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
					//printf("[YUME] -> 섹션을 맵핑할수없습니다. 0x%x\n", GetLastError());
					VirtualFreeEx(hHijackProc, pTargetBase, 0, MEM_RELEASE);
					return;
				}
			}
		}

		//Mapping params
		BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hHijackProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!MappingDataAlloc) {
			//printf("[YUME] -> 타겟 프로세스 맵핑 할당을 실패했습니다. 0x%X\n", GetLastError());
			VirtualFreeEx(hHijackProc, pTargetBase, 0, MEM_RELEASE);
			return;
		}
		if (!WriteProcessMemory(hHijackProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
			//printf("[YUME] -> 매핑을 프로세스에 쓸수없습니다. 0x%X\n", GetLastError());
			VirtualFreeEx(hHijackProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hHijackProc, MappingDataAlloc, 0, MEM_RELEASE);
			return;
		}
		//Shell code
		void* pShellcode = VirtualAllocEx(hHijackProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pShellcode) {
			//printf("[YUME] -> 메모리 쉘코드 할당에 실패했습니다. 0x%X\n", GetLastError());
			VirtualFreeEx(hHijackProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hHijackProc, MappingDataAlloc, 0, MEM_RELEASE);
			return;
		}
		if (!WriteProcessMemory(hHijackProc, pShellcode, Shellcode, 0x1000, nullptr)) {
			//printf("[YUME] -> 쉘코드를 쓰는데 실패했습니다. 0x%X\n", GetLastError());
			VirtualFreeEx(hHijackProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hHijackProc, MappingDataAlloc, 0, MEM_RELEASE);
			VirtualFreeEx(hHijackProc, pShellcode, 0, MEM_RELEASE);
			return;
		}

		//printf("[YUME] -> DLL이 %p에 맵핑되었습니다.\n", pTargetBase);
		//printf("[YUME] -> DLL맵핑 정보가 %p에 할당되었습니다.\n", MappingDataAlloc);
		//printf("[YUME] -> 쉘코드가 %p에 할당되었습니다.\n", pShellcode);
		//printf("[YUME] -> 데이터가 전부 할당되었습니다.\n");

		/* 수동맵핑 끝 */
		/* 인젝팅 시작 */

		// NtCreateThreadEx 주소 불러옴
		pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
		if (NtCreateThreadEx == NULL) {
			CloseHandle(hHijackProc);
			//printf("[YUME] -> NtCreateThreadEx의 주소를 가져오는데 실패했습니다.\n");
			return;
		}
		
		HANDLE ThreadHandle = NULL;
		LPVOID LoadLibraryAddress = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
		if (LoadLibraryAddress = NULL) {
			CloseHandle(hHijackProc);
			//printf("[YUME] -> LoadLibraryA의 주소를 가져오는데 실패했습니다.\n");
			return;
		}
		NtCreateThreadEx(&ThreadHandle, 0x1FFFFF, NULL, hHijackProc, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, FALSE, NULL, NULL, NULL, NULL);
		if (ThreadHandle == NULL)
		{
			CloseHandle(hHijackProc);
			//printf("[YUME] -> 쓰레드 핸들관련 오류입니다.\n");
			return;
		}
		if (WaitForSingleObject(ThreadHandle, INFINITE) == WAIT_FAILED)
		{
			//printf("[YUME] -> WaitForSingleObject에 실패했습니다.\n");
			return;
		}
		CloseHandle(hHijackProc);
		CloseHandle(ThreadHandle);

		/* 먼지 모르겟는거 */
		HINSTANCE hCheck = NULL;
		while (!hCheck) {
			DWORD exitcode = 0;
			GetExitCodeProcess(hHijackProc, &exitcode);
			if (exitcode != STILL_ACTIVE) {
				//printf("[YUME] -> 프로세스가 팅겼습니다. 에러코드 : %d\n", exitcode);
				return;
			}

			MANUAL_MAPPING_DATA data_checked{ 0 };
			ReadProcessMemory(hHijackProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
			hCheck = data_checked.hMod;

			if (hCheck == (HINSTANCE)0x404040) {
				//printf("[YUME] -> 맵핑 포인터가 잘못되었습니다.\n");
				VirtualFreeEx(hHijackProc, pTargetBase, 0, MEM_RELEASE);
				VirtualFreeEx(hHijackProc, MappingDataAlloc, 0, MEM_RELEASE);
				VirtualFreeEx(hHijackProc, pShellcode, 0, MEM_RELEASE);
				return;
			}
			else if (hCheck == (HINSTANCE)0x505050) {
				//printf("[YUME] -> 예외처리에 실패하였습니다.\n");
			}

			Sleep(10);
		}

		/* PE Header 제거 */
		BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
		if (emptyBuffer == nullptr) {
			//printf("[YUME] -> PE Header제거를 위한 메모리 할당에 실패하였습니다.\n");
			return;
		}
		memset(emptyBuffer, 0, 1024 * 1024 * 20);

		//CLEAR PE HEAD
		if (1) { // PE Header 제거
			if (!WriteProcessMemory(hHijackProc, pTargetBase, emptyBuffer, 0x1000, nullptr)) {
				//printf("[YUME] -> PE Header제거에 실패하였습니다.\n");
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
						//printf("[YUME] -> 프로세싱 %s 지우기완료.\n", pSectionHeader->Name);
						if (!WriteProcessMemory(hHijackProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr)) {
							//printf("[YUME] -> 섹션을 지우지 못했습니다. %s : 0x%x\n", pSectionHeader->Name, GetLastError());
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
						//printf("[YUME] -> 섹션이 %s에 설정되지않았습니다. %lX\n", (char*)pSectionHeader->Name, newP);
					}
					else {
						//printf("[YUME] -> 섹션이 %s에 설정되지않았습니다. %lX\n", (char*)pSectionHeader->Name, newP);
					}
				}
			}
			DWORD old = 0;
			VirtualProtectEx(hHijackProc, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
		}

		if (!WriteProcessMemory(hHijackProc, pShellcode, emptyBuffer, 0x1000, nullptr)) {
			//printf("[YUME] -> 쉘코드를 정리하지 못했습니다.\n");
		}
		if (!VirtualFreeEx(hHijackProc, pShellcode, 0, MEM_RELEASE)) {
			//printf("[YUME] -> 쉘코드 메모리를 릴리즈하지 못했습니다.\n");
		}
		if (!VirtualFreeEx(hHijackProc, MappingDataAlloc, 0, MEM_RELEASE)) {
			//printf("[YUME] -> 매핑 데이터 메모리를 릴리즈하지 못했습니다.\n");
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
