#include "EasyHook.hpp"
#include<sstream>
#include<fstream>
#include <Windows.h>
#include <TlHelp32.h>

#pragma comment(lib, "ntdll.lib")

EXTERN_C NTSTATUS NTAPI ZwWriteVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToRead,
	PULONG NumberOfBytesReaded
);

HOOKINIT(
	WriteProcessMemory_F,								// the type created 
	WriteProcessMemory,								// the function prototyped
	WriteProcessMemory_Tramp,							// the trampoline to the original function
	WriteProcessMemory_Prologue						// the prologue object of the function used for this hook
)
HOOKINIT(
	NtWriteVirtualMemory_F,								// the type created 
	ZwWriteVirtualMemory,								// the function prototyped
	_NtWriteVirtualMemory_Tramp,							// the trampoline to the original function
	_NtWriteVirtualMemory_Prologue						// the prologue object of the function used for this hook
)
HOOKINIT(
	VirtualAllocEx_F,								// the type created 
	VirtualAllocEx,								// the function prototyped
	VirtualAllocEx_Trump,							// the trampoline to the original function
	VirtualAllocEx_Prologue						// the prologue object of the function used for this hook
)
HOOKINIT(
	VirtualAlloc_F,								// the type created 
	VirtualAlloc,								// the function prototyped
	VirtualAlloc_Trump,							// the trampoline to the original function
	VirtualAlloc_Prologue						// the prologue object of the function used for this hook
)
HOOKINIT(
	LoadLibraryA_F,								// the type created 
	LoadLibraryA,								// the function prototyped
	LoadLibraryA_Trump,							// the trampoline to the original function
	LoadLibraryA_Prologue						// the prologue object of the function used for this hook
)


EasyHook::Hook32 hooker;						// an object meant to service you

std::string uniqueName() {
	auto randchar = []() -> char
	{
		const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(4, 0);
	std::generate_n(str.begin(), 4, randchar);
	return str;
}

int WINAPI LoadLibraryA_H(LPCSTR lpLibFileName) {
	exit(0);
}



int WINAPI WriteProcessMemory_H(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {

	if (WriteProcessMemory_Tramp)						// call the original function with the altered parameters if it exists.
		return WriteProcessMemory_Tramp(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
};

SIZE_T ImageSize = 0;
PVOID ImageBase = 0;

int NTAPI NtWriteVirtualMemory_H(HANDLE pHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumOfBytesToWrite, PULONG) {

	std::string log = "C:\\Users\\Thomas\\Desktop\\dick\\Log.txt";
	std::ofstream myfile;
	myfile.open(log, std::ios_base::app);
	myfile << "[*] NtWriteVirtualMemory from [0x" << Buffer << "]" << " >> [0x" << BaseAddress << "] : " << NumOfBytesToWrite << std::endl;
	myfile.close();
	if (_NtWriteVirtualMemory_Tramp)						// call the original function with the altered parameters if it exists.
		return _NtWriteVirtualMemory_Tramp(pHandle, BaseAddress, Buffer, NumOfBytesToWrite, nullptr);
};


LPVOID WINAPI VirtualAllocEx_H(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {

	if (dwSize == 8) { //Hook Alloc loader memory and dump stuff

		/*PVOID FileBuffer = VirtualAlloc(nullptr, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		ReadProcessMemory(hProcess, ImageBase, FileBuffer, ImageSize, __nullptr);*/
		//std::string Dll = "C:\\Users\\Thomas\\Desktop\\dick\\Image.dll";
		//HANDLE hFile = CreateFile(Dll.c_str(), GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		//WriteFile(hFile, Buffer, ImageSize, nullptr, nullptr);
		MessageBoxA(NULL, "Attach and get DLL", "Gibbone", NULL);
		exit(0);
	}

	if (VirtualAllocEx_Trump) {
		LPVOID base = VirtualAllocEx_Trump(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
		if (ImageSize < dwSize) { //GetchImage
			ImageSize = dwSize;
			//ImageBase = base;
		} 
		std::string log = "C:\\Users\\Thomas\\Desktop\\dick\\Log.txt";
		std::ofstream myfile;
		myfile.open(log, std::ios_base::app);
		myfile << "[*] VirtualAllocEx at [0x" << base << "]" << " : " << dwSize << std::endl;
		myfile.close();
		return base;
	}
}

LPVOID WINAPI VirtualAlloc_H(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {

	if (VirtualAlloc_Trump) {
		LPVOID base = VirtualAlloc_Trump(lpAddress, dwSize, flAllocationType, flProtect);
		std::string log = "C:\\Users\\Thomas\\Desktop\\dick\\Log.txt";
		std::ofstream myfile;
		myfile.open(log, std::ios_base::app);
		myfile << "[*] VirtualAlloc at [0x" << base << "]" << " : " << dwSize << std::endl;
		myfile.close();
		return base;
	}
}

void Hook() {

	FARPROC WriteProcessMemory = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteProcessMemory");
	FARPROC mNtWriteVirtualMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	FARPROC LoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	FARPROC VirtualAllocEx = GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAllocEx");
	FARPROC VirtualAlloc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
	WriteProcessMemory_Tramp = (WriteProcessMemory_F)hooker.hook(WriteProcessMemory, WriteProcessMemory_Prologue, WriteProcessMemory_H);
	_NtWriteVirtualMemory_Tramp = (NtWriteVirtualMemory_F)hooker.hook(mNtWriteVirtualMemory, _NtWriteVirtualMemory_Prologue, NtWriteVirtualMemory_H);
	//LoadLibraryA_Trump = (LoadLibraryA_F)hooker.hook(LoadLibraryA, LoadLibraryA_Prologue, NtWriteVirtualMemory_H);
	VirtualAllocEx_Trump = (VirtualAllocEx_F)hooker.hook(VirtualAllocEx, VirtualAllocEx_Prologue, VirtualAllocEx_H);
	VirtualAlloc_Trump = (VirtualAlloc_F)hooker.hook(VirtualAlloc, VirtualAlloc_Prologue, VirtualAlloc_H);
	MessageBoxA(NULL, "Hook is active", "Gibbone", NULL);
	return;
}



BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		Hook();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

