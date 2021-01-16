#include "EasyHook.hpp"

HOOKINIT(
	WriteProcessMemory_F,								// the type created 
	WriteProcessMemory,								// the function prototyped
	WriteProcessMemory_Tramp,							// the trampoline to the original function
	WriteProcessMemory_Prologue						// the prologue object of the function used for this hook
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


int WINAPI WriteProcessMemory_H(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T* lpNumberOfBytesWritten) {
	std::string Dll = "C:\\Users\\Thomas\\Desktop\\dick\\" + uniqueName() +".mem";
	//HANDLE hFile = CreateFile(Dll.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, nullptr); // Open the DLL
	HANDLE hFile = CreateFile(Dll.c_str(), GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile, lpBuffer, nSize, lpNumberOfBytesWritten, nullptr);
	CloseHandle(hFile);
	if (WriteProcessMemory_Tramp)						// call the original function with the altered parameters if it exists.
		return WriteProcessMemory_Tramp(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
};



void Hook() {

	FARPROC func = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteProcessMemory");
	WriteProcessMemory_Tramp = (WriteProcessMemory_F)hooker.hook(func, WriteProcessMemory_Prologue, WriteProcessMemory_H);
	MessageBoxA(NULL, "Hook is active", "1", NULL);
	return;
}



BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		Hook();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

