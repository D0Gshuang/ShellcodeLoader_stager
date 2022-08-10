#pragma once
//#include "struct.h"
#include "Function.h"


class Init
{

public:
	static Init* myInit;

	FN_GetProcAddress fn_GetProcAddress;
	FN_LoadLibraryW fn_LoadLibraryW;
	FN_LoadLibraryA fn_LoadLibraryA;
	FM_VirtualAlloc fn_VirtualAlloc;
	FM_VirtualProtect fn_VirtualProtect;

	Fn_InternetOpenA fn_InternetOpenA;
	Fn_InternetConnectA fn_InternetConnectA;
	Fn_HttpOpenRequestA fn_HttpOpenRequestA;
	Fn_HttpSendRequestW fn_HttpSendRequestW;
	Fn_InternetQueryOptionW fn_InternetQueryOptionW;
	Fn_InternetSetOptionW fn_InternetSetOptionW;
	Fn_InternetReadFile fn_InternetReadFile;
	Fn_InternetCloseHandle fn_InternetCloseHandle;

public:
	static Init* GetInstance();
	void FindFuncionAddr();

private:

};

