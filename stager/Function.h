#pragma once
#include <windows.h>

typedef FARPROC(WINAPI* FN_GetProcAddress)(_In_ HMODULE hModule,_In_ LPCSTR lpProcName);
typedef HMODULE(WINAPI* FN_LoadLibraryW)(_In_ LPCWSTR lpLibFileName);
typedef HMODULE(WINAPI* FN_LoadLibraryA)(_In_ LPCSTR lpLibFileName);
typedef BOOL(WINAPI* FM_VirtualProtect)(_In_  LPVOID lpAddress,_In_  SIZE_T dwSize,_In_  DWORD flNewProtect,_Out_ PDWORD lpflOldProtect);
typedef PVOID(WINAPI*FM_VirtualAlloc)( _In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize,_In_ DWORD flAllocationType, _In_ DWORD flProtect);

typedef LPVOID(_stdcall* Fn_InternetOpenA)(_In_opt_ LPCSTR lpszAgent,_In_ DWORD dwAccessType,_In_opt_ LPCSTR lpszProxy,_In_opt_ LPCSTR lpszProxyBypass,_In_ DWORD dwFlags);
typedef LPVOID(_stdcall* Fn_InternetConnectA)(_In_ LPVOID hInternet,_In_ LPCSTR lpszServerName,_In_ WORD nServerPort,_In_opt_ LPCSTR lpszUserName,_In_opt_ LPCSTR lpszPassword,_In_ DWORD dwService,_In_ DWORD dwFlags,_In_opt_ DWORD_PTR dwContext);
typedef LPVOID(_stdcall* Fn_HttpOpenRequestA)(_In_ LPVOID hConnect,_In_opt_ LPCSTR lpszVerb,_In_opt_ LPCSTR lpszObjectName,_In_opt_ LPCSTR lpszVersion,_In_opt_ LPCSTR lpszReferrer,_In_opt_z_ LPCSTR FAR* lplpszAcceptTypes,_In_ DWORD dwFlags,_In_opt_ DWORD_PTR dwContext);
typedef BOOL (_stdcall* Fn_HttpSendRequestW)(_In_ LPVOID hRequest,_In_reads_opt_(dwHeadersLength) LPCWSTR lpszHeaders,_In_ DWORD dwHeadersLength,_In_reads_bytes_opt_(dwOptionalLength) LPVOID lpOptional,_In_ DWORD dwOptionalLength);
typedef BOOL (_stdcall* Fn_InternetQueryOptionW)(_In_opt_ LPVOID hInternet,_In_ DWORD dwOption,_Out_writes_bytes_to_opt_(*lpdwBufferLength, *lpdwBufferLength) __out_data_source(NETWORK) LPVOID lpBuffer,_Inout_ LPDWORD lpdwBufferLength);
typedef BOOL (_stdcall* Fn_InternetSetOptionW)(_In_opt_ LPVOID hInternet,_In_ DWORD dwOption,_In_opt_ LPVOID lpBuffer,_In_ DWORD dwBufferLength);
typedef BOOL(_stdcall* Fn_HttpSendRequestW)(_In_ LPVOID hRequest,_In_reads_opt_(dwHeadersLength) LPCWSTR lpszHeaders,_In_ DWORD dwHeadersLength,_In_reads_bytes_opt_(dwOptionalLength) LPVOID lpOptional,_In_ DWORD dwOptionalLength);
typedef BOOL (_stdcall* Fn_InternetReadFile)(_In_ LPVOID hFile,_Out_writes_bytes_(dwNumberOfBytesToRead) __out_data_source(NETWORK) LPVOID lpBuffer,_In_ DWORD dwNumberOfBytesToRead,_Out_ LPDWORD lpdwNumberOfBytesRead);
typedef BOOL (_stdcall* Fn_InternetCloseHandle)(_In_ LPVOID hInternet);