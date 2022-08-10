#include "Function.h"

//FARPROC getProcAddress(HMODULE hModuleBase)
//{
//    PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)hModuleBase;
//    PIMAGE_NT_HEADERS64 lpNtHeader = (PIMAGE_NT_HEADERS64)((ULONG64)hModuleBase + lpDosHeader->e_lfanew);
//    if (!lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
//        return NULL;
//    }
//    if (!lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
//        return NULL;
//    }
//    PIMAGE_EXPORT_DIRECTORY lpExports = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)hModuleBase + (ULONG64)lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
//    PDWORD lpdwFunName = (PDWORD)((ULONG64)hModuleBase + (ULONG64)lpExports->AddressOfNames);
//    PWORD lpword = (PWORD)((ULONG64)hModuleBase + (ULONG64)lpExports->AddressOfNameOrdinals);
//    PDWORD  lpdwFunAddr = (PDWORD)((ULONG64)hModuleBase + (ULONG64)lpExports->AddressOfFunctions);
//
//    DWORD dwLoop = 0;
//    FARPROC pRet = NULL;
//    for (; dwLoop <= lpExports->NumberOfNames - 1; dwLoop++) {
//        char* pFunName = (char*)(lpdwFunName[dwLoop] + (ULONG64)hModuleBase);
//
//        if (pFunName[0] == 'G' &&
//            pFunName[1] == 'e' &&
//            pFunName[2] == 't' &&
//            pFunName[3] == 'P' &&
//            pFunName[4] == 'r' &&
//            pFunName[5] == 'o' &&
//            pFunName[6] == 'c' &&
//            pFunName[7] == 'A' &&
//            pFunName[8] == 'd' &&
//            pFunName[9] == 'd' &&
//            pFunName[10] == 'r' &&
//            pFunName[11] == 'e' &&
//            pFunName[12] == 's' &&
//            pFunName[13] == 's')
//        {
//            pRet = (FARPROC)(lpdwFunAddr[lpword[dwLoop]] + (ULONG64)hModuleBase);
//            break;
//        }
//    }
//    return pRet;
//}
