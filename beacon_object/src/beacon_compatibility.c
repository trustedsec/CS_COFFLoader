/*
 * Cobalt Strike 4.X BOF compatibility layer
 * -----------------------------------------
 * The whole point of these files are to allow beacon object files built for CS
 * to run fine inside of other tools without recompiling.
 * 
 * Built off of the beacon.h file provided to build for CS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#ifdef _WIN32
#include <windows.h>

#include "beacon_compatibility.h"

#define DEFAULTPROCESSNAME "rundll32.exe"
#ifdef _WIN64
#define X86PATH "SysWOW64"
#define X64PATH "System32"
#else
#define X86PATH "System32"
#define X64PATH "sysnative"
#endif

//MSVCRT
WINBASEAPI char *__cdecl MSVCRT$_ultoa(unsigned long _Value,char *_Dest,int _Radix);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);
WINBASEAPI int __cdecl MSVCRT$memcmp(const void *_Buf1,const void *_Buf2,size_t _Size);
WINBASEAPI void *__cdecl MSVCRT$realloc(void *_Memory, size_t _NewSize);
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char * __restrict__ d,size_t n,const char * __restrict__ format,va_list arg);
WINBASEAPI int __cdecl MSVCRT$vprintf(const char * __restrict__ format,va_list arg);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
//KERNEL32
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
WINBASEAPI WINBOOL WINAPI KERNEL32$CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandle, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation );
//ADVAPI32
WINBASEAPI WINBOOL WINAPI ADVAPI32$SetThreadToken(PHANDLE Thread, HANDLE Token);
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI WINBOOL WINAPI ADVAPI32$RevertToSelf();

int main()
{
return 0;
}
/* Data Parsing */

/*
beacon_function_t BeaconInternalMapping[BEACONINTERNALMAPPINGCOUNT] = {
    {0xe2494ba2, (void*)BeaconDataParse},
    {0xaf1afdd2, (void*)BeaconDataInt},
    {0xe2835ef7, (void*)BeaconDataShort},
    {0x22641d29, (void*)BeaconDataLength},
    {0x80d46722, (void*)BeaconDataExtract},
    {0x4caae0e1, (void*)BeaconFormatAlloc},
    {0x4ddac759, (void*)BeaconFormatReset},
    {0x7e749f38, (void*)BeaconFormatFree},
    {0xe25167ce, (void*)BeaconFormatAppend},
    {0x56f4aa9, (void*)BeaconFormatPrintf},
    {0xb59f4df0, (void*)BeaconFormatToString},
    {0x3a229cc1, (void*)BeaconFormatInt},
    {0x700d8660, (void*)BeaconPrintf},
    {0x6df4b81e, (void*)BeaconOutput},
    {0x889e48bb, (void*)BeaconUseToken},
    {0xf2744ba6, (void*)BeaconRevertToken},
    {0x566264d2, (void*)BeaconIsAdmin},
    {0x1e7c9fb9, (void*)BeaconGetSpawnTo},
    {0xd6c57438, (void*)BeaconSpawnTemporaryProcess},
    {0xea75b09, (void*)BeaconInjectProcess},
    {0x9e22498c, (void*)BeaconInjectTemporaryProcess},
    {0xcee62b74, (void*)BeaconCleanupProcess},
    {0x59fcf3cf, (void*)toWideChar},
    {0x30eece3c, (void*)KERNEL32$FreeLibrary},
    {0x5fbff0fb, (void*)KERNEL32$LoadLibraryA},
    {0x504e3837, (void*)KERNEL32$GetModuleHandle},
    {0x5a153f58, (void*)KERNEL32$GetModuleHandleA},
    {0xcf31bb1f, (void*)KERNEL32$GetProcAddress},
    {0xe60e6ae5, (void*)-1}         //This is supposed to be the __C_specific_handler from kernel32.dll, for now we aren't supporting exception handling, so setting to -1.
};
*/

uint32_t hash_djb(char* string){
   int c;
   uint32_t hash = 5381;

   while((c = *string++)){
      hash = ((hash << 5) + hash) + c; // hash * 33 + c
   }
   return hash;
}


uint32_t swap_endianess(uint32_t indata){
    uint32_t testint = 0xaabbccdd;
    uint32_t outint = indata;
    if (((unsigned char*)&testint)[0] == 0xdd){
        ((unsigned char*)&outint)[0] = ((unsigned char*)&indata)[3];
        ((unsigned char*)&outint)[1] = ((unsigned char*)&indata)[2];
        ((unsigned char*)&outint)[2] = ((unsigned char*)&indata)[1];
        ((unsigned char*)&outint)[3] = ((unsigned char*)&indata)[0];
    }
    return outint;
}

char* beacon_compatibility_output = NULL;
int beacon_compatibility_size = 0;
int beacon_compatibility_offset = 0;

void BeaconDataParse(datap* parser, char* buffer, int size){
    if (parser == NULL){
        return;
    }
    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size-4;
    parser->size = size-4;
    parser->buffer += 4;
    return;
}

int BeaconDataInt(datap* parser){
    int32_t fourbyteint = 0;
    if (parser->length < 4){
        return 0;
    }
    MSVCRT$memcpy(&fourbyteint, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return (int)fourbyteint;
}

short BeaconDataShort(datap* parser){
    int16_t retvalue = 0;
    if (parser->length < 2){
        return 0;
    }
    MSVCRT$memcpy(&retvalue, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return (short)retvalue;
}

int BeaconDataLength(datap* parser){
    return parser->length;
}

char* BeaconDataExtract(datap* parser, int* size){
    uint32_t length = 0;
    char* outdata = NULL;
    /*Length prefixed binary blob, going to assume uint32_t for this.*/
    if (parser->length < 4){
        return NULL;
    }
    MSVCRT$memcpy(&length, parser->buffer, 4);
    parser->buffer += 4;
    
    outdata = parser->buffer;
    if (outdata == NULL){
        return NULL;
    }
    parser->length -=4;
    parser->length -= length;
    parser->buffer += length;
    if (size != NULL && outdata != NULL){
        *size = length;
    }
    return outdata;
}

/* format API */

void BeaconFormatAlloc(formatp* format, int maxsz){
    if (format == NULL){
        return;
    }
    format->original = MSVCRT$calloc(maxsz, 1);
    format->buffer = format->original;
    format->length = 0;
    format->size = maxsz;
    return;
}

void BeaconFormatReset(formatp* format){
    MSVCRT$memset(format->original, 0, format->size);
    format->buffer = format->original;
    format->length = format->size;
    return;
}

void BeaconFormatFree(formatp* format){
    if (format == NULL){
        return;
    }
    if (format->original){
        MSVCRT$free(format->original);
        format->original = NULL;
    }
    format->buffer = NULL;
    format->length = 0;
    format->size = 0;
    return;
}

void BeaconFormatAppend(formatp* format, char* text, int len){
    MSVCRT$memcpy(format->buffer, text, len);
    format->buffer+= len;
    format->length+= len;
    return;
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...){
    /*Take format string, and sprintf it into here*/
    va_list args;
    int length = 0;

    va_start (args, fmt);
    length = MSVCRT$vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (format->length + length > format->size){
        return;
    }

    va_start (args, fmt);
    (void)MSVCRT$vsnprintf(format->buffer, length, fmt, args);
    va_end(args);
    format->length += length;
    format->buffer+= length;
    return;
}


char* BeaconFormatToString(formatp* format, int* size){
    *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp* format, int value){
    uint32_t indata = value;
    uint32_t outdata = 0;
    if (format->length + 4 > format->size){
        return;
    }
    outdata = swap_endianess(indata);
    MSVCRT$memcpy(format->buffer, &outdata, 4);
    format->length += 4;
    format->buffer += 4;
    return;
}
/* Main output functions */

void BeaconPrintf(int type, char* fmt, ...){
    /* Change to maintain internal buffer, and return after done running. */
    int length = 0;
    char* tempptr = NULL;
    va_list args;
    va_start (args, fmt);
    MSVCRT$vprintf(fmt, args);
    va_end(args);

    va_start (args, fmt);
    length = MSVCRT$vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    tempptr = MSVCRT$realloc(beacon_compatibility_output, beacon_compatibility_size+length+1);
    if (tempptr == NULL){
        return;
    }
    beacon_compatibility_output = tempptr;
    MSVCRT$memset(beacon_compatibility_output+beacon_compatibility_offset, 0, length+1);
    va_start (args, fmt);
    length = MSVCRT$vsnprintf(beacon_compatibility_output+beacon_compatibility_offset, length+1, fmt, args);
    beacon_compatibility_size+=length;
    beacon_compatibility_offset+=length;
    va_end(args);
    return;
}

void BeaconOutput(int type, char* data, int len){
    char* tempptr = NULL;
    tempptr = MSVCRT$realloc(beacon_compatibility_output, beacon_compatibility_size+len+1);
    beacon_compatibility_output = tempptr;
    if (tempptr == NULL){
        return;
    }
    MSVCRT$memset(beacon_compatibility_output+beacon_compatibility_offset, 0, len+1);
    MSVCRT$memcpy(beacon_compatibility_output+beacon_compatibility_offset, data, len);
    beacon_compatibility_size+=len;
    beacon_compatibility_offset+=len;
    return;
}

/* Token Functions */

BOOL BeaconUseToken(HANDLE token){
    /* Probably needs to handle DuplicateTokenEx too */
    ADVAPI32$SetThreadToken(NULL, token);
    return TRUE;
}

void BeaconRevertToken(void){
    if (!ADVAPI32$RevertToSelf()){
        #ifdef DEBUG
        printf("RevertToSelf Failed!\n");
        #endif
    }
    return;
}

BOOL BeaconIsAdmin(void){
    /* Leaving this to be implemented by people needing it */
    #ifdef DEBUG
    printf("BeaconIsAdmin Called\n");
    #endif
    return FALSE;
}

/* Injection/spawning related stuffs
 * 
 * These functions are basic place holders, and if implemented into something
 * real should be just calling internal functions for your tools. */
void BeaconGetSpawnTo(BOOL x86, char* buffer, int length){
    char* tempBufferPath = NULL;
    if (buffer == NULL){
        return;
    }
    if (x86){
        tempBufferPath = "C:\\Windows\\"X86PATH"\\"DEFAULTPROCESSNAME;
        if (MSVCRT$strlen(tempBufferPath) > length){
            return;
        }
        MSVCRT$memcpy(buffer, tempBufferPath, MSVCRT$strlen(tempBufferPath));
    }
    else{
        tempBufferPath = "C:\\Windows\\"X64PATH"\\"DEFAULTPROCESSNAME;
        if (MSVCRT$strlen(tempBufferPath) > length){
            return;
        }
        MSVCRT$memcpy(buffer, tempBufferPath, MSVCRT$strlen(tempBufferPath));
       
    }
    return;
}

BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * sInfo, PROCESS_INFORMATION * pInfo){
    BOOL bSuccess = FALSE;
    if (x86){
        bSuccess = KERNEL32$CreateProcessA(NULL, (char*)"C:\\Windows\\"X86PATH"\\"DEFAULTPROCESSNAME, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
    }
    else{
        bSuccess = KERNEL32$CreateProcessA(NULL, (char*)"C:\\Windows\\"X64PATH"\\"DEFAULTPROCESSNAME, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
    }
    return bSuccess;
}

void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char * arg, int a_len){
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len){
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo){
    (void)KERNEL32$CloseHandle(pInfo->hThread);
    (void)KERNEL32$CloseHandle(pInfo->hProcess);
    return;
}

BOOL toWideChar(char* src, wchar_t* dst, int max){
    /* Leaving this to be implemented by people needing/wanting it */
    return FALSE;
}

char* BeaconGetOutputData(int *outsize){
    char* outdata = beacon_compatibility_output;
    *outsize = beacon_compatibility_size;
    beacon_compatibility_output = NULL;
    beacon_compatibility_size = 0;
    beacon_compatibility_offset = 0;
    return outdata;
}

#endif
