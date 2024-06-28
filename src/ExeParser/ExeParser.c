#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <math.h>

#define SET_COLOR(color) SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color)
#define RESET_COLOR() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7)

BOOL ReadPeFile(LPCSTR lpFileName, PBYTE* pPe, SIZE_T* sPe);
VOID ParsePe(PBYTE pPE, FILE* outFile);
VOID banner();
double CalculateEntropy(PBYTE data, SIZE_T size);
BOOL IsPacked(PBYTE pPE, SIZE_T sPE);

void banner() {
    SET_COLOR(10);
    printf(
        "\n\t\tREM    ___  ____    ____________   _  ___  __________ \n"
        "\t\tREM   / _ \\/ __/___/ __/ ___/ _ | / |/ / |/ / __/ _ \\ \n"
        "\t\tREM  / ___/ _//___/\\ \\/ /__/ __ |/    /    / _// , _/ \t [ by k3rnel-dev ]\n"
        "\t\tREM /_/  /___/   /___/\\___/_/ |_|/_/|_/_/|_/___/_/|_| \t [ https://github.com/k3rnel-dev ]\n"
    );

    RESET_COLOR();
}

BOOL ReadPeFile(LPCSTR lpFileName, PBYTE* pPe, SIZE_T* sPe) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PBYTE pBuff = NULL;
    DWORD dwFileSize = 0, dwNumberOfBytesRead = 0;

    SET_COLOR(11);
    printf("[i] Reading \"%s\"... ", lpFileName);

    hFile = CreateFileA(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        SET_COLOR(12);
        printf("[!] CreateFileA failed with error: %d\n", GetLastError());
        RESET_COLOR();
        goto _EndOfFunction;
    }

    dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == 0) {
        SET_COLOR(12);
        printf("[!] GetFileSize failed with error: %d\n", GetLastError());
        RESET_COLOR();
        goto _EndOfFunction;
    }

    pBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
    if (pBuff == NULL) {
        SET_COLOR(12);
        printf("[!] HeapAlloc failed with error: %d\n", GetLastError());
        RESET_COLOR();
        goto _EndOfFunction;
    }

    if (!ReadFile(hFile, pBuff, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
        SET_COLOR(12);
        printf("[!] ReadFile failed with error: %d\n", GetLastError());
        printf("[!] Bytes read: %d of %d\n", dwNumberOfBytesRead, dwFileSize);
        RESET_COLOR();
        goto _EndOfFunction;
    }

    SET_COLOR(10);
    printf("[+] DONE\n");
    RESET_COLOR();

_EndOfFunction:
    *pPe = pBuff;
    *sPe = dwFileSize;
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
    if (*pPe == NULL || *sPe == 0) {
        return FALSE;
    }
    return TRUE;
}

double CalculateEntropy(PBYTE data, SIZE_T size) {
    if (size == 0) return 0.0;

    int frequency[256] = { 0 };
    for (SIZE_T i = 0; i < size; ++i) {
        frequency[data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (frequency[i] > 0) {
            double p = (double)frequency[i] / size;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

BOOL IsPacked(PBYTE pPE, SIZE_T sPE) {
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPE + pImgDosHdr->e_lfanew);
    PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdrs) + sizeof(IMAGE_NT_HEADERS));

    for (size_t i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
        double entropy = CalculateEntropy(pPE + pImgSectionHdr->PointerToRawData, pImgSectionHdr->SizeOfRawData);
        if (entropy > 7.0) {
            return TRUE; // High entropy suggests the file is packed
        }
        pImgSectionHdr++;
    }
    return FALSE;
}


void ParsePe(PBYTE pPE, SIZE_T sPE, FILE* outFile) {
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        SET_COLOR(12);
        printf("[!] Invalid DOS signature\n");
        if (outFile) fprintf(outFile, "[!] Invalid DOS signature\n");
        RESET_COLOR();
        return;
    }

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPE + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        SET_COLOR(12);
        printf("[!] Invalid NT signature\n");
        if (outFile) fprintf(outFile, "[!] Invalid NT signature\n");
        RESET_COLOR();
        return;
    }

    SET_COLOR(14);
    printf("\n#####################[ FILE HEADER ]#####################\n\n");
    if (outFile) fprintf(outFile, "\n#####################[ FILE HEADER ]#####################\n\n");
    RESET_COLOR();

    IMAGE_FILE_HEADER ImgFileHdr = pImgNtHdrs->FileHeader;

    if (ImgFileHdr.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
        SET_COLOR(11);
        printf("[i] Executable file detected as: ");
        if (outFile) fprintf(outFile, "[i] Executable file detected as: ");
        if (ImgFileHdr.Characteristics & IMAGE_FILE_DLL) {
            printf("DLL\n");
            if (outFile) fprintf(outFile, "DLL\n");
        }
        else if (ImgFileHdr.Characteristics & IMAGE_SUBSYSTEM_NATIVE) {
            printf("SYS\n");
            if (outFile) fprintf(outFile, "SYS\n");
        }
        else {
            printf("EXE\n");
            if (outFile) fprintf(outFile, "EXE\n");
        }
    }

    SET_COLOR(11);
    printf("[i] File architecture: %s\n", ImgFileHdr.Machine == IMAGE_FILE_MACHINE_I386 ? "x32" : "x64");
    if (outFile) fprintf(outFile, "[i] File architecture: %s\n", ImgFileHdr.Machine == IMAGE_FILE_MACHINE_I386 ? "x32" : "x64");
    printf("[i] Number of sections: %d\n", ImgFileHdr.NumberOfSections);
    if (outFile) fprintf(outFile, "[i] Number of sections: %d\n", ImgFileHdr.NumberOfSections);
    printf("[i] Size of the optional header: %d bytes\n", ImgFileHdr.SizeOfOptionalHeader);
    if (outFile) fprintf(outFile, "[i] Size of the optional header: %d bytes\n", ImgFileHdr.SizeOfOptionalHeader);
    RESET_COLOR();

    SET_COLOR(14);
    printf("\n#####################[ OPTIONAL HEADER ]#####################\n\n");
    if (outFile) fprintf(outFile, "\n#####################[ OPTIONAL HEADER ]#####################\n\n");
    RESET_COLOR();

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    SET_COLOR(11);
    printf("[i] Linker version: %d.%d\n", ImgOptHdr.MajorLinkerVersion, ImgOptHdr.MinorLinkerVersion);
    if (outFile) fprintf(outFile, "[i] Linker version: %d.%d\n", ImgOptHdr.MajorLinkerVersion, ImgOptHdr.MinorLinkerVersion);
    printf("[i] Image size: %d bytes\n", ImgOptHdr.SizeOfImage);
    if (outFile) fprintf(outFile, "[i] Image size: %d bytes\n", ImgOptHdr.SizeOfImage);
    printf("[i] Headers size: %d bytes\n", ImgOptHdr.SizeOfHeaders);
    if (outFile) fprintf(outFile, "[i] Headers size: %d bytes\n", ImgOptHdr.SizeOfHeaders);
    printf("[i] Entry point: 0x%0.8X\n", ImgOptHdr.AddressOfEntryPoint);
    if (outFile) fprintf(outFile, "[i] Entry point: 0x%0.8X\n", ImgOptHdr.AddressOfEntryPoint);
    printf("[i] Operating System version: %d.%d\n", ImgOptHdr.MajorOperatingSystemVersion, ImgOptHdr.MinorOperatingSystemVersion);
    if (outFile) fprintf(outFile, "[i] Operating System version: %d.%d\n", ImgOptHdr.MajorOperatingSystemVersion, ImgOptHdr.MinorOperatingSystemVersion);
    printf("[i] Subsystem: %d\n", ImgOptHdr.Subsystem);
    if (outFile) fprintf(outFile, "[i] Subsystem: %d\n", ImgOptHdr.Subsystem);
    RESET_COLOR();

    SET_COLOR(14);
    printf("\n#####################[ DATA DIRECTORIES ]#####################\n\n");
    if (outFile) fprintf(outFile, "\n#####################[ DATA DIRECTORIES ]#####################\n\n");
    SET_COLOR(10);

    printf("[*] Export Table at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (outFile) fprintf(outFile, "[*] Export Table at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    printf("[*] Import Table at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (outFile) fprintf(outFile, "[*] Import Table at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    printf("[*] Resource Table at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
    if (outFile) fprintf(outFile, "[*] Resource Table at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
    printf("[*] Exception Table at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
    if (outFile) fprintf(outFile, "[*] Exception Table at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
    printf("[*] Certificate Table at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress);
    if (outFile) fprintf(outFile, "[*] Certificate Table at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress);
    printf("[*] Base Relocation Table at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    if (outFile) fprintf(outFile, "[*] Base Relocation Table at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    printf("[*] Debug Directory at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
    if (outFile) fprintf(outFile, "[*] Debug Directory at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
    printf("[*] TLS Directory at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    if (outFile) fprintf(outFile, "[*] TLS Directory at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    printf("[*] Import Address Table at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
    if (outFile) fprintf(outFile, "[*] Import Address Table at 0x%p, size: %d\n\t\t[RVA: 0x%0.8X]\n",
        (PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress),
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size,
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);

    SET_COLOR(14);
    printf("\n#####################[ SECTION HEADER ]#####################\n\n");
    if (outFile) fprintf(outFile, "\n#####################[ SECTION HEADER ]#####################\n\n");
    RESET_COLOR();

    PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdrs) + sizeof(IMAGE_NT_HEADERS));
    for (size_t i = 0; i < ImgFileHdr.NumberOfSections; i++) {
        SET_COLOR(11);
        printf("[i] Section name: %s\n", pImgSectionHdr->Name);
        if (outFile) fprintf(outFile, "[i] Section name: %s\n", pImgSectionHdr->Name);
        printf("[i] Section raw size: %d bytes\n", pImgSectionHdr->SizeOfRawData);
        if (outFile) fprintf(outFile, "[i] Section raw size: %d bytes\n", pImgSectionHdr->SizeOfRawData);
        printf("[i] Section virtual size: %d bytes\n", pImgSectionHdr->Misc.VirtualSize);
        if (outFile) fprintf(outFile, "[i] Section virtual size: %d bytes\n", pImgSectionHdr->Misc.VirtualSize);
        printf("[i] Section entropy: %f\n", CalculateEntropy(pPE + pImgSectionHdr->PointerToRawData, pImgSectionHdr->SizeOfRawData));
        if (outFile) fprintf(outFile, "[i] Section entropy: %f\n", CalculateEntropy(pPE + pImgSectionHdr->PointerToRawData, pImgSectionHdr->SizeOfRawData));
        RESET_COLOR();
        pImgSectionHdr++;
    }
    if (IsPacked(pPE, sPE)) {
        SET_COLOR(12);
        printf("[!] The file appears to be packed!\n");
        if (outFile) fprintf(outFile, "[!] The file appears to be packed!\n");
        RESET_COLOR();
    }
    else {
        SET_COLOR(10);
        printf("[+] The file does not appear to be packed.\n");
        if (outFile) fprintf(outFile, "[+] The file does not appear to be packed.\n");
        RESET_COLOR();
    }

}

int main(int argc, char* argv[]) {
    banner();
    if (argc < 2) {
        SET_COLOR(12);
        printf("\nUsage: %s <path_to_pe_file> [-w output_file.txt]\n", argv[0]);
        RESET_COLOR();
        return 1;
    }

    PBYTE pPe = NULL;
    SIZE_T sPe = 0;
    FILE* outFile = NULL;

    if (argc == 4 && strcmp(argv[2], "-w") == 0) {
        outFile = fopen(argv[3], "w");
        if (!outFile) {
            printf("Could not open output file: %s\n", argv[3]);
            return 1;
        }
    }

    if (ReadPeFile(argv[1], &pPe, &sPe)) {
        ParsePe(pPe, sPe, outFile);
        HeapFree(GetProcessHeap(), 0, pPe);
    }

    if (outFile) {
        fclose(outFile);
    }

    SET_COLOR(10);
    printf("> [0x0] Press < Enter > to exit ...");
    getchar();

    return 0;
}
