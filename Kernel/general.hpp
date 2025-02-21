#pragma once
#include "utils.hpp"
namespace general
{
    void DumpDriver(char* driver_name)
    {
        PVOID moduleBase = nullptr;
        ULONG moduleSize = 0;
        moduleBase = utils::FindModuleBaseAndSize(driver_name, &moduleSize);
        if (!moduleBase)
        {
            utils::LogToFile("Module not found\n");
            return;
        }
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            utils::LogToFile("DOS Signature not found\n");
            return;
        }
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)moduleBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            utils::LogToFile("NT Signature Invalid\n");
            return;
        }
        ULONG dumpSize = ntHeaders->OptionalHeader.SizeOfImage;
        PUCHAR dumpBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, dumpSize, 'dmpD');
        if (!dumpBuffer)
        {
            utils::LogToFile("Failed to allocate memory to dumpBuffer\n");
            return;
        }
        ULONG headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
        SIZE_T bytesCopied = 0;
        MM_COPY_ADDRESS sourceAddress;
        sourceAddress.VirtualAddress = moduleBase;
        NTSTATUS status = MmCopyMemory(dumpBuffer, sourceAddress, headerSize, MM_COPY_MEMORY_VIRTUAL, &bytesCopied);
        if (!NT_SUCCESS(status))
        {
            utils::LogToFile("Failed in MmCopyMemory to headers\n");
            ExFreePoolWithTag(dumpBuffer, 'dmpD');
            return;
        }
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(ntHeaders);
        for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
        {
            PUCHAR dest = dumpBuffer + pSection[i].VirtualAddress;
            SIZE_T sectionSize = pSection[i].Misc.VirtualSize;
            if (pSection[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
            {
                RtlZeroMemory(dest, sectionSize);
            }
            else
            {
                SIZE_T bytesCopiedSection = 0;
                MM_COPY_ADDRESS sectionSource;
                sectionSource.VirtualAddress = (PUCHAR)moduleBase + pSection[i].VirtualAddress;
                status = MmCopyMemory(dest, sectionSource, sectionSize, MM_COPY_MEMORY_VIRTUAL, &bytesCopiedSection);
                if (!NT_SUCCESS(status))
                {
                    utils::LogToFile("Failed in MmCopyMemory to the section\n");
                    RtlZeroMemory(dest, sectionSize);
                }
            }
        }
        PIMAGE_DOS_HEADER dosDump = (PIMAGE_DOS_HEADER)dumpBuffer;
        PIMAGE_NT_HEADERS ntDump = (PIMAGE_NT_HEADERS)(dumpBuffer + dosDump->e_lfanew);
        DWORD fileAlignment = ntDump->OptionalHeader.FileAlignment;
        DWORD sizeOfHeaders = ntDump->OptionalHeader.SizeOfHeaders;
        DWORD newHeadersSize = ((sizeOfHeaders + fileAlignment - 1) / fileAlignment) * fileAlignment;
        PIMAGE_SECTION_HEADER pDumpSection = IMAGE_FIRST_SECTION(ntDump);
        DWORD numberOfSections = ntDump->FileHeader.NumberOfSections;
        DWORD currentOffset = newHeadersSize, newFileSize = newHeadersSize;
        DWORD* newSectionOffsets = (DWORD*)ExAllocatePoolWithTag(NonPagedPool, numberOfSections * sizeof(DWORD), 'ofsD');
        if (!newSectionOffsets)
        {
            utils::LogToFile("Failed to allocate memory to newSectionOffsets\n");
            ExFreePoolWithTag(dumpBuffer, 'dmpD');
            return;
        }
        for (DWORD i = 0; i < numberOfSections; i++)
        {
            DWORD virtualSize = pDumpSection[i].Misc.VirtualSize;
            DWORD alignedSize = ((virtualSize + fileAlignment - 1) / fileAlignment) * fileAlignment;
            newSectionOffsets[i] = currentOffset;
            currentOffset += alignedSize;
        }
        newFileSize = currentOffset;
        PUCHAR rebuiltBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, newFileSize, 'rebD');
        if (!rebuiltBuffer)
        {
            utils::LogToFile("Failed to allocate memory to rebuiltBuffer\n");
            ExFreePoolWithTag(newSectionOffsets, 'ofsD');
            ExFreePoolWithTag(dumpBuffer, 'dmpD');
            return;
        }
        RtlZeroMemory(rebuiltBuffer, newFileSize);
        RtlCopyMemory(rebuiltBuffer, dumpBuffer, sizeOfHeaders);
        PIMAGE_NT_HEADERS newNtHeaders = (PIMAGE_NT_HEADERS)(rebuiltBuffer + dosDump->e_lfanew);
        PIMAGE_SECTION_HEADER newSections = IMAGE_FIRST_SECTION(newNtHeaders);
        for (DWORD i = 0; i < numberOfSections; i++)
        {
            PIMAGE_SECTION_HEADER origSection = &pDumpSection[i];
            DWORD virtualSize = origSection->Misc.VirtualSize;
            DWORD alignedSize = ((virtualSize + fileAlignment - 1) / fileAlignment) * fileAlignment;
            DWORD newOffset = newSectionOffsets[i];
            newSections[i].PointerToRawData = newOffset;
            newSections[i].SizeOfRawData = alignedSize;
            RtlCopyMemory(rebuiltBuffer + newOffset, dumpBuffer + origSection->VirtualAddress, virtualSize);
        }
        ExFreePoolWithTag(newSectionOffsets, 'ofsD');
        WCHAR dirPath[256];
        swprintf_s(dirPath, sizeof(dirPath) / sizeof(WCHAR), L"\\??\\C:\\driver_dump_%hs", driver_name);
        UNICODE_STRING dirName;
        RtlInitUnicodeString(&dirName, dirPath);
        OBJECT_ATTRIBUTES dirObjAttrs;
        InitializeObjectAttributes(&dirObjAttrs, &dirName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        HANDLE dirHandle;
        IO_STATUS_BLOCK dirIoStatus;
        status = ZwCreateFile(&dirHandle, FILE_LIST_DIRECTORY, &dirObjAttrs, &dirIoStatus, NULL, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_DIRECTORY_FILE, NULL, 0);
        if (NT_SUCCESS(status))
            ZwClose(dirHandle);
        WCHAR filePath[256];
        swprintf_s(filePath, sizeof(filePath) / sizeof(WCHAR), L"\\??\\C:\\driver_dump_%hs\\%hs_dump.sys", driver_name, driver_name);
        UNICODE_STRING fileName;
        RtlInitUnicodeString(&fileName, filePath);
        OBJECT_ATTRIBUTES objAttrs;
        InitializeObjectAttributes(&objAttrs, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        HANDLE fileHandle;
        IO_STATUS_BLOCK ioStatus = { 0 };
        status = ZwCreateFile(&fileHandle, GENERIC_WRITE, &objAttrs, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(status))
        {
            utils::LogToFile("Failaed to create dump file\n");
            ExFreePoolWithTag(rebuiltBuffer, 'rebD');
            ExFreePoolWithTag(dumpBuffer, 'dmpD');
            return;
        }
        status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus, rebuiltBuffer, newFileSize, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            utils::LogToFile("Failed to write to the dump file\n");
            ZwClose(fileHandle);
            ExFreePoolWithTag(rebuiltBuffer, 'rebD');
            ExFreePoolWithTag(dumpBuffer, 'dmpD');
            return;
        }
        ZwClose(fileHandle);
        ExFreePoolWithTag(rebuiltBuffer, 'rebD');
        ExFreePoolWithTag(dumpBuffer, 'dmpD');
    }
    void DumpModule(PEPROCESS target_process, ULONG process_id, PLDR_DATA_TABLE_ENTRY pLdrEntry)
    {
        NTSTATUS status;
        SIZE_T bytesCopied = 0;
        PUCHAR headerBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 4096, 'hdrM');
        if (!headerBuffer)
        {
            utils::LogToFile("Failed to allocate headerBuffer\n");
            return;
        }
        status = MmCopyVirtualMemory(target_process, pLdrEntry->DllBase, PsGetCurrentProcess(), headerBuffer, 4096, KernelMode, &bytesCopied);
        if (!NT_SUCCESS(status) || bytesCopied != 4096)
        {
            utils::LogToFile("Failed to copy header from memory, attempting file read\n");
            ExFreePoolWithTag(headerBuffer, 'hdrM');
            if (pLdrEntry->FullDllName.Buffer && pLdrEntry->FullDllName.Length > 0)
            {
                WCHAR filePath[512] = { 0 };
                status = MmCopyVirtualMemory(target_process, pLdrEntry->FullDllName.Buffer, PsGetCurrentProcess(), filePath, pLdrEntry->FullDllName.Length, KernelMode, &bytesCopied);
                if (!NT_SUCCESS(status) || bytesCopied != pLdrEntry->FullDllName.Length)
                {
                    utils::LogToFile("Failed to copy full DLL name from memory\n");
                    return;
                }
                UNICODE_STRING fullDllName;
                RtlInitUnicodeString(&fullDllName, filePath);
                OBJECT_ATTRIBUTES objAttrs;
                InitializeObjectAttributes(&objAttrs, &fullDllName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
                HANDLE fileHandle;
                IO_STATUS_BLOCK ioStatus = { 0 };
                status = ZwOpenFile(&fileHandle, GENERIC_READ, &objAttrs, &ioStatus, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
                if (!NT_SUCCESS(status))
                {
                    utils::LogToFile("Failed to open DLL file for reading\n");
                    return;
                }
                headerBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 4096, 'hdrM');
                if (!headerBuffer)
                {
                    utils::LogToFile("Failed to allocate headerBuffer for file read\n");
                    ZwClose(fileHandle);
                    return;
                }
                status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatus, headerBuffer, 4096, NULL, NULL);
                ZwClose(fileHandle);
                if (!NT_SUCCESS(status) || ioStatus.Information != 4096)
                {
                    utils::LogToFile("Failed to read header from file\n");
                    ExFreePoolWithTag(headerBuffer, 'hdrM');
                    return;
                }
            }
            else
            {
                utils::LogToFile("Full DLL name not available\n");
                return;
            }
        }
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headerBuffer;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew >= 4096)
        {
            utils::LogToFile("Invalid DOS header\n");
            ExFreePoolWithTag(headerBuffer, 'hdrM');
            return;
        }
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(headerBuffer + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            utils::LogToFile("Invalid NT header\n");
            ExFreePoolWithTag(headerBuffer, 'hdrM');
            return;
        }
        ULONG dumpSize = ntHeaders->OptionalHeader.SizeOfImage;
        PUCHAR dumpBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, dumpSize, 'dmpM');
        if (!dumpBuffer)
        {
            utils::LogToFile("Failed to allocate dumpBuffer\n");
            ExFreePoolWithTag(headerBuffer, 'hdrM');
            return;
        }
        RtlCopyMemory(dumpBuffer, headerBuffer, 4096);
        ExFreePoolWithTag(headerBuffer, 'hdrM');
        HANDLE procHandle;
        status = ObOpenObjectByPointer(target_process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &procHandle);
        if (NT_SUCCESS(status))
        {
            PVOID queryAddr = pLdrEntry->DllBase;
            MEMORY_BASIC_INFORMATION mbi;
            while (NT_SUCCESS(ZwQueryVirtualMemory(procHandle, queryAddr, MemoryBasicInformation, &mbi, sizeof(mbi), NULL)))
            {
                if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
                {
                    PVOID regionAddr = mbi.BaseAddress;
                    SIZE_T regionSize = mbi.RegionSize;
                    ULONG oldProtect;
                    if (!NT_SUCCESS(ZwProtectVirtualMemory(procHandle, &regionAddr, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect)))
                    {
                        utils::LogToFile("Failed to unprotect memory\n");
                    }
                }
                queryAddr = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
                if ((ULONG_PTR)queryAddr >= (ULONG_PTR)pLdrEntry->DllBase + dumpSize)
                    break;
            }
            ZwClose(procHandle);
        }
        else
        {
            utils::LogToFile("Failed to open process handle for memory unprotection\n");
        }
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(ntHeaders);
        for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
        {
            PUCHAR dest = dumpBuffer + pSection[i].VirtualAddress;
            SIZE_T sectionSize = pSection[i].Misc.VirtualSize;
            status = MmCopyVirtualMemory(target_process, (PUCHAR)pLdrEntry->DllBase + pSection[i].VirtualAddress, PsGetCurrentProcess(), dest, sectionSize, KernelMode, &bytesCopied);
            if (!NT_SUCCESS(status) || bytesCopied != sectionSize)
            {
                utils::LogToFile("Failed to copy section, zeroing memory\n");
                RtlZeroMemory(dest, sectionSize);
            }
        }
        PIMAGE_DOS_HEADER dosDump = (PIMAGE_DOS_HEADER)dumpBuffer;
        PIMAGE_NT_HEADERS ntDump = (PIMAGE_NT_HEADERS)(dumpBuffer + dosDump->e_lfanew);
        DWORD fileAlignment = ntDump->OptionalHeader.FileAlignment;
        DWORD sizeOfHeaders = ntDump->OptionalHeader.SizeOfHeaders;
        DWORD newHeadersSize = ((sizeOfHeaders + fileAlignment - 1) / fileAlignment) * fileAlignment;
        PIMAGE_SECTION_HEADER pDumpSection = IMAGE_FIRST_SECTION(ntDump);
        DWORD numberOfSections = ntDump->FileHeader.NumberOfSections;
        DWORD currentOffset = newHeadersSize, newFileSize = newHeadersSize;
        DWORD* newSectionOffsets = (DWORD*)ExAllocatePoolWithTag(NonPagedPool, numberOfSections * sizeof(DWORD), 'ofsM');
        if (!newSectionOffsets)
        {
            utils::LogToFile("Failed to allocate section offsets\n");
            ExFreePoolWithTag(dumpBuffer, 'dmpM');
            return;
        }
        for (DWORD i = 0; i < numberOfSections; i++)
        {
            DWORD virtualSize = pDumpSection[i].Misc.VirtualSize;
            DWORD alignedSize = ((virtualSize + fileAlignment - 1) / fileAlignment) * fileAlignment;
            newSectionOffsets[i] = currentOffset;
            currentOffset += alignedSize;
        }
        newFileSize = currentOffset;
        PUCHAR rebuiltBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, newFileSize, 'rebM');
        if (!rebuiltBuffer)
        {
            utils::LogToFile("Failed to allocate rebuiltBuffer\n");
            ExFreePoolWithTag(newSectionOffsets, 'ofsM');
            ExFreePoolWithTag(dumpBuffer, 'dmpM');
            return;
        }
        RtlZeroMemory(rebuiltBuffer, newFileSize);
        RtlCopyMemory(rebuiltBuffer, dumpBuffer, sizeOfHeaders);
        PIMAGE_NT_HEADERS newNtHeaders = (PIMAGE_NT_HEADERS)(rebuiltBuffer + dosDump->e_lfanew);
        PIMAGE_SECTION_HEADER newSections = IMAGE_FIRST_SECTION(newNtHeaders);
        for (DWORD i = 0; i < numberOfSections; i++)
        {
            PIMAGE_SECTION_HEADER origSection = &pDumpSection[i];
            DWORD virtualSize = origSection->Misc.VirtualSize;
            DWORD alignedSize = ((virtualSize + fileAlignment - 1) / fileAlignment) * fileAlignment;
            DWORD newOffset = newSectionOffsets[i];
            newSections[i].PointerToRawData = newOffset;
            newSections[i].SizeOfRawData = alignedSize;
            RtlCopyMemory(rebuiltBuffer + newOffset, dumpBuffer + origSection->VirtualAddress, virtualSize);
        }
        ExFreePoolWithTag(newSectionOffsets, 'ofsM');
        {
            WCHAR procDir[256];
            swprintf_s(procDir, sizeof(procDir) / sizeof(WCHAR), L"\\??\\C:\\process_dump_%lu", process_id);
            UNICODE_STRING procDirStr;
            RtlInitUnicodeString(&procDirStr, procDir);
            OBJECT_ATTRIBUTES procDirObj;
            InitializeObjectAttributes(&procDirObj, &procDirStr, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            HANDLE procDirHandle;
            IO_STATUS_BLOCK procDirIo;
            status = ZwCreateFile(&procDirHandle, FILE_LIST_DIRECTORY, &procDirObj, &procDirIo, NULL, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_DIRECTORY_FILE, NULL, 0);
            if (NT_SUCCESS(status))
                ZwClose(procDirHandle);
        }
        WCHAR localDllName[256] = { 0 };
        UNICODE_STRING localBaseDllName;
        if (pLdrEntry->BaseDllName.Length < sizeof(localDllName))
        {
            status = MmCopyVirtualMemory(target_process, pLdrEntry->BaseDllName.Buffer, PsGetCurrentProcess(), localDllName, pLdrEntry->BaseDllName.Length, KernelMode, &bytesCopied);
            if (!NT_SUCCESS(status) || bytesCopied != pLdrEntry->BaseDllName.Length)
                RtlStringCchCopyW(localDllName, 256, L"Unknown");
            localBaseDllName.Buffer = localDllName;
            localBaseDllName.Length = (USHORT)(wcslen(localDllName) * sizeof(WCHAR));
            localBaseDllName.MaximumLength = sizeof(localDllName);
        }
        else
        {
            RtlStringCchCopyW(localDllName, 256, L"Unknown");
            localBaseDllName.Buffer = localDllName;
            localBaseDllName.Length = (USHORT)(wcslen(localDllName) * sizeof(WCHAR));
            localBaseDllName.MaximumLength = sizeof(localDllName);
        }
        WCHAR file_name_unicode[256];
        swprintf_s(file_name_unicode, sizeof(file_name_unicode) / sizeof(WCHAR), L"\\??\\C:\\process_dump_%lu\\process_%lu_module_%wZ_dump.dll", process_id, process_id, &localBaseDllName);
        UNICODE_STRING fileName;
        RtlInitUnicodeString(&fileName, file_name_unicode);
        OBJECT_ATTRIBUTES objAttrs;
        InitializeObjectAttributes(&objAttrs, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        HANDLE fileHandle;
        IO_STATUS_BLOCK ioStatus = { 0 };
        status = ZwCreateFile(&fileHandle, GENERIC_WRITE, &objAttrs, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(status))
        {
            utils::LogToFile("Failed to create dump file\n");
            ExFreePoolWithTag(rebuiltBuffer, 'rebM');
            ExFreePoolWithTag(dumpBuffer, 'dmpM');
            return;
        }
        status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus, rebuiltBuffer, newFileSize, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            utils::LogToFile("Failed to write dump file\n");
            ZwClose(fileHandle);
            ExFreePoolWithTag(rebuiltBuffer, 'rebM');
            ExFreePoolWithTag(dumpBuffer, 'dmpM');
            return;
        }
        ZwClose(fileHandle);
        ExFreePoolWithTag(rebuiltBuffer, 'rebM');
        ExFreePoolWithTag(dumpBuffer, 'dmpM');
    }
    void DumpProcessModules(ULONG process_id)
    {
        NTSTATUS status;
        PEPROCESS target_process;
        status = PsLookupProcessByProcessId((HANDLE)process_id, &target_process);
        if (!NT_SUCCESS(status))
        {
            utils::LogToFile("Failed to lookup process\n");
            return;
        }
        PPEB peb = PsGetProcessPeb(target_process);
        if (!peb)
        {
            utils::LogToFile("Failed to get PEB\n");
            ObDereferenceObject(target_process);
            return;
        }
        PEB localPeb;
        SIZE_T bytesCopied = 0;
        status = MmCopyVirtualMemory(target_process, peb, PsGetCurrentProcess(), &localPeb, sizeof(PEB), KernelMode, &bytesCopied);
        if (!NT_SUCCESS(status) || bytesCopied != sizeof(PEB))
        {
            utils::LogToFile("Failed to copy PEB\n");
            ObDereferenceObject(target_process);
            return;
        }
        PPEB_LDR_DATA ldrData = localPeb.Ldr;
        if (!ldrData)
        {
            utils::LogToFile("PEB->Ldr is null\n");
            ObDereferenceObject(target_process);
            return;
        }
        PEB_LDR_DATA localLdrData;
        status = MmCopyVirtualMemory(target_process, ldrData, PsGetCurrentProcess(), &localLdrData, sizeof(PEB_LDR_DATA), KernelMode, &bytesCopied);
        if (!NT_SUCCESS(status) || bytesCopied != sizeof(PEB_LDR_DATA))
        {
            utils::LogToFile("Failed to copy PEB_LDR_DATA\n");
            ObDereferenceObject(target_process);
            return;
        }
        PLIST_ENTRY pListEntry = localLdrData.InLoadOrderModuleList.Flink;
        PLIST_ENTRY listHead = &ldrData->InLoadOrderModuleList;
        while (pListEntry && pListEntry != listHead)
        {
            LDR_DATA_TABLE_ENTRY ldrEntry = { 0 };
            status = MmCopyVirtualMemory(target_process, pListEntry, PsGetCurrentProcess(), &ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), KernelMode, &bytesCopied);
            if (!NT_SUCCESS(status) || bytesCopied != sizeof(LDR_DATA_TABLE_ENTRY))
            {
                utils::LogToFile("Failed to copy LDR_DATA_TABLE_ENTRY\n");
                break;
            }
            DumpModule(target_process, process_id, &ldrEntry);
            pListEntry = ldrEntry.InLoadOrderLinks.Flink;
            if (pListEntry == listHead)
                break;
        }
        ObDereferenceObject(target_process);
    }
    void DumpProcessMemory(ULONG process_id)
    {
        PEPROCESS target_process;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)process_id, &target_process);
        if (!NT_SUCCESS(status))
        {
            utils::LogToFile("Failed to lookup process\n");
            return;
        }
        PVOID base_address = PsGetProcessSectionBaseAddress(target_process);
        if (!base_address)
        {
            utils::LogToFile("Failed to get process base address\n");
            ObDereferenceObject(target_process);
            return;
        }
        PUCHAR tempBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 4096, 'tmpD');
        if (!tempBuffer)
        {
            utils::LogToFile("Failed to allocate tempBuffer\n");
            ObDereferenceObject(target_process);
            return;
        }
        if (!NT_SUCCESS(utils::PsSuspendProcess(target_process)))
        {
            utils::LogToFile("Failed to suspend process\n");
            ExFreePoolWithTag(tempBuffer, 'tmpD');
            ObDereferenceObject(target_process);
            return;
        }
        HANDLE processHandle;
        status = ObOpenObjectByPointer(target_process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &processHandle);
        MEMORY_BASIC_INFORMATION mbi;
        PVOID base_address_query = NULL;
        while (NT_SUCCESS(ZwQueryVirtualMemory(processHandle, base_address_query, MemoryBasicInformation, &mbi, sizeof(mbi), NULL)))
        {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            {
                PVOID region_address = mbi.BaseAddress;
                SIZE_T region_size = mbi.RegionSize;
                ULONG old_protect;
                if (!NT_SUCCESS(ZwProtectVirtualMemory(processHandle, &region_address, &region_size, PAGE_EXECUTE_READWRITE, &old_protect)))
                {
                    utils::LogToFile("Failed to unprotect memory\n");
                }
            }
            base_address_query = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
        }
        SIZE_T bytesCopied = 0;
        status = MmCopyVirtualMemory(target_process, base_address, PsGetCurrentProcess(), tempBuffer, 4096, KernelMode, &bytesCopied);
        if (!NT_SUCCESS(status) || bytesCopied != 4096)
        {
            utils::LogToFile("Failed to copy process header from memory, trying file\n");
            PUCHAR nameBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 1024, 'nmeD');
            if (!nameBuffer)
            {
                utils::LogToFile("Failed to allocate nameBuffer\n");
                ZwClose(processHandle);
                ExFreePoolWithTag(tempBuffer, 'tmpD');
                ObDereferenceObject(target_process);
                return;
            }
            ULONG returnLength;
            status = ZwQueryInformationProcess(processHandle, ProcessImageFileName, nameBuffer, 1024, &returnLength);
            if (!NT_SUCCESS(status))
            {
                utils::LogToFile("Failed to query process image file name\n");
                ExFreePoolWithTag(nameBuffer, 'nmeD');
                ZwClose(processHandle);
                ExFreePoolWithTag(tempBuffer, 'tmpD');
                ObDereferenceObject(target_process);
                return;
            }
            UNICODE_STRING* processImageName = (UNICODE_STRING*)nameBuffer;
            OBJECT_ATTRIBUTES objAttrs;
            InitializeObjectAttributes(&objAttrs, processImageName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            HANDLE fileHandle;
            IO_STATUS_BLOCK ioStatus = { 0 };
            status = ZwOpenFile(&fileHandle, GENERIC_READ, &objAttrs, &ioStatus, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
            if (!NT_SUCCESS(status))
            {
                utils::LogToFile("Failed to open process image file\n");
                ExFreePoolWithTag(nameBuffer, 'nmeD');
                ZwClose(processHandle);
                ExFreePoolWithTag(tempBuffer, 'tmpD');
                ObDereferenceObject(target_process);
                return;
            }
            status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatus, tempBuffer, 4096, NULL, NULL);
            if (!NT_SUCCESS(status) || ioStatus.Information != 4096)
            {
                utils::LogToFile("Failed to read process header from file\n");
                ZwClose(fileHandle);
                ExFreePoolWithTag(nameBuffer, 'nmeD');
                ZwClose(processHandle);
                ExFreePoolWithTag(tempBuffer, 'tmpD');
                ObDereferenceObject(target_process);
                return;
            }
            ZwClose(fileHandle);
            ExFreePoolWithTag(nameBuffer, 'nmeD');
        }
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)tempBuffer;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew >= 4096)
        {
            utils::LogToFile("Invalid DOS header\n");
            ZwClose(processHandle);
            ExFreePoolWithTag(tempBuffer, 'tmpD');
            ObDereferenceObject(target_process);
            return;
        }
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(tempBuffer + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            utils::LogToFile("Invalid NT header\n");
            ZwClose(processHandle);
            ExFreePoolWithTag(tempBuffer, 'tmpD');
            ObDereferenceObject(target_process);
            return;
        }
        ULONG dumpSize = ntHeaders->OptionalHeader.SizeOfImage;
        PUCHAR dumpBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, dumpSize, 'dmpD');
        if (!dumpBuffer)
        {
            utils::LogToFile("Failed to allocate dumpBuffer\n");
            ZwClose(processHandle);
            ExFreePoolWithTag(tempBuffer, 'tmpD');
            ObDereferenceObject(target_process);
            return;
        }
        RtlCopyMemory(dumpBuffer, tempBuffer, 4096);
        ExFreePoolWithTag(tempBuffer, 'tmpD');
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(ntHeaders);
        for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
        {
            PUCHAR dest = dumpBuffer + pSection[i].VirtualAddress;
            SIZE_T sectionSize = pSection[i].Misc.VirtualSize;
            PVOID sourceAddress = (PUCHAR)base_address + pSection[i].VirtualAddress;
            SIZE_T bytesCopiedSection = 0;
            status = MmCopyVirtualMemory(target_process, sourceAddress, PsGetCurrentProcess(), dest, sectionSize, KernelMode, &bytesCopiedSection);
            if (!NT_SUCCESS(status) || bytesCopiedSection != sectionSize)
            {
                utils::LogToFile("Failed to copy section, zeroing memory\n");
                ZwClose(processHandle);
                RtlZeroMemory(dest, sectionSize);
            }
        }
        ObDereferenceObject(target_process);
        PIMAGE_DOS_HEADER dosDump = (PIMAGE_DOS_HEADER)dumpBuffer;
        PIMAGE_NT_HEADERS ntDump = (PIMAGE_NT_HEADERS)(dumpBuffer + dosDump->e_lfanew);
        DWORD fileAlignment = ntDump->OptionalHeader.FileAlignment;
        DWORD sizeOfHeaders = ntDump->OptionalHeader.SizeOfHeaders;
        DWORD newHeadersSize = ((sizeOfHeaders + fileAlignment - 1) / fileAlignment) * fileAlignment;
        PIMAGE_SECTION_HEADER pDumpSection = IMAGE_FIRST_SECTION(ntDump);
        DWORD numberOfSections = ntDump->FileHeader.NumberOfSections;
        DWORD currentOffset = newHeadersSize, newFileSize = newHeadersSize;
        DWORD* newSectionOffsets = (DWORD*)ExAllocatePoolWithTag(NonPagedPool, numberOfSections * sizeof(DWORD), 'ofsD');
        if (!newSectionOffsets)
        {
            utils::LogToFile("Failed to allocate section offsets\n");
            ZwClose(processHandle);
            ExFreePoolWithTag(dumpBuffer, 'dmpD');
            return;
        }
        for (DWORD i = 0; i < numberOfSections; i++)
        {
            DWORD virtualSize = pDumpSection[i].Misc.VirtualSize;
            DWORD alignedSize = ((virtualSize + fileAlignment - 1) / fileAlignment) * fileAlignment;
            newSectionOffsets[i] = currentOffset;
            currentOffset += alignedSize;
        }
        newFileSize = currentOffset;
        PUCHAR rebuiltBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, newFileSize, 'rebD');
        if (!rebuiltBuffer)
        {
            utils::LogToFile("Failed to allocate rebuiltBuffer\n");
            ZwClose(processHandle);
            ExFreePoolWithTag(newSectionOffsets, 'ofsD');
            ExFreePoolWithTag(dumpBuffer, 'dmpD');
            return;
        }
        RtlZeroMemory(rebuiltBuffer, newFileSize);
        RtlCopyMemory(rebuiltBuffer, dumpBuffer, sizeOfHeaders);
        PIMAGE_NT_HEADERS newNtHeaders = (PIMAGE_NT_HEADERS)(rebuiltBuffer + dosDump->e_lfanew);
        PIMAGE_SECTION_HEADER newSections = IMAGE_FIRST_SECTION(newNtHeaders);
        for (DWORD i = 0; i < numberOfSections; i++)
        {
            PIMAGE_SECTION_HEADER origSection = &pDumpSection[i];
            DWORD virtualSize = origSection->Misc.VirtualSize;
            DWORD alignedSize = ((virtualSize + fileAlignment - 1) / fileAlignment) * fileAlignment;
            DWORD newOffset = newSectionOffsets[i];
            newSections[i].PointerToRawData = newOffset;
            newSections[i].SizeOfRawData = alignedSize;
            RtlCopyMemory(rebuiltBuffer + newOffset, dumpBuffer + origSection->VirtualAddress, virtualSize);
        }
        ExFreePoolWithTag(newSectionOffsets, 'ofsD');
        {
            WCHAR procDir[256];
            swprintf_s(procDir, sizeof(procDir) / sizeof(WCHAR), L"\\??\\C:\\process_dump_%lu", process_id);
            UNICODE_STRING procDirStr;
            RtlInitUnicodeString(&procDirStr, procDir);
            OBJECT_ATTRIBUTES procDirObj;
            InitializeObjectAttributes(&procDirObj, &procDirStr, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            HANDLE procDirHandle;
            IO_STATUS_BLOCK procDirIo;
            status = ZwCreateFile(&procDirHandle, FILE_LIST_DIRECTORY, &procDirObj, &procDirIo, NULL, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_DIRECTORY_FILE, NULL, 0);
            if (NT_SUCCESS(status))
                ZwClose(procDirHandle);
        }
        WCHAR file_name_unicode[256];
        swprintf_s(file_name_unicode, sizeof(file_name_unicode) / sizeof(WCHAR), L"\\??\\C:\\process_dump_%lu\\process_%lu_dump.exe", process_id, process_id);
        UNICODE_STRING fileName;
        RtlInitUnicodeString(&fileName, file_name_unicode);
        OBJECT_ATTRIBUTES objAttrs;
        InitializeObjectAttributes(&objAttrs, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        HANDLE fileHandle;
        IO_STATUS_BLOCK ioStatus = { 0 };
        status = ZwCreateFile(&fileHandle, GENERIC_WRITE, &objAttrs, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(status))
        {
            utils::LogToFile("Failed to create dump file\n");
            ZwClose(processHandle);
            ExFreePoolWithTag(rebuiltBuffer, 'rebD');
            ExFreePoolWithTag(dumpBuffer, 'dmpD');
            return;
        }
        status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus, rebuiltBuffer, newFileSize, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            utils::LogToFile("Failed to write dump file\n");
            ZwClose(processHandle);
            ZwClose(fileHandle);
            ExFreePoolWithTag(rebuiltBuffer, 'rebD');
            ExFreePoolWithTag(dumpBuffer, 'dmpD');
            return;
        }
        ZwClose(processHandle);
        ZwClose(fileHandle);
        ExFreePoolWithTag(rebuiltBuffer, 'rebD');
        ExFreePoolWithTag(dumpBuffer, 'dmpD');
        DumpProcessModules(process_id);
    }
}
