#include "general.hpp"
#pragma once

namespace ioctl
{
    NTSTATUS ctl_io(PDEVICE_OBJECT device_obj, PIRP irp) {
        UNREFERENCED_PARAMETER(device_obj);
        irp->IoStatus.Information = sizeof(info_t);
        auto stack = IoGetCurrentIrpStackLocation(irp);
        auto buffer = (info_t*)irp->AssociatedIrp.SystemBuffer;
        if (stack && buffer && sizeof(*buffer) >= sizeof(info_t)) {
            const auto ctl_code = stack->Parameters.DeviceIoControl.IoControlCode;
            switch (ctl_code) {
            case dump_driver_code:
                if (buffer->driver_name) {
                    general::DumpDriver(buffer->driver_name);
                }
                break;
            case dump_process_code:
                if (buffer->process_pid) {
                    general::DumpProcessMemory(buffer->process_pid);
                }
                break;
            default:
                break;
            }
        }
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    NTSTATUS unsupported_io(PDEVICE_OBJECT device_obj, PIRP irp) {
        UNREFERENCED_PARAMETER(device_obj);
        irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return irp->IoStatus.Status;
    }

    NTSTATUS create_io(PDEVICE_OBJECT device_obj, PIRP irp) {
        UNREFERENCED_PARAMETER(device_obj);
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return irp->IoStatus.Status;
    }

    NTSTATUS close_io(PDEVICE_OBJECT device_obj, PIRP irp) {
        UNREFERENCED_PARAMETER(device_obj);
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return irp->IoStatus.Status;
    }

    NTSTATUS DriverMain(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path) {
        UNREFERENCED_PARAMETER(registery_path);
        UNICODE_STRING dev_name, sym_link;
        PDEVICE_OBJECT dev_obj;
        RtlInitUnicodeString(&dev_name, L"\\Device\\BrazilPastingOnTop");
        NTSTATUS status = IoCreateDevice(driver_obj, 0, &dev_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev_obj);
        if (!NT_SUCCESS(status)) {
            utils::LogToFile("Failed to create device\n");
            return status;
        }
        RtlInitUnicodeString(&sym_link, L"\\DosDevices\\BrazilPastingOnTop");
        status = IoCreateSymbolicLink(&sym_link, &dev_name);
        if (!NT_SUCCESS(status)) {
            utils::LogToFile("Failed to create symbolic link\n");
            IoDeleteDevice(dev_obj);
            return status;
        }
        SetFlag(dev_obj->Flags, DO_BUFFERED_IO);
        for (int t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
            driver_obj->MajorFunction[t] = unsupported_io;
        driver_obj->MajorFunction[IRP_MJ_CREATE] = create_io;
        driver_obj->MajorFunction[IRP_MJ_CLOSE] = close_io;
        driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ctl_io;
        driver_obj->DriverUnload = NULL;
        ClearFlag(dev_obj->Flags, DO_DEVICE_INITIALIZING);
        return status;
    }

    NTSTATUS DriverEntry() {
        if (!NT_SUCCESS(utils::InitializeExports()))
        {
            return STATUS_UNSUCCESSFUL;
        }

        UNICODE_STRING  drv_name;
        RtlInitUnicodeString(&drv_name, L"\\Driver\\BrazilPastingOnTop");
        NTSTATUS status = IoCreateDriver(&drv_name, &DriverMain);
        return status;
    }
}