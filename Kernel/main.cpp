#include "ioctl.hpp"

NTSTATUS CustomDriverEntry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path)
{
    UNREFERENCED_PARAMETER(driver_obj);
    UNREFERENCED_PARAMETER(registery_path);
    return ioctl::DriverEntry();
}
