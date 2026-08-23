/*++

Module Name:

    abkvhidctl.cpp

Abstract:

    Creates, inspects and removes the root-enumerated devnode that the ABK
    FIDO virtual HID driver binds to. pnputil can stage and even install a
    driver package, but it cannot invent a devnode for hardware that does not
    exist, which is exactly what a software-only HID source needs - so this
    does the same three SetupAPI calls devcon's `install` command makes.

    Usage:

        abkvhidctl install <path to abkfidovhid.inf>
        abkvhidctl remove
        abkvhidctl status

    install and remove need an elevated command prompt.

--*/

#include <windows.h>
#include <setupapi.h>
#include <newdev.h>
#include <cfgmgr32.h>
#include <strsafe.h>
#include <stdio.h>

// Must match the hardware id in abkfidovhid.inx.
static const wchar_t kHardwareId[] = L"root\\ABKFIDOVHID";

// Must match g_AbkSymbolicLink in abkfidovhid.c.
static const wchar_t kControlDevice[] = L"\\\\.\\ABKFidoVhid";

static void ReportError(_In_z_ const wchar_t* what)
{
    const DWORD err = GetLastError();
    wchar_t* text = nullptr;

    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, err, 0, reinterpret_cast<LPWSTR>(&text), 0, nullptr);
    fwprintf(stderr, L"%s failed (0x%08lX) %s\n", what, err, text ? text : L"\n");
    if (text != nullptr) {
        LocalFree(text);
    }
}
static bool IsElevated()
{
    HANDLE token = nullptr;
    TOKEN_ELEVATION elevation = {};
    DWORD returned = 0;
    bool elevated = false;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned)) {
            elevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(token);
    }
    return elevated;
}

// True when the devnode's hardware id list contains kHardwareId. The list is a
// REG_MULTI_SZ, and a devnode created by `install` carries a generated instance
// path (ROOT\SYSTEM\000n), so the hardware id is the only stable handle on it.
static bool MatchesHardwareId(_In_ HDEVINFO Devices, _In_ PSP_DEVINFO_DATA Info)
{
    BYTE buffer[4096] = {};
    DWORD required = 0;
    DWORD type = 0;

    if (!SetupDiGetDeviceRegistryPropertyW(Devices, Info, SPDRP_HARDWAREID, &type, buffer,
                                           sizeof(buffer) - 2 * sizeof(wchar_t), &required)) {
        return false;
    }
    if (type != REG_MULTI_SZ && type != REG_SZ) {
        return false;
    }

    for (const wchar_t* id = reinterpret_cast<const wchar_t*>(buffer); *id != L'\0';
         id += wcslen(id) + 1) {
        if (_wcsicmp(id, kHardwareId) == 0) {
            return true;
        }
    }
    return false;
}

typedef bool (*DeviceVisitor)(HDEVINFO Devices, PSP_DEVINFO_DATA Info, void* Context);

// Returns the number of matching devnodes, or -1 on failure.
static int ForEachDevice(_In_opt_ DeviceVisitor Visit, _In_opt_ void* Context)
{
    SP_DEVINFO_DATA info = {};
    int matched = 0;

    HDEVINFO devices = SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_ALLCLASSES);
    if (devices == INVALID_HANDLE_VALUE) {
        ReportError(L"SetupDiGetClassDevs");
        return -1;
    }

    info.cbSize = sizeof(info);
    for (DWORD index = 0; SetupDiEnumDeviceInfo(devices, index, &info); index++) {
        if (!MatchesHardwareId(devices, &info)) {
            continue;
        }
        matched++;
        if (Visit != nullptr && !Visit(devices, &info, Context)) {
            break;
        }
    }

    SetupDiDestroyDeviceInfoList(devices);
    return matched;
}
static int CommandInstall(_In_z_ const wchar_t* InfArgument)
{
    wchar_t infPath[MAX_PATH] = {};
    wchar_t className[MAX_CLASS_NAME_LEN] = {};
    wchar_t hardwareIds[LINE_LEN + 2] = {};
    GUID classGuid = {};
    BOOL reboot = FALSE;

    const DWORD length = GetFullPathNameW(InfArgument, MAX_PATH, infPath, nullptr);
    if (length == 0 || length >= MAX_PATH) {
        fwprintf(stderr, L"bad inf path: %s\n", InfArgument);
        return 1;
    }
    if (GetFileAttributesW(infPath) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"inf not found: %s\n", infPath);
        return 1;
    }

    const int existing = ForEachDevice(nullptr, nullptr);
    if (existing < 0) {
        return 1;
    }

    if (existing == 0) {
        if (!SetupDiGetINFClassW(infPath, &classGuid, className, ARRAYSIZE(className), nullptr)) {
            ReportError(L"SetupDiGetINFClass");
            return 1;
        }

        HDEVINFO devices = SetupDiCreateDeviceInfoList(&classGuid, nullptr);
        if (devices == INVALID_HANDLE_VALUE) {
            ReportError(L"SetupDiCreateDeviceInfoList");
            return 1;
        }

        SP_DEVINFO_DATA info = {};
        info.cbSize = sizeof(info);

        bool created = false;
        if (!SetupDiCreateDeviceInfoW(devices, className, &classGuid, nullptr, 0,
                                      DICD_GENERATE_ID, &info)) {
            ReportError(L"SetupDiCreateDeviceInfo");
        } else if (FAILED(StringCchCopyW(hardwareIds, LINE_LEN, kHardwareId))) {
            fwprintf(stderr, L"hardware id too long\n");
        } else if (!SetupDiSetDeviceRegistryPropertyW(
                       devices, &info, SPDRP_HARDWAREID,
                       reinterpret_cast<const BYTE*>(hardwareIds),
                       // REG_MULTI_SZ: one id plus both terminators.
                       static_cast<DWORD>((wcslen(hardwareIds) + 2) * sizeof(wchar_t)))) {
            ReportError(L"SetupDiSetDeviceRegistryProperty");
        } else if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, devices, &info)) {
            ReportError(L"DIF_REGISTERDEVICE");
        } else {
            created = true;
        }

        SetupDiDestroyDeviceInfoList(devices);
        if (!created) {
            return 1;
        }
        wprintf(L"created devnode for %s\n", kHardwareId);
    } else {
        wprintf(L"devnode for %s already present, updating the driver\n", kHardwareId);
    }

    // Stages the package in the driver store and binds it to the devnode.
    if (!UpdateDriverForPlugAndPlayDevicesW(nullptr, kHardwareId, infPath, INSTALLFLAG_FORCE,
                                            &reboot)) {
        ReportError(L"UpdateDriverForPlugAndPlayDevices");
        fwprintf(stderr,
                 L"\nIf this reported a signature problem: the package has to be signed by a\n"
                 L"certificate this machine trusts, and the machine has to allow it to load\n"
                 L"(test signing for a self-signed package).\n");
        return 1;
    }

    wprintf(L"installed %s\n", infPath);
    if (reboot) {
        wprintf(L"a reboot is needed to finish\n");
    }
    return 0;
}
static bool RemoveVisitor(_In_ HDEVINFO Devices, _In_ PSP_DEVINFO_DATA Info, _In_opt_ void* Context)
{
    SP_REMOVEDEVICE_PARAMS remove = {};
    wchar_t instanceId[MAX_DEVICE_ID_LEN] = {};
    int* failures = static_cast<int*>(Context);

    if (!SetupDiGetDeviceInstanceIdW(Devices, Info, instanceId, ARRAYSIZE(instanceId), nullptr)) {
        StringCchCopyW(instanceId, ARRAYSIZE(instanceId), L"<unknown>");
    }

    remove.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
    remove.ClassInstallHeader.InstallFunction = DIF_REMOVE;
    remove.Scope = DI_REMOVEDEVICE_GLOBAL;
    remove.HwProfile = 0;

    if (!SetupDiSetClassInstallParamsW(Devices, Info, &remove.ClassInstallHeader, sizeof(remove)) ||
        !SetupDiCallClassInstaller(DIF_REMOVE, Devices, Info)) {
        ReportError(L"DIF_REMOVE");
        fwprintf(stderr, L"%s: not removed\n", instanceId);
        if (failures != nullptr) {
            (*failures)++;
        }
    } else {
        wprintf(L"%s: removed\n", instanceId);
    }
    return true;
}

static int CommandRemove()
{
    int failures = 0;

    const int matched = ForEachDevice(RemoveVisitor, &failures);
    if (matched < 0) {
        return 1;
    }
    if (matched == 0) {
        wprintf(L"no devnode for %s is present\n", kHardwareId);
        return 0;
    }
    // The driver package stays in the driver store on purpose: removing it
    // needs its published oem*.inf name, and `pnputil /enum-drivers` is the
    // right tool for that.
    return failures == 0 ? 0 : 1;
}

static bool StatusVisitor(_In_ HDEVINFO Devices, _In_ PSP_DEVINFO_DATA Info, _In_opt_ void* Context)
{
    wchar_t instanceId[MAX_DEVICE_ID_LEN] = {};
    ULONG status = 0;
    ULONG problem = 0;

    UNREFERENCED_PARAMETER(Context);

    if (!SetupDiGetDeviceInstanceIdW(Devices, Info, instanceId, ARRAYSIZE(instanceId), nullptr)) {
        StringCchCopyW(instanceId, ARRAYSIZE(instanceId), L"<unknown>");
    }

    if (CM_Get_DevNode_Status(&status, &problem, Info->DevInst, 0) != CR_SUCCESS) {
        wprintf(L"%s: status unavailable\n", instanceId);
        return true;
    }

    if (problem != 0) {
        wprintf(L"%s: problem code %lu\n", instanceId, problem);
        if (problem == CM_PROB_UNSIGNED_DRIVER) {
            wprintf(L"  the driver was blocked from loading; this is what an untrusted or\n"
                    L"  unsigned driver looks like when test signing is off\n");
        }
    } else if ((status & DN_STARTED) != 0) {
        wprintf(L"%s: started\n", instanceId);
    } else {
        wprintf(L"%s: present, not started\n", instanceId);
    }
    return true;
}
static int CommandStatus()
{
    const int matched = ForEachDevice(StatusVisitor, nullptr);
    if (matched < 0) {
        return 1;
    }
    if (matched == 0) {
        wprintf(L"no devnode for %s is present; run `abkvhidctl install "
                L"abkfidovhid.inf` first\n",
                kHardwareId);
        return 1;
    }

    // The end-to-end check: this is the handle the agent opens, so if it opens
    // here the driver is loaded, started and reachable.
    HANDLE control = CreateFileW(kControlDevice, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                 OPEN_EXISTING, 0, nullptr);
    if (control == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        if (err == ERROR_SHARING_VIOLATION) {
            wprintf(L"%s: open by another process (the agent is running)\n", kControlDevice);
            return 0;
        }
        SetLastError(err);
        ReportError(L"opening the control device");
        return 1;
    }
    CloseHandle(control);
    wprintf(L"%s: ready\n", kControlDevice);
    return 0;
}

static void Usage()
{
    wprintf(L"abkvhidctl - manage the ABK FIDO virtual HID devnode\n\n"
            L"  abkvhidctl install <path to abkfidovhid.inf>\n"
            L"  abkvhidctl remove\n"
            L"  abkvhidctl status\n\n"
            L"install and remove need an elevated command prompt.\n");
}

int __cdecl wmain(int argc, wchar_t** argv)
{
    if (argc < 2) {
        Usage();
        return 1;
    }

    if (_wcsicmp(argv[1], L"install") == 0) {
        if (argc < 3) {
            Usage();
            return 1;
        }
        if (!IsElevated()) {
            fwprintf(stderr, L"install needs an elevated command prompt\n");
            return 1;
        }
        return CommandInstall(argv[2]);
    }
    if (_wcsicmp(argv[1], L"remove") == 0) {
        if (!IsElevated()) {
            fwprintf(stderr, L"remove needs an elevated command prompt\n");
            return 1;
        }
        return CommandRemove();
    }
    if (_wcsicmp(argv[1], L"status") == 0) {
        return CommandStatus();
    }

    Usage();
    return 1;
}

