/*++

Module Name:

    abkvhidctl.cpp

Abstract:

    Creates, inspects and removes the root-enumerated devnode that the ABK
    FIDO virtual HID driver binds to. pnputil can stage and even install a
    driver package, but it cannot invent a devnode for hardware that does not
    exist, which is exactly what a software-only HID source needs - so this
    does the same three SetupAPI calls devcon's `install` command makes.

    It also carries the `loopback` command, which plays both host and key to
    prove whether the driver actually carries a CTAP frame through the HID
    stack in each direction.

    Usage:

        abkvhidctl install <path to abkfidovhid.inf>
        abkvhidctl remove
        abkvhidctl status
        abkvhidctl loopback

    install, remove and loopback need an elevated command prompt.

--*/

#include <windows.h>
#include <winioctl.h>
#include <setupapi.h>
#include <newdev.h>
#include <cfgmgr32.h>
#include <strsafe.h>
#include <stdio.h>
#include <string.h>
extern "C" {
#include <hidusage.h>
#include <hidsdi.h>
#include <hidpi.h>
}

// Must match the hardware id in abkfidovhid.inx.
static const wchar_t kHardwareId[] = L"root\\ABKFIDOVHID";

// Must match g_AbkSymbolicLink in abkfidovhid.c.
static const wchar_t kControlDevice[] = L"\\\\.\\ABKFidoVhid";

// Must match ABK_VENDOR_ID / ABK_PRODUCT_ID / ABK_REPORT_SIZE in abkfidovhid.h.
static const USHORT kVendorId = 0xABCD;
static const USHORT kProductId = 0x1D02;
static const DWORD  kReportSize = 64;

// FIDO Alliance usage page, CTAP HID authenticator usage.
static const USHORT kFidoUsagePage = 0xF1D0;
static const USHORT kFidoUsage = 0x01;

// ABK_IOCTL_SET_REPORT_MODE and the ABK_REPORT_MODE_* values it takes, from
// abkfidovhid.h. The mode lives in the device context, so it stays set after
// this tool exits and applies to the agent that runs next.
static const DWORD kIoctlSetReportMode =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA);
static const DWORD kReportModePlain = 1;
static const DWORD kReportModeLeadingId = 2;

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

//
// Everything below drives the `loopback` command, which answers the one
// question the agent's own logs cannot: whether a report handed to the driver
// actually comes back out of the HID stack. It plays both parts - the host
// writing an output report through the HID interface Windows published, and the
// key answering through \\.\ABKFidoVhid - so a broken leg is named without the
// phone, the relay or webauthn.dll being involved at all.
//

// Locates the HID interface VHF published for this driver, and reads back the
// report lengths HIDClass computed from the descriptor. Opened with no access,
// which is all HidD_GetAttributes needs and all that a device already opened
// for I/O elsewhere will grant.
static bool FindAbkHidPath(_Out_writes_(PathChars) wchar_t* Path, _In_ size_t PathChars,
                           _Out_ HIDP_CAPS* Caps)
{
    GUID hidGuid = {};
    struct {
        SP_DEVICE_INTERFACE_DETAIL_DATA_W header;
        wchar_t                          space[MAX_PATH];
    } detail = {};
    SP_DEVICE_INTERFACE_DATA ifData = {};
    bool found = false;

    *Path = L'\0';
    ZeroMemory(Caps, sizeof(*Caps));

    HidD_GetHidGuid(&hidGuid);
    HDEVINFO devices = SetupDiGetClassDevsW(&hidGuid, nullptr, nullptr,
                                           DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    if (devices == INVALID_HANDLE_VALUE) {
        ReportError(L"SetupDiGetClassDevs(HID)");
        return false;
    }

    ifData.cbSize = sizeof(ifData);
    for (DWORD index = 0;
         !found && SetupDiEnumDeviceInterfaces(devices, nullptr, &hidGuid, index, &ifData);
         index++) {
        detail.header.cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        if (!SetupDiGetDeviceInterfaceDetailW(devices, &ifData, &detail.header, sizeof(detail),
                                              nullptr, nullptr)) {
            continue;
        }

        HANDLE device = CreateFileW(detail.header.DevicePath, 0,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                    0, nullptr);
        if (device == INVALID_HANDLE_VALUE) {
            continue;
        }

        HIDD_ATTRIBUTES attributes = {};
        PHIDP_PREPARSED_DATA preparsed = nullptr;
        attributes.Size = sizeof(attributes);
        if (HidD_GetAttributes(device, &attributes) && attributes.VendorID == kVendorId &&
            attributes.ProductID == kProductId && HidD_GetPreparsedData(device, &preparsed)) {
            if (HidP_GetCaps(preparsed, Caps) == HIDP_STATUS_SUCCESS &&
                SUCCEEDED(StringCchCopyW(Path, PathChars, detail.header.DevicePath))) {
                found = true;
            }
            HidD_FreePreparsedData(preparsed);
        }
        CloseHandle(device);
    }

    SetupDiDestroyDeviceInfoList(devices);
    return found;
}

static void DumpFrame(_In_z_ const wchar_t* Label, _In_reads_bytes_(Length) const BYTE* Frame,
                      _In_ DWORD Length)
{
    wprintf(L"  %s", Label);
    for (DWORD i = 0; i < Length; i++) {
        wprintf(L"%s%02X", (i % 16) == 0 ? L"\n    " : L" ", static_cast<unsigned>(Frame[i]));
    }
    wprintf(L"\n");
}

//
// A read that is posted before the write that should satisfy it, because that
// is the order both real sides use: the agent keeps a read outstanding on the
// control device, and the HID stack has a read pending on the input pipe.
//
struct PendingRead {
    HANDLE     handle;
    OVERLAPPED overlapped;
    BYTE       buffer[1 + kReportSize + 8];
};

static bool StartRead(_Out_ PendingRead* Pending, _In_ HANDLE Handle, _In_ DWORD Length,
                      _In_z_ const wchar_t* What)
{
    ZeroMemory(Pending, sizeof(*Pending));
    Pending->handle = Handle;
    Pending->overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (Pending->overlapped.hEvent == nullptr) {
        ReportError(L"CreateEvent");
        return false;
    }
    if (!ReadFile(Handle, Pending->buffer, Length, nullptr, &Pending->overlapped) &&
        GetLastError() != ERROR_IO_PENDING) {
        ReportError(What);
        CloseHandle(Pending->overlapped.hEvent);
        Pending->overlapped.hEvent = nullptr;
        return false;
    }
    return true;
}

// Bytes read, or -1 when the deadline passed or the read failed. Either way the
// request is off the queue and the event is closed by the time this returns.
static int FinishRead(_Inout_ PendingRead* Pending, _In_ DWORD TimeoutMs,
                      _In_z_ const wchar_t* What)
{
    DWORD read = 0;
    int   result = -1;

    const DWORD wait = WaitForSingleObject(Pending->overlapped.hEvent, TimeoutMs);
    if (wait == WAIT_TIMEOUT) {
        fwprintf(stderr, L"%s: nothing arrived within %lu ms\n", What, TimeoutMs);
        CancelIoEx(Pending->handle, &Pending->overlapped);
        WaitForSingleObject(Pending->overlapped.hEvent, INFINITE);
    } else if (wait != WAIT_OBJECT_0) {
        ReportError(L"WaitForSingleObject");
    } else if (!GetOverlappedResult(Pending->handle, &Pending->overlapped, &read, FALSE)) {
        ReportError(What);
    } else {
        result = static_cast<int>(read);
    }

    CloseHandle(Pending->overlapped.hEvent);
    Pending->overlapped.hEvent = nullptr;
    return result;
}

// Drops a posted read whose triggering write never happened, quietly: the write
// already said what went wrong.
static void CancelRead(_Inout_ PendingRead* Pending)
{
    DWORD read = 0;

    CancelIoEx(Pending->handle, &Pending->overlapped);
    WaitForSingleObject(Pending->overlapped.hEvent, INFINITE);
    GetOverlappedResult(Pending->handle, &Pending->overlapped, &read, FALSE);
    CloseHandle(Pending->overlapped.hEvent);
    Pending->overlapped.hEvent = nullptr;
}

static bool WriteReport(_In_ HANDLE Handle, _In_reads_bytes_(Length) const BYTE* Buffer,
                        _In_ DWORD Length, _In_z_ const wchar_t* What)
{
    OVERLAPPED overlapped = {};
    DWORD      written = 0;
    bool       ok = false;

    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (overlapped.hEvent == nullptr) {
        ReportError(L"CreateEvent");
        return false;
    }
    if (WriteFile(Handle, Buffer, Length, nullptr, &overlapped) ||
        GetLastError() == ERROR_IO_PENDING) {
        if (WaitForSingleObject(overlapped.hEvent, 2000) != WAIT_OBJECT_0) {
            fwprintf(stderr, L"%s: did not complete within 2000 ms\n", What);
            CancelIoEx(Handle, &overlapped);
            WaitForSingleObject(overlapped.hEvent, INFINITE);
        } else if (!GetOverlappedResult(Handle, &overlapped, &written, FALSE)) {
            ReportError(What);
        } else if (written != Length) {
            fwprintf(stderr, L"%s: wrote %lu of %lu bytes\n", What, written, Length);
        } else {
            ok = true;
        }
    } else {
        ReportError(What);
    }

    CloseHandle(overlapped.hEvent);
    return ok;
}

// Tells the driver which shape to submit input reports in. The handle is
// overlapped, so even a control request that finishes instantly has to be
// waited on.
static bool SetReportMode(_In_ HANDLE Control, _In_ DWORD Mode)
{
    OVERLAPPED overlapped = {};
    DWORD      returned = 0;
    DWORD      mode = Mode;
    bool       ok = false;

    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (overlapped.hEvent == nullptr) {
        ReportError(L"CreateEvent");
        return false;
    }
    if (DeviceIoControl(Control, kIoctlSetReportMode, &mode, sizeof(mode), nullptr, 0, &returned,
                        &overlapped) ||
        GetLastError() == ERROR_IO_PENDING) {
        if (WaitForSingleObject(overlapped.hEvent, 2000) == WAIT_OBJECT_0 &&
            GetOverlappedResult(Control, &overlapped, &returned, FALSE)) {
            ok = true;
        } else {
            ReportError(L"setting the report mode");
        }
    } else {
        ReportError(L"setting the report mode");
    }

    CloseHandle(overlapped.hEvent);
    return ok;
}

// A CTAPHID_INIT on the broadcast channel: the first thing any host sends, and
// the exchange the Windows WebAuthn stack is currently stuck repeating.
static void BuildInitRequest(_Out_writes_bytes_all_(kReportSize) BYTE* Frame)
{
    ZeroMemory(Frame, kReportSize);
    Frame[0] = 0xFF;    // broadcast channel
    Frame[1] = 0xFF;
    Frame[2] = 0xFF;
    Frame[3] = 0xFF;
    Frame[4] = 0x86;    // CTAPHID_INIT
    Frame[6] = 0x08;    // 8-byte payload
    for (DWORD i = 0; i < 8; i++) {
        Frame[7 + i] = static_cast<BYTE>(0xA0 + i);
    }
}

static void BuildInitReply(_In_reads_bytes_(kReportSize) const BYTE* Request,
                           _Out_writes_bytes_all_(kReportSize) BYTE* Frame)
{
    ZeroMemory(Frame, kReportSize);
    memcpy(Frame, Request, 4);           // answered on the channel it came in on
    Frame[4] = 0x86;
    Frame[6] = 0x11;                     // nonce + channel + 5 version bytes
    memcpy(Frame + 7, Request + 7, 8);   // the host matches the reply by its nonce
    Frame[15] = 0x12;                    // allocated channel id
    Frame[16] = 0x34;
    Frame[17] = 0x56;
    Frame[18] = 0x78;
    Frame[19] = 0x02;                    // CTAPHID protocol version
    Frame[20] = 0x01;                    // device version major/minor/build
    Frame[23] = 0x0D;                    // WINK | CBOR | NMSG
}

// Leg one: an output report written to the HID interface has to reach the agent
// as read data on the control device.
static bool LoopbackHostToDevice(_In_ HANDLE Hid, _In_ HANDLE Control, _In_ DWORD OutputLength,
                                 _In_reads_bytes_(kReportSize) const BYTE* Request)
{
    PendingRead pending = {};
    BYTE        report[1 + kReportSize] = {};

    if (!StartRead(&pending, Control, kReportSize, L"read from the control device")) {
        return false;
    }

    // HIDClass sizes an output report as report id plus payload, so the report
    // id byte stays 0 for this unnumbered descriptor.
    memcpy(report + 1, Request, kReportSize);
    if (!WriteReport(Hid, report, OutputLength, L"writing an output report")) {
        CancelRead(&pending);
        return false;
    }

    const int got = FinishRead(&pending, 2000, L"read from the control device");
    if (got < 0) {
        fwprintf(stderr, L"host -> device: FAILED. The output report never reached the "
                         L"control device.\n");
        return false;
    }
    if (got != static_cast<int>(kReportSize) ||
        memcmp(pending.buffer, Request, kReportSize) != 0) {
        fwprintf(stderr, L"host -> device: FAILED. %d bytes came back, and not the ones "
                         L"written.\n", got);
        DumpFrame(L"sent:", Request, kReportSize);
        DumpFrame(L"read:", pending.buffer, static_cast<DWORD>(got));
        return false;
    }

    wprintf(L"host -> device: ok, 64 bytes arrived unchanged\n");
    return true;
}

// Leg two: a frame the agent writes to the control device has to come back out
// of the HID stack as an input report. This is the leg the INIT loop points at.
static bool LoopbackDeviceToHost(_In_ HANDLE Hid, _In_ HANDLE Control, _In_ DWORD InputLength,
                                 _In_reads_bytes_(kReportSize) const BYTE* Reply)
{
    PendingRead pending = {};

    if (!StartRead(&pending, Hid, InputLength, L"reading an input report")) {
        return false;
    }

    if (!WriteReport(Control, Reply, kReportSize, L"writing the reply to the control device")) {
        CancelRead(&pending);
        return false;
    }

    const int got = FinishRead(&pending, 2000, L"reading an input report");
    if (got < 0) {
        fwprintf(stderr,
                 L"device -> host: FAILED. The driver accepted the frame but the HID stack\n"
                 L"                never handed it back, so this is what the Windows WebAuthn\n"
                 L"                stack sees: a key that is written to and never answers.\n");
        return false;
    }

    // HIDClass hands an input report up with its report id in the first byte,
    // so a correct reply is 65 bytes of 0x00 followed by the frame. A 64-byte
    // read, or a frame shifted by one, is the report-id convention being wrong.
    const BYTE* payload = pending.buffer;
    if (got == static_cast<int>(InputLength) && InputLength == kReportSize + 1) {
        payload = pending.buffer + 1;
        if (pending.buffer[0] != 0) {
            fwprintf(stderr, L"device -> host: report id byte is 0x%02X, expected 0x00\n",
                     static_cast<unsigned>(pending.buffer[0]));
        }
    } else if (got != static_cast<int>(kReportSize)) {
        fwprintf(stderr, L"device -> host: FAILED. %d bytes came back, expected %lu.\n", got,
                 InputLength);
        DumpFrame(L"read:", pending.buffer, static_cast<DWORD>(got));
        return false;
    }

    if (memcmp(payload, Reply, kReportSize) != 0) {
        fwprintf(stderr, L"device -> host: FAILED. The frame came back altered.\n");
        DumpFrame(L"sent:", Reply, kReportSize);
        DumpFrame(L"read:", pending.buffer, static_cast<DWORD>(got));
        return false;
    }

    wprintf(L"device -> host: ok, the reply came back as a %d byte input report\n", got);
    return true;
}

static int CommandLoopback()
{
    wchar_t   path[MAX_PATH] = {};
    HIDP_CAPS caps = {};
    BYTE      request[kReportSize] = {};
    BYTE      reply[kReportSize] = {};

    if (!FindAbkHidPath(path, ARRAYSIZE(path), &caps)) {
        fwprintf(stderr,
                 L"no HID device with VID_%04X&PID_%04X is present. The driver is not started,\n"
                 L"or it started without VHF publishing the virtual key - run `abkvhidctl "
                 L"status`.\n",
                 static_cast<unsigned>(kVendorId), static_cast<unsigned>(kProductId));
        return 1;
    }

    wprintf(L"hid device: %s\n", path);
    wprintf(L"  usage page 0x%04X usage 0x%02X, reports: input %u, output %u, feature %u\n",
            static_cast<unsigned>(caps.UsagePage), static_cast<unsigned>(caps.Usage),
            static_cast<unsigned>(caps.InputReportByteLength),
            static_cast<unsigned>(caps.OutputReportByteLength),
            static_cast<unsigned>(caps.FeatureReportByteLength));
    if (caps.UsagePage != kFidoUsagePage || caps.Usage != kFidoUsage) {
        fwprintf(stderr, L"  this is not a CTAP HID collection (expected usage page 0x%04X "
                         L"usage 0x%02X); no WebAuthn stack will look at it\n",
                 static_cast<unsigned>(kFidoUsagePage), static_cast<unsigned>(kFidoUsage));
    }
    if (caps.InputReportByteLength != kReportSize + 1 ||
        caps.OutputReportByteLength != kReportSize + 1) {
        fwprintf(stderr, L"  expected %lu-byte reports (report id + 64 bytes of CTAP frame)\n",
                 kReportSize + 1);
    }
    if (caps.OutputReportByteLength == 0 || caps.OutputReportByteLength > 1 + kReportSize ||
        caps.InputReportByteLength == 0 || caps.InputReportByteLength > 1 + kReportSize) {
        fwprintf(stderr, L"  report lengths are unusable, stopping here\n");
        return 1;
    }

    // The same handle the agent opens, and the driver admits one client at a
    // time, so the two cannot both be running.
    HANDLE control = CreateFileW(kControlDevice, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                 OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (control == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_SHARING_VIOLATION) {
            fwprintf(stderr, L"%s is already open: stop the desktop agent first, the loopback "
                             L"plays its part.\n", kControlDevice);
            return 1;
        }
        ReportError(L"opening the control device");
        return 1;
    }

    HANDLE hid = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                             FILE_FLAG_OVERLAPPED, nullptr);
    if (hid == INVALID_HANDLE_VALUE) {
        ReportError(L"opening the HID device");
        CloseHandle(control);
        return 1;
    }

    BuildInitRequest(request);
    BuildInitReply(request, reply);

    bool ok = LoopbackHostToDevice(hid, control, caps.OutputReportByteLength, request);
    if (!ok) {
        fwprintf(stderr, L"\nthe host -> device leg is broken, so the agent never sees a request "
                         L"at all.\n");
    } else {
        // Both shapes get a turn rather than a rebuild each. The build byte of
        // the reply carries the attempt number so a frame left over from the
        // previous shape cannot pass for this one.
        const DWORD modes[] = {kReportModePlain, kReportModeLeadingId};

        ok = false;
        for (DWORD i = 0; !ok && i < ARRAYSIZE(modes); i++) {
            wprintf(L"\nsubmitting input reports %s report id byte:\n",
                    modes[i] == kReportModePlain ? L"with no" : L"with a leading");
            reply[22] = static_cast<BYTE>(i + 1);
            if (!SetReportMode(control, modes[i])) {
                break;
            }
            ok = LoopbackDeviceToHost(hid, control, caps.InputReportByteLength, reply);
        }

        if (ok) {
            wprintf(L"\nboth directions work, and the driver keeps this shape for as long as "
                    L"it stays\nloaded: start the agent and try a WebAuthn page again.\n");
        } else {
            fwprintf(stderr,
                     L"\nneither shape came back out of the HID stack, so the report shape is "
                     L"not what\nis wrong: nothing this driver submits reaches a reader at all.\n");
        }
    }

    CloseHandle(hid);
    CloseHandle(control);
    return ok ? 0 : 1;
}

static void Usage()
{
    wprintf(L"abkvhidctl - manage the ABK FIDO virtual HID devnode\n\n"
            L"  abkvhidctl install <path to abkfidovhid.inf>\n"
            L"  abkvhidctl remove\n"
            L"  abkvhidctl status\n"
            L"  abkvhidctl loopback\n\n"
            L"install, remove and loopback need an elevated command prompt. loopback moves a\n"
            L"CTAPHID_INIT through the driver in both directions and needs the agent stopped.\n");
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
    if (_wcsicmp(argv[1], L"loopback") == 0) {
        if (!IsElevated()) {
            fwprintf(stderr, L"loopback needs an elevated command prompt: the control device "
                             L"only admits SYSTEM and Administrators\n");
            return 1;
        }
        return CommandLoopback();
    }

    Usage();
    return 1;
}

