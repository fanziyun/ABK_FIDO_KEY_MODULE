/*++

Module Name:

    abkfidovhid.c

Abstract:

    ABK FIDO virtual HID driver.

    Windows has no in-box equivalent of Linux' /dev/uhid, and the Windows
    WebAuthn stack only talks to devices that the HID class driver enumerated,
    so relaying CTAP traffic from the phone over the LAN needs a real HID
    device on the desktop. This driver is that device: VHF publishes a CTAP
    HID authenticator (usage page 0xF1D0, 64-byte unnumbered reports) on
    behalf of a root-enumerated software devnode, and the agent moves frames
    through \\.\ABKFidoVhid with ordinary reads and writes.

Environment:

    Kernel mode only.

--*/

#include "abkfidovhid.h"

//
// CTAP HID report descriptor: one application collection with a 64-byte input
// report and a 64-byte output report, both unnumbered. Byte for byte the same
// descriptor the Linux uhid path writes in buildUHIDCreate2, because the
// browsers on both platforms match a security key on exactly these items.
//
static UCHAR g_AbkReportDescriptor[] = {
    0x06, 0xD0, 0xF1,       // USAGE_PAGE (FIDO Alliance)
    0x09, 0x01,             // USAGE (CTAP HID authenticator)
    0xA1, 0x01,             // COLLECTION (Application)
    0x09, 0x20,             //   USAGE (Input Report Data)
    0x15, 0x00,             //   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00,       //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,             //   REPORT_SIZE (8)
    0x95, 0x40,             //   REPORT_COUNT (64)
    0x81, 0x02,             //   INPUT (Data,Var,Abs)
    0x09, 0x21,             //   USAGE (Output Report Data)
    0x15, 0x00,             //   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00,       //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,             //   REPORT_SIZE (8)
    0x95, 0x40,             //   REPORT_COUNT (64)
    0x91, 0x02,             //   OUTPUT (Data,Var,Abs)
    0xC0                    // END_COLLECTION
};
DECLARE_CONST_UNICODE_STRING(g_AbkDeviceName, L"\\Device\\ABKFidoVhid");
DECLARE_CONST_UNICODE_STRING(g_AbkSymbolicLink, L"\\DosDevices\\ABKFidoVhid");

//
// Whoever holds a handle to this device is the security key: it can answer
// registration and assertion requests on behalf of the user. Restrict it to
// SYSTEM and the local Administrators group, which is also why the agent has
// to run elevated.
//
DECLARE_CONST_UNICODE_STRING(g_AbkSddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

static EVT_WDF_OBJECT_CONTEXT_CLEANUP AbkEvtDeviceCleanup;
static NTSTATUS AbkQueuesCreate(_In_ PABK_DEVICE_CONTEXT Context);
static NTSTATUS AbkVhfInitialize(_In_ PABK_DEVICE_CONTEXT Context);
static VOID AbkDeliverHostReport(_In_ PABK_DEVICE_CONTEXT Context,
                                 _In_reads_bytes_(ABK_REPORT_SIZE) PUCHAR Frame);
static VOID AbkCompleteReadWithFrame(_In_ WDFREQUEST Request,
                                     _In_reads_bytes_(ABK_REPORT_SIZE) PUCHAR Frame);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, AbkEvtDeviceAdd)
#pragma alloc_text(PAGE, AbkEvtDeviceSelfManagedIoInit)
#pragma alloc_text(PAGE, AbkEvtDeviceSelfManagedIoCleanup)
#pragma alloc_text(PAGE, AbkEvtDeviceCleanup)
#pragma alloc_text(PAGE, AbkQueuesCreate)
#pragma alloc_text(PAGE, AbkVhfInitialize)
#endif

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    WDF_DRIVER_CONFIG config;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    WDF_DRIVER_CONFIG_INIT(&config, AbkEvtDeviceAdd);

    return WdfDriverCreate(DriverObject,
                           RegistryPath,
                           WDF_NO_OBJECT_ATTRIBUTES,
                           &config,
                           WDF_NO_HANDLE);
}
NTSTATUS
AbkEvtDeviceAdd(
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
{
    NTSTATUS                     status;
    WDF_OBJECT_ATTRIBUTES        attributes;
    WDF_PNPPOWER_EVENT_CALLBACKS pnpPower;
    WDFDEVICE                    device;
    PABK_DEVICE_CONTEXT          context;

    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    status = WdfDeviceInitAssignName(DeviceInit, &g_AbkDeviceName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Only meaningful together with the name assigned above.
    status = WdfDeviceInitAssignSDDLString(DeviceInit, &g_AbkSddl);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WdfDeviceInitSetIoType(DeviceInit, WdfDeviceIoBuffered);

    // One relay at a time. A second agent would otherwise steal half of the
    // frames from the first and both transactions would time out.
    WdfDeviceInitSetExclusive(DeviceInit, TRUE);

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPower);
    pnpPower.EvtDeviceSelfManagedIoInit = AbkEvtDeviceSelfManagedIoInit;
    pnpPower.EvtDeviceSelfManagedIoCleanup = AbkEvtDeviceSelfManagedIoCleanup;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPower);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, ABK_DEVICE_CONTEXT);
    attributes.EvtCleanupCallback = AbkEvtDeviceCleanup;

    status = WdfDeviceCreate(&DeviceInit, &attributes, &device);
    if (!NT_SUCCESS(status)) {
        KdPrint(("abkfidovhid: WdfDeviceCreate failed 0x%x\n", status));
        return status;
    }

    context = AbkGetDeviceContext(device);
    context->Device = device;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ParentObject = device;
    status = WdfSpinLockCreate(&attributes, &context->Lock);
    if (!NT_SUCCESS(status)) {
        KdPrint(("abkfidovhid: WdfSpinLockCreate failed 0x%x\n", status));
        return status;
    }

    status = AbkQueuesCreate(context);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = AbkVhfInitialize(context);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // \\.\ABKFidoVhid, the path the agent opens.
    status = WdfDeviceCreateSymbolicLink(device, &g_AbkSymbolicLink);
    if (!NT_SUCCESS(status)) {
        KdPrint(("abkfidovhid: WdfDeviceCreateSymbolicLink failed 0x%x\n", status));
    }

    return status;
}

static NTSTATUS
AbkQueuesCreate(
    _In_ PABK_DEVICE_CONTEXT Context
    )
{
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE            defaultQueue;
    NTSTATUS            status;

    PAGED_CODE();

    //
    // Neither queue is power managed. The agent keeps a read outstanding for
    // as long as it runs, and a power-managed queue holding it would make
    // every device power transition wait for a frame that only arrives when
    // the user touches a web page.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoRead = AbkEvtIoRead;
    queueConfig.EvtIoWrite = AbkEvtIoWrite;
    queueConfig.EvtIoDeviceControl = AbkEvtIoDeviceControl;
    queueConfig.PowerManaged = WdfFalse;

    status = WdfIoQueueCreate(Context->Device,
                              &queueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES,
                              &defaultQueue);
    if (!NT_SUCCESS(status)) {
        KdPrint(("abkfidovhid: default WdfIoQueueCreate failed 0x%x\n", status));
        return status;
    }

    //
    // Reads that arrive with an empty backlog wait here. The framework owns
    // them until AbkDeliverHostReport pulls one out, so it also cancels them
    // when the agent closes its handle or the device is removed.
    //
    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    queueConfig.PowerManaged = WdfFalse;

    status = WdfIoQueueCreate(Context->Device,
                              &queueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES,
                              &Context->ReadQueue);
    if (!NT_SUCCESS(status)) {
        KdPrint(("abkfidovhid: manual WdfIoQueueCreate failed 0x%x\n", status));
    }

    return status;
}
static NTSTATUS
AbkVhfInitialize(
    _In_ PABK_DEVICE_CONTEXT Context
    )
{
    VHF_CONFIG config;
    NTSTATUS   status;

    PAGED_CODE();

    VHF_CONFIG_INIT(&config,
                    WdfDeviceWdmGetDeviceObject(Context->Device),
                    (USHORT)sizeof(g_AbkReportDescriptor),
                    g_AbkReportDescriptor);

    config.VhfClientContext = Context;
    config.VendorID = ABK_VENDOR_ID;
    config.ProductID = ABK_PRODUCT_ID;
    config.VersionNumber = ABK_VERSION;

    //
    // Output reports are the traffic CTAP HID is built around, but a host is
    // free to fetch a response with IOCTL_HID_GET_INPUT_REPORT instead of
    // reading the input pipe, and leaving that callback NULL makes VHF fail
    // those requests - which looks to the host like a key that never answers.
    // Feature reports have no meaning for this descriptor and stay unhandled.
    // EvtVhfReadyForNextReadReport is deliberately absent too - without it VHF
    // buffers submitted reports, so AbkEvtIoWrite may hand it a stack buffer
    // and return.
    //
    config.EvtVhfAsyncOperationWriteReport = AbkEvtVhfWriteReport;
    config.EvtVhfAsyncOperationGetInputReport = AbkEvtVhfGetInputReport;

    status = VhfCreate(&config, &Context->VhfHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("abkfidovhid: VhfCreate failed 0x%x\n", status));
    }

    return status;
}

NTSTATUS
AbkEvtDeviceSelfManagedIoInit(
    _In_ WDFDEVICE Device
    )
{
    PABK_DEVICE_CONTEXT context = AbkGetDeviceContext(Device);
    NTSTATUS            status;

    PAGED_CODE();

    // VHF callbacks stay silent until this point, so everything the driver
    // needs is already in place.
    status = VhfStart(context->VhfHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("abkfidovhid: VhfStart failed 0x%x\n", status));
        return status;
    }

    WdfSpinLockAcquire(context->Lock);
    context->VhfStarted = TRUE;
    WdfSpinLockRelease(context->Lock);

    return STATUS_SUCCESS;
}

VOID
AbkEvtDeviceSelfManagedIoCleanup(
    _In_ WDFDEVICE Device
    )
{
    PABK_DEVICE_CONTEXT context = AbkGetDeviceContext(Device);

    PAGED_CODE();

    //
    // Clearing the flag under the lock is the barrier VhfDelete needs: a
    // submit either took the lock before this and finished, or it will see
    // VhfStarted == FALSE and never touch the handle.
    //
    WdfSpinLockAcquire(context->Lock);
    context->VhfStarted = FALSE;
    WdfSpinLockRelease(context->Lock);

    if (context->VhfHandle != NULL) {
        VhfDelete(context->VhfHandle, TRUE);
        context->VhfHandle = NULL;
    }
}

//
// Reached when the device is destroyed without ever having started its
// self-managed I/O, for instance because VhfStart failed. Without this the VHF
// handle created in AbkEvtDeviceAdd would leak.
//
static VOID
AbkEvtDeviceCleanup(
    _In_ WDFOBJECT Object
    )
{
    PABK_DEVICE_CONTEXT context = AbkGetDeviceContext((WDFDEVICE)Object);

    PAGED_CODE();

    if (context->VhfHandle != NULL) {
        VhfDelete(context->VhfHandle, TRUE);
        context->VhfHandle = NULL;
    }
}
VOID
AbkEvtIoRead(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     Length
    )
{
    PABK_DEVICE_CONTEXT context = AbkGetDeviceContext(WdfIoQueueGetDevice(Queue));
    UCHAR               frame[ABK_REPORT_SIZE] = { 0 };
    BOOLEAN             haveFrame = FALSE;
    NTSTATUS            status = STATUS_SUCCESS;

    if (Length < ABK_REPORT_SIZE) {
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return;
    }

    WdfSpinLockAcquire(context->Lock);
    if (context->Count > 0) {
        RtlCopyMemory(frame, context->Ring[context->Tail], ABK_REPORT_SIZE);
        context->Tail = (context->Tail + 1) % ABK_RING_SLOTS;
        context->Count--;
        haveFrame = TRUE;
    } else {
        status = WdfRequestForwardToIoQueue(Request, context->ReadQueue);
    }
    WdfSpinLockRelease(context->Lock);

    if (haveFrame) {
        AbkCompleteReadWithFrame(Request, frame);
    } else if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
    }
}

VOID
AbkEvtIoWrite(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     Length
    )
{
    PABK_DEVICE_CONTEXT context = AbkGetDeviceContext(WdfIoQueueGetDevice(Queue));
    HID_XFER_PACKET     packet;
    PVOID               buffer;
    size_t              bufferLength;
    PUCHAR              data;
    UCHAR               report[1 + ABK_REPORT_SIZE];
    BOOLEAN             reportIdLeads;
    NTSTATUS            status;

    if (Length < ABK_REPORT_SIZE) {
        WdfRequestComplete(Request, STATUS_INVALID_BUFFER_SIZE);
        return;
    }

    status = WdfRequestRetrieveInputBuffer(Request, ABK_REPORT_SIZE, &buffer, &bufferLength);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    // Accept a leading zero report id as well, so a caller that follows the
    // numbered-report convention is not off by one byte.
    data = (PUCHAR)buffer;
    if (bufferLength > ABK_REPORT_SIZE && data[0] == 0) {
        data++;
    }

    //
    // HID_XFER_PACKET carries the report id as the first byte of the buffer,
    // and whether HIDClass applies that to an unnumbered descriptor is only
    // half answered by the traffic coming the other way: the host's output
    // reports arrive in AbkEvtVhfWriteReport in some shape, and the reply is
    // sent back in the same one unless ABK_IOCTL_SET_REPORT_MODE says
    // otherwise. Submitting the wrong shape puts every reply one byte out of
    // place - HIDClass reads our first byte, 0xff for the broadcast channel, as
    // a report id it has never heard of - and the host sees nothing but its own
    // CTAPHID_INIT timing out.
    //
    WdfSpinLockAcquire(context->Lock);
    switch (context->ReportMode) {
    case ABK_REPORT_MODE_PLAIN:
        reportIdLeads = FALSE;
        break;
    case ABK_REPORT_MODE_LEADING_ID:
        reportIdLeads = TRUE;
        break;
    default:
        reportIdLeads = context->ReportIdSeen ? context->ReportIdLeads : TRUE;
        break;
    }
    WdfSpinLockRelease(context->Lock);

    if (reportIdLeads) {
        report[0] = 0;
        RtlCopyMemory(report + 1, data, ABK_REPORT_SIZE);
        packet.reportBuffer = report;
        packet.reportBufferLen = 1 + ABK_REPORT_SIZE;
    } else {
        packet.reportBuffer = data;
        packet.reportBufferLen = ABK_REPORT_SIZE;
    }
    packet.reportId = 0;

    WdfSpinLockAcquire(context->Lock);
    if (context->VhfStarted) {
        status = VhfReadReportSubmit(context->VhfHandle, &packet);
        if (status == STATUS_INVALID_BUFFER_SIZE ||
            status == STATUS_INVALID_PARAMETER) {
            // Whatever this VHF build wants, it is not what was just tried.
            KdPrint(("abkfidovhid: %u-byte submit refused 0x%x, retrying with %u\n",
                     packet.reportBufferLen, status,
                     reportIdLeads ? ABK_REPORT_SIZE : 1 + ABK_REPORT_SIZE));
            if (reportIdLeads) {
                packet.reportBuffer = data;
                packet.reportBufferLen = ABK_REPORT_SIZE;
            } else {
                report[0] = 0;
                RtlCopyMemory(report + 1, data, ABK_REPORT_SIZE);
                packet.reportBuffer = report;
                packet.reportBufferLen = 1 + ABK_REPORT_SIZE;
            }
            status = VhfReadReportSubmit(context->VhfHandle, &packet);
        }
    } else {
        status = STATUS_DEVICE_NOT_READY;
    }

    context->Stats.LastSubmitStatus = (ULONG)status;
    context->Stats.LastSubmitLen = packet.reportBufferLen;
    if (NT_SUCCESS(status)) {
        context->Stats.Submitted++;
        // Keep the frame for a host that polls with GET_INPUT_REPORT rather
        // than reading the input pipe. Oldest goes first: a reply the host
        // never collected belongs to a transaction it has given up on.
        if (context->ReplyCount == ABK_REPLY_SLOTS) {
            context->ReplyTail = (context->ReplyTail + 1) % ABK_REPLY_SLOTS;
            context->ReplyCount--;
        }
        RtlCopyMemory(context->Replies[context->ReplyHead], data, ABK_REPORT_SIZE);
        context->ReplyHead = (context->ReplyHead + 1) % ABK_REPLY_SLOTS;
        context->ReplyCount++;
        context->Stats.ReplyBacklog = context->ReplyCount;
    } else {
        context->Stats.SubmitFailures++;
    }
    WdfSpinLockRelease(context->Lock);

    WdfRequestCompleteWithInformation(Request, status, NT_SUCCESS(status) ? Length : 0);
}
VOID
AbkEvtVhfWriteReport(
    _In_     PVOID              VhfClientContext,
    _In_     VHFOPERATIONHANDLE VhfOperationHandle,
    _In_opt_ PVOID              VhfOperationContext,
    _In_     PHID_XFER_PACKET   HidTransferPacket
    )
{
    PABK_DEVICE_CONTEXT context = (PABK_DEVICE_CONTEXT)VhfClientContext;
    UCHAR               frame[ABK_REPORT_SIZE];
    PUCHAR              data;
    ULONG               length;

    UNREFERENCED_PARAMETER(VhfOperationContext);

    data = HidTransferPacket->reportBuffer;
    length = HidTransferPacket->reportBufferLen;

    if (data == NULL || length == 0) {
        VhfAsyncOperationComplete(VhfOperationHandle, STATUS_INVALID_PARAMETER);
        return;
    }

    //
    // The descriptor is unnumbered, so a frame is 64 bytes of payload. A
    // caller that prepends the customary zero report id arrives here with 65;
    // dropping that byte is the same correction parseUHIDOutput makes on
    // Linux, and without it every relayed frame is shifted by one and the
    // authenticator sees garbage. Remember which shape this HIDClass uses:
    // AbkEvtIoWrite has to submit input reports the same way.
    //
    WdfSpinLockAcquire(context->Lock);
    context->ReportIdLeads = (length > ABK_REPORT_SIZE) ? TRUE : FALSE;
    context->ReportIdSeen = TRUE;
    context->Stats.HostReports++;
    context->Stats.LastHostReportLen = length;
    WdfSpinLockRelease(context->Lock);

    if (length > ABK_REPORT_SIZE && data[0] == 0) {
        data++;
        length--;
    }
    if (length > ABK_REPORT_SIZE) {
        length = ABK_REPORT_SIZE;
    }

    // A CTAP frame is fixed width, while a host may send only the bytes it
    // filled in; pad rather than forward a short frame the phone would reject.
    RtlZeroMemory(frame, sizeof(frame));
    RtlCopyMemory(frame, data, length);

    AbkDeliverHostReport(context, frame);

    VhfAsyncOperationComplete(VhfOperationHandle, STATUS_SUCCESS);
}

VOID
AbkEvtIoDeviceControl(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     OutputBufferLength,
    _In_ size_t     InputBufferLength,
    _In_ ULONG      IoControlCode
    )
{
    PABK_DEVICE_CONTEXT context = AbkGetDeviceContext(WdfIoQueueGetDevice(Queue));
    PVOID               buffer;
    size_t              bufferLength;
    NTSTATUS            status;

    if (IoControlCode == ABK_IOCTL_SET_REPORT_MODE) {
        ULONG mode;

        if (InputBufferLength < sizeof(ULONG)) {
            WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
            return;
        }
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(ULONG), &buffer, &bufferLength);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
            return;
        }
        mode = *(PULONG)buffer;
        if (mode > (ULONG)ABK_REPORT_MODE_LEADING_ID) {
            WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
            return;
        }

        WdfSpinLockAcquire(context->Lock);
        context->ReportMode = mode;
        context->Stats.ReportMode = mode;
        WdfSpinLockRelease(context->Lock);

        KdPrint(("abkfidovhid: report mode set to %u\n", mode));
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;
    }

    if (IoControlCode != ABK_IOCTL_GET_STATS) {
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        return;
    }
    if (OutputBufferLength < sizeof(ABK_STATS)) {
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return;
    }

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(ABK_STATS), &buffer,
                                            &bufferLength);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    WdfSpinLockAcquire(context->Lock);
    context->Stats.Size = sizeof(ABK_STATS);
    context->Stats.Dropped = context->Dropped;
    context->Stats.ReplyBacklog = context->ReplyCount;
    context->Stats.ReportMode = context->ReportMode;
    RtlCopyMemory(buffer, &context->Stats, sizeof(ABK_STATS));
    WdfSpinLockRelease(context->Lock);

    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(ABK_STATS));
}

//
// A host that fetches responses with IOCTL_HID_GET_INPUT_REPORT instead of
// reading the input pipe ends up here. Hand it the oldest reply that has not
// been collected yet; with nothing queued there is nothing to report, and
// STATUS_NO_MORE_ENTRIES tells the host to come back rather than that the
// device is broken.
//
VOID
AbkEvtVhfGetInputReport(
    _In_     PVOID              VhfClientContext,
    _In_     VHFOPERATIONHANDLE VhfOperationHandle,
    _In_opt_ PVOID              VhfOperationContext,
    _In_     PHID_XFER_PACKET   HidTransferPacket
    )
{
    PABK_DEVICE_CONTEXT context = (PABK_DEVICE_CONTEXT)VhfClientContext;
    UCHAR               frame[ABK_REPORT_SIZE];
    PUCHAR              out;
    ULONG               capacity;
    BOOLEAN             haveFrame = FALSE;

    UNREFERENCED_PARAMETER(VhfOperationContext);

    out = HidTransferPacket->reportBuffer;
    capacity = HidTransferPacket->reportBufferLen;
    if (out == NULL || capacity == 0) {
        VhfAsyncOperationComplete(VhfOperationHandle, STATUS_INVALID_PARAMETER);
        return;
    }

    WdfSpinLockAcquire(context->Lock);
    context->Stats.GetInputReports++;
    if (context->ReplyCount > 0) {
        RtlCopyMemory(frame, context->Replies[context->ReplyTail], ABK_REPORT_SIZE);
        context->ReplyTail = (context->ReplyTail + 1) % ABK_REPLY_SLOTS;
        context->ReplyCount--;
        context->Stats.GetInputServed++;
        context->Stats.ReplyBacklog = context->ReplyCount;
        haveFrame = TRUE;
    }
    WdfSpinLockRelease(context->Lock);

    if (!haveFrame) {
        VhfAsyncOperationComplete(VhfOperationHandle, STATUS_NO_MORE_ENTRIES);
        return;
    }

    // Mirror whatever shape the caller asked for: a 65-byte buffer wants the
    // zero report id first, a 64-byte one just the frame.
    if (capacity > ABK_REPORT_SIZE) {
        out[0] = 0;
        RtlCopyMemory(out + 1, frame, ABK_REPORT_SIZE);
        HidTransferPacket->reportBufferLen = 1 + ABK_REPORT_SIZE;
    } else {
        RtlCopyMemory(out, frame, ABK_REPORT_SIZE);
        HidTransferPacket->reportBufferLen = ABK_REPORT_SIZE;
    }
    HidTransferPacket->reportId = 0;

    VhfAsyncOperationComplete(VhfOperationHandle, STATUS_SUCCESS);
}

static VOID
AbkDeliverHostReport(
    _In_ PABK_DEVICE_CONTEXT Context,
    _In_reads_bytes_(ABK_REPORT_SIZE) PUCHAR Frame
    )
{
    WDFREQUEST request = NULL;

    WdfSpinLockAcquire(Context->Lock);

    // Handing the frame straight to a waiting reader is only correct while the
    // backlog is empty, otherwise frames would overtake each other.
    if (Context->Count == 0) {
        if (!NT_SUCCESS(WdfIoQueueRetrieveNextRequest(Context->ReadQueue, &request))) {
            request = NULL;
        }
    }

    if (request == NULL) {
        if (Context->Count == ABK_RING_SLOTS) {
            //
            // The relay is not draining. Drop the oldest frame - it belongs to
            // a transaction the host has long since timed out - and keep the
            // newest, which is the one still worth answering.
            //
            Context->Tail = (Context->Tail + 1) % ABK_RING_SLOTS;
            Context->Count--;
            Context->Dropped++;
            KdPrint(("abkfidovhid: host report backlog full, dropped %u total\n",
                     Context->Dropped));
        }
        RtlCopyMemory(Context->Ring[Context->Head], Frame, ABK_REPORT_SIZE);
        Context->Head = (Context->Head + 1) % ABK_RING_SLOTS;
        Context->Count++;
    }

    WdfSpinLockRelease(Context->Lock);

    if (request != NULL) {
        AbkCompleteReadWithFrame(request, Frame);
    }
}

static VOID
AbkCompleteReadWithFrame(
    _In_ WDFREQUEST Request,
    _In_reads_bytes_(ABK_REPORT_SIZE) PUCHAR Frame
    )
{
    NTSTATUS status;
    PVOID    buffer;

    status = WdfRequestRetrieveOutputBuffer(Request, ABK_REPORT_SIZE, &buffer, NULL);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    RtlCopyMemory(buffer, Frame, ABK_REPORT_SIZE);
    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, ABK_REPORT_SIZE);
}

