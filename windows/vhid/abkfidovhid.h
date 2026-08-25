/*++

Module Name:

    abkfidovhid.h

Abstract:

    Shared declarations for the ABK FIDO virtual HID driver: a KMDF function
    driver for the root-enumerated device root\ABKFIDOVHID that uses the
    Virtual HID Framework (VHF) to publish a CTAP HID authenticator to the
    Windows HID stack, and a plain read/write control device
    (\\.\ABKFidoVhid) that the desktop agent uses to move the 64-byte CTAP
    frames to and from the phone.

    Direction naming follows the HID stack, not the agent:

      host -> device  output reports, delivered by VHF to
                      AbkEvtVhfWriteReport, handed to user mode as READ data
      device -> host  input reports, taken from user-mode WRITE data and
                      handed to VHF with VhfReadReportSubmit

Environment:

    Kernel mode only.

--*/

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <vhf.h>

// A CTAP HID report is always exactly 64 bytes and carries no report id.
#define ABK_REPORT_SIZE 64

// Depth of the host->device backlog kept while no read is pending. Matches
// hidHub's maxPendingPackets in the agent, so both sides tolerate the same
// burst before anything is dropped.
#define ABK_RING_SLOTS 64

// Identity of the virtual key. Kept identical to the Linux uhid path
// (uhidVendorID / uhidProductID in agent/hid_linux.go) so the phone shows up
// as the same authenticator model on both platforms.
#define ABK_VENDOR_ID  0xABCD
#define ABK_PRODUCT_ID 0x1D02
#define ABK_VERSION    0x0100

//
// Counters the agent can read back, because a host stack that ignores this
// device says nothing about why. Fetched with ABK_IOCTL_GET_STATS on the same
// handle the agent already holds, since the control device is exclusive.
//
typedef struct _ABK_STATS {
    ULONG Size;
    ULONG HostReports;         // output reports VHF handed us
    ULONG LastHostReportLen;   // 65 when HIDClass leads with a report id
    ULONG Submitted;           // input reports accepted by VHF
    ULONG SubmitFailures;
    ULONG LastSubmitStatus;
    ULONG LastSubmitLen;
    ULONG GetInputReports;     // times the host polled for an input report
    ULONG GetInputServed;      // ... and got a queued reply
    ULONG ReplyBacklog;
    ULONG Dropped;
} ABK_STATS, *PABK_STATS;

#define ABK_IOCTL_GET_STATS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

// Depth of the device->host replies kept for a host that polls with
// IOCTL_HID_GET_INPUT_REPORT instead of reading the input pipe.
#define ABK_REPLY_SLOTS 8

typedef struct _ABK_DEVICE_CONTEXT {
    WDFDEVICE   Device;

    VHFHANDLE   VhfHandle;

    // Cleared before VhfDelete so that no new VhfReadReportSubmit can start
    // once teardown begins. Read and written under Lock.
    BOOLEAN     VhfStarted;

    // Manual queue holding user-mode reads that arrived before the host sent
    // an output report. The framework cancels whatever is left in it when the
    // handle closes or the device goes away, so requests never leak.
    WDFQUEUE    ReadQueue;

    WDFSPINLOCK Lock;

    // Whether HIDClass leads a report buffer with its report id. The two
    // directions use the same convention, so the length of the host's output
    // reports is what decides how input reports have to be submitted; guessing
    // wrong sends every reply one byte out of place. Guarded by Lock.
    BOOLEAN     ReportIdSeen;
    BOOLEAN     ReportIdLeads;

    // Host->device backlog, guarded by Lock.
    ULONG       Head;
    ULONG       Tail;
    ULONG       Count;
    ULONG       Dropped;
    UCHAR       Ring[ABK_RING_SLOTS][ABK_REPORT_SIZE];

    // Device->host replies already submitted to VHF, kept so a host that polls
    // with IOCTL_HID_GET_INPUT_REPORT can still be served. Guarded by Lock.
    ULONG       ReplyHead;
    ULONG       ReplyTail;
    ULONG       ReplyCount;
    UCHAR       Replies[ABK_REPLY_SLOTS][ABK_REPORT_SIZE];

    ABK_STATS   Stats;
} ABK_DEVICE_CONTEXT, *PABK_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(ABK_DEVICE_CONTEXT, AbkGetDeviceContext)

DRIVER_INITIALIZE                       DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD               AbkEvtDeviceAdd;
EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT     AbkEvtDeviceSelfManagedIoInit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_CLEANUP  AbkEvtDeviceSelfManagedIoCleanup;
EVT_WDF_IO_QUEUE_IO_READ                AbkEvtIoRead;
EVT_WDF_IO_QUEUE_IO_WRITE               AbkEvtIoWrite;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL      AbkEvtIoDeviceControl;
EVT_VHF_ASYNC_OPERATION                 AbkEvtVhfWriteReport;
EVT_VHF_ASYNC_OPERATION                 AbkEvtVhfGetInputReport;
