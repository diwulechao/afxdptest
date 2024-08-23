//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <xdpapi.h>
#include <afxdp_helper.h>
#include "xskfwd.h"

#define htons(x) ((uint16_t)((((uint16_t)(x) & 0x00FF) << 8) | (((uint16_t)(x) & 0xFF00) >> 8)))

const CHAR* UsageText =
"xskfwd.exe <IfIndex>"
"\n"
"Forwards RX traffic using an XDP program and AF_XDP sockets. This sample\n"
"application forwards traffic on the specified IfIndex originally destined to\n"
"UDP port 1234 back to the sender. Only the 0th data path queue on the interface\n"
"is used.\n"
;

const XDP_HOOK_ID XdpInspectRxL2 = {
    XDP_HOOK_L2, XDP_HOOK_RX, XDP_HOOK_INSPECT
};

#define LOGERR(...) \
    fprintf(stderr, "ERR: "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n")

static
VOID
TranslateRxToTx(
    _Inout_ UCHAR* Frame,
    _In_ UINT32 Length
)
{
    ethhdr* eth = (ETHERNET_HEADER*)Frame;
    iphdr* iph = (iphdr*)(Frame + sizeof(*eth));
    udphdr* udph = (udphdr*)((unsigned char*)iph + (iph->ihl * 4));
    /*
        UCHAR MacAddress[6];
        if (Length >= sizeof(MacAddress) * 2) {
        RtlCopyMemory(MacAddress, Frame, sizeof(MacAddress));
        RtlCopyMemory(Frame, Frame + sizeof(MacAddress), sizeof(MacAddress));
        RtlCopyMemory(Frame + sizeof(MacAddress), MacAddress, sizeof(MacAddress));
    }*/
}

static
VOID
PrintFrame(
    _Inout_ UCHAR* Frame,
    _In_ UINT32 Length
)
{
    ethhdr* eth = (ETHERNET_HEADER*)Frame;
    iphdr* iph = (iphdr*)(Frame + sizeof(*eth));
    // udphdr* udph = (udphdr*)((unsigned char*)iph + (iph->ihl * 4));
    
    uint8_t octet1 = (iph->SourceAddress >> 24) & 0xFF;
    uint8_t octet2 = (iph->SourceAddress >> 16) & 0xFF;
    uint8_t octet3 = (iph->SourceAddress >> 8) & 0xFF;
    uint8_t octet4 = iph->SourceAddress & 0xFF;

    // Format the octets into the IPv4 address string
    printf("%u.%u.%u.%u Protocol %u\n", octet4, octet3, octet2, octet1, iph->protocol);
}

unsigned char packet[] = { 0x00 ,0x00 ,0x5e ,0x00 ,0x01 ,0xd2 ,0x00 ,0x15 ,0x5d ,0x8c ,0x6b ,0x02 ,0x08 ,0x00 ,0x45 ,0x00
 ,0x00 ,0x64 ,0x60 ,0x37 ,0x00 ,0x00 ,0x80 ,0x11 ,0x07 ,0x62 ,0x0a ,0x82 ,0x43 ,0x0c ,0x28 ,0x42
 ,0x5d ,0x20 ,0xe4 ,0x9d ,0x00 ,0x35 ,0x00 ,0x50 ,0x4c ,0xac ,0xc4 ,0xd6 ,0x01 ,0x20 ,0x00 ,0x01
 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,0x08 ,0x6e ,0x78 ,0x64 ,0x6f ,0x6d ,0x61 ,0x69 ,0x6e ,0x06
 ,0x67 ,0x6c ,0x6f ,0x62 ,0x61 ,0x6c ,0x09 ,0x64 ,0x6e ,0x73 ,0x68 ,0x65 ,0x61 ,0x6c ,0x74 ,0x68
 ,0x05 ,0x61 ,0x7a ,0x75 ,0x72 ,0x65 ,0x00 ,0x00 ,0xfe ,0x00 ,0x01 ,0x00 ,0x00 ,0x29 ,0x10 ,0x00
 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x0c ,0x00 ,0x0a ,0x00 ,0x08 ,0xea ,0x0e ,0x48 ,0xd4 ,0x07 ,0x39
 ,0x4b ,0x49

};

INT
__cdecl
main(
    INT argc,
    CHAR** argv
)
{
    const XDP_API_TABLE* XdpApi;
    HRESULT Result;
    HANDLE Socket;
    HANDLE Program;
    UINT32 IfIndex;
    XDP_RULE Rule;
    UCHAR Frame[1514];
    XSK_UMEM_REG UmemReg = { 0 };
    const UINT32 RingSize = 1;
    XSK_RING_INFO_SET RingInfo;
    UINT32 OptionLength;
    XSK_RING RxRing;
    XSK_RING RxFillRing;
    XSK_RING TxRing;
    XSK_RING TxCompRing;
    UINT32 RingIndex;

    memset(&Rule, 0, sizeof(Rule));
    IfIndex = 10;

    if (argc >= 2) {
        IfIndex = atoi(argv[1]);
    }

    //
    // Retrieve the XDP API dispatch table.
    //
    Result = XdpOpenApi(XDP_API_VERSION_1, &XdpApi);
    if (FAILED(Result)) {
        LOGERR("XdpOpenApi failed: %x", Result);
        return EXIT_FAILURE;
    }

    //
    // Create an AF_XDP socket. The newly created socket is not connected.
    //
    Result = XdpApi->XskCreate(&Socket);
    if (FAILED(Result)) {
        LOGERR("XskCreate failed: %x", Result);
        return EXIT_FAILURE;
    }

    //
    // Register our frame buffer(s) with the AF_XDP socket. For simplicity, we
    // register a buffer containing a single frame. The registered buffer is
    // available mapped into AF_XDP's address space, and elements of descriptor
    // rings refer to relative offets from the start of the UMEM.
    //
    UmemReg.TotalSize = sizeof(Frame);
    UmemReg.ChunkSize = sizeof(Frame);
    UmemReg.Address = Frame;

    Result = XdpApi->XskSetSockopt(Socket, XSK_SOCKOPT_UMEM_REG, &UmemReg, sizeof(UmemReg));
    if (FAILED(Result)) {
        LOGERR("XSK_UMEM_REG failed: %x", Result);
        return EXIT_FAILURE;
    }

    //
    // Bind the AF_XDP socket to the specified interface and 0th data path
    // queue, and indicate the intent to perform RX and TX actions.
    //
    Result = XdpApi->XskBind(Socket, IfIndex, 0, XSK_BIND_FLAG_RX | XSK_BIND_FLAG_TX);
    if (FAILED(Result)) {
        LOGERR("XskBind failed: %x", Result);
        return EXIT_FAILURE;
    }

    //
    // Request a set of RX, RX fill, TX, and TX completion descriptor rings.
    // Request a capacity of one frame in each ring for simplicity. XDP will
    // create the rings and map them into the process address space as part of
    // the XskActivate step further below.
    //

    Result = XdpApi->XskSetSockopt(Socket, XSK_SOCKOPT_RX_RING_SIZE, &RingSize, sizeof(RingSize));
    if (FAILED(Result)) {
        LOGERR("XSK_SOCKOPT_RX_RING_SIZE failed: %x", Result);
        return EXIT_FAILURE;
    }

    Result = XdpApi->XskSetSockopt(Socket, XSK_SOCKOPT_RX_FILL_RING_SIZE, &RingSize, sizeof(RingSize));
    if (FAILED(Result)) {
        LOGERR("XSK_SOCKOPT_RX_FILL_RING_SIZE failed: %x", Result);
        return EXIT_FAILURE;
    }

    Result = XdpApi->XskSetSockopt(Socket, XSK_SOCKOPT_TX_RING_SIZE, &RingSize, sizeof(RingSize));
    if (FAILED(Result)) {
        LOGERR("XSK_SOCKOPT_TX_RING_SIZE failed: %x", Result);
        return EXIT_FAILURE;
    }

    Result = XdpApi->XskSetSockopt(Socket, XSK_SOCKOPT_TX_COMPLETION_RING_SIZE, &RingSize, sizeof(RingSize));
    if (FAILED(Result)) {
        LOGERR("XSK_SOCKOPT_TX_COMPLETION_RING_SIZE failed: %x", Result);
        return EXIT_FAILURE;
    }

    //
    // Activate the AF_XDP socket. Once activated, descriptor rings are
    // available and RX and TX can occur.
    //
    Result = XdpApi->XskActivate(Socket, XSK_ACTIVATE_FLAG_NONE);
    if (FAILED(Result)) {
        LOGERR("XskActivate failed: %x", Result);
        return EXIT_FAILURE;
    }

    //
    // Retrieve the RX, RX fill, TX, and TX completion ring info from AF_XDP.
    //
    OptionLength = sizeof(RingInfo);
    Result = XdpApi->XskGetSockopt(Socket, XSK_SOCKOPT_RING_INFO, &RingInfo, &OptionLength);
    if (FAILED(Result)) {
        LOGERR("XSK_SOCKOPT_RING_INFO failed: %x", Result);
        return EXIT_FAILURE;
    }

    //
    // Initialize the optional AF_XDP helper library with the socket ring info.
    // These helpers simplify manipulation of the shared rings.
    //
    XskRingInitialize(&RxRing, &RingInfo.Rx);
    XskRingInitialize(&RxFillRing, &RingInfo.Fill);
    XskRingInitialize(&TxRing, &RingInfo.Tx);
    XskRingInitialize(&TxCompRing, &RingInfo.Completion);

    //
    // Create an XDP program using the parsed rule at the L2 inspect hook point.
    // The rule intercepts all UDP frames destined to local port 1234 and
    // redirects them to the AF_XDP socket.
    //

    Rule.Match = XDP_MATCH_UDP_DST;
    Rule.Pattern.Port = htons(53);
    Rule.Action = XDP_PROGRAM_ACTION_REDIRECT;
    Rule.Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
    Rule.Redirect.Target = Socket;

    Result = XdpApi->XdpCreateProgram(IfIndex, &XdpInspectRxL2, 0, XDP_CREATE_PROGRAM_FLAG_NONE, &Rule, 1, &Program);
    if (FAILED(Result)) {
        LOGERR("XdpCreateProgram failed: %x", Result);
        return EXIT_FAILURE;
    }

    XskRingProducerReserve(&RxFillRing, 1, &RingIndex);

    //
    // The value of each RX fill and TX completion ring element is an offset
    // from the start of the UMEM to the start of the frame. Since this sample
    // is using a single buffer, the offset is always zero.
    //
    *(UINT64*)XskRingGetElement(&RxFillRing, RingIndex) = 0;

    XskRingProducerSubmit(&RxFillRing, 1);

    while (TRUE) {

        if (XskRingConsumerReserve(&RxRing, 1, &RingIndex) == 1) {
            XSK_BUFFER_DESCRIPTOR* RxBuffer;
            XSK_BUFFER_DESCRIPTOR* TxBuffer;
            XSK_NOTIFY_RESULT_FLAGS NotifyResult;

            //
            // A new RX frame appeared on the RX ring. Forward it to the TX
            // ring.

            RxBuffer = (XSK_BUFFER_DESCRIPTOR * )XskRingGetElement(&RxRing, RingIndex);

            //
            // Reserve space in the TX ring. Since we're only using one frame in
            // this sample, space is guaranteed to be available.
            //
            XskRingProducerReserve(&RxFillRing, 1, &RingIndex);
            TxBuffer = (XSK_BUFFER_DESCRIPTOR*)XskRingGetElement(&RxFillRing, RingIndex);

            PrintFrame(
                &Frame[RxBuffer->Address.BaseAddress + RxBuffer->Address.Offset],
                RxBuffer->Length);

            //
            // Since the RX and TX buffer descriptor formats are identical,
            // simply copy the descriptor across rings.
            //
            *TxBuffer = *RxBuffer;

            //
            // Advance the consumer index of the RX ring and the producer index
            // of the TX ring, which allows XDP to write and read the descriptor
            // elements respectively.
            //
            XskRingConsumerRelease(&RxRing, 1);
            XskRingProducerSubmit(&RxFillRing, 1);

            //
            // Notify XDP that a new element is available on the TX ring, since
            // XDP isn't continuously checking the shared ring. This can be
            // optimized further using the XskRingProducerNeedPoke helper.
            //
            Result = XdpApi->XskNotifySocket(Socket, XSK_NOTIFY_FLAG_POKE_TX, 0, &NotifyResult);
            if (FAILED(Result)) {
                LOGERR("XskNotifySocket failed: %x", Result);
                return EXIT_FAILURE;
            }
        }

        /*
        if (XskRingConsumerReserve(&TxCompRing, 1, &RingIndex) == 1) {
            UINT64* Tx;
            UINT64* Rx;

            //
            // A TX frame address appeared on the TX completion ring. Recycle
            // the frame onto the RX fill ring.
            //

            Tx = (UINT64 *) XskRingGetElement(&TxCompRing, RingIndex);

            //
            // Reserve space in the RX fill ring. Since we're only using one
            // frame in this sample, space is guaranteed to be available.
            //
            XskRingProducerReserve(&TxRing, 1, &RingIndex);
            Rx = (UINT64*) XskRingGetElement(&TxRing, RingIndex);

            //
            // Since the TX completion and RX fill descriptor formats are
            // identical, simply copy the descriptor across rings.
            //
            *Rx = *Tx;
            tx->Length = sizeof(packet);
            //
            // Advance the consumer index of the RX ring and the producer index
            // of the TX ring, which allows XDP to write and read the descriptor
            // elements respectively.
            //
            XskRingConsumerRelease(&TxCompRing, 1);
            XskRingProducerSubmit(&TxRing, 1);
        }*/
    }

    //
    // Close the XDP program. Traffic will no longer be intercepted by XDP.
    //
    CloseHandle(Program);

    //
    // Close the AF_XDP socket. All socket resources will be cleaned up by XDP.
    //
    CloseHandle(Socket);

    return EXIT_SUCCESS;
}
