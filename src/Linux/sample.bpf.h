/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#ifndef SAMPLE_BPF_H
#define SAMPLE_BPF_H 1

#if defined(__cplusplus)
extern "C" {
#endif

#define MAX_INTERFACES 128
#define MAX_PKT_HDR_LEN 256 // should match HSP_MAX_HEADER_BYTES in hsflowd.h
#define HSP_BPF_RING_BUFFER_BYTES (1 << 16)

struct packet_event_t {
    __u64 timestamp;
    __u32 ifindex;
    __u32 sampling_rate;
    __u32 ingress_ifindex;
    __u32 routed_ifindex;
    __u32 pkt_len;
    __u8  direction;
    __u8  hdr[MAX_PKT_HDR_LEN];
} __attribute__((packed));

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif // SAMPLE_BPF_H
