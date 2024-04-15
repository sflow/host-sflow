/* Copyright (c) 2002-2022 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#ifndef SFLOW_XDR_H
#define SFLOW_XDR_H 1

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#include <arpa/inet.h>
#endif //_WIN32
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "sflow.h" // for SFLAddress

  // sFlow datagram encoding (XDR)
  // Multi-threading considerations:
  // The SFD* functions may require synchronization if the counter-samples are
  // supplied by a different thread than the packet samples or discards, but
  // the sfd_xdr_* functions operate on a separate SFDBuf that can always
  // be private to one thread. So theoretically several threads could work
  // on encoding samples in parallel and only the operations involving SFDDgram
  // would need a semaphore.
  
  // Set an upper-limit on the size of any flow/counter/discard sample.
#define SFD_MAX_SAMPLE_SIZE 1400
#define SFD_MAX_SAMPLE_QUADS (SFD_MAX_SAMPLE_SIZE >> 2)
// Set an upper limit on the number of flow/counter/discard samples in one datagram.
#define SFD_MAX_DATAGRAM_SAMPLES 64
  // Set an upper limit on the nesting of XDR structures.
#define SFD_XDR_MAX_STACKDEPTH 16

  //#include <assert.h>
  //#define SFD_ASSERT(x) assert(x)
#define SFD_ASSERT(x)

  // Each flow/counter/discard sample will be one SFDBuf which can
  // encode multiple nested elements within it. For example, a flow-sample
  // may contain the elements packet-header, extended-switch and extended-router.
  // Simularly, a counter-sample may contain generic-counters, ethernet-counters
  // and optical-counter elements.
  
  typedef struct _SFDBuf {
    struct _SFDBuf *nxt;
    uint32_t cursor;
    uint32_t nstack;
    uint32_t stack[SFD_XDR_MAX_STACKDEPTH];
    uint32_t xdr[SFD_MAX_SAMPLE_QUADS];
  } SFDBuf;

  // XDR encoding is quad-aligned, network-byte order.

  void sfd_xdr_init(SFDBuf *buf);
  uint32_t *sfd_xdr_ptr(SFDBuf *buf);
  uint32_t sfd_xdr_len(SFDBuf *buf);
  void sfd_xdr_enc_int32(SFDBuf *buf, uint32_t val32);
  void sfd_xdr_enc_int64(SFDBuf *buf, uint64_t val64);
  void sfd_xdr_enc_float(SFDBuf *buf, float valf);
  void sfd_xdr_enc_dbl(SFDBuf *buf, double vald);
  void sfd_xdr_enc_bytes(SFDBuf *buf, u_char *data, uint32_t len);
  void sfd_xdr_enc_quads(SFDBuf *buf, uint32_t *data32, uint32_t quads);
  void sfd_xdr_enc_str(SFDBuf *buf, const char *str, uint32_t len);
  void sfd_xdr_enc_mac(SFDBuf *buf, u_char *mac);
  void sfd_xdr_enc_ip4(SFDBuf *buf, uint32_t ipv4);
  void sfd_xdr_enc_ip6(SFDBuf *buf, u_char *ip6);
  void sfd_xdr_enc_ip(SFDBuf *buf, SFLAddress *ip);
  void sfd_xdr_start_tlv(SFDBuf *buf, uint32_t tag);
  void sfd_xdr_end_tlv(SFDBuf *buf);

  // Datagram functions.

  // The datagram object knows how to encode the header and
  // compose datagrams with minimal copying.

  typedef void (*f_send_t)(void *magic, struct iovec *iov, int iovcnt);
  typedef uint64_t (*f_now_mS_t)(void *magic);
  typedef void *(*f_alloc_t)(void *magic, size_t bytes);
  typedef void (*f_free_t)(void *magic, void *obj);
  typedef void (*f_err_t)(void *magic, char *msg);
  typedef int (*f_hook_t)(void *magic, SFDBuf *dbuf);
  
  typedef struct {
    SFLAddress agentAddress;
    uint32_t agentSubId;
    uint32_t dgramSeqNo;
    uint64_t bootTime_mS;
    uint64_t lastSend_mS;
    uint32_t dgramLen;
    uint32_t maxDgramLen;
    uint32_t cursor0;
    uint32_t headerLen;
    SFDBuf hdr;
    SFDBuf *bufs;
    uint32_t nsamples;
    SFDBuf *samples[SFD_MAX_DATAGRAM_SAMPLES];
    struct iovec iov[SFD_MAX_DATAGRAM_SAMPLES + 1];
    void *magic;
    f_send_t f_send;
    f_now_mS_t f_now_mS;
    f_alloc_t f_alloc;
    f_free_t f_free;
    f_err_t f_err;
    f_hook_t f_hook;
  } SFDDgram;

  SFDDgram *SFDNew(uint32_t maxDgramLen,
		   SFLAddress *agentAddress,
		   uint32_t agentSubId,
		   void *magic,
		   f_alloc_t allocFn,
		   f_free_t freeFn,
		   f_now_mS_t nowFn,
		   f_send_t sendFn,
		   f_err_t errFn,
		   f_hook_t hookFn);

  // Datagram recycles xdr buffers, but only if allocated here.
#define SFD_RECYCLE (SFDBuf *)0xD1CEC0DE

  SFDBuf *SFDSampleNew(SFDDgram *sfdg);
  void SFDSampleCopy(SFDBuf *to, SFDBuf *from);
  int SFDSampleFree(SFDDgram *sfdg, SFDBuf *buf);
  void SFDSend(SFDDgram *sfdg);
  void SFDAddSample(SFDDgram *sfdg, SFDBuf *buf);
  void SFDFree(SFDDgram *sfdg);
    

#if defined(__cplusplus)
}  /* extern "C" */
#endif

#endif /* SFLOW_XDR_H */
