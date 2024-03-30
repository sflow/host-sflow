/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

  #include "sflow_xdr.h"

  // XDR encoding is quad-aligned, network-byte order.

  void sfd_xdr_init(SFDBuf *buf) {
    buf->cursor = 0;
    buf->nstack = 0;
    buf->nxt = NULL;
  }

  uint32_t *sfd_xdr_ptr(SFDBuf *buf) {
    return (buf->xdr + buf->cursor);
  }

  uint32_t sfd_xdr_len(SFDBuf *buf) {
    return (buf->cursor << 2);
  }

  void sfd_xdr_enc_int32(SFDBuf *buf, uint32_t val32) {
    SFD_ASSERT(buf->cursor < SFD_MAX_SAMPLE_QUADS-1);
    buf->xdr[buf->cursor++] = htonl(val32);
  }

  void sfd_xdr_enc_int64(SFDBuf *buf, uint64_t val64) {
    uint32_t hi = (val64 >> 32);
    uint32_t lo = val64;
    sfd_xdr_enc_int32(buf, hi);
    sfd_xdr_enc_int32(buf, lo);
  }

  void sfd_xdr_enc_float(SFDBuf *buf, float valf) {
    uint32_t val;
    memcpy(&val, &valf, 4);
    sfd_xdr_enc_int32(buf, val);
  }

  void sfd_xdr_enc_dbl(SFDBuf *buf, double vald) {
    uint64_t val64;
    memcpy(&val64, &vald, 8);
    sfd_xdr_enc_int64(buf, val64);
  }

  void sfd_xdr_enc_bytes(SFDBuf *buf, u_char *data, uint32_t len) {
    if(len) {
      uint32_t quads = (len + 3) >> 2;
      u_char *ptr = (u_char *)sfd_xdr_ptr(buf);
      buf->cursor += quads;
      SFD_ASSERT(buf->cursor < SFD_MAX_SAMPLE_QUADS-1);
      buf->xdr[buf->cursor] = 0; // Clear the 'landing pad' (so any pad bytes are 00s).
      memcpy(ptr, data, len);
    }
  }

  void sfd_xdr_enc_quads(SFDBuf *buf, uint32_t *data32, uint32_t quads) {
    SFD_ASSERT(buf->cursor < (SFD_MAX_SAMPLE_QUADS - quads));
    for(uint32_t ii=0; ii<quads; ii++)
      buf->xdr[buf->cursor++] = htonl(data32[ii]);
  }

  void sfd_xdr_enc_str(SFDBuf *buf, const char *str, uint32_t len) {
    sfd_xdr_enc_int32(buf, len);
    sfd_xdr_enc_bytes(buf, (u_char *)str, len);
  }

  void sfd_xdr_enc_mac(SFDBuf *buf, u_char *mac) {
    sfd_xdr_enc_bytes(buf, mac, 6);
  }

  void sfd_xdr_enc_ip4(SFDBuf *buf, uint32_t ipv4) {
    SFD_ASSERT(buf->cursor < SFD_MAX_SAMPLE_QUADS-1);
    buf->xdr[buf->cursor++] = ipv4; // no byte-swap
  }

  void sfd_xdr_enc_ip6(SFDBuf *buf, u_char *ip6) {
    sfd_xdr_enc_bytes(buf, ip6, 16);
  }

  void sfd_xdr_enc_ip(SFDBuf *buf, SFLAddress *ip) {
    SFD_ASSERT(buf->cursor < (SFD_MAX_SAMPLE_QUADS-2));
    sfd_xdr_enc_int32(buf, ip->type);
    if(ip->type == SFLADDRESSTYPE_IP_V6)
      sfd_xdr_enc_bytes(buf, (u_char *)&ip->address.ip_v6.addr, 16);
    else
      sfd_xdr_enc_ip4(buf, ip->address.ip_v4.addr);
  }

  void sfd_xdr_start_tlv(SFDBuf *buf, uint32_t tag) {
    SFD_ASSERT(buf->cursor < (SFD_MAX_SAMPLE_QUADS-2));
    SFD_ASSERT(buf->nstack < (SFD_XDR_MAX_STACKDEPTH-1));
    buf->xdr[buf->cursor++] = htonl(tag);
    buf->stack[buf->nstack++] = buf->cursor; // remember cursor offset
    buf->xdr[buf->cursor++] = htonl(0); // place-holder for length
  }

  void sfd_xdr_end_tlv(SFDBuf *buf) {
    SFD_ASSERT(buf->nstack > 0);
    uint32_t c_len = buf->stack[--buf->nstack];
    SFD_ASSERT(c_len < (SFD_MAX_SAMPLE_QUADS-1));
    buf->xdr[c_len] = htonl((buf->cursor - c_len - 1) << 2);
  }

  // Datagram functions.

  // The datagram object knows how to encode the header and
  // compose datagrams with minimal copying.

  SFDDgram *SFDNew(uint32_t maxDgramLen,
		   SFLAddress *agentAddress,
		   uint32_t agentSubId,
		   void *magic,
		   f_alloc_t allocFn,
		   f_free_t freeFn,
		   f_now_mS_t nowFn,
		   f_send_t sendFn,
		   f_err_t errFn,
		   f_hook_t hookFn) {
    SFD_ASSERT(agentAddress->type == SFLADDRESSTYPE_IP_V4
	       || agentAddress->type == SFLADDRESSTYPE_IP_V6);
    SFD_ASSERT(allocFn != NULL);
    SFDDgram *sfdg = (SFDDgram *)allocFn(magic, sizeof(SFDDgram));
    memset(sfdg, 0, sizeof(*sfdg));
    sfdg->maxDgramLen = maxDgramLen;
    sfdg->agentAddress = *agentAddress;
    sfdg->agentSubId = agentSubId;
    sfdg->magic = magic;
    sfdg->f_alloc = allocFn;
    sfdg->f_free = freeFn;
    sfdg->f_now_mS = nowFn;
    sfdg->f_send = sendFn;
    sfdg->f_err = errFn;
    sfdg->f_hook = hookFn;
    sfdg->bootTime_mS = sfdg->f_now_mS(sfdg->magic);
    // We can do the first part of the header encoding here
    // because it is always the same.
    SFDBuf *hdr = &(sfdg->hdr);
    sfd_xdr_enc_int32(hdr, SFLDATAGRAM_VERSION5);
    sfd_xdr_enc_ip(hdr, &sfdg->agentAddress);
    sfd_xdr_enc_int32(hdr, sfdg->agentSubId);
    // Remember where we should reset to.
    sfdg->cursor0 = hdr->cursor;
    // And we already know what iov[0] will be
    // after we add three more fields...
    sfdg->headerLen = ((hdr->cursor + 3) << 2);
    sfdg->dgramLen = sfdg->headerLen;
    sfdg->iov[0].iov_base = hdr->xdr;
    sfdg->iov[0].iov_len = sfdg->headerLen;
    return sfdg;
  }

  SFDBuf *SFDSampleNew(SFDDgram *sfdg) {
    SFDBuf *buf = sfdg->bufs;
    if(buf)
      sfdg->bufs = buf->nxt;
    else
     buf = (SFDBuf *)sfdg->f_alloc(sfdg->magic, sizeof(SFDBuf));
    sfd_xdr_init(buf);
    // Sheep-brand buf as coming from here.
    buf->nxt = SFD_RECYCLE;
    return buf;
  }

  void SFDSampleCopy(SFDBuf *to, SFDBuf *from) {
    SFD_ASSERT(to);
    SFD_ASSERT(from);
    to->cursor = from->cursor;
    for(uint32_t cc = 0; cc < from->cursor; cc++)
      to->xdr[cc] = from->xdr[cc];
    to->nstack = from->nstack;
    for(uint32_t ss = 0; ss < from->nstack; ss++)
      to->stack[ss] = from->stack[ss];
  }
  
  int SFDSampleFree(SFDDgram *sfdg, SFDBuf *buf) {
    if(buf->nxt == SFD_RECYCLE) {
      buf->nxt = sfdg->bufs;
      sfdg->bufs = buf;
      return 1;
    }
    else if(sfdg->f_err) {
      sfdg->f_err(sfdg->magic, "SFDSampleFree: sample not allocated by SFDSampleNew");
    }
    return 0;
  }

  void SFDSend(SFDDgram *sfdg) {
    // Something to send?
    if(sfdg->nsamples == 0)
      return;
    // Get timestamp.
    sfdg->lastSend_mS = sfdg->f_now_mS(sfdg->magic);
    // Complete the header.
    SFDBuf *hdr = &(sfdg->hdr);
    hdr->cursor = sfdg->cursor0;
    sfd_xdr_enc_int32(hdr, ++sfdg->dgramSeqNo);
    sfd_xdr_enc_int32(hdr, (sfdg->lastSend_mS - sfdg->bootTime_mS));
    sfd_xdr_enc_int32(hdr, sfdg->nsamples);
    // Send out datagram.
    sfdg->f_send(sfdg->magic, sfdg->iov, sfdg->nsamples + 1);
    // And reset.
    // Recycle bufs if they were mine.
    // TODO: should maybe insist that they be mine?
    // (Otherwise the lifecycle is hard for the clients
    // to know.  The buffer needs to stay untouched
    // until after it is sent out, which might happen
    // a full second later.)
    for(uint32_t ii=0; ii<sfdg->nsamples; ii++) {
      SFDBuf *buf = sfdg->samples[ii];
      SFDSampleFree(sfdg, buf);
    }
    // And reset for next datagram.
    sfdg->nsamples = 0;
    sfdg->dgramLen = sfdg->headerLen;
  }

  static uint64_t SFDLastSend_mS(SFDDgram *sfdg) {
    return sfdg->lastSend_mS;
  }
  
  void SFDAddSample(SFDDgram *sfdg, SFDBuf *buf) {
    // optional hook function returns true to consume xdr-encoded sample
    if(sfdg->f_hook
       && sfdg->f_hook(sfdg->magic, buf))
      return;
    // otherwise we add to datagram as normal
    SFD_ASSERT(buf->nstack == 0);
    SFD_ASSERT(sfdg->nsamples <= SFD_MAX_DATAGRAM_SAMPLES);
    // May need to send what we have first.
    uint32_t len = sfd_xdr_len(buf);
    if((sfdg->dgramLen + len) >= sfdg->maxDgramLen)
      SFDSend(sfdg);
    // Count the samples that are submitted.
    sfdg->samples[sfdg->nsamples++] = buf;
    // Add to iovec.
    sfdg->iov[sfdg->nsamples].iov_base = buf->xdr;
    sfdg->iov[sfdg->nsamples].iov_len = len;
    // Update datagram length.
    sfdg->dgramLen += len;
  }

  void SFDFree(SFDDgram *sfdg) {
    SFD_ASSERT(sfdg->f_free != NULL);
    for(uint32_t ii=0; ii<sfdg->nsamples; ii++) {
      SFDBuf *buf = sfdg->samples[ii];
      if(buf->nxt == SFD_RECYCLE)
	sfdg->f_free(sfdg->magic, buf);
    }
    sfdg->f_free(sfdg->magic, sfdg);
  }
    

#if defined(__cplusplus)
}  /* extern "C" */
#endif
