/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>
#include <pwd.h>

  // mod_tcp developed with grateful reference to:
  // https://github.com/kristrev/inet-diag-example

  // Kernel TCP states. /include/net/tcp_states.h
  enum{
    TCP_ESTABLISHED = 1,
      TCP_SYN_SENT,
      TCP_SYN_RECV,
      TCP_FIN_WAIT1,
      TCP_FIN_WAIT2,
      TCP_TIME_WAIT,
      TCP_CLOSE,
      TCP_CLOSE_WAIT,
      TCP_LAST_ACK,
      TCP_LISTEN,
      TCP_CLOSING 
      };

  // pull in the struct tcp_info from a recent OS so we can
  // compile this on one platform and run successfully in another
  struct my_tcp_info {
    __u8	tcpi_state;
    __u8	tcpi_ca_state;
    __u8	tcpi_retransmits;
    __u8	tcpi_probes;
    __u8	tcpi_backoff;
    __u8	tcpi_options;
    __u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
    
    __u32	tcpi_rto;
    __u32	tcpi_ato;
    __u32	tcpi_snd_mss;
    __u32	tcpi_rcv_mss;
    
    __u32	tcpi_unacked;
    __u32	tcpi_sacked;
    __u32	tcpi_lost;
    __u32	tcpi_retrans;
    __u32	tcpi_fackets;
    
    /* Times. */
    __u32	tcpi_last_data_sent;
    __u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
    __u32	tcpi_last_data_recv;
    __u32	tcpi_last_ack_recv;
    
    /* Metrics. */
    __u32	tcpi_pmtu;
    __u32	tcpi_rcv_ssthresh;
    __u32	tcpi_rtt;
    __u32	tcpi_rttvar;
    __u32	tcpi_snd_ssthresh;
    __u32	tcpi_snd_cwnd;
    __u32	tcpi_advmss;
    __u32	tcpi_reordering;
    
    __u32	tcpi_rcv_rtt;
    __u32	tcpi_rcv_space;
    
    __u32	tcpi_total_retrans;
    
    __u64	tcpi_pacing_rate;
    __u64	tcpi_max_pacing_rate;
    __u64	tcpi_bytes_acked;    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
    __u64	tcpi_bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
    __u32	tcpi_segs_out;	     /* RFC4898 tcpEStatsPerfSegsOut */
    __u32	tcpi_segs_in;	     /* RFC4898 tcpEStatsPerfSegsIn */
    
    __u32	tcpi_notsent_bytes;
    __u32	tcpi_min_rtt;
    __u32	tcpi_data_segs_in;	/* RFC4898 tcpEStatsDataSegsIn */
    __u32	tcpi_data_segs_out;	/* RFC4898 tcpEStatsDataSegsOut */
  };

#define HSP_READNL_RCV_BUF 8192
#define HSP_READNL_BATCH 100

  typedef struct _HSPTCPSample {
    struct _HSPTCPSample *prev; // timeoutQ
    struct _HSPTCPSample *next; // timeoutQ
    UTArray *samples; // HSPPendingSample
    SFLAddress src;
    SFLAddress dst;
    bool flipped;
    struct inet_diag_req_v2 conn_req;
    struct timespec qtime;
#define HSP_TCP_TIMEOUT_MS 400
    EnumPktDirection pktdirn;
  } HSPTCPSample;
    
  typedef struct _HSP_mod_TCP {
    EVBus *packetBus;
    int nl_sock;
    UTHash *sampleHT;
    UTQ(HSPTCPSample) timeoutQ;
  } HSP_mod_TCP;



  /*_________________---------------------------__________________
    _________________     tcpSampleNew/Free     __________________
    -----------------___________________________------------------
  */
  static HSPTCPSample *tcpSampleNew(void) {
    HSPTCPSample *ts = (HSPTCPSample *)my_calloc(sizeof(HSPTCPSample));
    ts->samples = UTArrayNew(UTARRAY_DFLT);
    return ts;
  }
  
  static void tcpSampleFree(HSPTCPSample *ts) {
    UTArrayFree(ts->samples);
    my_free(ts);
  }

  static char *tcpSamplePrint(HSPTCPSample *ts) {
    static char buf[128];
    char ip1[51],ip2[51];
    snprintf(buf, 128, "TCPSample: %s - %s samples:%u %s",
	     SFLAddress_print(&ts->src, ip1, 50),
	     SFLAddress_print(&ts->dst, ip2, 50),
	     UTArrayN(ts->samples),
	     ts->flipped ? "FLIPPED": "");
    return buf;
  }

  /*_________________---------------------------__________________
    _________________    diag_sockid_print      __________________
    -----------------___________________________------------------
  */

  static char *diag_sockid_print(struct inet_diag_sockid *sockid) {
    static char buf[256];
    snprintf(buf, 256, "%08x:%08x:%08x:%08x %u - %08x:%08x:%08x:%08x %u if:%u",
	     sockid->idiag_src[0],
	     sockid->idiag_src[1],
	     sockid->idiag_src[2],
	     sockid->idiag_src[3],
	     sockid->idiag_sport,
	     sockid->idiag_dst[0],
	     sockid->idiag_dst[1],
	     sockid->idiag_dst[2],
	     sockid->idiag_dst[3],
	     sockid->idiag_dport,
	     sockid->idiag_if);
    return buf;
  }
	     
  /*_________________---------------------------__________________
    _________________      send_diag_msg        __________________
    -----------------___________________________------------------
  */

#define MAGIC_SEQ 0x50C00L

  static int send_diag_msg(int sockfd, struct inet_diag_req_v2 *conn_req) {
    struct nlmsghdr nlh = { 0 };
    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(*conn_req));
    nlh.nlmsg_flags = NLM_F_REQUEST;
    nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    nlh.nlmsg_seq = MAGIC_SEQ;

    struct iovec iov[2];
    iov[0].iov_base = (void*) &nlh;
    iov[0].iov_len = sizeof(nlh);
    iov[1].iov_base = (void*)conn_req;
    iov[1].iov_len = sizeof(*conn_req);
    
    struct sockaddr_nl sa = { 0 };
    sa.nl_family = AF_NETLINK;
    
    struct msghdr msg = { 0 };
    msg.msg_name = (void*) &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    return sendmsg(sockfd, &msg, 0);
  }

  /*_________________---------------------------__________________
    _________________     parse_diag_msg        __________________
    -----------------___________________________------------------
  */

  static void parse_diag_msg(EVMod *mod, struct inet_diag_msg *diag_msg, int rtalen)
  {
    HSP_mod_TCP *mdata = (HSP_mod_TCP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    // user info.  Prefer getpwuid_r() if avaiable...
    // struct passwd *uid_info = getpwuid(diag_msg->idiag_uid);
    // myDebug(1, "diag_msg: UID=%u(%s) inode=%u",
    // diag_msg->idiag_uid,
    // uid_info->pw_name,
    // diag_msg->idiag_inode);
    // Theoretically we could follow the inode back to
    // the socket and get the application (command line)
    // but there does not seem to be a direct lookup
    // for that.

    if(rtalen > 0) {
      struct rtattr *attr = (struct rtattr *)(diag_msg + 1);
      
      while(RTA_OK(attr, rtalen)) {
	if(attr->rta_type == INET_DIAG_INFO) {
	  // The payload is a struct tcp_info as defined in linux/tcp.h,  but we use
	  // struct my_tcp_info - copied from a system running kernel rev 4.7.3.  New
	  // fields are only added to the end of the struct so this works for forwards
	  // and backwards compatibilty:
	  // Unknown fields in in the sFlow structure should be exported as 0,  so we
	  // initialize our struct my_tcp_info with zeros.  Then we copy in the tcp_info
	  // we get from the kernel, up to the size of struct my_tcp_info.  Now if the
	  // kernel tcp_info has fewer fields the extras will all be 0 (correct),
	  // or if the kernel's has more fields they will simply be ignored (no problem,
	  // but we should check back in case they are worth exporting!)
	  struct my_tcp_info tcpi = { 0 };
	  int readLen = RTA_PAYLOAD(attr);
	  if(readLen > sizeof(struct my_tcp_info)) {
	    myDebug(2, "New kernel has new fields in struct tcp_info. Check it out!");
	    readLen = sizeof(struct my_tcp_info);
	  }
	  memcpy(&tcpi, RTA_DATA(attr), readLen);
	  myDebug(1, "TCP diag: RTT=%uuS (variance=%uuS) [%s]",
		  tcpi.tcpi_rtt, tcpi.tcpi_rttvar,
		  diag_sockid_print(&diag_msg->id));
	  // now see if we can get back to the sample that triggered this lookup
	  HSPTCPSample search = { .conn_req.id = diag_msg->id };
	  HSPTCPSample *found = UTHashDelKey(mdata->sampleHT, &search);
	  if(found) {
	    myDebug(1, "found TCPSample: %s RTT:%uuS", tcpSamplePrint(found), tcpi.tcpi_rtt);
	    // unlink from Q
	    UTQ_REMOVE(mdata->timeoutQ, found);
	    HSPPendingSample *ps;
	    UTARRAY_WALK(found->samples, ps) {
	      // populate tcp_info structure
	      SFLFlow_sample_element *tcpElem = pendingSample_calloc(ps, sizeof(SFLFlow_sample_element));
	      tcpElem->tag = SFLFLOW_EX_TCP_INFO;
	      tcpElem->flowType.tcp_info.dirn = found->pktdirn;
	      tcpElem->flowType.tcp_info.snd_mss = tcpi.tcpi_snd_mss;
	      tcpElem->flowType.tcp_info.rcv_mss = tcpi.tcpi_rcv_mss;
	      tcpElem->flowType.tcp_info.unacked = tcpi.tcpi_unacked;
	      tcpElem->flowType.tcp_info.lost = tcpi.tcpi_lost;
	      tcpElem->flowType.tcp_info.retrans = tcpi.tcpi_total_retrans;
	      tcpElem->flowType.tcp_info.pmtu = tcpi.tcpi_pmtu;
	      tcpElem->flowType.tcp_info.rtt = tcpi.tcpi_rtt;
	      tcpElem->flowType.tcp_info.rttvar = tcpi.tcpi_rttvar;
	      tcpElem->flowType.tcp_info.snd_cwnd = tcpi.tcpi_snd_cwnd;
	      tcpElem->flowType.tcp_info.reordering = tcpi.tcpi_reordering;
	      tcpElem->flowType.tcp_info.min_rtt = tcpi.tcpi_min_rtt;
	      // add to sample
	      SFLADD_ELEMENT(ps->fs, tcpElem);
	      // release sample
	      releasePendingSample(sp, ps);
	    }
	    // and free my control-block
	    tcpSampleFree(found);
	  }
	}
	attr = RTA_NEXT(attr, rtalen); 
      }
    }
  }

  /*_________________---------------------------__________________
    _________________         readNL            __________________
    -----------------___________________________------------------
  */

  static void readNL(EVMod *mod, EVSocket *sock, void *magic)
  {
    HSP_mod_TCP *mdata = (HSP_mod_TCP *)mod->data;
    uint8_t recv_buf[HSP_READNL_RCV_BUF];
    int batch = 0;
    if(mdata->nl_sock > 0) {
      for( ; batch < HSP_READNL_BATCH; batch++) {
	int numbytes = recv(mdata->nl_sock, recv_buf, sizeof(recv_buf), 0);
	if(numbytes <= 0)
	  break;
	struct nlmsghdr *nlh = (struct nlmsghdr*) recv_buf;
	while(NLMSG_OK(nlh, numbytes)){
	  if(nlh->nlmsg_type == NLMSG_DONE)
	    break;
	  if(nlh->nlmsg_type == NLMSG_ERROR){
            struct nlmsgerr *err_msg = (struct nlmsgerr *)NLMSG_DATA(nlh);
	    // Frequently see:
	    // "device or resource busy" (especially with NLM_F_DUMP set)
	    // "netlink error" (IPv6 but connection not established)
	    // so only log when debugging:
	    myDebug(1, "Error in netlink message: %d : %s", err_msg->error, strerror(-err_msg->error));
	    break;
	  }
	  if(nlh->nlmsg_seq == MAGIC_SEQ) {
	    struct inet_diag_msg *diag_msg = (struct inet_diag_msg*) NLMSG_DATA(nlh);
	    int rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));
	    parse_diag_msg(mod, diag_msg, rtalen);
	  }
	  nlh = NLMSG_NEXT(nlh, numbytes);
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________       evt_deci            __________________
    -----------------___________________________------------------
  */

  static void evt_deci(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_TCP *mdata = (HSP_mod_TCP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    // myLog(LOG_INFO, "evt_deci: samplerHT elements=%u", UTHashN(mdata->sampleHT));
    for(HSPTCPSample *ts = mdata->timeoutQ.head; ts; ) {
      if(EVTimeDiff_nS(&ts->qtime, &mdata->packetBus->now) <= (HSP_TCP_TIMEOUT_MS * 1000000)) {
	// not timed-out yet: we know everything after this point is current, so stop walking.
	break;
      }
      else {
	myDebug(1, "removing timed-out request (%s)", tcpSamplePrint(ts));
	HSPTCPSample *next_ts = ts->next;
	// remove from Q
	UTQ_REMOVE(mdata->timeoutQ, ts);
	// remove from HT
	UTHashDel(mdata->sampleHT, ts);
	// let the samples go
	HSPPendingSample *ps;
	UTARRAY_WALK(ts->samples, ps) {
	  releasePendingSample(sp, ps);
	}
	// free
	tcpSampleFree(ts);
	// walk
	ts = next_ts;
      }
    }
  }

  /*_________________---------------------------__________________
    _________________     decodeHeader          __________________
    -----------------___________________________------------------
  */

#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500

#define NFT_MIN_SIZ (NFT_ETHHDR_SIZ + sizeof(struct myiphdr))

  static int decodeHeader(SFLSampled_header *header, uint8_t *ipproto, int *l3_offset, int *l4_offset)
  {
    uint8_t *start = header->header_bytes;
    uint8_t *end = start + header->header_length;
    uint8_t *ptr = start;
    uint16_t type_len = 0;
    
    switch(header->header_protocol) {

    case SFLHEADER_IPv4:
      type_len = 0x0800;
      break;

    case SFLHEADER_IPv6:
      type_len = 0x86DD;
      break;

    case SFLHEADER_ETHERNET_ISO8023:
      // ethernet
      if((end - ptr) < NFT_ETHHDR_SIZ)
	return -1; // not enough for an Ethernet header
      ptr += 6;
      ptr += 6;
      type_len = (ptr[0] << 8) + ptr[1];
      ptr += 2;
      
      if(type_len == 0x8100) {
	// 802.1Q
	if((end - ptr) < 4)
	  return -1; // not enough for an 802.1Q header
	// VLAN  - next two bytes
	// uint32_t vlanData = (ptr[0] << 8) + ptr[1];
	// uint32_t vlan = vlanData & 0x0fff;
	// uint32_t priority = vlanData >> 13;
	ptr += 2;
	//  _____________________________________ 
	// |   pri  | c |         vlan-id        | 
	//  ------------------------------------- 
	// [priority = 3bits] [Canonical Format Flag = 1bit] [vlan-id = 12 bits] 
	// now get the type_len again (next two bytes) 
	type_len = (ptr[0] << 8) + ptr[1];
	ptr += 2;
      }

      // now we're just looking for IP or IP6
      if((end - start) < sizeof(struct iphdr))
	return -1; // not enough for an IPv4 header (or IPX, or SNAP) 
      
      if(type_len <= NFT_MAX_8023_LEN) {
	// assume 802.3+802.2 header 
	// check for SNAP 
	if(ptr[0] == 0xAA &&
	   ptr[1] == 0xAA &&
	   ptr[2] == 0x03) {
	  ptr += 3;
	  if(ptr[0] != 0 ||
	     ptr[1] != 0 ||
	     ptr[2] != 0) {
	    return -1; // no further decode for vendor-specific protocol 
	  }
	  ptr += 3;
	  // OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) 
	  type_len = (ptr[0] << 8) + ptr[1];
	  ptr += 2;
	}
	else {
	  if (ptr[0] == 0x06 &&
	      ptr[1] == 0x06 &&
	      (ptr[2] & 0x01)) {
	    // IP over 8022 
	    ptr += 3;
	    // force the type_len to be IP so we can inline the IP decode below 
	    type_len = 0x0800;
	  }
	  else
	    return -1;
	}
      }
    }
    
    // type_len should be ethernet-type now
    switch(type_len) {
    case 0x0800:
      // IPV4 - check again that we have enough header bytes 
      if((end - ptr) < sizeof(struct iphdr))
	return -1;
      // look at first byte of header.... 
      //  ___________________________ 
      // |   version   |    hdrlen   | 
      //  --------------------------- 
      if((*ptr >> 4) != 4)
	return -1; // not version 4 
      if((*ptr & 15) < 5)
	return -1; // not IP (hdr len must be 5 quads or more) 
      // survived all the tests - store the offset to the start of the ip header 
      *l3_offset = (ptr - start);
      *l4_offset = (*l3_offset) + ((*ptr & 15) * 4);
      *ipproto = ptr[9];
      return 4; // IPv4
      
    case 0x86DD:
      // IPV6 
      // look at first byte of header.... 
      if((*ptr >> 4) != 6)
	return -1; // not version 6 
      // survived all the tests - store the offset to the start of the ip6 header 
      *l3_offset = (ptr - start);
      *ipproto = ptr[6];
      ptr += sizeof(struct ip6_hdr);
      bool decodingOptions = YES;
      while(decodingOptions
	    && ptr < end) {
	switch(*ipproto) {
	  // these we can skip
	case 0:  // hop
	case 43: // routing
	case 51: // auth
	case 60: // dest options
	  *ipproto = ptr[0];
	  // second byte gives option len in units of 8, not counting first 8
	  ptr += 8 * (ptr[1] + 1);
	  break;
	  // the rest we cannot skip (or don't want to)
	  // case 1: // ICMP6
	  // case 6: // TCP
	  // case 17: // UDP
	  // case 44: // fragment
	  // case 50: // encyption
	default:
	  decodingOptions = NO;
	  break;
	}
      }
      *l4_offset = (ptr - start);
      return 6; // IPv6
    }

    // type_len did not match
    return 0;
  }
  
  /*_________________---------------------------__________________
    _________________       evt_flow_sample     __________________
    -----------------___________________________------------------
  */

  static void evt_flow_sample(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_TCP *mdata = (HSP_mod_TCP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPPendingSample *ps = (HSPPendingSample *)data;
    for(SFLFlow_sample_element *elem = ps->fs->elements; elem != NULL; elem = elem->nxt) {
      if(elem->tag == SFLFLOW_HEADER) {
	SFLSampled_header *header = &elem->flowType.header;
	uint8_t *hdr = header->header_bytes;
	uint8_t ipproto=0;
	int offset_l3;
	int offset_l4;
	int ip_ver = decodeHeader(header, &ipproto, &offset_l3, &offset_l4);
	if(ipproto == IPPROTO_TCP) {
	  // next decide on the packet-direction
	  SFLAddress src, dst;
	  uint16_t tcp_ports[2];
	  bool local_src, local_dst;
	  if(ip_ver == 4) {
	    src.type = dst.type = SFLADDRESSTYPE_IP_V4;
	    memcpy(&src.address.ip_v4, hdr + offset_l3 + 12, 4);
	    memcpy(&dst.address.ip_v4, hdr + offset_l3 + 16, 4);
	    local_src = UTHashGet(sp->localIP, &src) ? YES : NO;
	    local_dst = UTHashGet(sp->localIP, &dst) ? YES : NO;
	  }
	  else {
	    src.type = dst.type = SFLADDRESSTYPE_IP_V6;
	    memcpy(&src.address.ip_v6, hdr + offset_l3 + 8, 16);
	    memcpy(&dst.address.ip_v6, hdr + offset_l3 + 24, 16);
	    local_src = UTHashGet(sp->localIP6, &src) ? YES : NO;
	    local_dst = UTHashGet(sp->localIP6, &dst) ? YES : NO;
	  }
          if(debug(2)) {
            char ipb1[51], ipb2[51];
            myDebug(2, "TCP sample ip_ver==%d local_src=%u local_dst=%u, src=%s dst=%s",
		    ip_ver,local_src, local_dst,
		    SFLAddress_print(&src,ipb1,50),
		    SFLAddress_print(&dst,ipb2,50));
          }
	  if(local_src != local_dst) {
	    // OK,  we are going to look this one up
	    HSPTCPSample *tcpSample = tcpSampleNew();
	    tcpSample->qtime = mdata->packetBus->now;
	    tcpSample->pktdirn = local_src ? PKTDIR_sent : PKTDIR_received;
	    // just the established TCP connections
	    tcpSample->conn_req.sdiag_protocol = IPPROTO_TCP;
	    tcpSample->conn_req.idiag_states = (1<<TCP_ESTABLISHED);
	    // just the tcp_info
	    tcpSample->conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
	    // src+dst tcp_ports are at start of TCP header
	    memcpy(tcp_ports, hdr + offset_l4, 4);
	    // copy into inet_diag_sockid, but flip if we are the destination
	    struct inet_diag_sockid *sockid = &tcpSample->conn_req.id;
	    // addresses
	    tcpSample->src = src;
	    tcpSample->dst = dst;
	    if(ip_ver == 4) {
	      tcpSample->conn_req.sdiag_family = AF_INET;
	      if(local_src) {
		memcpy(sockid->idiag_src, &src.address.ip_v4, 4);
		memcpy(sockid->idiag_dst, &dst.address.ip_v4, 4);
	      }
	      else {
		tcpSample->flipped = YES;
		memcpy(sockid->idiag_src, &dst.address.ip_v4, 4);
		memcpy(sockid->idiag_dst, &src.address.ip_v4, 4);
	      }
	    }
	    else {
	      tcpSample->conn_req.sdiag_family = AF_INET6;
	      if(local_src) {
		memcpy(sockid->idiag_src, &src.address.ip_v6, 16);
		memcpy(sockid->idiag_dst, &dst.address.ip_v6, 16);
	      }
	      else {
		memcpy(sockid->idiag_src, &dst.address.ip_v6, 16);
		memcpy(sockid->idiag_dst, &src.address.ip_v6, 16);
	      }
	    }
	    // tcp ports
	    if(local_src) {
	      sockid->idiag_sport = tcp_ports[0];
	      sockid->idiag_dport = tcp_ports[1];
	    }
	    else {
	      sockid->idiag_sport = tcp_ports[1];
	      sockid->idiag_dport = tcp_ports[0];
	    }
	    // specify the ifIndex in case the socket is bound
	    // see INET_MATCH in net/ipv4/inet_hashtables.c
	    sockid->idiag_if = SFL_DS_INDEX(ps->sampler->dsi);
	    // I have no cookie :(
	    sockid->idiag_cookie[0] = INET_DIAG_NOCOOKIE;
	    sockid->idiag_cookie[1] = INET_DIAG_NOCOOKIE;
	    // put a hold on this one while we look it up
	    holdPendingSample(ps);
	    HSPTCPSample *tsInQ = UTHashGet(mdata->sampleHT, tcpSample);
	    if(tsInQ) {
	      myDebug(1, "request already pending");
	      UTArrayAdd(tsInQ->samples, ps);
	      tcpSampleFree(tcpSample);
	    }
	    else {
	      myDebug(1, "new request: %s", tcpSamplePrint(tcpSample));
	      UTArrayAdd(tcpSample->samples, ps);
	      // add to HT and timeout queue
	      UTHashAdd(mdata->sampleHT, tcpSample);
	      UTQ_ADD_TAIL(mdata->timeoutQ, tcpSample);
	      // send the netlink request
	      send_diag_msg(mdata->nl_sock, &tcpSample->conn_req);
	    }
	  }
	}
      }
    }
  }
  
  /*_________________---------------------------__________________
    _________________    evt_config_first       __________________
    -----------------___________________________------------------
  */

  static void evt_config_first(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_TCP *mdata = (HSP_mod_TCP *)mod->data;

    // open the netlink monitoring socket
    if((mdata->nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1) {
      myLog(LOG_ERR, "nl_sock open failed: %s", strerror(errno));
      return;
    }
     
    // set the socket to non-blocking
    int fdFlags = fcntl(mdata->nl_sock, F_GETFL);
    fdFlags |= O_NONBLOCK;
    if(fcntl(mdata->nl_sock, F_SETFL, fdFlags) < 0) {
      myLog(LOG_ERR, "NFLOG fcntl(O_NONBLOCK) failed: %s", strerror(errno));
      return;
    }
    
    // make sure it doesn't get inherited, e.g. when we fork a script
    fdFlags = fcntl(mdata->nl_sock, F_GETFD);
    fdFlags |= FD_CLOEXEC;
    if(fcntl(mdata->nl_sock, F_SETFD, fdFlags) < 0) {
      myLog(LOG_ERR, "NFLOG fcntl(F_SETFD=FD_CLOEXEC) failed: %s", strerror(errno));
      return;
    }

    EVBusAddSocket(mod, mdata->packetBus, mdata->nl_sock, readNL, NULL);
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_tcp(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_TCP));
    HSP_mod_TCP *mdata = (HSP_mod_TCP *)mod->data;
    mdata->sampleHT = UTHASH_NEW(HSPTCPSample, conn_req.id, UTHASH_DFLT);
    // trim the hash-key len to select only the socket part of inet_diag_sockid
    // and leave out the interface and the cookie
    mdata->sampleHT->f_len = 36;
    // register call-backs
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_CONFIG_FIRST), evt_config_first);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, EVEVENT_DECI), evt_deci);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_FLOW_SAMPLE), evt_flow_sample);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
