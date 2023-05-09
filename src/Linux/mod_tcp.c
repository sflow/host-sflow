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

#include "util_netlink.h"

  // mod_tcp developed with grateful reference to:
  // https://github.com/kristrev/inet-diag-example

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

    __u64       tcpi_delivery_rate;

    __u64	tcpi_busy_time;      /* Time (usec) busy sending data */
    __u64	tcpi_rwnd_limited;   /* Time (usec) limited by receive window */
    __u64	tcpi_sndbuf_limited; /* Time (usec) limited by send buffer */

    __u32	tcpi_delivered;
    __u32	tcpi_delivered_ce;

    __u64	tcpi_bytes_sent;     /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
    __u64	tcpi_bytes_retrans;  /* RFC4898 tcpEStatsPerfOctetsRetrans */
    __u32	tcpi_dsack_dups;     /* RFC4898 tcpEStatsStackDSACKDups */
    __u32	tcpi_reord_seen;     /* reordering events seen */

    __u32	tcpi_rcv_ooopack;    /* Out-of-order packets received */

    __u32	tcpi_snd_wnd;	     /* peer's advertised receive window after
				      * scaling (bytes)
				      */
  };

#define HSP_READNL_RCV_BUF 8192
#define HSP_READNL_BATCH 100

  /* Replicate some definitions we need from inet_diag.h here,
     so we can compile on an older OS if necessary. This assumes
     that the kernel will only ever add to these, and never
     change them.
  */
#define INET_DIAG_INFO 2
#define INET_DIAG_SHUTDOWN 8
#define INET_DIAG_MARK 15
#define INET_DIAG_CLASS_ID 17
#define INET_DIAG_CGROUP_ID 21
#define INET_DIAG_SOCKOPT 22

  typedef struct _HSPTCPSample {
    struct _HSPTCPSample *prev; // timeoutQ
    struct _HSPTCPSample *next; // timeoutQ
    UTArray *samples; // HSPPendingSample
    SFLAddress src;
    SFLAddress dst;
    bool flipped:1;
    bool udp:1;
    struct inet_diag_req_v2 conn_req;
    struct inet_diag_sockid normalized_id;
    struct timespec qtime;
#define HSP_TCP_TIMEOUT_MS 400
    EnumPktDirection pktdirn;
  } HSPTCPSample;

  typedef struct _HSP_mod_TCP {
    EVBus *packetBus;
    int nl_sock;
    uint32_t nl_seq_tx;
    uint32_t nl_seq_rx;
    uint32_t nl_seq_lost;
    uint32_t diag_tx;
    uint32_t diag_rx;
    uint32_t samples_annotated;
    uint32_t diag_timeouts;
    uint32_t n_lastTick;
    uint32_t ipip_tx;
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
    _________________     parse_diag_msg        __________________
    -----------------___________________________------------------
  */

  static void parse_diag_msg(EVMod *mod, struct inet_diag_msg *diag_msg, int rtalen, uint32_t seqNo)
  {
    HSP_mod_TCP *mdata = (HSP_mod_TCP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    mdata->diag_rx++;

    if(diag_msg == NULL)
      return;
    if(diag_msg->idiag_family != AF_INET
       && diag_msg->idiag_family != AF_INET6)
      return;

    // see if we can get back to the HSPTCPSample that triggered this lookup
    HSPTCPSample search = { .normalized_id = diag_msg->id };
    // kernel may have IPv4 addresses in 0:0:FFFF0000:IP form, so detect that
    // here and make it match what we would have queried with:
    if(UTNLDiag_sockid_normalize(&search.normalized_id))
      myDebug(2, "tcp: sockid normalized");
    HSPTCPSample *found = UTHashDelKey(mdata->sampleHT, &search);

    if(found) {
      // use this to confirm seqNo advance so we can report on
      // the number of our requests that seem to be outstanding
      // or lost (assumes requests answered in order)
      uint32_t lost = seqNo - mdata->nl_seq_rx - 1;
      mdata->nl_seq_lost += lost;
      mdata->nl_seq_rx = seqNo;
    }

    // user info.  Prefer getpwuid_r() if avaiable...
    struct passwd *uid_info = getpwuid(diag_msg->idiag_uid);
    myDebug(2, "tcp: diag_msg: found=%s prot=%s UID=%u(%s) inode=%u (tx=%u,rx=%u,queued=%u,lost=%u)",
	    found ? "YES" : "NO",
	    found ? (found->udp ? "UDP":"TCP") : "",
	    diag_msg->idiag_uid,
	    uid_info ? uid_info->pw_name : "<user not found>",
	    diag_msg->idiag_inode,
	    mdata->diag_tx,
	    mdata->diag_rx,
	    mdata->nl_seq_tx - mdata->nl_seq_rx,
	    mdata->nl_seq_lost);
    // Theoretically we could follow the inode back to
    // the socket and get the application (command line)
    // but there does not seem to be a direct lookup
    // for that.
    // More efficient is to look up the cgroup_id that
    // is supplied by newer kernels (starting with
    // ubuntu22, i.e. approx kernel 5.15)

    if(rtalen > 0) {
      uint64_t cgroup_id = 0;
      uint32_t mark = 0;
      uint8_t shutdown = 0;
      uint32_t class_id = 0;
      uint16_t sockopt_flags = 0;
      
      struct rtattr *attr = (struct rtattr *)(diag_msg + 1);

      while(RTA_OK(attr, rtalen)) {
	switch (attr->rta_type) {
	case INET_DIAG_MARK: {
	  if(RTA_PAYLOAD(attr) == 4) {
	    memcpy(&mark, RTA_DATA(attr), 4);
	    myDebug(1, "tcp: INET_DIAG_MARK=%u", mark);
	  }
	}
	  break;
	case INET_DIAG_CGROUP_ID: {
	  if(RTA_PAYLOAD(attr) == 8) {
	    memcpy(&cgroup_id, RTA_DATA(attr), 8);
	    myDebug(1, "tcp: INET_DIAG_CGROUP_ID=%"PRIu64, cgroup_id);
	  }
	}
	  break;
	case INET_DIAG_SHUTDOWN: {
	  if(RTA_PAYLOAD(attr) == 1) {
	    memcpy(&shutdown, RTA_DATA(attr), 1);
	    myDebug(1, "tcp: INET_DIAG_SHUTDOWN=%u", shutdown);
	  }
	}
	  break;
	case INET_DIAG_CLASS_ID: {
	  if(RTA_PAYLOAD(attr) == 4) {
	    memcpy(&class_id, RTA_DATA(attr), 4);
	    myDebug(1, "tcp: INET_DIAG_CLASS=%u", class_id);
	  }
	}
	  break;
	case INET_DIAG_SOCKOPT: {
	  if(RTA_PAYLOAD(attr) == 2) {
	    memcpy(&sockopt_flags, RTA_DATA(attr), 2);
	    myDebug(1, "tcp: INET_DIAG_SOCKOPT=0x%02X", sockopt_flags);
	  }
	}
	  break;
	case  INET_DIAG_INFO: {
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
	    myDebug(3, "tcp: New kernel has new fields in struct tcp_info. Check it out!");
	    readLen = sizeof(struct my_tcp_info);
	  }
	  memcpy(&tcpi, RTA_DATA(attr), readLen);
	  myDebug(2, "tcp: TCP diag: RTT=%uuS (variance=%uuS) [%s]",
		  tcpi.tcpi_rtt, tcpi.tcpi_rttvar,
		  UTNLDiag_sockid_print(&diag_msg->id));
	  if(found) {
	    uint32_t nSamples = UTArrayN(found->samples);
	    myDebug(2, "tcp: found TCPSample: %s RTT:%uuS, annotating %u packet samples",
		    tcpSamplePrint(found),
		    tcpi.tcpi_rtt,
		    nSamples);
	    mdata->samples_annotated += nSamples;
	    HSPPendingSample *ps;
	    UTARRAY_WALK(found->samples, ps) {
	      // populate tcp_info structure
	      SFLFlow_sample_element *tcpElem = pendingSample_calloc(ps, sizeof(SFLFlow_sample_element));
	      tcpElem->tag = SFLFLOW_EX_TCP_INFO;
	      // both sent and received samples may be in this list, so we have
	      // to look at the localSrc flag sample-by-sample to determine the direction
	      // we should report:
	      tcpElem->flowType.tcp_info.dirn = ps->localSrc ? PKTDIR_sent : PKTDIR_received;
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
	      // tag the the sample with additional meta-data learned here
	      ps->cgroup_id = cgroup_id;
	      // release sample
	      releasePendingSample(sp, ps);
	    }
	  }
	}
	  break;
	default:
	  myDebug(1, "tcp: INET_DIAG_(%u): payload=%u", attr->rta_type, RTA_PAYLOAD(attr));
	  break;
	}
	attr = RTA_NEXT(attr, rtalen);
      }
    }

    if(found) {
      // unlink from Q
      UTQ_REMOVE(mdata->timeoutQ, found);
      // and free my control-block
      tcpSampleFree(found);
    }
  }


  /*_________________---------------------------__________________
    _________________         readNL            __________________
    -----------------___________________________------------------
  */

  static void diagCB(void *magic, int sockFd, uint32_t seqNo, struct inet_diag_msg *diag_msg, int rtalen) {
      parse_diag_msg((EVMod *)magic, diag_msg, rtalen, seqNo);
  }

  static void readNL(EVMod *mod, EVSocket *sock, void *magic)
  {
    HSP_mod_TCP *mdata = (HSP_mod_TCP *)mod->data;
    UTNLDiag_recv(mod, mdata->nl_sock, diagCB);
  }

  /*_________________---------------------------__________________
    _________________       evt_tick            __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_TCP *mdata = (HSP_mod_TCP *)mod->data;
    uint32_t n_thisTick = mdata->diag_tx + mdata->diag_rx + mdata->nl_seq_lost + mdata->diag_timeouts;
    if(n_thisTick != mdata->n_lastTick) {
      myDebug(1, "tcp: tx=%u, rx=%u, lost=%u, timeout=%u, annotated=%u, ipip_tx=%u",
	      mdata->diag_tx,
	      mdata->diag_rx,
	      mdata->nl_seq_lost,
	      mdata->diag_timeouts,
	      mdata->samples_annotated,
	      mdata->ipip_tx);
     mdata->n_lastTick = n_thisTick;
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
	myDebug(2, "tcp: removing timed-out request (%s)", tcpSamplePrint(ts));
	HSPTCPSample *next_ts = ts->next;
	// remove from Q
	UTQ_REMOVE(mdata->timeoutQ, ts);
	// remove from HT
	UTHashDel(mdata->sampleHT, ts);
	// count
	mdata->diag_timeouts++;
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
    _________________       lookup_sample       __________________
    -----------------___________________________------------------
  */

  static void lookup_sample(EVMod *mod, HSPPendingSample *ps, SFLAddress *ipsrc, SFLAddress *ipdst, uint8_t ipproto, uint16_t sport, uint16_t dport, bool localSrc) {
    HSP_mod_TCP *mdata = (HSP_mod_TCP *)mod->data;
    
    if(debug(2)) {
      char ipb1[51], ipb2[51];
      myDebug(2, "tcp: proto=%u local_src=%u src=%s:%u dst=%s:%u",
	      ipproto,
	      localSrc,
	      SFLAddress_print(ipsrc,ipb1,50),
	      sport,
	      SFLAddress_print(ipdst,ipb2,50),
	      dport);
    }

    // OK,  we are going to look this one up
    HSPTCPSample *tcpSample = tcpSampleNew();
    tcpSample->qtime = mdata->packetBus->now;
    tcpSample->pktdirn = localSrc ? PKTDIR_sent : PKTDIR_received;
    // just the established TCP connections
    tcpSample->conn_req.sdiag_protocol = ipproto;
    tcpSample->udp = (ipproto == IPPROTO_UDP);
    if(ipproto == IPPROTO_TCP) {
      tcpSample->conn_req.idiag_states = (1<<TCP_ESTABLISHED);
      // just the tcp_info
      tcpSample->conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
    }
    else {
      // TODO: is this necessary?
      tcpSample->conn_req.idiag_states = 0xFFFF;
      tcpSample->conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
    }
    // copy into inet_diag_sockid, but flip if we are the destination
    struct inet_diag_sockid *sockid = &tcpSample->conn_req.id;
    // addresses
    tcpSample->src = *ipsrc;
    tcpSample->dst = *ipdst;
    if(ipsrc->type == SFLADDRESSTYPE_IP_V4) {
      tcpSample->conn_req.sdiag_family = AF_INET;
      if(localSrc) {
	memcpy(sockid->idiag_src, &ipsrc->address.ip_v4, 4);
	memcpy(sockid->idiag_dst, &ipdst->address.ip_v4, 4);
      }
      else {
	tcpSample->flipped = YES;
	memcpy(sockid->idiag_src, &ipdst->address.ip_v4, 4);
	memcpy(sockid->idiag_dst, &ipsrc->address.ip_v4, 4);
      }
    }
    else {
      tcpSample->conn_req.sdiag_family = AF_INET6;
      if(localSrc) {
	memcpy(sockid->idiag_src, &ipsrc->address.ip_v6, 16);
	memcpy(sockid->idiag_dst, &ipdst->address.ip_v6, 16);
      }
      else {
	memcpy(sockid->idiag_src, &ipdst->address.ip_v6, 16);
	memcpy(sockid->idiag_dst, &ipsrc->address.ip_v6, 16);
      }
    }
    // L4 ports
    if(localSrc) {
      sockid->idiag_sport = htons(sport);
      sockid->idiag_dport = htons(dport);
    }
    else {
      sockid->idiag_sport = htons(dport);
      sockid->idiag_dport = htons(sport);
    }
    // specify the ifIndex in case the socket is bound
    // see INET_MATCH in net/ipv4/inet_hashtables.c
    sockid->idiag_if = SFL_DS_INDEX(ps->sampler->dsi);
    // I have no cookie :(
    sockid->idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    sockid->idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    // normalize for sampleHT key
    tcpSample->normalized_id = *sockid;
    UTNLDiag_sockid_normalize(&tcpSample->normalized_id);
    // put a hold on this one while we look it up
    holdPendingSample(ps);
    HSPTCPSample *tsInQ = UTHashGet(mdata->sampleHT, tcpSample);
    if(tsInQ) {
      myDebug(2, "tcp: request already pending");
      UTArrayAdd(tsInQ->samples, ps);
      tcpSampleFree(tcpSample);
    }
    else {
      myDebug(2, "tcp: new request: %s", tcpSamplePrint(tcpSample));
      UTArrayAdd(tcpSample->samples, ps);
      // add to HT and timeout queue
      UTHashAdd(mdata->sampleHT, tcpSample);
      UTQ_ADD_TAIL(mdata->timeoutQ, tcpSample);
      // send the netlink request
      UTNLDiag_send(mdata->nl_sock,
		    &tcpSample->conn_req,
		    sizeof(tcpSample->conn_req),
		    tcpSample->udp, // set DUMP flag if UDP
		    ++mdata->nl_seq_tx);
      mdata->diag_tx++;
    }
  }

  /*_________________---------------------------__________________
    _________________       evt_flow_sample     __________________
    -----------------___________________________------------------
  */

  static void evt_flow_sample(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPPendingSample *ps = (HSPPendingSample *)data;
    int ip_ver = decodePendingSample(ps);
    if(ip_ver == 4
       || ip_ver == 6) {
      if (ps->ipproto == IPPROTO_TCP
	  || (sp->tcp.udp && !ps->gotInnerIP)) {
	// was it to or from this host / management IP?
	if(!ps->localTest) {
	  ps->localSrc = isLocalAddress(sp, &ps->src);
	  ps->localDst = isLocalAddress(sp, &ps->dst);
	  ps->localTest = YES;
	}
	if(ps->localSrc != ps->localDst)
	  lookup_sample(mod,
			ps,
			&ps->src,
			&ps->dst,
			ps->ipproto,
			ps->l4_sport,
			ps->l4_dport,
			ps->localSrc);
      }
      else if (sp->tcp.tunnel
	       && ps->gotInnerIP
	       && ps->ipproto_1 == IPPROTO_TCP
	       && ps->hdr_protocol == SFLHEADER_ETHERNET_ISO8023) {
	// look up using the inner IP addresses instead
	// this behavior is only enabled with tcp {tunnel=on}.
	// Setting tunnel=on should only ever be done when
	// running on an end-host. If running on a router this
	// might trigger a storm of pointless netlink lookups.
	
	// to determine direction, use the MAC layer
	ps->localSrc = (adaptorByMac(sp, &ps->macsrc) != NULL);
	ps->localDst = (adaptorByMac(sp, &ps->macdst) != NULL);
	if(ps->localSrc != ps->localDst)
	  lookup_sample(mod,
			ps,
			&ps->src_1,
			&ps->dst_1,
			ps->ipproto_1,
			ps->l4_sport_1,
			ps->l4_dport_1,
			ps->localSrc);
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
    if((mdata->nl_sock = UTNLDiag_open()) == -1) {
      myLog(LOG_ERR, "nl_sock open failed: %s", strerror(errno));
      return;
    }
    EVBusAddSocket(mod, mdata->packetBus, mdata->nl_sock, readNL, NULL);
    mdata->nl_seq_tx = mdata->nl_seq_rx = 0x50C00L;
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_tcp(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_TCP));
    HSP_mod_TCP *mdata = (HSP_mod_TCP *)mod->data;
    mdata->sampleHT = UTHASH_NEW(HSPTCPSample, normalized_id, UTHASH_DFLT);
    // trim the hash-key len to select only the socket part of inet_diag_sockid
    // and leave out the interface and the cookie
    mdata->sampleHT->f_len = 36;
    // register call-backs
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_CONFIG_FIRST), evt_config_first);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, EVEVENT_TICK), evt_tick);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, EVEVENT_DECI), evt_deci);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_FLOW_SAMPLE), evt_flow_sample);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
