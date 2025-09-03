/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

  // includes for setsockopt(SO_ATTACH_FILTER)
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <sys/select.h>
#include <bpf/libbpf.h>
#include "sample.skel.h"
#include "sample.bpf.h"

#define HSP_IPV4_FORWARDING_PROC "/proc/sys/net/ipv4/ip_forward"
#define HSP_IPV6_FORWARDING_PROC "/proc/sys/net/ipv6/conf/all/forwarding"
#define HSP_READPACKET_BATCH_EPCAP 100

  typedef struct _HSPEpcapDev {
    uint32_t ifIndex;
    char *deviceName;
    uint32_t samplingRate;
    struct bpf_link *bpf_link_ingress;
    struct bpf_link *bpf_link_egress;
  } HSPEpcapDev;

  typedef struct _HSP_mod_EPCAP {
    EVBus *packetBus;
    struct sample_bpf *skel;
    struct ring_buffer *rb;
    EVSocket *rb_sock;
    bool rb_busy;
    int rb_quota;
    bool routingLookup;
    UTHash *devs;
  } HSP_mod_EPCAP;

  static void cleanup_dev(EVMod *mod, HSPEpcapDev *dev);
  static void readPackets_epcap(EVMod *mod, EVSocket *sock, void *magic);

  /*_________________---------------------------__________________
    _________________     Logging               __________________
    -----------------___________________________------------------
  */

  int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level < LIBBPF_WARN)
      myLogv2(0, YES, LOG_ERR, (char *)format, args);
    return 0;
  }

  /*_________________---------------------------__________________
    _________________        evt_busy           __________________
    -----------------___________________________------------------
  */
  
  static void evt_busy(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;
    // If we didn't fully empty the ringbuffer on the last call, then we need
    // to poll it again in the idle loop until it is empty. The adaptive
    // notification system means we only get an file-descriptor notification
    // when the ringbuffer goes from empty to non-empty on write.
    readPackets_epcap(mod, mdata->rb_sock, NULL);
  }

  /*_________________---------------------------__________________
    _________________      readPackets          __________________
    -----------------___________________________------------------
  */

  static void readPackets_epcap(EVMod *mod, EVSocket *sock, void *magic) {
    HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;
    // ring_buffer__consume_n() only appeared in version 1.5,
    // so we manage the quota this way.
    mdata->rb_quota = HSP_READPACKET_BATCH_EPCAP;
    ring_buffer__consume(mdata->rb);
    if(mdata->rb_quota == 0) {
      // if we got a complete batch then remember to check again in BUSY
      if(!mdata->rb_busy) {
	mdata->rb_busy = YES;
	EVEventRx(mod, EVGetEvent(mdata->packetBus, EVEVENT_BUSY), evt_busy);
      }
    }
    else {
      // if not, remember to turn off BUSY
      if(mdata->rb_busy) {
	EVEventRxOff(mod, EVGetEvent(mdata->packetBus, EVEVENT_BUSY), evt_busy);
	mdata->rb_busy = NO;
      }
    }
  }

  /*_________________---------------------------__________________
    _________________     handle_event          __________________
    -----------------___________________________------------------
  */

  static int handle_event(void *ctx, void *data, size_t data_sz) {
    EVMod *mod = (EVMod *)ctx;
    HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    struct packet_event_t *evt = data;
    if (data_sz < sizeof(*evt)) {
      EVDebug(mod, 1, "Invalid event size: %zu (< %u)", data_sz, sizeof(*evt));
      return -2;
    }
    EVDebug(mod, 2, "Timestamp: %llu, Ifindex: %u, Ingress: %u, Routed: %u, Direction %s, Packet length: %u, Header: ",
	    evt->timestamp, evt->ifindex, evt->ingress_ifindex, evt->routed_ifindex, evt->direction ? "egress" : "ingress", evt->pkt_len);
    int hdr_len = evt->pkt_len < MAX_PKT_HDR_LEN ? evt->pkt_len : MAX_PKT_HDR_LEN;
    u_char hex[128];
    printHex(evt->hdr, hdr_len, hex, 128, NO);
    EVDebug(mod, 0, (char *)hex);
    uint32_t in = evt->ingress_ifindex;
    uint32_t out = (evt->direction == 1) ? evt->ifindex : evt->routed_ifindex;
    SFLAdaptor *tapDev = adaptorByIndex(sp, evt->ifindex);
    SFLAdaptor *srcDev = adaptorByIndex(sp, in);
    SFLAdaptor *dstDev = adaptorByIndex(sp, out);

    uint32_t ds_options = (HSP_SAMPLEOPT_DEV_SAMPLER
			   | HSP_SAMPLEOPT_DEV_POLLER);
    bool isBridge = (ADAPTOR_NIO(tapDev)->devType == HSPDEV_BRIDGE);
    if(isBridge)
      ds_options |= HSP_SAMPLEOPT_BRIDGE;
 
#if 0
    // ask for vport counters if vport=on in config, or
      // if vport is not specified in config and the device
      // is a bridge device.
    if(bpfs->vport
       || (bpfs->vport_set == NO
	   && isBridge))
      ds_options |= HSP_SAMPLEOPT_IF_POLLER;
#endif
    
    u_char *mac_hdr = evt->hdr;
    uint32_t mac_len = 14;
    
    takeSample(sp,
	       srcDev,
	       dstDev,
	       tapDev,
	       DLT_EN10MB,
	       ds_options,
	       0, // hook
	       mac_hdr,
	       mac_len,
	       evt->hdr + mac_len, // payload
	       hdr_len - mac_len, // length of captured payload
	       evt->pkt_len,
	       0, // drops
	       evt->sampling_rate,
	       NULL);
    if(--mdata->rb_quota == 0) {
      // This may be reported as an error, but all we are doing is relinquishing
      // control so that we can't spin forever in this loop. Essentially a
      // green-thread "yield".
      return -1;
    }
    return 0; // OK
  }

  /*_________________---------------------------__________________
    _________________     init_ring_buffer      __________________
    -----------------___________________________------------------
  */

  bool init_ring_buffer(EVMod *mod, bool routing) {
    HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;
    libbpf_set_print(libbpf_print_fn);
    struct sample_bpf *skel = mdata->skel = sample_bpf__open_and_load();
    if (!skel) {
      myLog(LOG_ERR, "Failed to open and load BPF skeleton\n");
      return NO;
    }

    int key = 0;
    int ret = bpf_map__update_elem(skel->maps.routing, &key, sizeof(int), &routing, sizeof(int), 0);
    if (ret < 0) {
      EVDebug(mod, 0, "Failed to update routing map: %s\n", strerror(-ret));
      return NO;
    }

    mdata->rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, mod, NULL);
    if (!mdata->rb) {
      EVDebug(mod, 0, "Failed to create ring buffer\n");
      return NO;
    }

    int rb_fd = ring_buffer__epoll_fd(mdata->rb);
    if (rb_fd < 0) {
      EVDebug(mod, 0, "Failed to get ring buffer fd\n");
      return NO;
    }
    mdata->rb_sock = EVBusAddSocket(mod, mdata->packetBus, rb_fd, readPackets_epcap, NULL);
    return YES;
  }

    /*_______________-------------------------__________________
    _________________   enable_dev_sampling   __________________
    -----------------_________________________------------------
  */

  bool enable_dev_sampling(EVMod *mod, HSPEpcapDev *dev) {
    HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;

    struct sample_bpf *skel = mdata->skel;
    uint32_t rate = dev->samplingRate;

    if(skel==NULL)
      return NO;

    int key = dev->ifIndex;
    int ret = bpf_map__update_elem(skel->maps.sampling, &key, sizeof(int), &rate, sizeof(int), 0);
    if (ret < 0) {
      EVDebug(mod, 0, "Failed to update sample_rate map: %s\n", strerror(-ret));
      return NO;
    }
    struct bpf_tcx_opts opts = {
        .sz = sizeof(opts),
    };
    dev->bpf_link_ingress = bpf_program__attach_tcx(skel->progs.tcx_ingress, dev->ifIndex, &opts);
    if (!dev->bpf_link_ingress) {
      EVDebug(mod, 0, "Failed to attach TC program for ingress: %s\n", strerror(errno));
      return NO;
    }

    dev->bpf_link_egress = bpf_program__attach_tcx(skel->progs.tcx_egress, dev->ifIndex, &opts);
    if (!dev->bpf_link_egress) {
      EVDebug(mod, 0, "Failed to attach TC program for egress: %s\n", strerror(errno));
      return NO;
    }

    return YES;
  }

  /*_________________---------------------------__________________
    _________________     addBPFSocket          __________________
    -----------------___________________________------------------
  */
  static bool addBPFSocket(EVMod *mod,  HSPPcap *pcap, SFLAdaptor *adaptor) {
    HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPEpcapDev *dev = my_calloc(sizeof(*dev));
    dev->ifIndex = adaptor->ifIndex;
    dev->deviceName = my_strdup(adaptor->deviceName);
    HSPEpcapDev *search = UTHashGet(mdata->devs, dev);
    if(search) {
      EVDebug(mod, 0, "addBPFSocket: dev %s already added", adaptor->deviceName);
      my_free(dev);
      return NO;
    }
    UTHashAdd(mdata->devs, dev);
    dev->samplingRate = lookupPacketSamplingRate(adaptor, sp->sFlowSettings);
    enable_dev_sampling(mod, dev);
    return YES;
  }

  /*_________________---------------------------__________________
    _________________  removeAndFreeBPFSocket   __________________
    -----------------___________________________------------------
  */

  static bool removeAndFreeBPFSocket(EVMod *mod,  HSPEpcapDev *dev) {
    HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;
    HSPEpcapDev *removed = UTHashDel(mdata->devs, dev);
    if(removed == NULL) {
      EVDebug(mod, 1, "removeAndFree: dev %s not found", dev->deviceName);
      return NO;
    }
    cleanup_dev(mod, dev);
    my_free(dev->deviceName);
    my_free(dev);
    return YES;
  }

  /*_________________---------------------------__________________
    _________________      speedTestOK          __________________
    -----------------___________________________------------------
  */

  static bool speedTestOK(EVMod *mod, HSPPcap *pcap, SFLAdaptor *adaptor) {
    return ((adaptor->ifSpeed == pcap->speed_min && pcap->speed_max == 0)
	    || (adaptor->ifSpeed >= pcap->speed_min
		&& adaptor->ifSpeed <= pcap->speed_max));
  }

  /*_________________---------------------------__________________
    _________________    evt_config_first       __________________
    -----------------___________________________------------------
  */

  static void evt_config_first(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);

    // the list of pcap {} sections may expand to a longer list of BPFSoc
    // objects if we are matching with patterns or on ifSpeed etc.
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByName, adaptor) {
      for(HSPPcap *pcap = sp->epcap.pcaps; pcap; pcap = pcap->nxt) {
	if(pcap->dynamic) // ignore dynamic pcaps here
	  continue;
	if(pcap->dev
	   && adaptorByName(sp, pcap->dev) != adaptor)
	  continue;
	if(pcap->dev_regex
	   && regexec(pcap->dev_regex, adaptor->deviceName, 0, NULL, 0) != 0)
	  continue;
	if(pcap->speed_set
	   && !speedTestOK(mod, pcap, adaptor))
	    continue;
	// passed speed test, but there may be other reasons to reject:
	HSPAdaptorNIO *nio = (HSPAdaptorNIO *)adaptor->userData;
	if(nio->bond_master) {
	  EVDebug(mod, 1, "skip %s (bond_master)", adaptor->deviceName);
	  continue;
	}
	if(nio->vlan != HSP_VLAN_ALL) {
	  EVDebug(mod, 1, "skip %s (vlan=%u)", adaptor->deviceName, nio->vlan);
	  continue;
	}
	if(nio->devType != HSPDEV_PHYSICAL
	   && nio->devType != HSPDEV_OTHER) {
	  EVDebug(mod, 1, "skip %s (devType=%s)",
		  adaptor->deviceName,
		  devTypeName(nio->devType));
	  continue;
	}
	// passed all the tests
	addBPFSocket(mod, pcap, adaptor);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________       evt_get_tap         __________________
    -----------------___________________________------------------
  */

  static void evt_get_tap(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(dataLen != sizeof(uint32_t))
      return;
    uint32_t ifIndex = 0;
    memcpy(&ifIndex, data, dataLen);
    SFLAdaptor *adaptor = adaptorByIndex(sp, ifIndex);
    if(adaptor == NULL) {
      EVDebug(mod, 1, "evt_get_tap: adaptor not found for ifIndex %u", ifIndex);
      return;
    }
    // next we have to find a dynamic epcap{} that will match this device
    // on all specified criteria.
    for(HSPPcap *pcap = sp->epcap.pcaps; pcap; pcap = pcap->nxt) {
      if(!pcap->dynamic)  // only dynamic pcaps here
	continue;
      if(pcap->dev
	 && adaptorByName(sp, pcap->dev) != adaptor)
	continue;
      if(pcap->dev_regex
	 && regexec(pcap->dev_regex, adaptor->deviceName, 0, NULL, 0) != 0)
	continue;
      if(pcap->speed_set
	 && !speedTestOK(mod, pcap, adaptor))
	continue;
      // we don't apply the other filters here (bond_master, vlan, dev-type)
      // in case that was actually part of the requestor's plan.
      EVDebug(mod, 1, "evt_get_tap: dynamic add pcap tap on %s", adaptor->deviceName);
      addBPFSocket(mod, pcap, adaptor);
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_intfs_changed      __________________
    -----------------___________________________------------------
  */

  static void evt_intfs_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    // close sockets and remove adaptor references for anything that no longer exists
    UTArray *elems = UTHashElements(mdata->devs);
    HSPEpcapDev  *dev;
    UTARRAY_WALK(elems, dev) {
      if(adaptorByName(sp, dev->deviceName) == NULL) {
	removeAndFreeBPFSocket(mod, dev);
      }
    }
    UTArrayFree(elems);
  }
  
  /*_________________---------------------------__________________
    _________________     cleanup_dev           __________________
    -----------------___________________________------------------
  */

  static void cleanup_dev(EVMod *mod, HSPEpcapDev *dev) {
    HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;
    if(mdata->skel) {
      if(dev->bpf_link_ingress) {
	bpf_link__destroy(dev->bpf_link_ingress);
	dev->bpf_link_ingress = NULL;
      }
      if(dev->bpf_link_egress) {
	bpf_link__destroy(dev->bpf_link_egress);
	dev->bpf_link_egress = NULL;
      }
      int key = dev->ifIndex;
      int ret = bpf_map__delete_elem(mdata->skel->maps.sampling, &key, sizeof(int), 0);
      if(ret < 0) {
	myLog(LOG_ERR, "Failed to delete from sample_rate map: %s\n", strerror(-ret));
      }
    }
  }
  
  /*_________________---------------------------__________________
    _________________        evt_final          __________________
    -----------------___________________________------------------
    on packetBus - so it is sync'd with the above
  */
  
  static void evt_final(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;
    HSPEpcapDev *dev;
    UTHASH_WALK(mdata->devs, dev)
      cleanup_dev(mod, dev);
    if(mdata->skel) {
      sample_bpf__destroy(mdata->skel);
    }
    if(mdata->rb) {
      ring_buffer__free(mdata->rb);
    }
  }
  
  /*_________________---------------------------__________________
    _________________     ipRoutingTest         __________________
    -----------------___________________________------------------
  */
  
  static bool ipRoutingTestProc(EVMod *mod, const char *procPath) {
    int forwarding = 0;
    FILE *ff = fopen(procPath, "r");
    if(ff == NULL) {
      myLog(LOG_ERR, "ipRoutingTestProc failed to open %s : %s", procPath, strerror(errno));
    }
    else {
      fscanf(ff, "%d", &forwarding);
      fclose(ff);
    }
    return (forwarding == 1);
  }

  static bool ipRoutingOn(EVMod *mod) {
    return ipRoutingTestProc(mod, HSP_IPV4_FORWARDING_PROC)
      || ipRoutingTestProc(mod, HSP_IPV6_FORWARDING_PROC);
  }
    

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_epcap(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_EPCAP));
    HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;
    mdata->devs = UTHASH_NEW(HSPEpcapDev, ifIndex, UTHASH_DFLT);
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    mdata->routingLookup = ipRoutingOn(mod);
    init_ring_buffer(mod, mdata->routingLookup);
    // register call-backs
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_CONFIG_FIRST), evt_config_first);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_INTFS_CHANGED), evt_intfs_changed);
    // dynamic tap request api
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_GET_TAP), evt_get_tap);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, EVEVENT_FINAL), evt_final);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
