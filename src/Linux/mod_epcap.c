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

// Must match sample.bpf.c
#define MAX_PKT_HDR_LEN 128

  // Must match sample.bpf.c
  struct packet_event_t {
    __u64 timestamp;
    __u32 ifindex;
    __u32 sampling_rate;
    __u32 ingress_ifindex;
    __u32 routed_ifindex;
    __u32 pkt_len;
    __u8 direction;
    __u8 hdr[MAX_PKT_HDR_LEN];
  } __attribute__((packed));
  

  typedef struct _HSPEpcapDev {
    uint32_t ifIndex;
    char *deviceName;
    uint32_t samplingRate;
    bool routingLookup;
    struct bpf_link *bpf_link_ingress;
    struct bpf_link *bpf_link_egress;
  } HSPEpcapDev;

  typedef struct _HSP_mod_EPCAP {
    EVBus *packetBus;
    struct sample_bpf *skel;
    struct perf_buffer *pb;
    UTHash *devs;
    uint32_t num_cpus;
  } HSP_mod_EPCAP;


  static void cleanup_dev(EVMod *mod, HSPEpcapDev *dev);

  /*_________________---------------------------__________________
    _________________     logging               __________________
    -----------------___________________________------------------
  */

  int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level < LIBBPF_WARN)
      myLogv2(0, YES, LOG_ERR, (char *)format, args);
    return 0;
  }

  /*_________________---------------------------__________________
    _________________      readPackets          __________________
    -----------------___________________________------------------
  */

  static void readPackets_epcap(EVMod *mod, EVSocket *sock, void *magic) {
    HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;
    uint32_t cpu = (intptr_t)magic;
    EVDebug(mod, 0, "readPackets_epcap cpu=%u", cpu);
    if (perf_buffer__consume_buffer(mdata->pb, cpu) < 0) {
      myLog(LOG_ERR, "perf_buffer__consume_buffer(cpu=%d) failed\n", cpu);
    }
  }

  /*_________________---------------------------__________________
    _________________     handle_event          __________________
    -----------------___________________________------------------
  */

  static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    EVMod *mod = (EVMod *)ctx;
    // HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    struct packet_event_t *evt = data;
    if (data_sz < sizeof(*evt)) {
      EVDebug(mod, 0, "Invalid event size: %u", data_sz);
      return;
    }
    EVDebug(mod, 0, "Timestamp: %llu, Ifindex: %u, Ingress: %u, Routed: %u, Direction %s, Packet length: %u, Header: ",
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
	       0, // DLT_EN10MB?
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
  }

  /*_________________---------------------------__________________
    _________________     init_perf_buffer      __________________
    -----------------___________________________------------------
  */

  bool init_perf_buffer(EVMod *mod) {
    HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;
    libbpf_set_print(libbpf_print_fn);
    struct sample_bpf *skel = mdata->skel = sample_bpf__open_and_load();
    if (!skel) {
      myLog(LOG_ERR, "Failed to open and load BPF skeleton\n");
      return NO;
    }
    struct perf_buffer *pb = mdata->pb = perf_buffer__new(bpf_map__fd(skel->maps.events),
							  64, /* page_cnt */
							  handle_event,
							  NULL, /* lost_cb */
							  mod,
							  NULL /* opts */);
    if (!pb) {
      myLog(LOG_ERR, "Failed to create perf buffer\n");
      return NO;
    }

    for (int cpu = 0; cpu < mdata->num_cpus; cpu++) {
      int fd = perf_buffer__buffer_fd(pb, cpu);
      if (fd < 0)
	continue;
      EVBusAddSocket(mod, mdata->packetBus, fd, readPackets_epcap, (void *)(intptr_t)cpu);
    }

    return YES;
  }

    /*_______________-------------------------__________________
    _________________   enable_dev_sampling   __________________
    -----------------_________________________------------------
  */

  bool enable_dev_sampling(EVMod *mod, HSPEpcapDev *dev) {
    HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;

    struct sample_bpf *skel = mdata->skel;
    struct perf_buffer *pb = mdata->pb;
    uint32_t rate = dev->samplingRate;
    uint32_t routing = dev->routingLookup;

    if(skel==NULL
       || pb==NULL)
      return NO;

    int key = dev->ifIndex;
    int ret = bpf_map__update_elem(skel->maps.sampling, &key, sizeof(int), &rate, sizeof(int), 0);
    if (ret < 0) {
      EVDebug(mod, 0, "Failed to update sample_rate map: %s\n", strerror(-ret));
      return NO;
    }
    key = 0;
    ret = bpf_map__update_elem(skel->maps.routing, &key, sizeof(int), &routing, sizeof(int), 0);
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
      ret = bpf_map__delete_elem(mdata->skel->maps.routing, &key, sizeof(int), 0);
      if(ret < 0) {
	myLog(LOG_ERR, "Failed to delete from routing map: %s\n", strerror(-ret));
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
    if(mdata->pb) {
      perf_buffer__free(mdata->pb);
    }
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_epcap(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_EPCAP));
    HSP_mod_EPCAP *mdata = (HSP_mod_EPCAP *)mod->data;
    mdata->num_cpus = libbpf_num_possible_cpus();
    mdata->devs = UTHASH_NEW(HSPEpcapDev, ifIndex, UTHASH_DFLT);
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    init_perf_buffer(mod);
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
