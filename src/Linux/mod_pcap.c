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

#include <pcap.h>
#define HSP_READPACKET_BATCH_PCAP 10000

  typedef struct _BPFSoc {
    EVMod *module;
    char *deviceName;
    SFLAdaptor *adaptor;
    EVSocket *sock;
    uint32_t samplingRate;
    uint32_t subSamplingRate;
    uint32_t drops;
    bool promisc:1;
    bool vport:1;
    bool vport_set:1;
    bool outbound_only:1;
    pcap_t *pcap;
    char pcap_err[PCAP_ERRBUF_SIZE];
  } BPFSoc;

  typedef struct _HSP_mod_PCAP {
    UTArray *bpf_socs;
    EVBus *packetBus;
  } HSP_mod_PCAP;

  static void tap_close(EVMod *mod, BPFSoc *bpfs);

  /*_________________---------------------------__________________
    _________________      readPackets          __________________
    -----------------___________________________------------------
  */

  // function of type pcap_handler

  static void readPackets_pcap_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *buf)
  {
    static uint32_t MySkipCount=1;
    BPFSoc *bpfs = (BPFSoc *)user;
    uint32_t sr = bpfs->subSamplingRate;

    if(sr == 0) {
      // sampling disabled by setting to 0
      return;
    }

    if(--MySkipCount == 0) {
      /* reached zero. Set the next skip */
      MySkipCount = sr == 1 ? 1 : sfl_random((2 * sr) - 1);

      EVMod *mod = bpfs->module;
      HSP *sp = (HSP *)EVROOTDATA(mod);

      // global MAC -> adaptor
      SFLMacAddress macdst, macsrc;
      memset(&macdst, 0, sizeof(macdst));
      memset(&macsrc, 0, sizeof(macsrc));
      memcpy(macdst.mac, buf, 6);
      memcpy(macsrc.mac, buf+6, 6);
      SFLAdaptor *srcdev = adaptorByMac(sp, &macsrc);
      SFLAdaptor *dstdev = adaptorByMac(sp, &macdst);

      if(getDebug() > 2) {
	u_char mac_s[13], mac_d[13];
	printHex(macsrc.mac, 6, mac_s, 13, NO);
	printHex(macdst.mac, 6, mac_d, 13, NO);
	myLog(LOG_INFO, "PCAP: macsrc=%s, macdst=%s", mac_s, mac_d);
	if(srcdev) {
	  myLog(LOG_INFO, "PCAP: srcdev=%s(%u)(peer=%u)",
		srcdev->deviceName,
		srcdev->ifIndex,
		srcdev->peer_ifIndex);
	}
	if(dstdev) {
	  myLog(LOG_INFO, "PCAP: dstdev=%s(%u)(peer=%u)",
		dstdev->deviceName,
		dstdev->ifIndex,
		dstdev->peer_ifIndex);
	}
      }

      uint32_t ds_options = (HSP_SAMPLEOPT_DEV_SAMPLER
			     | HSP_SAMPLEOPT_DEV_POLLER);
      bool isBridge = (ADAPTOR_NIO(bpfs->adaptor)->devType == HSPDEV_BRIDGE);
      if(isBridge)
	ds_options |= HSP_SAMPLEOPT_BRIDGE;
      // ask for vport counters if vport=on in config, or
      // if vport is not specified in config and the device
      // is a bridge device.
      if(bpfs->vport
	 || (bpfs->vport_set == NO
	     && isBridge))
	ds_options |= HSP_SAMPLEOPT_IF_POLLER;

      takeSample(sp,
		 srcdev,
		 dstdev,
		 bpfs->adaptor,
		 ds_options,
		 0 /*hook*/,
		 buf /* mac hdr*/,
		 14 /* mac len */,
		 buf + 14 /* payload */,
		 hdr->caplen - 14, /* length of captured payload */
		 hdr->len - 14, /* length of packet (pdu) */
		 bpfs->drops, /* droppedSamples */
		 bpfs->samplingRate,
		 NULL);
    }
  }

  static void readPackets_pcap(EVMod *mod, EVSocket *sock, void *magic)
  {
    BPFSoc *bpfs = (BPFSoc *)magic;
    int batch = pcap_dispatch(bpfs->pcap,
			      HSP_READPACKET_BATCH_PCAP,
			      readPackets_pcap_cb,
			      (u_char *)bpfs);
    if(batch == -1) {
      myLog(LOG_ERR, "pcap_dispatch error : %s\n", pcap_geterr(bpfs->pcap));
      // may get here if the interface was removed
      tap_close(mod, bpfs);
    }
  }

  /*_________________---------------------------__________________
    _________________   setKernelSampling       __________________
    -----------------___________________________------------------

    https://www.kernel.org/doc/Documentation/networking/filter.txt

    Apply a packet-sampling BPF filter to the socket we are going
    to read packets from.  We could possibly have expressed this
    as a struct bpf_program and called the libpcap pcap_setfilter()
    to set the filter,  but that would have involved re-casting the
    instructions becuse the struct bpf_insn differs from the
    from the kernel's struct sock_filter.  The only way this
    makes sense is if the filter makes it all the way into the
    kernel and works using the SKF_AD_RANDOM negative-offset hack,
    so here we just try it directly.
    (Since pcap_setfilter() calls fix_offset() to adust the width
    of the offset fields there was a risk that putting in an
    offset of, say,  -56 would come out differently in the
    resulting sock_filter).
    There is an assumption here that SF_AD_RANDOM will always
    be offset=-56 (== 0xffffff038) and that the other opcodes
    will not change their values either.
  */

  static uint64_t kernelVer64(HSP *sp) {
    // return the kernel version as an integer,  so that
    // for example "4.3.3" becomes 400030003000.  This
    // makes it easier to test for kernel > x.y.z at
    // runtime.
    char buf[8];
    char *p = sp->os_release;
    uint64_t ver = 0;
    for(int ii = 0; ii < 3; ii++) {
      char *str = parseNextTok(&p, ".", NO, 0, NO, buf, 8);
      if(str) ver = (ver * 1000) + strtol(str, NULL, 0);
    }
    return ver;
  }

  static int setKernelSampling(HSP *sp, BPFSoc *bpfs, int fd)
  {
    if(getDebug()) {
      myLog(LOG_INFO, "PCAP: setKernelSampling() kernel version (as int) == %"PRIu64,
	    kernelVer64(sp));
    }

    if(kernelVer64(sp) < 3019000L) {
      // kernel earlier than 3.19 == not new enough.
      // This would fail silently,  so we have to bail
      // here and rely on uesr-space sampling.  It may
      // have come in before 3.19,  but this is the
      // earliest version that I have tested on
      // successfully.
      myLog(LOG_ERR, "PCAP: warning: kernel too old for BPF sampling. Fall back on user-space sampling.");
      return NO;
    }

    struct sock_filter code[] = {
      // for outbound_only check
      { 0x28,  0,  0, 0xfffff004 }, // ld direction
      { 0x15,  0,  4, 0x00000004 }, // true:outbound, false:inbound
      // for stochastic sampling
      { 0x20,  0,  0, 0xfffff038 }, // ld rand
      { 0x94,  0,  0, 0x00000100 }, // mod #256
      { 0x15,  0,  1, 0x00000001 }, // jneq #1, drop
      { 0x06,  0,  0, 0xffffffff }, // ret #-1
      { 0x06,  0,  0, 0000000000 }, // drop: ret #0
    };

    // overwrite the sampling-rate
    code[3].k = bpfs->samplingRate;
    myDebug(1, "PCAP: sampling rate set to %u for dev=%s", code[3].k, bpfs->deviceName);

    // set filter code range for outboud_only or all
    struct sock_fprog bpf = { 0, 0 };
    if (bpfs->outbound_only) {
      bpf.len = 7;
      bpf.filter = code;
    }
    else {
      bpf.len = 5;
      bpf.filter = code + 2;
    }
    myDebug(1, "PCAP: sampling outbound_only=%s", bpfs->outbound_only? "on" : "off");

    // install the sock_filter directly, rather than using pcap_setfilter()
    int status = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
    myDebug(1, "PCAP: setsockopt (SO_ATTACH_FILTER) status=%d", status);
    if(status == -1) {
      myLog(LOG_ERR, "PCAP: setsockopt (SO_ATTACH_FILTER) status=%d : %s", status, strerror(errno));
      return NO;
    }

    // success - now we don't need to sub-sample in user-space
    bpfs->subSamplingRate = 1;
    myDebug(1, "PCAP: kernel sampling OK");
    return YES;
  }

  /*_________________---------------------------__________________
    _________________    evt_tick               __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_PCAP *mdata = (HSP_mod_PCAP *)mod->data;
    // read pcap stats to get drops - will go out with
    // packet samples sent from readPackets.c
    BPFSoc *bpfs;
    UTARRAY_WALK(mdata->bpf_socs, bpfs) {
      struct pcap_stat stats;
      if(bpfs->pcap
	 && pcap_stats(bpfs->pcap, &stats) == 0) {
	bpfs->drops = stats.ps_drop;
      }
    }
  }

  /*_________________---------------------------__________________
    _________________      tap_open             __________________
    -----------------___________________________------------------
  */
  
  static void tap_open(EVMod *mod, BPFSoc *bpfs) {
    HSP_mod_PCAP *mdata = (HSP_mod_PCAP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    
    bpfs->samplingRate = lookupPacketSamplingRate(bpfs->adaptor, sp->sFlowSettings);
    bpfs->subSamplingRate = bpfs->samplingRate;

    // create pcap
    if((bpfs->pcap = pcap_create(bpfs->deviceName, bpfs->pcap_err)) == NULL) {
      myLog(LOG_ERR, "PCAP: device %s open failed: %s", bpfs->deviceName, bpfs->pcap_err);
      return;
    }

    // immediate mode
    if(kernelVer64(sp) < 3019000L) {
      myDebug(1, "PCAP: kernel too old for BPF sampling, so not setting immediate mode");
    }
    else if(pcap_set_immediate_mode(bpfs->pcap, YES) != 0) {
      myLog(LOG_ERR, "PCAP: pcap_set_immediate_mode(%s) failed", bpfs->deviceName);
    }

    // snaplen
    if(pcap_set_snaplen(bpfs->pcap, sp->sFlowSettings_file->headerBytes) != 0)
      myLog(LOG_ERR, "PCAP: pcap_set_snaplen(%s) failed", bpfs->deviceName);

    // promiscuous mode
    if(pcap_set_promisc(bpfs->pcap, bpfs->promisc) != 0)
      myLog(LOG_ERR, "PCAP: pcap_set_promisc(%s) failed", bpfs->deviceName);

    // read timeout
    if(pcap_set_timeout(bpfs->pcap, 0) != 0)    // indicate we are going to poll
      myLog(LOG_ERR, "PCAP: pcap_set_timeout(%s) failed", bpfs->deviceName);

    // activate
    int status = pcap_activate(bpfs->pcap);
    if(status < 0) {
      myLog(LOG_ERR, "PCAP: activate(%s) ERROR: %s", bpfs->deviceName, pcap_geterr(bpfs->pcap));
      return;
    }
    else if(status > 0) {
      myLog(LOG_INFO, "PCAP: activate(%s) warning: %s", bpfs->deviceName, pcap_geterr(bpfs->pcap));
    }
    
    myDebug(1, "PCAP: device %s opened OK", bpfs->deviceName);

    // get file descriptor
    int fd = pcap_fileno(bpfs->pcap);

    // configure BPF sampling
    if(bpfs->samplingRate > 1)
      setKernelSampling(sp, bpfs, fd);

    // register
    bpfs->sock = EVBusAddSocket(mod, mdata->packetBus, fd, readPackets_pcap, bpfs);

    // assume we always want to get counters for anything we are tapping.
    // Have to force this here in case there are no samples that would
    // trigger it in readPackets.c:takeSample()
    forceCounterPolling(sp, bpfs->adaptor);
  }

  /*_________________---------------------------__________________
    _________________      tap_close            __________________
    -----------------___________________________------------------
  */
  
  static void tap_close(EVMod *mod, BPFSoc *bpfs) {
    bpfs->adaptor = NULL;
    bpfs->sock->fd = -1;
    if(bpfs->pcap) {
      pcap_close(bpfs->pcap);
      bpfs->pcap = NULL;
    }
    EVSocketClose(mod, bpfs->sock, YES);
    bpfs->sock = NULL;
  }

  /*_________________---------------------------__________________
    _________________     addBPFSocket          __________________
    -----------------___________________________------------------
  */
  static void addBPFSocket(EVMod *mod,  HSPPcap *pcap, SFLAdaptor *adaptor) {
    HSP_mod_PCAP *mdata = (HSP_mod_PCAP *)mod->data;
    myDebug(1, "PCAP addBPFSocket(%s) speed=%"PRIu64, adaptor->deviceName, adaptor->ifSpeed);
    BPFSoc *bpfs = (BPFSoc *)my_calloc(sizeof(BPFSoc));
    UTArrayAdd(mdata->bpf_socs, bpfs);
    bpfs->module = mod;
    bpfs->adaptor = adaptor;
    bpfs->deviceName = adaptor->deviceName;
    bpfs->promisc = pcap->promisc;
    bpfs->vport = pcap->vport;
    bpfs->vport_set = pcap->vport_set;
    bpfs->outbound_only = pcap->outbound_only;
    tap_open(mod, bpfs);
  }

  /*_________________---------------------------__________________
    _________________    evt_config_first        __________________
    -----------------___________________________------------------
  */

  static void evt_config_first(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);

    // the list of pcap {} sections may expand to a longer list of BPFSoc
    // objects if we are matching with patterns or on ifSpeed etc.
    for(HSPPcap *pcap = sp->pcap.pcaps; pcap; pcap = pcap->nxt) {
      if(pcap->dev) {
	SFLAdaptor *adaptor = adaptorByName(sp, pcap->dev);
	if(adaptor == NULL) {
	  myLog(LOG_ERR, "PCAP: device %s not found", pcap->dev);
	  continue;
	}
	addBPFSocket(mod, pcap, adaptor);
      }
      else if(pcap->speed_set) {
	if(debug(1)) {
	  char sp1[20], sp2[20];
	  printSpeed(pcap->speed_min, sp1, 20);
	  printSpeed(pcap->speed_max, sp2, 20);
	  myDebug(1, "PCAP: searching devices with speed %s-%s", sp1, sp2);
	}
	SFLAdaptor *adaptor;
	UTHASH_WALK(sp->adaptorsByName, adaptor) {
 	  myDebug(2, "PCAP: consider %s (speed=%"PRIu64")", adaptor->deviceName, adaptor->ifSpeed);
	  if((adaptor->ifSpeed == pcap->speed_min && pcap->speed_max == 0)
	     || (adaptor->ifSpeed >= pcap->speed_min
		 && adaptor->ifSpeed <= pcap->speed_max)) {
	    myDebug(2, "PCAP: %s speed OK", adaptor->deviceName);
	    // passed the speed test,  but there may be other
	    // reasons to reject this one:
	    HSPAdaptorNIO *nio = (HSPAdaptorNIO *)adaptor->userData;
	    if(nio->bond_master) {
	      myDebug(1, "PCAP: skip %s (bond_master)", adaptor->deviceName);
	    }
	    else if(nio->vlan != HSP_VLAN_ALL) {
	      myDebug(1, "PCAP: skip %s (vlan=%u)", adaptor->deviceName, nio->vlan);
	    }
	    else if(nio->devType != HSPDEV_PHYSICAL
		    && nio->devType != HSPDEV_OTHER) {
	      myDebug(1, "PCAP: skip %s (devType=%s)",
		      adaptor->deviceName,
		      devTypeName(nio->devType));
	    }
	    else {
	      // passed all the tests
	      addBPFSocket(mod, pcap, adaptor);
	    }
	  }
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_intfs_changed      __________________
    -----------------___________________________------------------
  */

  static void evt_intfs_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_PCAP *mdata = (HSP_mod_PCAP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    // close sockets and remove adaptor references for anything that no longer exists
    BPFSoc *bpfs;
    UTARRAY_WALK(mdata->bpf_socs, bpfs) {
      if(adaptorByName(sp, bpfs->deviceName) == NULL) {
	// no longer found
	tap_close(mod, bpfs);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_pcap(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_PCAP));
    HSP_mod_PCAP *mdata = (HSP_mod_PCAP *)mod->data;
    mdata->bpf_socs = UTArrayNew(UTARRAY_DFLT);
    // register call-backs
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_CONFIG_FIRST), evt_config_first);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_INTFS_CHANGED), evt_intfs_changed);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, EVEVENT_TICK), evt_tick);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
