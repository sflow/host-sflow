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
    int soc;
    uint32_t samplingRate;
    uint32_t subSamplingRate;
    uint32_t drops;
    uint32_t isBridge:1;
    uint32_t promisc:1;
    pcap_t *pcap;
    char pcap_err[PCAP_ERRBUF_SIZE];
  } BPFSoc;

  typedef struct _HSP_mod_PCAP {
    UTArray *bpf_socs;
    EVBus *packetBus;
    bool pcap_configured;
  } HSP_mod_PCAP;

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
      SFLMacAddress macdst,macsrc;
      memcpy(macdst.mac, buf, 6);
      memcpy(macsrc.mac, buf+6, 6);
      SFLAdaptor *srcdev = adaptorByMac(sp, &macsrc);
      SFLAdaptor *dstdev = adaptorByMac(sp, &macdst);
      SFLAdaptor *tapdev = bpfs->promisc ? adaptorByName(sp, bpfs->deviceName) : NULL;

      if(getDebug() > 2) {
	if(srcdev) {
	  myLog(LOG_INFO, "srcdev=%s(%u)(peer=%u)",
		srcdev->deviceName,
		srcdev->ifIndex,
		srcdev->peer_ifIndex);
	}
	if(dstdev) {
	  myLog(LOG_INFO, "dstdev=%s(%u)(peer=%u)",
		dstdev->deviceName,
		dstdev->ifIndex,
		dstdev->peer_ifIndex);
	}
      }

      takeSample(sp,
		 srcdev,
		 dstdev,
		 tapdev,
		 bpfs->isBridge,
		 0 /*hook*/,
		 buf /* mac hdr*/,
		 14 /* mac len */,
		 buf + 14 /* payload */,
		 hdr->caplen - 14, /* length of captured payload */
		 hdr->len, /* length of packet (pdu) */
		 bpfs->drops, /* droppedSamples */
		 bpfs->samplingRate);
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
      // TODO: perhaps we should exit altogether in this case?
      EVSocketClose(mod, sock);
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

  static int setKernelSampling(HSP *sp, BPFSoc *bpfs)
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
      { 0x20,  0,  0, 0xfffff038 }, // ld rand
      { 0x94,  0,  0, 0x00000100 }, // mod #256
      { 0x15,  0,  1, 0x00000001 }, // jneq #1, drop
      { 0x06,  0,  0, 0xffffffff }, // ret #-1
      { 0x06,  0,  0, 0000000000 }, // drop: ret #0
    };

    // overwrite the sampling-rate
    code[1].k = bpfs->samplingRate;
    myDebug(1, "PCAP: sampling rate set to %u for dev=%s", code[1].k, bpfs->deviceName);
    struct sock_fprog bpf = {
      .len = 5, // ARRAY_SIZE(code),
      .filter = code,
    };

    // install the filter
    int status = setsockopt(bpfs->soc, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
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
      if(pcap_stats(bpfs->pcap, &stats) == 0) {
	bpfs->drops = stats.ps_drop;
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_config_changed     __________________
    -----------------___________________________------------------
  */

  static void evt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_PCAP *mdata = (HSP_mod_PCAP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    if(mdata->pcap_configured) {
      // already configured the first time (when we still had root privileges)
      return;
    }

    for(HSPPcap *pcap = sp->pcap.pcaps; pcap; pcap = pcap->nxt) {
      BPFSoc *bpfs = (BPFSoc *)my_calloc(sizeof(BPFSoc));
      UTArrayAdd(mdata->bpf_socs, bpfs);
      bpfs->module = mod;
      SFLAdaptor *adaptor = adaptorByName(sp, pcap->dev);
      if(adaptor == NULL) {
	myLog(LOG_ERR, "PCAP: device not found: %s", pcap->dev);
      }
      else {
	bpfs->deviceName = strdup(pcap->dev);
	bpfs->isBridge = (ADAPTOR_NIO(adaptor)->devType == HSPDEV_BRIDGE);
	bpfs->samplingRate = lookupPacketSamplingRate(adaptor, sp->sFlowSettings);
	bpfs->subSamplingRate = bpfs->samplingRate;
	bpfs->pcap = pcap_open_live(pcap->dev,
				    sp->sFlowSettings_file->headerBytes,
				    pcap->promisc,
				    0, /* timeout==poll */
				    bpfs->pcap_err);
	if(bpfs->pcap) {
	  myDebug(1, "PCAP: device %s opened OK", pcap->dev);
	  bpfs->soc = pcap_fileno(bpfs->pcap);
	  bpfs->promisc = pcap->promisc;
	  setKernelSampling(sp, bpfs);
	  EVBusAddSocket(mod, mdata->packetBus, bpfs->soc, readPackets_pcap, bpfs);
	}
	else {
	  myDebug(1, "PCAP: device %s open failed", pcap->dev);
	}
      }
    }

    mdata->pcap_configured = YES;
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
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, EVEVENT_TICK), evt_tick);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
