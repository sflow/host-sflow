/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#ifdef HSP_ETHTOOL_STATS
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#endif

  extern int debug;

  /*_________________---------------------------__________________
    _________________    updateBondCounters     __________________
    -----------------___________________________------------------
  */
  
  void updateBondCounters(HSP *sp, SFLAdaptor *bond) {
    char procFileName[256];
    snprintf(procFileName, 256, "/proc/net/bonding/%s", bond->deviceName);
    FILE *procFile = fopen(procFileName, "r");
    if(procFile) {
      // limit the number of chars we will read from each line
      // (there can be more than this - fgets will chop for us)
#define MAX_PROC_LINE_CHARS 240
      char line[MAX_PROC_LINE_CHARS];
      SFLAdaptor *currentSlave = NULL;
      HSPAdaptorNIO *slave_nio = NULL;
      HSPAdaptorNIO *bond_nio = (HSPAdaptorNIO *)bond->userData;
      bond_nio->lacp.attachedAggID = bond->ifIndex;
      uint32_t aggID = 0;
      int readingMaster = YES; // bond master data comes first
      while(fgets(line, MAX_PROC_LINE_CHARS, procFile)) {
	char buf_var[MAX_PROC_LINE_CHARS];
	char buf_val[MAX_PROC_LINE_CHARS];
	// buf_var is up to first ':', buf_val is the rest
	if(sscanf(line, "%[^:]:%[^\n]", buf_var, buf_val) == 2) {
	  char *tok_var = trimWhitespace(buf_var);
	  char *tok_val = trimWhitespace(buf_val);

	  if(readingMaster) {
	    if(my_strequal(tok_var, "MII Status")) {
	      if(my_strequal(tok_val, "up")) {
		bond_nio->lacp.portState.v.actorAdmin = 2; // dot3adAggPortActorAdminState
		bond_nio->lacp.portState.v.actorOper = 2;
		bond_nio->lacp.portState.v.partnerAdmin = 2;
		bond_nio->lacp.portState.v.partnerOper = 2;
	      }
	      else {
		bond_nio->lacp.portState.all = 0;
	      }
	    }

	    if(my_strequal(tok_var, "Partner Mac Address")) {
	      if(debug) {
		myLog(LOG_INFO, "updateBondCounters: %s partner mac is %s",
		      bond->deviceName,
		      tok_val);
	      }
	      if(hexToBinary((u_char *)tok_val,bond_nio->lacp.partnerSystemID, 6) != 6) {
		myLog(LOG_ERR, "updateBondCounters: partner mac read error: %s", tok_val);
	      }
	      // Assume actorSystemID should be set to bond's MAC
	      memcpy(bond_nio->lacp.actorSystemID, bond->macs[0].mac, 6);
	    }

	    if(my_strequal(tok_var, "Aggregator ID")) {
	      aggID = strtol(tok_val, NULL, 0);
	      if(debug) {
		myLog(LOG_INFO, "updateBondCounters: %s aggID %u", bond->deviceName, aggID);
	      }
	    }
	  }

	  // initially the data is for the bond, but subsequently
	  // we get info about each slave. So we started with
	  // (readingMaster=YES,currentSlave=NULL), and now we
	  // detect transitions to slave data:
	  if(my_strequal(tok_var, "Slave Interface")) {
	    readingMaster = NO;
	    currentSlave = adaptorListGet(sp->adaptorList, trimWhitespace(tok_val));
	    slave_nio = currentSlave ? (HSPAdaptorNIO *)currentSlave->userData : NULL;
	    if(debug) {
	      myLog(LOG_INFO, "updateBondCounters: bond %s slave %s %s",
		    bond->deviceName,
		    tok_val,
		    currentSlave ? "found" : "not found");
	    }
	    if(slave_nio) {
	      slave_nio->lacp.attachedAggID = bond->ifIndex;
	      memcpy(slave_nio->lacp.partnerSystemID, bond_nio->lacp.partnerSystemID, 6);
	      memcpy(slave_nio->lacp.actorSystemID, bond_nio->lacp.actorSystemID, 6);
	      // make sure the parent is going to export separate
	      // counters if the slave is going to (because it was
	      // marked as a switchPort):
	      if(slave_nio->switchPort) {
		bond_nio->switchPort = YES;
	      }
	      // and vice-versa
	      if(bond_nio->switchPort) {
		slave_nio->switchPort = YES;
	      }
	    }
	  }

	  if(readingMaster == NO && slave_nio) {
	    if(my_strequal(tok_var, "MII Status")) {
	      if(my_strequal(tok_val, "up")) {
		slave_nio->lacp.portState.v.actorAdmin = 2; // dot3adAggPortActorAdminState
		slave_nio->lacp.portState.v.actorOper = 2;
		slave_nio->lacp.portState.v.partnerAdmin = 2;
		slave_nio->lacp.portState.v.partnerOper = 2;
	      }
	      else {
		slave_nio->lacp.portState.all = 0;
	      }
	    }

	    if(my_strequal(tok_var, "Permanent HW addr")) {
	      // not sure what this is - may just be the interface MAC that we
	      // already know. Log a warning if it's not.  Currently seeing a
	      // case where the first LAG component has his own MAC here but then
	      // the second one logs a discrepancy because although a unique mac
	      // shows up here, the interface mac has been set equal to that of
	      // the first slave.
	      u_char hwaddr[6];
	      if(hexToBinary((u_char *)tok_val,hwaddr, 6) != 6) {
		myLog(LOG_ERR, "updateBondCounters: permanent HW addr read error: %s", tok_val);
	      }
	      if(memcmp(hwaddr, currentSlave->macs[0].mac, 6) != 0) {
		if(debug) {
		  myLog(LOG_INFO, "updateBondCounters: warning: %s permanent HW addr: %s != slave MAC",
			currentSlave->deviceName,
			tok_val);
		}
	      }
	    }

	    if(my_strequal(tok_var, "Aggregator ID")) {
	      uint32_t slave_aggID = strtol(tok_val, NULL, 0);
	      if(slave_aggID != aggID) {
		myLog(LOG_ERR, "updateBondCounters: slave %s aggID (%u) != bond aggID (%u)",
		      currentSlave->deviceName,
		      slave_aggID,
		      aggID);
	      }
	    }
	  }
	}
      }
      fclose(procFile);
    }
  }

  /* ================== example of /proc/net/bonding/<if> ====================

	Ethernet Channel Bonding Driver: v3.7.1 (April 27, 2011)

	  Bonding Mode: IEEE 802.3ad Dynamic link aggregation
	  Transmit Hash Policy: layer2 (0)
	  MII Status: up
	  MII Polling Interval (ms): 100
	  Up Delay (ms): 0
	  Down Delay (ms): 0

	  802.3ad info
	  LACP rate: fast
	  Min links: 0
	  Aggregator selection policy (ad_select): stable
	  Active Aggregator Info:
	  Aggregator ID: 1
	  Number of ports: 2
	  Actor Key: 17
	  Partner Key: 17
	  Partner Mac Address: 08:9e:01:f8:9b:45
	  
	  Slave Interface: swp3
	  MII Status: up
	  Speed: 1000 Mbps
	  Duplex: full
	  Link Failure Count: 1
	  Permanent HW addr: 08:9e:01:f8:9b:af
	  Aggregator ID: 1
	  Slave queue ID: 0

	  Slave Interface: swp4
	  MII Status: up
	  Speed: 1000 Mbps
	  Duplex: full
	  Link Failure Count: 1
	  Permanent HW addr: 08:9e:01:f8:9b:b0
	  Aggregator ID: 1
	  Slave queue ID: 0
  */

  /*_________________---------------------------__________________
    _________________    readBondState          __________________
    -----------------___________________________------------------
  */

  void readBondState(HSP *sp) {
    for(uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
      SFLAdaptor *adaptor = sp->adaptorList->adaptors[i];
      if(adaptor && adaptor->ifIndex) {
	HSPAdaptorNIO *niostate = (HSPAdaptorNIO *)adaptor->userData;
	if(niostate) {
	  if(niostate->bond_master) {
	    updateBondCounters(sp, adaptor);
	  }
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    syncBondPolling        __________________
    -----------------___________________________------------------
  */

  static void syncSlavePolling(HSP *sp, SFLAdaptor *bond) {
    HSPAdaptorNIO *bond_nio = (HSPAdaptorNIO *)bond->userData;
    if(bond_nio) {
      for(uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
	SFLAdaptor *adaptor = sp->adaptorList->adaptors[i];
	if(adaptor && adaptor->ifIndex) {
	  HSPAdaptorNIO *nio = (HSPAdaptorNIO *)adaptor->userData;
	  if(nio
	     && nio->bond_slave
	     && nio->lacp.attachedAggID == bond_nio->lacp.attachedAggID) {
	    // put the slave on the same polling schedule as the master.
	    // This isn't strictly necessary, but it will reduce the
	    // frequency of access to th /proc/net/bonding file.
	    if(bond_nio->poller
	       && nio->poller) {
	      if(debug) {
		myLog(LOG_INFO, "sync polling so that slave %s goes with bond %s",
		      adaptor->deviceName,
		      bond->deviceName);
	      }
	      sfl_poller_synchronize_polling(nio->poller, bond_nio->poller);
	    }
	  }
	}
      }
    }
  }
  
  void syncBondPolling(HSP *sp) {
    for(uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
      SFLAdaptor *adaptor = sp->adaptorList->adaptors[i];
      if(adaptor && adaptor->ifIndex) {
	HSPAdaptorNIO *nio = (HSPAdaptorNIO *)adaptor->userData;
	if(nio && nio->bond_master) {
	  syncSlavePolling(sp, adaptor);
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    updateNioCounters      __________________
    -----------------___________________________------------------
  */
  
  void updateNioCounters(HSP *sp) {

    // don't do anything if we already refreshed the numbers less than a second ago
    if(sp->nio_last_update == sp->clk) {
      return;
    }
    sp->nio_last_update = sp->clk;

    FILE *procFile;
    procFile= fopen("/proc/net/dev", "r");
    if(procFile) {
#ifdef HSP_ETHTOOL_STATS
      int fd = socket (PF_INET, SOCK_DGRAM, 0);
      struct ifreq ifr;
      memset (&ifr, 0, sizeof(ifr));
#endif
      // ASCII numbers in /proc/diskstats may be 64-bit (if not now
      // then someday), so it seems safer to read into
      // 64-bit ints with scanf first,  then copy them
      // into the host_nio structure from there.
      uint64_t bytes_in = 0;
      uint64_t pkts_in = 0;
      uint64_t errs_in = 0;
      uint64_t drops_in = 0;
      uint64_t bytes_out = 0;
      uint64_t pkts_out = 0;
      uint64_t errs_out = 0;
      uint64_t drops_out = 0;
      // limit the number of chars we will read from each line
      // (there can be more than this - fgets will chop for us)
#define MAX_PROC_LINE_CHARS 240
      char line[MAX_PROC_LINE_CHARS];
      while(fgets(line, MAX_PROC_LINE_CHARS, procFile)) {
	char deviceName[MAX_PROC_LINE_CHARS];
	// assume the format is:
	// Inter-|   Receive                                                |  Transmit
	//  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
	if(sscanf(line, "%[^:]:%"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %*u %*u %*u %*u %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64"",
		  deviceName,
		  &bytes_in,
		  &pkts_in,
		  &errs_in,
		  &drops_in,
		  &bytes_out,
		  &pkts_out,
		  &errs_out,
		  &drops_out) == 9) {
	  SFLAdaptor *adaptor = adaptorListGet(sp->adaptorList, trimWhitespace(deviceName));
	  if(adaptor && adaptor->userData) {
	    HSPAdaptorNIO *niostate = (HSPAdaptorNIO *)adaptor->userData;
#ifdef HSP_ETHTOOL_STATS
	    HSP_ethtool_counters et_ctrs = { 0 }, et_delta = { 0 };
	    if (niostate->et_nfound) {
	      // get the latest stats block for this device via ethtool
	      // and read out the counters that we located by name
	      uint32_t bytes = sizeof(struct ethtool_stats);
	      bytes += niostate->et_nctrs * sizeof(uint64_t);
	      struct ethtool_stats *et_stats = (struct ethtool_stats *)my_calloc(bytes);
	      et_stats->cmd = ETHTOOL_GSTATS;
	      et_stats->n_stats = niostate->et_nctrs;
	      strncpy(ifr.ifr_name, adaptor->deviceName, sizeof(ifr.ifr_name));
	      ifr.ifr_data = (char *)et_stats;
	      if(ioctl(fd, SIOCETHTOOL, &ifr) >= 0) {
		if(niostate->et_idx_mcasts_in) {
		  et_ctrs.mcasts_in = et_stats->data[niostate->et_idx_mcasts_in - 1];
		  et_delta.mcasts_in = et_ctrs.mcasts_in - niostate->et_last.mcasts_in;
		}
		if(niostate->et_idx_mcasts_out) {
		  et_ctrs.mcasts_out = et_stats->data[niostate->et_idx_mcasts_out - 1];
		  et_delta.mcasts_out = et_ctrs.mcasts_out - niostate->et_last.mcasts_out;
		}
		if(niostate->et_idx_bcasts_in) {
		  et_ctrs.bcasts_in = et_stats->data[niostate->et_idx_bcasts_in - 1];
		  et_delta.bcasts_in = et_ctrs.bcasts_in - niostate->et_last.bcasts_in;
		}
		if(niostate->et_idx_bcasts_out) {
		  et_ctrs.bcasts_out = et_stats->data[niostate->et_idx_bcasts_out - 1];
		  et_delta.bcasts_out = et_ctrs.bcasts_out - niostate->et_last.bcasts_out;
		}
	      }
	      my_free(et_stats);
	    }
#endif
	    // have to detect discontinuities here, so use a full
	    // set of latched counters and accumulators.
	    int accumulate = niostate->last_update ? YES : NO;
	    niostate->last_update = sp->clk;
	    uint64_t maxDeltaBytes = HSP_MAX_NIO_DELTA64;
	    
	    SFLHost_nio_counters delta;
#define NIO_COMPUTE_DELTA(field) delta.field = field - niostate->last_nio.field
	    NIO_COMPUTE_DELTA(pkts_in);
	    NIO_COMPUTE_DELTA(errs_in);
	    NIO_COMPUTE_DELTA(drops_in);
	    NIO_COMPUTE_DELTA(pkts_out);
	    NIO_COMPUTE_DELTA(errs_out);
	    NIO_COMPUTE_DELTA(drops_out);
	    
	    if(sp->nio_polling_secs == 0) {
	      // 64-bit byte counters
	      NIO_COMPUTE_DELTA(bytes_in);
	      NIO_COMPUTE_DELTA(bytes_out);
	    }
	    else {
	      // for case where byte counters are 32-bit,  we need
	      // to use 32-bit unsigned arithmetic to avoid spikes
	      delta.bytes_in = (uint32_t)bytes_in - niostate->last_bytes_in32;
	      delta.bytes_out = (uint32_t)bytes_out - niostate->last_bytes_out32;
	      niostate->last_bytes_in32 = bytes_in;
	      niostate->last_bytes_out32 = bytes_out;
	      maxDeltaBytes = HSP_MAX_NIO_DELTA32;
	      // if we detect that the OS is using 64-bits then we can turn off the faster
	      // NIO polling. This should probably be done based on the kernel version or some
	      // other include-file definition, but it's not expensive to do it here like this:
	      if(bytes_in > 0xFFFFFFFF || bytes_out > 0xFFFFFFFF) {
		myLog(LOG_INFO, "detected 64-bit counters in /proc/net/dev");
		sp->nio_polling_secs = 0;
	      }
	    }
	    
	    if(accumulate) {
	      // sanity check in case the counters were reset under out feet.
	      // normally we leave this to the upstream collector, but these
	      // numbers might be getting passed through from the hardware(?)
	      // so we treat them with particular distrust.
	      if(delta.bytes_in > maxDeltaBytes ||
		 delta.bytes_out > maxDeltaBytes ||
		 delta.pkts_in > HSP_MAX_NIO_DELTA32 ||
		 delta.pkts_out > HSP_MAX_NIO_DELTA32) {
		myLog(LOG_ERR, "detected counter discontinuity in /proc/net/dev for %s: deltaBytes=%"PRIu64",%"PRIu64" deltaPkts=%u,%u",
                      adaptor->deviceName,
                      delta.bytes_in,
                      delta.bytes_out,
                      delta.pkts_in,
                      delta.pkts_out);
		accumulate = NO;
	      }
#ifdef HSP_ETHTOOL_STATS
	      if(et_delta.mcasts_in > HSP_MAX_NIO_DELTA64  ||
		 et_delta.mcasts_out > HSP_MAX_NIO_DELTA64 ||
		 et_delta.bcasts_in > HSP_MAX_NIO_DELTA64  ||
		 et_delta.bcasts_out > HSP_MAX_NIO_DELTA64) {
		myLog(LOG_ERR, "detected counter discontinuity in ethtool stats");
		accumulate = NO;
	      }
#endif
	    }
	    
	    if(accumulate) {
#define NIO_ACCUMULATE(field) niostate->nio.field += delta.field
	      NIO_ACCUMULATE(bytes_in);
	      NIO_ACCUMULATE(pkts_in);
	      NIO_ACCUMULATE(errs_in);
	      NIO_ACCUMULATE(drops_in);
	      NIO_ACCUMULATE(bytes_out);
	      NIO_ACCUMULATE(pkts_out);
	      NIO_ACCUMULATE(errs_out);
	      NIO_ACCUMULATE(drops_out);
#ifdef HSP_ETHTOOL_STATS
#define ET_ACCUMULATE(field) niostate->et_total.field += et_delta.field
	      ET_ACCUMULATE(mcasts_in);
	      ET_ACCUMULATE(mcasts_out);
	      ET_ACCUMULATE(bcasts_in);
	      ET_ACCUMULATE(bcasts_out);
#endif
	    }
	    
#define NIO_LATCH(field) niostate->last_nio.field = field
	    NIO_LATCH(bytes_in);
	    NIO_LATCH(pkts_in);
	    NIO_LATCH(errs_in);
	    NIO_LATCH(drops_in);
	    NIO_LATCH(bytes_out);
	    NIO_LATCH(pkts_out);
	    NIO_LATCH(errs_out);
	    NIO_LATCH(drops_out);
#ifdef HSP_ETHTOOL_STATS
	    niostate->et_last = et_ctrs; // struct copy
#endif

	  }
	}
      }
#ifdef HSP_ETHTOOL_STATS
      if(fd >= 0) close(fd);
#endif
      fclose(procFile);
    }
  }
  

  /*_________________---------------------------__________________
    _________________      readNioCounters      __________________
    -----------------___________________________------------------
  */
  
  int readNioCounters(HSP *sp, SFLHost_nio_counters *nio, char *devFilter, SFLAdaptorList *adList) {
    int interface_count = 0;
    size_t devFilterLen = devFilter ? strlen(devFilter) : 0;

    // may need to schedule intermediate calls to updateNioCounters()
    // too (to avoid undetected wraps), but at the very least we need to do
    // it here to make sure the data is up to the second.
    updateNioCounters(sp);

    for(int i = 0; i < sp->adaptorList->num_adaptors; i++) {
      SFLAdaptor *adaptor = sp->adaptorList->adaptors[i];
      // note that the devFilter here is a prefix-match
      if(devFilter == NULL || !strncmp(devFilter, adaptor->deviceName, devFilterLen)) {
	if(adList == NULL || adaptorListGet(adList, adaptor->deviceName) != NULL) {
	  HSPAdaptorNIO *niostate = (HSPAdaptorNIO *)adaptor->userData;
	  
	  // in the case where we are adding up across all
	  // interfaces, be careful to avoid double-counting.
	  // By leaving this test until now we make it possible
	  // to know the counters for any interface or sub-interface
	  // if required (e.g. for the readPackets() module).
	  if(devFilter == NULL && (niostate->up == NO
				   || niostate->vlan != HSP_VLAN_ALL
				   || niostate->loopback
				   || niostate->bond_master)) {
	    continue;
	  }

	  interface_count++;
	  // report the sum over all devices that match the filter
	  nio->bytes_in += niostate->nio.bytes_in;
	  nio->pkts_in += niostate->nio.pkts_in;
	  nio->errs_in += niostate->nio.errs_in;
	  nio->drops_in += niostate->nio.drops_in;
	  nio->bytes_out += niostate->nio.bytes_out;
	  nio->pkts_out += niostate->nio.pkts_out;
	  nio->errs_out += niostate->nio.errs_out;
	  nio->drops_out += niostate->nio.drops_out;
	}
      }
    }
    return interface_count;
  }
  

#if defined(__cplusplus)
} /* extern "C" */
#endif

