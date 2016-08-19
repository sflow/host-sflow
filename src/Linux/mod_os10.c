/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#include "regex.h"
#define HSP_DEFAULT_SWITCHPORT_REGEX "^e[0-9]+-[0-9]+-[0-9]+$"
#define HSP_DEFAULT_OS10_PORT 20001

#define HSP_READPACKET_BATCH_OS10 10000
#define HSP_MAX_OS10_MSG_BYTES 10000
#define HSP_OS10_RCV_BUF 8000000

#define HSP_OS10_MIN_POLLING_INTERVAL 10

// HSP_OS10_SWITCHPORT_CONFIG_PROG is defined in hsflowd.h
// because it is used to auto-detect when we are on os10.

#define HSP_OS10_SWITCHPORT_SPEED_PROG "/opt/dell/os10/bin/os10-ethtool"

#define HSP_OS10_SWITCHPORT_STATS_PROG_0 "/opt/dell/os10/bin/os10-show-stats"
#define HSP_OS10_SWITCHPORT_STATS_PROG_1 "if_stat"

  typedef struct _HSP_mod_OS10 {
    // active on two threads (buses)
    EVBus *packetBus;
    EVBus *pollBus;
    // config
    bool configured_socket:1;
    // sample processing
    uint32_t os10_seqno;
    uint32_t os10_drops;

    // counter polling
    time_t last_poll;

    bool poll_phase_interface;

    // the current interface we are getting counters for
    SFLAdaptor *poll_current;

    // fields we collect before deciding on poll_current
    struct {
      SFLAdaptor *adaptor;
      SFLMacAddress mac;
      uint32_t ifIndex;
      uint64_t speed;
      bool enabled;
      uint32_t mtu;
      uint32_t operStatus;
      uint32_t adminStatus;
      bool duplex;
    } poll;

    // the counters
    SFLHost_nio_counters ctrs;
    HSP_ethtool_counters et_ctrs;
  } HSP_mod_OS10;

  /*_________________---------------------------__________________
    _________________      readPackets          __________________
    -----------------___________________________------------------
  */

  static void readPackets_os10(EVMod *mod, EVSocket *sock, void *magic)
  {
    HSP_mod_OS10 *mdata = (HSP_mod_OS10 *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    int batch = 0;

    if(sp->sFlowSettings == NULL) {
      // config was turned off
      return;
    }

    for( ; batch < HSP_READPACKET_BATCH_OS10; batch++) {
      uint32_t buf32[HSP_MAX_OS10_MSG_BYTES >> 2];
      int recvBytes = recvfrom(sock->fd, (char *)buf32, HSP_MAX_OS10_MSG_BYTES, 0, NULL, NULL);
      if(recvBytes <= 0)
	break;

      myDebug(2, "got OS10 msg: %u bytes", recvBytes);

      if(getDebug() > 2) {
	u_char pbuf[2000];
	printHex((u_char *)buf32, HSP_MAX_OS10_MSG_BYTES, pbuf, 2000, NO);
	myDebug(1, "got msg: %s", pbuf);
      }

     // check metadata signature
      if(buf32[0] != 0xDEADBEEF) {
	myDebug(1, "bad meta-data signature: %08X", buf32[0]);
	continue;
      }

      // meta-data length comes next
      int mdBytes = buf32[1];
      int32_t mdQuads = mdBytes >> 2;

      // tag and len are both 64-bits.  If that changes,  just
      // change the types uses here...
      uint64_t tag;
      uint64_t len;
      int32_t tlQuads = (sizeof(tag) + sizeof(len)) >> 2;

      // values we are looking for:
      uint32_t ifIn=0;
      uint32_t ifOut=0;
      uint32_t seqNo=0;
      uint32_t packetLen=0;

      uint32_t ii = 2;
      for(; ii <= (mdQuads - tlQuads); ) {
	uint32_t val32=0;
	uint64_t val64=0;

	// read tag and length (native byte order)
	memcpy(&tag, &buf32[ii], sizeof(tag));
	ii += sizeof(tag) >> 2;
	memcpy(&len, &buf32[ii], sizeof(len));
	ii += sizeof(len) >> 2;

	// read value
	if(len == 4) val32 = buf32[ii++];
	else if(len == 8) {
	  // collapse val64 to val32
	  memcpy(&val64, &buf32[ii], 8);
	  ii += 2;
	  val32 = (uint32_t)val64;
	}

	switch(tag) {
	case 0: ifIn = val32; break;
	case 1: ifOut = val32; break;
	case 2: seqNo = val32; break;
	case 3: packetLen = val32; break;
	}
      }

      if(ii != mdQuads) {
	myDebug(1, "metadata consumption error");
	continue;
      }

      u_char *pkt = (u_char *)&buf32[mdQuads];
      int headerLen = recvBytes - mdBytes;
      if(headerLen < 14) {
	myDebug(1, "packet too small");
	continue;
      }

      // check for drops indicated by sequence no
      uint32_t droppedSamples = 0;
      if(mdata->os10_seqno) {
	droppedSamples = seqNo - mdata->os10_seqno - 1;
	if(droppedSamples) {
	  mdata->os10_drops += droppedSamples;
	}
      }
      mdata->os10_seqno = seqNo;

      SFLAdaptor *dev_in = NULL;
      SFLAdaptor *dev_out = NULL;

      if(ifIn)
	dev_in = adaptorByIndex(sp, ifIn);
      if(ifOut)
	dev_out = adaptorByIndex(sp, ifOut);

      if(dev_in == NULL
	 || ADAPTOR_NIO(dev_in)->sampling_n_set == 0) {
	// sampling not configured yet - may have just
	// restarted hsflowd
	continue;
      }

      // looks like we get the FCS bytes too -- if the
      // packet is short enough to include them
      int chopped = packetLen - headerLen;
      int fcsBytes = (chopped < 4) ?  4 - chopped : 0;

      takeSample(sp,
		 dev_in,
		 dev_out,
		 NULL, // tap
		 YES, // bridge
		 0, // hook
		 pkt,
		 14,
		 pkt + 14,
		 headerLen - 14 - fcsBytes, /* length of captured payload */
		 packetLen - 14 - 4, /* length of packet (pdu) */
		 droppedSamples,
		 sp->sFlowSettings->samplingRate);
    }
  }

  /*_________________---------------------------__________________
    _________________     openOS10              __________________
    -----------------___________________________------------------
  */

  static int openOS10(EVMod *mod)
  {
    HSP *sp = (HSP *)EVROOTDATA(mod);

    // register call-backs
    uint16_t os10Port = sp->os10.port ?: HSP_DEFAULT_OS10_PORT;
    int fd = 0;
    if(os10Port) {
      // TODO: should this really be "::1" and PF_INET6?  Or should we bind to both "127.0.0.1" and "::1" (cf mod_json)
      fd = UTSocketUDP("127.0.0.1", PF_INET, os10Port, HSP_OS10_RCV_BUF);
     myDebug(1, "os10 socket is %d", fd);
    }

    return fd;
  }

  /*_________________---------------------------__________________
    _________________     setSamplingRate       __________________
    -----------------___________________________------------------
  */

  static int srateOutputLine(void *magic, char *line) {
    return YES;
  }

  static bool setSamplingRate(EVMod *mod, SFLAdaptor *adaptor) {
    HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);

    if(adaptor->ifSpeed == 0) {
      // by refusing to set a sampling rate for a port
      // with speed == 0 we can stabilize the startup.
      // Now sampling will only be configured as ports
      // are discovered or come up (or change speed).
      // TODO: if a port has gone down do we need to
      // clear the sampling rate back to 0, since it
      // may come up again with a different speed?
      return NO;
    }

    if(niostate->switchPort == NO
       || niostate->loopback
       || niostate->bond_master) {
      return NO;
    }
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPSFlowSettings *settings = sp->sFlowSettings;

    int hw_sampling = YES;
    UTStringArray *cmdline = strArrayNew();
    strArrayAdd(cmdline, HSP_OS10_SWITCHPORT_CONFIG_PROG);
    // usage:  <prog> [enable|disable] <interface> <direction>  <rate>
#define HSP_MAX_TOK_LEN 16
    strArrayAdd(cmdline, "enable");
    strArrayAdd(cmdline, adaptor->deviceName);
    strArrayAdd(cmdline, "ingress");
    strArrayAdd(cmdline, "0");  // placeholder for sampling N in slot 4
    strArrayAdd(cmdline, NULL); // extra NULL
#define HSP_MAX_EXEC_LINELEN 1024
    char outputLine[HSP_MAX_EXEC_LINELEN];
    niostate->sampling_n = lookupPacketSamplingRate(adaptor, settings);
    if(niostate->sampling_n != niostate->sampling_n_set) {
      myDebug(1, "setSwitchPortSamplingRate(%s) %u -> %u",
	      adaptor->deviceName,
	      niostate->sampling_n_set,
	      niostate->sampling_n);
      char srate[HSP_MAX_TOK_LEN];
      snprintf(srate, HSP_MAX_TOK_LEN, "%u", niostate->sampling_n);
      strArrayInsert(cmdline, 4, srate);

      if(debug(1)) {
	char *cmd_str = strArrayStr(cmdline, NULL, NULL, " ", NULL);
	myDebug(1, "exec command:[%s]", cmd_str);
	my_free(cmd_str);
      }

      int status;
      if(myExec(niostate, strArray(cmdline), srateOutputLine, outputLine, HSP_MAX_EXEC_LINELEN, &status)) {
	if(WEXITSTATUS(status) != 0) {
	  myLog(LOG_ERR, "myExec(%s) exitStatus=%d so assuming ULOG/NFLOG is 1:1",
		HSP_OS10_SWITCHPORT_CONFIG_PROG,
		WEXITSTATUS(status));
	  hw_sampling = NO;
	}
	else {
	  myDebug(1, "setSwitchPortSamplingRate(%s) succeeded", adaptor->deviceName);
	  // hardware or kernel sampling was successfully configured
	  niostate->sampling_n_set = niostate->sampling_n;
	  sp->hardwareSampling = YES;
	}
      }
      else {
	myLog(LOG_ERR, "myExec() calling %s failed (adaptor=%s)",
	      strArrayAt(cmdline, 0),
	      adaptor->deviceName);
      }
    }
    strArrayFree(cmdline);
    return hw_sampling;
  }

  /*_________________---------------------------__________________
    _________________    pollCounters           __________________
    -----------------___________________________------------------
  */

  UTStringArray *tokenize(char *in, char *sep, char *buf, int bufLen) {
    UTStringArray *ans = strArrayNew();
    char *p = in;
    while(parseNextTok(&p, sep, NO, 0, YES, buf, bufLen) != NULL)
      if(my_strlen(buf)) strArrayAdd(ans, buf);
    return ans;
  }

  static void checkByMac(EVMod *mod, SFLAdaptor *adaptor, SFLMacAddress *mac) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFLAdaptor *byMac = adaptorByMac(sp, mac);
    if(byMac != adaptor) {
      u_char macstr[13];
      macstr[0] = '\0';
      printHex(mac->mac, 6, macstr, 13, NO);
      myDebug(1, "OS10 mac %s points to interface %s (not %s)",
	      macstr,
	      byMac ? byMac->deviceName : "<none>",
	      adaptor->deviceName);
    }
  }

  static void checkByIndex(EVMod *mod, SFLAdaptor *adaptor, uint32_t ifIndex) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFLAdaptor *byIndex = adaptorByIndex(sp, ifIndex);
    if(byIndex != adaptor) {
      myDebug(1, "OS10 ifIndex %u points to interface %s (not %s)",
	      ifIndex,
	      byIndex ? byIndex->deviceName : "<none>",
	      adaptor->deviceName);
    }
  }

  static void setPollCurrent(EVMod *mod, SFLAdaptor *adaptor)
  {
    HSP_mod_OS10 *mdata = (HSP_mod_OS10 *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(mdata->poll_current != adaptor) {
      if(mdata->poll_current) {
	// finished with this adaptor - accumulate counters
	accumulateNioCounters(sp, mdata->poll_current, &mdata->ctrs, &mdata->et_ctrs);
	ADAPTOR_NIO(mdata->poll_current)->last_update = sp->pollBus->clk;
      }
      mdata->poll_current = adaptor;
      if(adaptor) {
	// starting new adaptor
	HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
        if(!nio->switchPort) {
          mdata->poll_current = NULL;
        }
        else {
	  // apply the interface-phase info we have collected
	  memset(&mdata->ctrs, 0, sizeof(mdata->ctrs));
	  memset(&mdata->et_ctrs, 0, sizeof(mdata->et_ctrs));
	  nio->up = mdata->poll.enabled;
	  mdata->et_ctrs.adminStatus = mdata->poll.adminStatus;
	  nio->et_found |= HSP_ETCTR_ADMIN;
	  mdata->et_ctrs.operStatus = mdata->poll.operStatus;
	  nio->et_found |= HSP_ETCTR_OPER;
	  adaptor->ifDirection = mdata->poll.duplex ? 1 : 2;
	  // setting the speed may trigger a sampling-rate change
	  setAdaptorSpeed(sp, adaptor, mdata->poll.speed);
	  // check that we already have the right MAC and ifIndex
	  checkByMac(mod, adaptor, &mdata->poll.mac);
	  checkByIndex(mod, adaptor, mdata->poll.ifIndex);
	  // clear poll structure for next interface phase
	  memset(&mdata->poll, 0, sizeof(mdata->poll));
	}
      }
    }
  }

  static int pollAllOutputLine(void *magic, char *line) {
    EVMod *mod = (EVMod *)magic;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSP_mod_OS10 *mdata = (HSP_mod_OS10 *)mod->data;
    // By making / a delimiter too we can ignore the prefix and look
    // only at the last two or three tokens.
    char tokbuf[HSP_MAX_EXEC_LINELEN];
    UTStringArray *tokens = tokenize(line, " /=", tokbuf, HSP_MAX_EXEC_LINELEN);
    int nt = strArrayN(tokens);
    if(nt < 3) goto out;
    char *phase = strArrayAt(tokens, nt - 3);
    char *var = strArrayAt(tokens, nt - 2);
    char *val = strArrayAt(tokens, nt - 1);
    if(! (phase && var && val)) goto out;
    uint64_t val64 = strtoll(val, NULL, 0);

    // we can look up by MAC, ifIndex or name,  but name is
    // the most reliable here because we use that to classify
    // the switch ports in the first place.  The others are
    // checked just for consistency.

    // We expect phase to transition from "interface" to "stats" to
    // "statistics". We just collect fields during the "interface" phase,
    // then and decide which port we are looking at (poll_current)
    // when it ends.

    if(my_strequal(phase, "interface")) {
      mdata->poll_phase_interface = YES;
    }
    else {
      if(mdata->poll_phase_interface) {
	// interface phase over - decision time:
	setPollCurrent(mod, mdata->poll.adaptor);
      }
      mdata->poll_phase_interface = NO;
    }
     
    if(mdata->poll_phase_interface) {
      if(my_strequal(var, "phys-address")) {
	if(hexToBinary((u_char *)val, (u_char *)&mdata->poll.mac.mac, 6) != 6) {
	  myLog(LOG_ERR, "badly formatted MAC: %s", val);
	}
      }
      else if(my_strequal(var, "speed")) mdata->poll.speed = val64;
      else if(my_strequal(var, "duplex")) mdata->poll.duplex = (bool)val64;
      else if(my_strequal(var, "if-index")) mdata->poll.ifIndex = val64;
      else if(my_strequal(var, "mtu")) 	mdata->poll.mtu = val64;
      else if(my_strequal(var, "enabled")) mdata->poll.enabled = (bool)val64;
      else if(my_strequal(var, "admin-status")) mdata->poll.adminStatus = val64;
      else if(my_strequal(var, "oper-status")) 	mdata->poll.operStatus = val64;
      else if(my_strequal(var, "name")) mdata->poll.adaptor = adaptorByName(sp, val);
    }
    else {
      if(!mdata->poll_current)
	goto out;

      SFLAdaptor *adaptor = mdata->poll_current;
      HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
      
      if(my_strequal(var, "in-octets"))  mdata->ctrs.bytes_in = val64;
      else if(my_strequal(var, "out-octets")) mdata->ctrs.bytes_out = val64;
      else if(my_strequal(var, "ether-rx-no-errors")) mdata->ctrs.pkts_in = val64; // includes bcasts and mcasts
      else if(my_strequal(var, "ether-tx-no-errors")) mdata->ctrs.pkts_out = val64; // includes bcasts and mcasts
      else if(my_strequal(var, "in-errors")) mdata->ctrs.errs_in = val64;
      else if(my_strequal(var, "out-errors")) mdata->ctrs.errs_out = val64;
      else if(my_strequal(var, "in-discards")) mdata->ctrs.drops_in = val64;
      else if(my_strequal(var, "out-discards")) mdata->ctrs.drops_out = val64;
      else if(my_strequal(var, "in-unknown-protos")) {
	mdata->et_ctrs.unknown_in = val64;
	nio->et_found |= HSP_ETCTR_UNKN;
      }
      else if(my_strequal(var, "in-multicast-pkts")) {
	mdata->et_ctrs.mcasts_in = val64;
	nio->et_found |= HSP_ETCTR_MC_IN;
      }
      else if(my_strequal(var, "out-multicast-pkts")) {
	mdata->et_ctrs.mcasts_out = val64;
	nio->et_found |= HSP_ETCTR_MC_OUT;
      }
      else if(my_strequal(var, "in-broadcast-pkts")) {
	mdata->et_ctrs.bcasts_in = val64;
	nio->et_found |= HSP_ETCTR_BC_IN;
      }
      else if(my_strequal(var, "out-broadcast-pkts")) {
	mdata->et_ctrs.bcasts_out = val64;
	nio->et_found |= HSP_ETCTR_BC_OUT;
      }
    }

  out:
    strArrayFree(tokens);
    return YES;
  }

  static bool pollAllCounters(EVMod *mod) {
    UTStringArray *cmdline = strArrayNew();
    strArrayAdd(cmdline, HSP_OS10_SWITCHPORT_STATS_PROG_0);
    strArrayAdd(cmdline, HSP_OS10_SWITCHPORT_STATS_PROG_1);
    strArrayAdd(cmdline, NULL); // trailing NULL

#define HSP_MAX_EXEC_LINELEN 1024
    char outputLine[HSP_MAX_EXEC_LINELEN];

    if(debug(1)) {
      char *cmd_str = strArrayStr(cmdline, NULL, NULL, " ", NULL);
      myDebug(1, "exec command:[%s]", cmd_str);
      my_free(cmd_str);
    }

    int status;
    if(myExec(mod, strArray(cmdline), pollAllOutputLine, outputLine, HSP_MAX_EXEC_LINELEN, &status)) {
      if(WEXITSTATUS(status) != 0) {
	myLog(LOG_ERR, "myExec(%s) exitStatus=%d",
	      HSP_OS10_SWITCHPORT_SPEED_PROG,
	      WEXITSTATUS(status));
      }
      else {
	myDebug(1, "pollAllCounters() succeeded");
      }
    }
    else {
      myLog(LOG_ERR, "myExec() calling %s failed",
	    strArrayAt(cmdline, 0));
    }
    setPollCurrent(mod, NULL);
    strArrayFree(cmdline);
    return YES;
  }

 /*_________________---------------------------__________________
    _________________   markSwitchPort         __________________
    -----------------__________________________------------------
  */

  static bool markSwitchPort(EVMod *mod, SFLAdaptor *adaptor)  {
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->os10.swp_regex_str == NULL) {
      // pattern not specified in config, so compile the default
      sp->os10.swp_regex_str = HSP_DEFAULT_SWITCHPORT_REGEX;
      sp->os10.swp_regex = UTRegexCompile(HSP_DEFAULT_SWITCHPORT_REGEX);
      assert(sp->os10.swp_regex);
    }

    // use pattern to mark the switch ports
    bool switchPort = NO;
    if(regexec(sp->os10.swp_regex, adaptor->deviceName, 0, NULL, 0) == 0) {
      switchPort = YES;
    }
    HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
    niostate->switchPort = switchPort;
    niostate->os10Port = switchPort;
    return switchPort;
  }

  /*_________________---------------------------__________________
    _________________    evt_config_changed     __________________
    -----------------___________________________------------------
  */

  static void evt_pkt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_OS10 *mdata = (HSP_mod_OS10 *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    if(!mdata->configured_socket) {
      int fd = openOS10(mod);
      if(fd > 0)
	EVBusAddSocket(mod, mdata->packetBus, fd, readPackets_os10, mod);
      mdata->configured_socket = YES;
    }
  }

  static void evt_poll_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    // The sampling-rate settings may have changed.
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByName, adaptor) {
	setSamplingRate(mod, adaptor);
      }
  }

  /*_________________---------------------------__________________
    _________________      evt_intf_read        __________________
    -----------------___________________________------------------
  */

  static void evt_poll_intf_read(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    SFLAdaptor *adaptor = *(SFLAdaptor **)data;
    if(markSwitchPort(mod, adaptor)) {
      HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
      // turn off the use of ethtool_GSET so it doesn't get the wrong speed
      // and turn off other ethtool requests because they won't add to the picture
      nio->ethtool_GSET = NO;
      nio->ethtool_GLINKSETTINGS = NO;
      nio->ethtool_GSTATS = NO;
      nio->ethtool_GDRVINFO = NO;
      // the /proc/net/dev counters are invalid too
      nio->procNetDev = NO;
    }
  }

  /*_________________---------------------------__________________
    _________________      evt_intfs_changed    __________________
    -----------------___________________________------------------
  */

  static void evt_poll_intfs_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    // need to refresh speed/status meta-data for all interfaces
    // may trigger sampling-rate setting if speed changes (see below)
    pollAllCounters(mod);
  }

  /*_________________---------------------------__________________
    _________________   evt_poll_speed_changed  __________________
    -----------------___________________________------------------
  */

  static void evt_poll_speed_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    SFLAdaptor *adaptor = *(SFLAdaptor **)data;

    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    setSamplingRate(mod, adaptor);
  }

  /*_________________---------------------------__________________
    _________________     evt_poll_update_nio   __________________
    -----------------___________________________------------------
  */

  static void evt_poll_update_nio(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
   SFLAdaptor *adaptor = *(SFLAdaptor **)data;
   HSP_mod_OS10 *mdata = (HSP_mod_OS10 *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    // We only need to override behavior for a port-specific request
    // so ignore the general updates with adaptor == NULL.  They are
    // for refreshing the host-adaptor counters (eth0 etc.)
    if(adaptor == NULL)
      return;
    
    if(mdata->last_poll != sp->pollBus->clk) {
      // update all counters in one go
       pollAllCounters(mod);
       mdata->last_poll = sp->pollBus->clk;
    }
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_os10(EVMod *mod) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    mod->data = my_calloc(sizeof(HSP_mod_OS10));
    HSP_mod_OS10 *mdata = (HSP_mod_OS10 *)mod->data;
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    mdata->pollBus = EVGetBus(mod, HSPBUS_POLL, YES);

    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTF_READ), evt_poll_intf_read);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTFS_CHANGED), evt_poll_intfs_changed);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTF_SPEED), evt_poll_speed_changed);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_UPDATE_NIO), evt_poll_update_nio);

    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_CHANGED), evt_poll_config_changed);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_CONFIG_CHANGED), evt_pkt_config_changed);

    // we know there are no 32-bit counters
    sp->nio_polling_secs = 0;

    // set a minimum polling interval
    if(sp->minPollingInterval < HSP_OS10_MIN_POLLING_INTERVAL) {
      sp->minPollingInterval = HSP_OS10_MIN_POLLING_INTERVAL;
    }
    // ask for polling to be sync'd so that clusters of interfaces are polled together.
    if(sp->syncPollingInterval < HSP_OS10_MIN_POLLING_INTERVAL) {
      sp->syncPollingInterval = HSP_OS10_MIN_POLLING_INTERVAL;
    }
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
