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

  typedef struct _HSP_mod_OS10 {
    EVBus *packetBus;
    bool os10_configured;
    int os10_soc;
    uint32_t os10_seqno;
    uint32_t os10_drops;
  } HSP_mod_OS10;

  /*_________________---------------------------__________________
    _________________      readPackets          __________________
    -----------------___________________________------------------
  */

  int readPackets_os10(EVMod *mod, EVBus *bus, int fd, void *data)
  {
    HSP_mod_OS10 *mdata = (HSP_mod_OS10 *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    int batch = 0;

    if(sp->sFlowSettings == NULL) {
      // config was turned off
      return 0;
    }
    
    for( ; batch < HSP_READPACKET_BATCH_OS10; batch++) {
      uint32_t buf32[HSP_MAX_OS10_MSG_BYTES >> 2];
      int recvBytes = recvfrom(mdata->os10_soc, (char *)buf32, HSP_MAX_OS10_MSG_BYTES, 0, NULL, NULL);
      if(recvBytes <= 0)
	break;
      
      myDebug(1, "got OS10 msg: %u bytes", recvBytes);

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

      takeSample(sp,
		 dev_in,
		 dev_out,
		 NULL, // tap
		 YES, // bridge
		 0, // hook
		 pkt,
		 14,
		 pkt + 14,
		 headerLen, /* length of captured payload */
		 packetLen, /* length of packet (pdu) */
		 droppedSamples,
		 sp->sFlowSettings->samplingRate);
    }
    return batch;
  }


  /*_________________---------------------------__________________
    _________________     openOS10              __________________
    -----------------___________________________------------------
  */

  static int openOS10(EVMod *mod)
  {
    HSP_mod_OS10 *mdata = (HSP_mod_OS10 *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    
    // register call-backs
    uint16_t os10Port = sp->os10.port ?: HSP_DEFAULT_OS10_PORT;

    if(os10Port) {
      // TODO: should this really be "::1" and PF_INET6?  Or should we bind to both "127.0.0.1" and "::1" (cf mod_json)
      mdata->os10_soc = UTSocketUDP("127.0.0.1", PF_INET, os10Port, HSP_OS10_RCV_BUF);
     myDebug(1, "os10 socket is %d", mdata->os10_soc);
    }
    
    return mdata->os10_soc;
  }

  /*_________________---------------------------__________________
    _________________     setSamplingRate       __________________
    -----------------___________________________------------------
  */

#define HSP_ENTRY_REGEX "^base-sflow/entry/id = ([0-9]+)$"
static regex_t *entryRegex = NULL;

  static int execOutputLine(void *magic, char *line) {
    if(!entryRegex) {
      entryRegex = UTRegexCompile(HSP_ENTRY_REGEX);
      assert(entryRegex != NULL);
    }
    HSPAdaptorNIO *niostate = (HSPAdaptorNIO *)magic;
    myDebug(1, "execOutputLine: %s", line);
    if(UTRegexExtractInt(entryRegex, line, 1, &niostate->os10_port_id, NULL, NULL))
      myDebug(1, "extracted port id = " + niostate->os10_port_id);
    return YES;
  }

  static bool setSamplingRate(EVMod *mod) {
    // HSP_mod_OS10 *mdata = (HSP_mod_OS10 *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPSFlowSettings *settings = sp->sFlowSettings;

    int hw_sampling = YES;
    UTStringArray *cmdline = strArrayNew();
    UTStringArray *cmdline2 = strArrayNew();
    strArrayAdd(cmdline, HSP_OS10_SWITCHPORT_CONFIG_PROG);
    strArrayAdd(cmdline2, HSP_OS10_SWITCHPORT_CONFIG_PROG);
    // usage:  <prog> [enable|disable] <interface> <direction>  <rate>
    // usage:  <prog> set_rate <id> <rate>
#define HSP_MAX_TOK_LEN 16
    strArrayAdd(cmdline, "enable");
    strArrayAdd(cmdline, NULL); // placeholder for port name in slot 2
    strArrayAdd(cmdline, "ingress");
    strArrayAdd(cmdline, "0");  // placeholder for sampling N in slot 4

    strArrayAdd(cmdline2, "set_rate");
    strArrayAdd(cmdline2, NULL); // placeholder for port id in slot 2
    strArrayAdd(cmdline, "0"); // placeholder for sampling N in slot 3

#define HSP_MAX_EXEC_LINELEN 1024
    char outputLine[HSP_MAX_EXEC_LINELEN];
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByIndex, adaptor) {
      HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
      if(niostate->switchPort
         && !niostate->loopback
         && !niostate->bond_master) {
        niostate->sampling_n = lookupPacketSamplingRate(adaptor, settings);
        if(niostate->sampling_n != niostate->sampling_n_set) {
          myDebug(1, "setSwitchPortSamplingRate(%s) %u -> %u",
                          adaptor->deviceName,
                          niostate->sampling_n_set,
                          niostate->sampling_n);
          char srate[HSP_MAX_TOK_LEN];
          snprintf(srate, HSP_MAX_TOK_LEN, "%u", niostate->sampling_n);
          char **cmdline_str = NULL;
          if(niostate->os10_port_id) {
            char portId[HSP_MAX_TOK_LEN];
	    snprintf(portId, HSP_MAX_TOK_LEN, "%u", niostate->os10_port_id);
            strArrayInsert(cmdline2, 2, portId);
            strArrayInsert(cmdline2, 3, srate);
            cmdline_str = strArray(cmdline2);
          }
          else {
            strArrayInsert(cmdline, 2, adaptor->deviceName);
            strArrayInsert(cmdline, 4, srate); // ingress
            cmdline_str = strArray(cmdline);
          }
          myDebug(1, "calling command: %s", cmdline_str);
          int status;
          if(myExec(niostate, cmdline_str, execOutputLine, outputLine, HSP_MAX_EXEC_LINELEN, &status)) {
            if(WEXITSTATUS(status) != 0) {

              myLog(LOG_ERR, "myExec(%s) exitStatus=%d so assuming ULOG/NFLOG is 1:1",
                    HSP_OS10_SWITCHPORT_CONFIG_PROG,
                    WEXITSTATUS(status));

              hw_sampling = NO;
              break;
            }
            else {
              myDebug(1, "setSwitchPortSamplingRate(%s) succeeded", adaptor->deviceName);
              // hardware or kernel sampling was successfully configured
              niostate->sampling_n_set = niostate->sampling_n;
            }
          }
          else {
            myLog(LOG_ERR, "myExec() calling %s failed (adaptor/id=%s)",
                  strArrayAt(cmdline, 0),
                  strArrayAt(cmdline, 2));
          }
        }
      }
    }
    strArrayFree(cmdline);
    strArrayFree(cmdline2);
    return hw_sampling;
  }

 /*_________________---------------------------__________________
    _________________   markSwitchPorts         __________________
    -----------------___________________________------------------
  */

  static void markSwitchPorts(EVMod *mod)  {
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->os10.swp_regex_str == NULL) {
      // pattern not specified in config, so compile the default
      sp->os10.swp_regex_str = HSP_DEFAULT_SWITCHPORT_REGEX;
      sp->os10.swp_regex = UTRegexCompile(HSP_DEFAULT_SWITCHPORT_REGEX);
      assert(sp->os10.swp_regex);
    }

    // use pattern to mark the switch ports
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByIndex, adaptor) {
      HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
      if(regexec(sp->os10.swp_regex, adaptor->deviceName, 0, NULL, 0) == 0) {
        niostate->switchPort = YES;
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_config_changed     __________________
    -----------------___________________________------------------
  */

  static void evt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_OS10 *mdata = (HSP_mod_OS10 *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    markSwitchPorts(mod);
    sp->hardwareSampling = setSamplingRate(mod);

    if(mdata->os10_configured) {
      // already configured from the first time (when we still had root privileges)
      return;
    }
    
    int fd = openOS10(mod);
    if(fd > 0)
      EVBusAddSocket(mod, mdata->packetBus, fd, readPackets_os10, mod);
    
    mdata->os10_configured = YES;
  }

  /*_________________---------------------------__________________
    _________________    evt_intf_changed       __________________
    -----------------___________________________------------------
  */

  static void evt_intf_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    evt_config_changed(mod, evt, data, dataLen);
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_os10(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_OS10));
    HSP_mod_OS10 *mdata = (HSP_mod_OS10 *)mod->data;
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_INTF_CHANGED), evt_intf_changed);
  }

  
#if defined(__cplusplus)
} /* extern "C" */
#endif

