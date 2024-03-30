/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include <systemd/sd-daemon.h>
#include "hsflowd.h"
#include "regex.h"

#include "dell-base-sflow.h"
#include "cps_api_object.h"
#include "cps_class_map.h"
#include "cps_api_object_key.h"
#include "iana-if-type.h"
#include "dell-base-if.h"
#include "dell-interface.h"
#include "ietf-interfaces.h"

#define HSP_DEFAULT_SWITCHPORT_REGEX "^e[0-9]+-[0-9]+-[0-9]+$"
#define HSP_DEFAULT_OPX_PORT 20001

#define HSP_READPACKET_BATCH_OPX 10000
#define HSP_MAX_OPX_MSG_BYTES 10000
#define HSP_OPX_RCV_BUF 8000000

#define HSP_OPX_MIN_POLLING_INTERVAL 10

#define HSP_MAX_EXEC_LINELEN 1024

  // lookup table copied from nas_os_if_utils.py
  static uint32_t opx_yang_speed_map_mbps[] = {
    0,
    10,     // 10Mbps
    100,    // 100 Mbps
    1000,   // 1Gbps
    10000,  // 10Gbps
    25000,  // 25 Gbps
    40000,  // 40Gbps
    100000, // 100Gbps
    0,      // default speed
    20000,  // 20 Gbps
    50000,  // 50 Gbps
    200000, // 200 Gbps
    400000, // 400 Gbps
    4000,   // 4GFC
    8000,   // 8 GFC
    16000,  // 16 GFC
    32000   // 32 GFC
  };
#define OPX_YANG_SPEED_MAP_MAXINDEX 16

  typedef struct _HSP_mod_OPX {
    // active on two threads (buses)
    EVBus *packetBus;
    EVBus *pollBus;
    // config
    bool configured_socket:1;
    // sample processing
    uint32_t opx_seqno;
    uint32_t opx_drops;
    // ports listed individually in config
    UTHash *switchPorts;
  } HSP_mod_OPX;


  /*_________________---------------------------__________________
    _________________      readPackets          __________________
    -----------------___________________________------------------
  */

  static void readPackets_opx(EVMod *mod, EVSocket *sock, void *magic)
  {
    HSP_mod_OPX *mdata = (HSP_mod_OPX *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    int batch = 0;

    if(sp->sFlowSettings == NULL) {
      // config was turned off
      return;
    }

    for( ; batch < HSP_READPACKET_BATCH_OPX; batch++) {
      uint32_t buf32[HSP_MAX_OPX_MSG_BYTES >> 2];
      int recvBytes = recvfrom(sock->fd, (char *)buf32, HSP_MAX_OPX_MSG_BYTES, 0, NULL, NULL);
      if(recvBytes <= 0)
	break;

      EVDebug(mod, 2, "got OPX msg: %u bytes", recvBytes);

      if(getDebug() > 2) {
	u_char pbuf[2000];
	printHex((u_char *)buf32, HSP_MAX_OPX_MSG_BYTES, pbuf, 2000, NO);
	EVDebug(mod, 1, "got msg: %s", pbuf);
      }

      // check metadata signature
      if(buf32[0] != 0xDEADBEEF) {
	EVDebug(mod, 1, "bad meta-data signature: %08X", buf32[0]);
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
	EVDebug(mod, 1, "metadata consumption error");
	continue;
      }

      u_char *pkt = (u_char *)&buf32[mdQuads];
      int headerLen = recvBytes - mdBytes;
      if(headerLen < 14) {
	EVDebug(mod, 1, "packet too small");
	continue;
      }

      // check for drops indicated by sequence no
      uint32_t droppedSamples = 0;
      if(mdata->opx_seqno) {
	droppedSamples = seqNo - mdata->opx_seqno - 1;
	if(droppedSamples) {
	  mdata->opx_drops += droppedSamples;
	}
      }
      mdata->opx_seqno = seqNo;

      SFLAdaptor *dev_in = NULL;
      SFLAdaptor *dev_out = NULL;

      if(ifIn)
	dev_in = adaptorByIndex(sp, ifIn);
      if(ifOut)
	dev_out = adaptorByIndex(sp, ifOut);

      if(dev_in == NULL
	 /* || ADAPTOR_NIO(dev_in)->sampling_n_set == 0*/) {
	// sampling not configured yet - may have just
	// restarted hsflowd
	continue;
      }

      // looks like we get the FCS bytes too -- if the
      // packet is short enough to include them
      int chopped = packetLen - headerLen;
      int fcsBytes = (chopped < 4) ?  4 - chopped : 0;
      uint32_t dsopts = (HSP_SAMPLEOPT_IF_SAMPLER
			 | HSP_SAMPLEOPT_IF_POLLER
			 | HSP_SAMPLEOPT_BRIDGE
			 | HSP_SAMPLEOPT_OPX
			 | HSP_SAMPLEOPT_INGRESS);
      takeSample(sp,
		 dev_in,
		 dev_out,
		 NULL, // tap
		 dsopts,
		 0, // hook
		 pkt,
		 14,
		 pkt + 14,
		 headerLen - 14 - fcsBytes, /* length of captured payload */
		 packetLen - 14 - 4, /* length of packet (pdu) */
		 droppedSamples,
		 sp->sFlowSettings->samplingRate,
		 NULL);
    }
  }

  /*_________________---------------------------__________________
    _________________     openOPX               __________________
    -----------------___________________________------------------
  */

  static int openOPX(EVMod *mod) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    // register call-backs
    uint16_t opxPort = sp->opx.port ?: HSP_DEFAULT_OPX_PORT;
    int fd = 0;
    if(opxPort) {
      // TODO: should this really be "::1" and PF_INET6?  Or should we bind to both "127.0.0.1" and "::1" (cf mod_json)
      fd = UTSocketUDP("127.0.0.1", PF_INET, opxPort, HSP_OPX_RCV_BUF);
      EVDebug(mod, 1, "opx socket is %d", fd);
    }
    return fd;
  }

  /*_________________---------------------------__________________
    _________________   CPSSetSampleUDPPort     __________________
    -----------------___________________________------------------
  */

  static bool CPSSetSampleUDPPort(EVMod *mod) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    cps_api_return_code_enum_val_t status;
    bool ok = NO;
    uint16_t udpPort =  sp->opx.port ?: HSP_DEFAULT_OPX_PORT;
    // prepare transaction
    cps_api_transaction_params_t tran;
    if (cps_api_transaction_init(&tran) != cps_api_ret_code_OK )
      return NO;
    cps_api_object_t obj;
    if((obj = cps_api_object_create()) == NULL)
      goto out;
    // TARGET key pointing to sFlow entry (yang model "list")
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), BASE_SFLOW_SOCKET_ADDRESS_OBJ, cps_api_qualifier_TARGET);
    // add attributes to set IP and port
    char ip[4] = { 127,0,0,1 }; // network byte order
    cps_api_object_attr_add(obj, BASE_SFLOW_SOCKET_ADDRESS_UDP_PORT, ip, 4);
    cps_api_object_attr_add_u16(obj, BASE_SFLOW_SOCKET_ADDRESS_UDP_PORT, udpPort);
    // add "set" action to transaction
    if((status = cps_api_set(&tran,obj)) != cps_api_ret_code_OK ) {
      EVDebug(mod, 1, "CPSSetSampleUDPPort: cps_api_set failed (status=%d)", status);
      goto out;
    }
    // commit
    if((status = cps_api_commit(&tran)) != cps_api_ret_code_OK ) {
      EVDebug(mod, 1, "CPSSetSampleUDPPort: cps_api_commit failed (status=%d)", status);
      goto out;
    }
    ok = YES;

  out:
    if(!ok)
      myLog(LOG_ERR, "CPSSetSampleUDPPort failed");
    cps_api_transaction_close(&tran);
    return ok;
  }

  /*_________________---------------------------__________________
    _________________   CPSSyncEntryIDs         __________________
    -----------------___________________________------------------
    Learn the CPS ids for any entries currently in the table
  */

  static bool CPSSyncEntryIDs(EVMod *mod) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    cps_api_return_code_enum_val_t status;
    bool ok = NO;
    // clear existing ids
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByIndex, adaptor)
      ADAPTOR_NIO(adaptor)->opx_id = 0;
    // prepare GET request
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);
    cps_api_object_t obj;
    if((obj = cps_api_object_list_create_obj_and_append(gp.filters)) == NULL)
      goto out;
    // TARGET key pointing to sFlow entry (yang model "list")
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), BASE_SFLOW_ENTRY_OBJ, cps_api_qualifier_TARGET);
    // GET
    if ((status = cps_api_get(&gp)) != cps_api_ret_code_OK) {
      EVDebug(mod, 1, "CPSSyncEntryIDs: cps_api_get failed (status=%d)", status);
      goto out;
    }
    ok = YES;
    size_t mx = cps_api_object_list_size(gp.list);
    for (size_t ix = 0 ; ix < mx ; ix++ ) {
      cps_api_object_t obj = cps_api_object_list_get(gp.list,ix);
      cps_api_object_attr_t attr_id = cps_api_object_attr_get(obj,BASE_SFLOW_ENTRY_ID);
      cps_api_object_attr_t attr_ifIndex = cps_api_object_attr_get(obj,BASE_SFLOW_ENTRY_IFINDEX);
      if(attr_id && attr_ifIndex) {
	uint32_t ifIndex = cps_api_object_attr_data_u32(attr_ifIndex);
	uint32_t id = cps_api_object_attr_data_u32(attr_id);
	SFLAdaptor *adaptor = adaptorByIndex(sp, ifIndex);
	if(adaptor) {
	  ADAPTOR_NIO(adaptor)->opx_id = id;
	  EVDebug(mod, 1, "interface %s ifIndex=%u cps_session_id=%u", adaptor->deviceName, ifIndex, id);
	}
      }
    }

  out:
    if(!ok)
      myLog(LOG_ERR, "CPSSyncEntryIDs failed");
    cps_api_get_request_close(&gp);
    return ok;
  }

  /*_________________---------------------------__________________
    _________________     CPSAddEntry           __________________
    -----------------___________________________------------------
    create new CPS entry and record the resulting ID
  */

  static bool CPSAddEntry(EVMod *mod, SFLAdaptor *adaptor, uint32_t sampling_n) {
    // prepare transaction
    cps_api_transaction_params_t tran;
    if (cps_api_transaction_init(&tran) != cps_api_ret_code_OK )
      return NO;
    cps_api_return_code_enum_val_t status;
    bool ok = NO;
    cps_api_object_t obj;
    if((obj = cps_api_object_create()) == NULL)
      goto out;
    // TARGET key pointing to sFlow entry (yang model "list")
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), BASE_SFLOW_ENTRY_OBJ, cps_api_qualifier_TARGET);
    // add attributes
    cps_api_object_attr_add_u32(obj, BASE_SFLOW_ENTRY_IFINDEX, adaptor->ifIndex);
    cps_api_object_attr_add_u32(obj, BASE_SFLOW_ENTRY_DIRECTION, BASE_CMN_TRAFFIC_PATH_INGRESS);
    cps_api_object_attr_add_u32(obj, BASE_SFLOW_ENTRY_SAMPLING_RATE, sampling_n);
    // "create" action
    if((status = cps_api_create(&tran,obj)) != cps_api_ret_code_OK) {
      EVDebug(mod, 1, "CPSAddEntry: cps_api_create failed (status=%d)", status);
      goto out;
    }
    // commit
    if((status = cps_api_commit(&tran)) != cps_api_ret_code_OK ) {
      EVDebug(mod, 1, "CPSAddEntry: cps_api_commit failed (status=%d)", status);
      goto out;
    }
    ok = YES;
    // read back new id
    cps_api_object_attr_t attr_id = cps_api_object_attr_get(obj, BASE_SFLOW_ENTRY_ID);
    if(attr_id)
      ADAPTOR_NIO(adaptor)->opx_id = cps_api_object_attr_data_u32(attr_id);

  out:
    if(!ok)
      myLog(LOG_ERR, "CPSAddEntry failed");
    cps_api_transaction_close(&tran);
    return ok;
  }

  /*_________________---------------------------__________________
    _________________      CPSGetEntry          __________________
    -----------------___________________________------------------
    read attributes from existing entry
  */

  static bool CPSGetEntry(EVMod *mod, SFLAdaptor *adaptor, uint32_t *p_sampling_n, uint32_t *p_dirn) {
    bool ok = NO;
    // prepare GET
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);
    cps_api_object_t obj;
    if((obj = cps_api_object_list_create_obj_and_append(gp.filters)) == NULL)
      return NO;
    // TARGET key pointing to sFlow entry (yang model "list")
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), BASE_SFLOW_ENTRY_OBJ, cps_api_qualifier_TARGET);
    // query by ENTRY_ID
    uint32_t id = ADAPTOR_NIO(adaptor)->opx_id;
    cps_api_set_key_data(obj, BASE_SFLOW_ENTRY_ID, cps_api_object_ATTR_T_U32, &id, sizeof(id));
    // GET
    cps_api_return_code_enum_val_t status;
    if ((status = cps_api_get(&gp)) != cps_api_ret_code_OK) {
      myLog(LOG_ERR, "CPSGetEntry cps_api_get failed (status=%d)", status);
      goto out;
    }
    size_t mx = cps_api_object_list_size(gp.list);
    EVDebug(mod, 1, "CPSGetEntry(%u) returned %u entries\n", id, mx);
    if(mx != 1)
      goto out;
    ok = YES;
    cps_api_object_t gobj = cps_api_object_list_get(gp.list, 0);
    cps_api_object_attr_t id_attr = cps_api_object_attr_get(gobj,BASE_SFLOW_ENTRY_ID);
    cps_api_object_attr_t ifIndex_attr = cps_api_object_attr_get(gobj,BASE_SFLOW_ENTRY_IFINDEX);
    cps_api_object_attr_t rate_attr = cps_api_object_attr_get(gobj,BASE_SFLOW_ENTRY_SAMPLING_RATE);
    cps_api_object_attr_t dirn_attr = cps_api_object_attr_get(gobj,BASE_SFLOW_ENTRY_DIRECTION);

    if(cps_api_object_attr_data_u32(id_attr) != id)
      goto out;
    if(cps_api_object_attr_data_u32(ifIndex_attr) != adaptor->ifIndex)
      goto out;

    if(rate_attr && p_sampling_n)
      (*p_sampling_n) = cps_api_object_attr_data_u32(rate_attr);
    if(dirn_attr && p_dirn)
      (*p_dirn) = cps_api_object_attr_data_u32(dirn_attr);

  out:
    if(!ok)
      myLog(LOG_ERR, "CPSGetEntry failed");
    cps_api_get_request_close(&gp);
    return ok;
  }
  /*_________________---------------------------__________________
    _________________      CPSDeleteEntry       __________________
    -----------------___________________________------------------
  */

  static bool CPSDeleteEntry(EVMod *mod, SFLAdaptor *adaptor) {
    // prepare transaction
    cps_api_transaction_params_t tran;
    if (cps_api_transaction_init(&tran) != cps_api_ret_code_OK )
      return NO;
    cps_api_return_code_enum_val_t status;
    bool ok = NO;
    // prepare DELETE
    cps_api_object_t obj;
    if((obj = cps_api_object_create()) == NULL)
      goto out;
    // TARGET key pointing to sFlow entry (yang model "list")
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), BASE_SFLOW_ENTRY_OBJ, cps_api_qualifier_TARGET);
    // query by ENTRY_ID
    uint32_t id = ADAPTOR_NIO(adaptor)->opx_id;
    cps_api_set_key_data(obj, BASE_SFLOW_ENTRY_ID, cps_api_object_ATTR_T_U32, &id, sizeof(id));
    // DELETE
    if ((status = cps_api_delete(&tran, obj)) != cps_api_ret_code_OK) {
      myLog(LOG_ERR, "CPSDeleteEntry cps_api_delete failed (status=%d)", status);
      goto out;
    }
    // commit
    if((status = cps_api_commit(&tran)) != cps_api_ret_code_OK ) {
      EVDebug(mod, 1, "CPSDeleteEntry: cps_api_commit failed (status=%d)", status);
      goto out;
    }
    ok = YES;
    // clear the id
    ADAPTOR_NIO(adaptor)->opx_id = 0;
  out:
    if(!ok)
      myLog(LOG_ERR, "CPSDeleteEntry failed");
    cps_api_transaction_close(&tran);
    return ok;
  }

  /*_________________---------------------------__________________
    _________________   CPSSetEntrySamplingRate __________________
    -----------------___________________________------------------
  */

  static bool CPSSetEntrySamplingRate(EVMod *mod, SFLAdaptor *adaptor, uint32_t sampling_n) {
    cps_api_return_code_enum_val_t status;
    bool ok = NO;
    // prepare transaction
    cps_api_transaction_params_t tran;
    if(cps_api_transaction_init(&tran) != cps_api_ret_code_OK )
      return false;
    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL)
      goto out;
    // TARGET attributes
    uint32_t id = ADAPTOR_NIO(adaptor)->opx_id;
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), BASE_SFLOW_ENTRY_OBJ, cps_api_qualifier_TARGET);
    cps_api_set_key_data(obj, BASE_SFLOW_ENTRY_ID,cps_api_object_ATTR_T_U32, &id, sizeof(id));
    cps_api_object_attr_add_u32(obj, BASE_SFLOW_ENTRY_SAMPLING_RATE, sampling_n);
    // SET
    if ((status = cps_api_set(&tran, obj)) != cps_api_ret_code_OK) {
      EVDebug(mod, 1, "CPSSetEntrySamplingRate: cps_api_set failed (status=%d)", status);
      goto out;
    }
    if((status = cps_api_commit(&tran)) != cps_api_ret_code_OK) {
      EVDebug(mod, 1, "CPSSetEntrySamplingRate: cps_api_commit failed (status=%d)", status);
      goto out;
    }
    ok = YES;

  out:
    if(!ok)
      myLog(LOG_ERR, "CPSSetEntrySamplingRate failed");
    cps_api_transaction_close(&tran);
    return ok;
  }

  /*_________________---------------------------__________________
    _________________   CPSSetEntrySamplingDirn __________________
    -----------------___________________________------------------
  */

  static bool CPSSetEntrySamplingDirn(EVMod *mod, SFLAdaptor *adaptor, uint32_t sampling_dirn) {
    cps_api_return_code_enum_val_t status;
    bool ok = NO;
    // prepare transaction
    cps_api_transaction_params_t tran;
    if(cps_api_transaction_init(&tran) != cps_api_ret_code_OK )
      return false;
    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL)
      goto out;
    // TARGET attributes
    uint32_t id = ADAPTOR_NIO(adaptor)->opx_id;
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), BASE_SFLOW_ENTRY_OBJ, cps_api_qualifier_TARGET);
    cps_api_set_key_data(obj, BASE_SFLOW_ENTRY_ID,cps_api_object_ATTR_T_U32, &id, sizeof(id));
    cps_api_object_attr_add_u32(obj, BASE_SFLOW_ENTRY_DIRECTION, sampling_dirn);
    // SET
    if ((status = cps_api_set(&tran, obj)) != cps_api_ret_code_OK) {
      EVDebug(mod, 1, "CPSSetEntrySamplingDirn: cps_api_set failed (status=%d)", status);
      goto out;
    }
    if((status = cps_api_commit(&tran)) != cps_api_ret_code_OK) {
      EVDebug(mod, 1, "CPSSetEntrySamplingDirn: cps_api_commit failed (status=%d)", status);
      goto out;
    }
    ok = YES;

  out:
    if(!ok)
      myLog(LOG_ERR, "CPSSetEntrySamplingDirn failed");
    cps_api_transaction_close(&tran);
    return ok;
  }

  /*_________________---------------------------__________________
    _________________      CPSSetEntry          __________________
    -----------------___________________________------------------
    write attributes to existing entry
  */

  static bool CPSSetEntry(EVMod *mod, SFLAdaptor *adaptor, uint32_t sampling_n) {
    return (CPSSetEntrySamplingRate(mod, adaptor, sampling_n)
	    && CPSSetEntrySamplingDirn(mod, adaptor, BASE_CMN_TRAFFIC_PATH_INGRESS));
  }

  /*_________________---------------------------__________________
    _________________   CPSSetSamplingRate      __________________
    -----------------___________________________------------------
  */

  static bool CPSSetSamplingRate(EVMod *mod, SFLAdaptor *adaptor, uint32_t sampling_n) {
    if(!ADAPTOR_NIO(adaptor)->opx_id)
      return CPSAddEntry(mod, adaptor, sampling_n); // not there - add it

    uint32_t current_n=0, current_dirn=0;
    if(!CPSGetEntry(mod, adaptor, &current_n, &current_dirn))
      return NO; // GET failed

    if(current_n == sampling_n
       && current_dirn == BASE_CMN_TRAFFIC_PATH_INGRESS)
      return YES; // no change

    return CPSSetEntry(mod, adaptor, sampling_n);
  }

  /*_________________---------------------------__________________
    _________________     setSamplingRate       __________________
    -----------------___________________________------------------
  */

  static bool setSamplingRate(EVMod *mod, SFLAdaptor *adaptor, uint32_t sampling_n) {
    HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
    if(adaptor->ifSpeed == 0) {
      // by refusing to set a sampling rate for a port
      // with speed == 0 we can stabilize the startup.
      // Now sampling will only be configured as ports
      // are discovered or come up (or change speed).
      EVDebug(mod, 1, "setSamplingRate: do not set: %s ifSpeed==0",
	      adaptor->deviceName);
      return NO;
    }

    if(niostate->switchPort == NO
       || niostate->loopback
       || niostate->bond_master) {
      EVDebug(mod, 1, "setSamplingRate: do not set: %s not switchPort component",
	      adaptor->deviceName);
      return NO;
    }

    niostate->sampling_n = sampling_n;
    if(niostate->sampling_n != niostate->sampling_n_set) {
      if(!CPSSetSamplingRate(mod, adaptor, sampling_n)) {
	// resync, delete and try again
	myLog(LOG_INFO, "setSamplingRate: resync, delete and try again");
	CPSSyncEntryIDs(mod);
	CPSDeleteEntry(mod, adaptor);
	if(!CPSSetSamplingRate(mod, adaptor, sampling_n)) {
	  myLog(LOG_ERR, "setSamplingRate: failed to set rate=%u on interface %s (opx_id==%u)",
		sampling_n,
		adaptor->deviceName,
		niostate->opx_id);
	  return NO;
	}
      }
      niostate->sampling_n_set = sampling_n;
    }
    return YES;
  }

  /*_________________---------------------------__________________
    _________________  CPSPollIfState           __________________
    -----------------___________________________------------------
  */

  static bool CPSPollIfState(EVMod *mod, SFLAdaptor *adaptor, SFLHost_nio_counters *ctrs, HSP_ethtool_counters *et_ctrs) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    cps_api_return_code_enum_val_t status;
    bool ok = NO;
    HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
    if(!nio->switchPort)
      return NO;
    // prepare GET
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if (obj == NULL)
      goto out;
    // OBSERVED key with ifType and name
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
				    DELL_BASE_IF_CMN_IF_INTERFACES_STATE_INTERFACE_OBJ,
				    cps_api_qualifier_OBSERVED);

    cps_api_object_attr_add(obj,IF_INTERFACES_STATE_INTERFACE_TYPE,
			    (const char *)IF_INTERFACE_TYPE_IANAIFT_IANA_INTERFACE_TYPE_IANAIFT_ETHERNETCSMACD,
			    sizeof(IF_INTERFACE_TYPE_IANAIFT_IANA_INTERFACE_TYPE_IANAIFT_ETHERNETCSMACD));

    cps_api_set_key_data(obj,
			 IF_INTERFACES_STATE_INTERFACE_NAME,
			 cps_api_object_ATTR_T_BIN,
			 adaptor->deviceName,
			 strlen(adaptor->deviceName)+1);
    // GET
    if ((status = cps_api_get(&gp)) != cps_api_ret_code_OK) {
      EVDebug(mod, 1, "CPSPollIfState: cps_api_get failed (status=%d)", status);
      goto out;
    }
    ok = YES;
    size_t mx = cps_api_object_list_size(gp.list);
    EVDebug(mod, 1, "CPSPollIfState: get returned %u results", mx);
    for (size_t ix = 0 ; ix < mx ; ++ix ) {
      cps_api_object_t gobj = cps_api_object_list_get(gp.list,ix);
      cps_api_object_it_t it;
      cps_api_object_it_begin(gobj,&it);
      for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
	uint32_t ctrid = cps_api_object_attr_id(it.attr);
	EVDebug(mod, 2, "CPSPollIfState: field id=%u", ctrid);
	uint64_t speed;
	switch(ctrid) {

	case IF_INTERFACES_INTERFACE_ENABLED:
	  nio->up = cps_api_object_attr_data_u32(it.attr);
	  EVDebug(mod, 1, "enabled=%u", nio->up);
	  break;

	case IF_INTERFACES_STATE_INTERFACE_IF_INDEX:
	  EVDebug(mod, 1, "ifIndex=%u (adaptor ifIndex=%u)",
		  cps_api_object_attr_data_u32(it.attr),
		  adaptor->ifIndex);
	  break;

	case IF_INTERFACES_STATE_INTERFACE_ADMIN_STATUS:
	  et_ctrs->adminStatus = cps_api_object_attr_data_u32(it.attr);
	  nio->et_found |= HSP_ETCTR_ADMIN;
	  EVDebug(mod, 1, "admin-status=%u", et_ctrs->adminStatus);
	  break;

	case IF_INTERFACES_STATE_INTERFACE_OPER_STATUS:
	  et_ctrs->operStatus = cps_api_object_attr_data_u32(it.attr);
	  nio->et_found |= HSP_ETCTR_OPER;
	  EVDebug(mod, 1, "oper-status=%u", et_ctrs->operStatus);
	  break;

	case IF_INTERFACES_STATE_INTERFACE_SPEED:
	  speed = cps_api_object_attr_data_u64(it.attr);
	  if(speed <= OPX_YANG_SPEED_MAP_MAXINDEX) {
	    speed = opx_yang_speed_map_mbps[speed];
	    speed *= 1000000LL;
	  }
	  // setting the speed may trigger a sampling-rate change
	  EVDebug(mod, 1, "ifSpeed=%"PRIu64, speed);
	  setAdaptorSpeed(sp, adaptor, speed, "mod_opx");
	  break;

	  // TODO: how to get these?
	  //case IF_INTERFACES_STATE_INTERFACE_TYPE:
	  //case IF_INTERFACES_STATE_INTERFACE_PHYS_ADDRESS:
	  //case DELL_IF_IF_INTERFACES_INTERFACE_PHYS_ADDRESS:
	  //case DELL_IF_IF_INTERFACES_STATE_INTERFACE_FC_MTU:
	  //case DELL_IF_IF_INTERFACES_STATE_INTERFACE_DUPLEX:
	}
      }
    }

  out:
    cps_api_get_request_close(&gp);
    return ok;
  }

  /*_________________---------------------------__________________
    _________________  CPSPollIfCounters        __________________
    -----------------___________________________------------------
  */

  static bool CPSPollIfCounters(EVMod *mod, SFLAdaptor *adaptor, SFLHost_nio_counters *ctrs, HSP_ethtool_counters *et_ctrs) {
    bool ok = NO;
    cps_api_return_code_enum_val_t status;
    HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
    if(!nio->switchPort)
      return NO;
    // prepare GET
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if (obj == NULL)
      goto out;

    // Setting for "OBSERVED" stats for now - assuming they are collected from hardware
    // at least every second.  This is an interim solution.  Should really be REALTIME,
    // or else the counters collected from the ASIC should be announced immediately they
    // are read so we can just listen for them here and send them out if they are due.
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
				    DELL_BASE_IF_CMN_IF_INTERFACES_STATE_INTERFACE_STATISTICS_OBJ,
				    cps_api_qualifier_OBSERVED);

    cps_api_object_attr_add(obj,IF_INTERFACES_STATE_INTERFACE_TYPE,
			    (const char *)IF_INTERFACE_TYPE_IANAIFT_IANA_INTERFACE_TYPE_IANAIFT_ETHERNETCSMACD,
			    sizeof(IF_INTERFACE_TYPE_IANAIFT_IANA_INTERFACE_TYPE_IANAIFT_ETHERNETCSMACD));

    cps_api_set_key_data(obj,
			 IF_INTERFACES_STATE_INTERFACE_NAME,
			 cps_api_object_ATTR_T_BIN,
			 adaptor->deviceName,
			 strlen(adaptor->deviceName)+1);
    // GET
    if ((status = cps_api_get(&gp)) != cps_api_ret_code_OK) {
      EVDebug(mod, 1, "CPSPollIfCounters: cps_api_get failed (status=%d)", status);
      goto out;
    }
    ok = YES;
    size_t mx = cps_api_object_list_size(gp.list);
    EVDebug(mod, 1, "CPSPollIfCounters: get returned %u results", mx);
    for (size_t ix = 0 ; ix < mx ; ++ix ) {
      cps_api_object_t gobj = cps_api_object_list_get(gp.list,ix);
      cps_api_object_it_t it;
      cps_api_object_it_begin(gobj,&it);
      for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
	uint32_t ctrid = cps_api_object_attr_id(it.attr);
	uint64_t ctr64 = cps_api_object_attr_data_u64(it.attr);
	EVDebug(mod, 2, "CPSPollIfCounters: %s id(%u) hex(%x) == %"PRIu64,
		adaptor->deviceName,
		ctrid,
		ctrid,
		ctr64);
	switch(ctrid) {
	case IF_INTERFACES_STATE_INTERFACE_STATISTICS_IN_OCTETS:
	  ctrs->bytes_in = ctr64;
	  break;
	case IF_INTERFACES_STATE_INTERFACE_STATISTICS_IN_UNICAST_PKTS:
	  ctrs->pkts_in = ctr64;
	  break;
	case IF_INTERFACES_STATE_INTERFACE_STATISTICS_IN_BROADCAST_PKTS:
	  et_ctrs->bcasts_in = ctr64;
	  nio->et_found |= HSP_ETCTR_BC_IN;
	  break;
	case IF_INTERFACES_STATE_INTERFACE_STATISTICS_IN_MULTICAST_PKTS:
	  et_ctrs->mcasts_in = ctr64;
	  nio->et_found |= HSP_ETCTR_MC_IN;
	  break;
	case IF_INTERFACES_STATE_INTERFACE_STATISTICS_IN_DISCARDS:
	  ctrs->drops_in = ctr64;
	  break;
	case IF_INTERFACES_STATE_INTERFACE_STATISTICS_IN_ERRORS:
	  ctrs->errs_in = ctr64;
	  break;
	case IF_INTERFACES_STATE_INTERFACE_STATISTICS_IN_UNKNOWN_PROTOS:
	  et_ctrs->unknown_in = ctr64;
	  nio->et_found |= HSP_ETCTR_UNKN;
	  break;
	case IF_INTERFACES_STATE_INTERFACE_STATISTICS_OUT_OCTETS:
	  ctrs->bytes_out = ctr64;
	  break;
	case IF_INTERFACES_STATE_INTERFACE_STATISTICS_OUT_UNICAST_PKTS:
	  ctrs->pkts_out = ctr64;
	  break;
	case IF_INTERFACES_STATE_INTERFACE_STATISTICS_OUT_BROADCAST_PKTS:
	  et_ctrs->bcasts_out = ctr64;
	  nio->et_found |= HSP_ETCTR_BC_OUT;
	  break;
	case IF_INTERFACES_STATE_INTERFACE_STATISTICS_OUT_MULTICAST_PKTS:
	  et_ctrs->mcasts_out = ctr64;
	  nio->et_found |= HSP_ETCTR_MC_OUT;
	  break;
	case IF_INTERFACES_STATE_INTERFACE_STATISTICS_OUT_DISCARDS:
	  ctrs->drops_out = ctr64;
	  break;
	case IF_INTERFACES_STATE_INTERFACE_STATISTICS_OUT_ERRORS:
	  ctrs->errs_out = ctr64;
	  break;
	  // case DELL_BASE_IF_CMN_IF_INTERFACES_STATE_INTERFACE_STATISTICS_TIME_STAMP:
	}
      }
    }

  out:
    cps_api_get_request_close(&gp);
    return ok;
  }

  /*_________________---------------------------__________________
    _________________    pollCounters           __________________
    -----------------___________________________------------------
  */

  static void pollCounters(EVMod *mod, SFLAdaptor *adaptor) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);

    if(nio->loopback
       || nio->bond_master) {
      // bond counters will be synthesized - don't try to poll them here
      return;
    }

    SFLHost_nio_counters ctrs = { 0 };
    HSP_ethtool_counters et_ctrs = { 0 };
    uint64_t allocated1 = cps_api_objects_allocated();

    CPSPollIfState(mod, adaptor, &ctrs, &et_ctrs);
    CPSPollIfCounters(mod, adaptor, &ctrs, &et_ctrs);
    accumulateNioCounters(sp, adaptor, &ctrs, &et_ctrs);
    nio->last_update = sp->pollBus->now.tv_sec;

    uint64_t allocated2 = cps_api_objects_allocated();
    if(allocated1 != allocated2) {
      myLog(LOG_ERR, "pollCounters(%s): CPS objects not freed=%"PRIu64,
	    adaptor->deviceName,
	    allocated2 - allocated1);
      cps_api_list_stats();
    }
  }

  /*_________________---------------------------__________________
    _________________   markSwitchPort          __________________
    -----------------___________________________------------------
  */

  static bool markSwitchPort(EVMod *mod, SFLAdaptor *adaptor)  {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSP_mod_OPX *mdata = (HSP_mod_OPX *)mod->data;

    bool switchPort = NO;

    // list supplied in config takes precendence over regex pattern.
    // This requires an exact (case-sensitive) match on the name.
    if(mdata->switchPorts) {
      HSPPort search = { .dev = adaptor->deviceName };
      if(UTHashGet(mdata->switchPorts, &search))
	switchPort = YES;
    }
    else {
      // fall back on regex
      if(sp->opx.swp_regex_str == NULL) {
	// pattern not specified in config, so compile the default
	sp->opx.swp_regex_str = HSP_DEFAULT_SWITCHPORT_REGEX;
	sp->opx.swp_regex = UTRegexCompile(HSP_DEFAULT_SWITCHPORT_REGEX);
	assert(sp->opx.swp_regex);
      }
      // use pattern to mark the switch ports
      if(regexec(sp->opx.swp_regex, adaptor->deviceName, 0, NULL, 0) == 0)
	switchPort = YES;
    }

    HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
    niostate->switchPort = switchPort;
    niostate->opxPort = switchPort;
    return switchPort;
  }

  /*_________________---------------------------__________________
    _________________    evt_poll_config_first  __________________
    -----------------___________________________------------------
  */

  static void evt_poll_config_first(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    // only get here if we have a valid config,  so we can announce
    // that we are ready to go. The man page says to ignore the
    // return value,  but we'll log it anyway when debugging...
    int ans = sd_notify(0, "READY=1");
    EVDebug(mod, 1, "opx.evt_poll_config_first(): sd_notify() returned %d", ans);
  }

  /*_________________---------------------------__________________
    _________________    evt_config_changed     __________________
    -----------------___________________________------------------
  */

  static void evt_pkt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_OPX *mdata = (HSP_mod_OPX *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    if(!mdata->configured_socket) {
      int fd = openOPX(mod);
      if(fd > 0)
	EVBusAddSocket(mod, mdata->packetBus, fd, readPackets_opx, mod);
      mdata->configured_socket = YES;
    }
  }

  static void evt_poll_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    // make sure CPS sFlow is pointed at the right socket
    CPSSetSampleUDPPort(mod);

    uint64_t allocated1 = cps_api_objects_allocated();

    // The sampling-rate settings may have changed.
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByName, adaptor) {
      uint32_t sampling_n = lookupPacketSamplingRate(adaptor, sp->sFlowSettings);
      setSamplingRate(mod, adaptor, sampling_n);
    }

    uint64_t allocated2 = cps_api_objects_allocated();
    if(allocated2 != allocated1) {
      EVDebug(mod, 1, "evt_poll_config_changed: CPS objects not freed=%"PRIu64,
	      allocated2 - allocated1);
      cps_api_list_stats();
    }
  }

  /*_________________---------------------------__________________
    _________________      evt_intf_read        __________________
    -----------------___________________________------------------
  */

  static void evt_poll_intf_read(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    SFLAdaptor *adaptor = *(SFLAdaptor **)data;
    markSwitchPort(mod, adaptor);
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

  /*_________________---------------------------__________________
    _________________      evt_intfs_changed    __________________
    -----------------___________________________------------------
  */

  static void evt_poll_intfs_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    // need to refresh speed/status meta-data for all interfaces
    // may trigger sampling-rate setting if speed changes (see below)
    CPSSyncEntryIDs(mod);
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByIndex, adaptor)
      pollCounters(mod, adaptor);
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

    uint64_t allocated1 = cps_api_objects_allocated();

    uint32_t sampling_n = lookupPacketSamplingRate(adaptor, sp->sFlowSettings);
    setSamplingRate(mod, adaptor, sampling_n);

    uint64_t allocated2 = cps_api_objects_allocated();
    if(allocated2 != allocated1) {
      EVDebug(mod, 1, "evt_poll_speed_changed: CPS objects not freed=%"PRIu64,
	      allocated2 - allocated1);
      cps_api_list_stats();
    }
  }

  /*_________________---------------------------__________________
    _________________     evt_poll_update_nio   __________________
    -----------------___________________________------------------
  */

  static void evt_poll_update_nio(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    SFLAdaptor *adaptor = *(SFLAdaptor **)data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    // We only need to override behavior for a port-specific request
    // so ignore the general updates with adaptor == NULL.  They are
    // for refreshing the host-adaptor counters (eth0 etc.)
    if(adaptor == NULL)
      return;

    pollCounters(mod, adaptor);
  }

  /*_________________---------------------------__________________
    _________________        evt_final          __________________
    -----------------___________________________------------------
  */

  static void evt_final(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(sp->sFlowSettings == NULL)
      return;
    // turn off any hardware-sampling that we enabled
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByName, adaptor) {
      if(ADAPTOR_NIO(adaptor)->opx_id) {
	setSamplingRate(mod, adaptor, 0);
	CPSDeleteEntry(mod, adaptor);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_opx(EVMod *mod) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    mod->data = my_calloc(sizeof(HSP_mod_OPX));
    HSP_mod_OPX *mdata = (HSP_mod_OPX *)mod->data;
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    mdata->pollBus = EVGetBus(mod, HSPBUS_POLL, YES);

    retainRootRequest(mod, "Needed to call out to OPX scripts (PYTHONPATH)");

    // ask that bond counters be accumuated from their components
    setSynthesizeBondCounters(mod, YES);

    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTF_READ), evt_poll_intf_read);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTFS_CHANGED), evt_poll_intfs_changed);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTF_SPEED), evt_poll_speed_changed);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_UPDATE_NIO), evt_poll_update_nio);

    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_FIRST), evt_poll_config_first);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_CHANGED), evt_poll_config_changed);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_CONFIG_CHANGED), evt_pkt_config_changed);

    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_FINAL), evt_final);

    // we know there are no 32-bit counters
    sp->nio_polling_secs = 0;

    // set a minimum polling interval
    if(sp->minPollingInterval < HSP_OPX_MIN_POLLING_INTERVAL) {
      sp->minPollingInterval = HSP_OPX_MIN_POLLING_INTERVAL;
    }
    // ask for polling to be sync'd so that clusters of interfaces are polled together.
    if(sp->syncPollingInterval < HSP_OPX_MIN_POLLING_INTERVAL) {
      sp->syncPollingInterval = HSP_OPX_MIN_POLLING_INTERVAL;
    }

    // ports may have been listed explicity in config file.  If so,
    // define a hash lookup for them.
    if(sp->opx.ports) {
      mdata->switchPorts = UTHASH_NEW(HSPPort, dev, UTHASH_SKEY);
      for(HSPPort *prt = sp->opx.ports; prt; prt = prt->nxt)
	UTHashAdd(mdata->switchPorts, prt);
    }
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif
