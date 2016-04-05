/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#ifdef HSP_VRT


  static void agentCB_getCounters_VRT(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    assert(poller->magic);
    HSPVMState *state = (HSPVMState *)poller->userData;
    if(state == NULL) {
      if(debug) myLog(LOG_INFO, "agentCB_getCounters_VRT: state==NULL");
      return;
    }
    if(state->vmType != VMTYPE_VRT) {
      myLog(LOG_ERR, "agentCB_getCounters_VRT(): not a LIBVIRT VM");
      return;
    }

    HSP *sp = (HSP *)poller->magic;
    if(sp->virConn) {
      virDomainPtr domainPtr = virDomainLookupByID(sp->virConn, state->domId);
      if(domainPtr == NULL) {
	sp->refreshVMList = YES;
      }
      else {
	// host ID
	SFLCounters_sample_element hidElem = { 0 };
	hidElem.tag = SFLCOUNTERS_HOST_HID;
	const char *hname = virDomainGetName(domainPtr); // no need to free this one
	if(hname) {
	  // copy the name out here so we can free it straight away
	  hidElem.counterBlock.host_hid.hostname.str = (char *)hname;
	  hidElem.counterBlock.host_hid.hostname.len = strlen(hname);
	  virDomainGetUUID(domainPtr, hidElem.counterBlock.host_hid.uuid);
	
	  // char *osType = virDomainGetOSType(domainPtr); $$$
	  hidElem.counterBlock.host_hid.machine_type = SFLMT_unknown;//$$$
	  hidElem.counterBlock.host_hid.os_name = SFLOS_unknown;//$$$
	  //hidElem.counterBlock.host_hid.os_release.str = NULL;
	  //hidElem.counterBlock.host_hid.os_release.len = 0;
	  SFLADD_ELEMENT(cs, &hidElem);
	}
      
	// host parent
	SFLCounters_sample_element parElem = { 0 };
	parElem.tag = SFLCOUNTERS_HOST_PAR;
	parElem.counterBlock.host_par.dsClass = SFL_DSCLASS_PHYSICAL_ENTITY;
	parElem.counterBlock.host_par.dsIndex = HSP_DEFAULT_PHYSICAL_DSINDEX;
	SFLADD_ELEMENT(cs, &parElem);

	// VM Net I/O
	SFLCounters_sample_element nioElem = { 0 };
	nioElem.tag = SFLCOUNTERS_HOST_VRT_NIO;
	// since we are already maintaining the accumulated network counters (and handling issues like 32-bit
	// rollover) then we can just use the same mechanism again.  On a non-linux platform we may
	// want to take advantage of the libvirt call to get the counters (it takes the domain id and the
	// device name as parameters so you have to call it multiple times),  but even then we would
	// probably do that down inside the readNioCounters() fn in case there is work to do on the
	// accumulation and rollover-detection.
	readNioCounters(sp, (SFLHost_nio_counters *)&nioElem.counterBlock.host_vrt_nio, NULL, state->interfaces);
	SFLADD_ELEMENT(cs, &nioElem);
      
	// VM cpu counters [ref xenstat.c]
	SFLCounters_sample_element cpuElem = { 0 };
	cpuElem.tag = SFLCOUNTERS_HOST_VRT_CPU;
	virDomainInfo domainInfo;
	int domainInfoOK = NO;
	if(virDomainGetInfo(domainPtr, &domainInfo) != 0) {
	  myLog(LOG_ERR, "virDomainGetInfo() failed");
	}
	else {
	  domainInfoOK = YES;
	  // enum virDomainState really is the same as enum SFLVirDomainState
	  cpuElem.counterBlock.host_vrt_cpu.state = domainInfo.state;
	  cpuElem.counterBlock.host_vrt_cpu.cpuTime = (domainInfo.cpuTime / 1000000);
	  cpuElem.counterBlock.host_vrt_cpu.nrVirtCpu = domainInfo.nrVirtCpu;
	  SFLADD_ELEMENT(cs, &cpuElem);
	}
      
	SFLCounters_sample_element memElem = { 0 };
	memElem.tag = SFLCOUNTERS_HOST_VRT_MEM;
	if(domainInfoOK) {
	  memElem.counterBlock.host_vrt_mem.memory = domainInfo.memory * 1024;
	  memElem.counterBlock.host_vrt_mem.maxMemory = (domainInfo.maxMem == UINT_MAX) ? -1 : (domainInfo.maxMem * 1024);
	  SFLADD_ELEMENT(cs, &memElem);
	}

    
	// VM disk I/O counters
	SFLCounters_sample_element dskElem = { 0 };
	dskElem.tag = SFLCOUNTERS_HOST_VRT_DSK;
	for(int i = strArrayN(state->disks); --i >= 0; ) {
	  /* state->volumes and state->disks are populated in lockstep
	   * so they always have the same number of elements
	   */
	  char *volPath = strArrayAt(state->volumes, i);
	  char *dskPath = strArrayAt(state->disks, i);
	  int gotVolInfo = NO;

#ifndef HSP_VRT_USE_DISKPATH
	  /* define HSP_VRT_USE_DISKPATH if you want to bypass this virStorageVolGetInfo
	   *  approach and just use virDomainGetBlockInfo instead.
	   */
	  virStorageVolPtr volPtr = virStorageVolLookupByPath(sp->virConn, volPath);
	  if(volPtr == NULL) {
	    myLog(LOG_ERR, "virStorageLookupByPath(%s) failed", volPath);
	  }
	  else {
	    virStorageVolInfo volInfo;
	    if(virStorageVolGetInfo(volPtr, &volInfo) != 0) {
	      myLog(LOG_ERR, "virStorageVolGetInfo(%s) failed", volPath);
	    }
	    else {
	      gotVolInfo = YES;
	      dskElem.counterBlock.host_vrt_dsk.capacity += volInfo.capacity;
	      dskElem.counterBlock.host_vrt_dsk.allocation += volInfo.allocation;
	      dskElem.counterBlock.host_vrt_dsk.available += (volInfo.capacity - volInfo.allocation);
	    }
	  }
#endif

#if (LIBVIR_VERSION_NUMBER >= 8001)
	  if(gotVolInfo == NO) {
	    /* try appealing directly to the disk path instead */
	    /* this call was only added in April 2010 (version 0.8.1).
	     * See http://markmail.org/message/mjafgt47f5e5zzfc
	     */
	    virDomainBlockInfo blkInfo;
	    if(virDomainGetBlockInfo(domainPtr, volPath, &blkInfo, 0) == -1) {
	      myLog(LOG_ERR, "virDomainGetBlockInfo(%s) failed", dskPath);
	    }
	    else {
	      dskElem.counterBlock.host_vrt_dsk.capacity += blkInfo.capacity;
	      dskElem.counterBlock.host_vrt_dsk.allocation += blkInfo.allocation;
	      dskElem.counterBlock.host_vrt_dsk.available += (blkInfo.capacity - blkInfo.allocation);
	      // don't need blkInfo.physical
	    }
	  }
#endif
	  /* we get reads, writes and errors from a different call */
	  virDomainBlockStatsStruct blkStats;
	  if(virDomainBlockStats(domainPtr, dskPath, &blkStats, sizeof(blkStats)) != -1) {
	    if(blkStats.rd_req != -1) dskElem.counterBlock.host_vrt_dsk.rd_req += blkStats.rd_req;
	    if(blkStats.rd_bytes != -1) dskElem.counterBlock.host_vrt_dsk.rd_bytes += blkStats.rd_bytes;
	    if(blkStats.wr_req != -1) dskElem.counterBlock.host_vrt_dsk.wr_req += blkStats.wr_req;
	    if(blkStats.wr_bytes != -1) dskElem.counterBlock.host_vrt_dsk.wr_bytes += blkStats.wr_bytes;
	    if(blkStats.errs != -1) dskElem.counterBlock.host_vrt_dsk.errs += blkStats.errs;
	  }
	}
	SFLADD_ELEMENT(cs, &dskElem);
      
	// include my slice of the adaptor list
	SFLCounters_sample_element adaptorsElem = { 0 };
	adaptorsElem.tag = SFLCOUNTERS_ADAPTORS;
	adaptorsElem.counterBlock.adaptors = state->interfaces;
	SFLADD_ELEMENT(cs, &adaptorsElem);
      
	SEMLOCK_DO(sp->sync_receiver) {
	  sfl_poller_writeCountersSample(poller, cs);
	}
      
	virDomainFree(domainPtr);
      }
    }
  }

  static void agentCB_getCounters_VRT_request(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    HSP *sp = (HSP *)poller->magic;
    UTArrayAdd(sp->pollActions, poller);
    UTArrayAdd(sp->pollActions, agentCB_getCounters_VRT);
  }

  /*_________________---------------------------__________________
    _________________    domain_xml_node        __________________
    -----------------___________________________------------------
  */


  static int domain_xml_path_equal(xmlNode *node, char *nodeName, ...) {
    if(node == NULL
       || node->name == NULL
       || node->type != XML_ELEMENT_NODE
       || !my_strequal(nodeName, (char *)node->name)) {
      return NO;
    }
    int match = YES;
    va_list names;
    va_start(names, nodeName);
    xmlNode *parentNode = node->parent;
    char *parentName;
    while((parentName = va_arg(names, char *)) != NULL) {
      if(parentNode == NULL
	 || parentNode->name == NULL
	 || !my_strequal(parentName, (char *)parentNode->name)) {
	match = NO;
	break;
      }
      parentNode = parentNode->parent;
    }
    va_end(names);
    return match;
  }

  static char *get_xml_attr(xmlNode *node, char *attrName) {
    for(xmlAttr *attr = node->properties; attr; attr = attr->next) {
      if(attr->name) {
	if(debug) myLog(LOG_INFO, "attribute %s", attr->name);
	if(attr->children && !strcmp((char *)attr->name, attrName)) {
	  return (char *)attr->children->content;
	}
      }
    }
    return NULL;
  }
    
  static void domain_xml_interface(xmlNode *node, char **ifname, char **ifmac) {
    for(xmlNode *n = node; n; n = n->next) {
      if(domain_xml_path_equal(n, "target", "interface", "devices", NULL)) {
	char *dev = get_xml_attr(n, "dev");
	if(dev) {
	  if(debug) myLog(LOG_INFO, "interface.dev=%s", dev);
	  if(ifname) *ifname = dev;
	}
      }
      else if(domain_xml_path_equal(n, "mac", "interface", "devices", NULL)) {
	char *addr = get_xml_attr(n, "address");
	if(debug) myLog(LOG_INFO, "interface.mac=%s", addr);
	if(ifmac) *ifmac = addr;
      }
    }
    if(node->children) domain_xml_interface(node->children, ifname, ifmac);
  }
    
  static void domain_xml_disk(xmlNode *node, char **disk_path, char **disk_dev) {
    for(xmlNode *n = node; n; n = n->next) {
      if(domain_xml_path_equal(n, "source", "disk", "devices", NULL)) {
	char *path = get_xml_attr(n, "file");
	if(path) {
	  if(debug) myLog(LOG_INFO, "disk.file=%s", path);
	  if(disk_path) *disk_path = path;
	}
      }
      else if(domain_xml_path_equal(n, "target", "disk", "devices", NULL)) {
	char *dev = get_xml_attr(n, "dev");
	if(debug) myLog(LOG_INFO, "disk.dev=%s", dev);
	if(disk_dev) *disk_dev = dev;
      }
      else if(domain_xml_path_equal(n, "readonly", "disk", "devices", NULL)) {
	if(debug) myLog(LOG_INFO, "ignoring readonly device");
	*disk_path = NULL;
	*disk_dev = NULL;
	return;
      }
    }
    if(node->children) domain_xml_disk(node->children, disk_path, disk_dev);
  }
  
  static void domain_xml_node(HSP *sp, xmlNode *node, HSPVMState *state) {
    for(xmlNode *n = node; n; n = n->next) {
      if(domain_xml_path_equal(n, "interface", "devices", "domain", NULL)) {
	char *ifname=NULL,*ifmac=NULL;
	domain_xml_interface(n, &ifname, &ifmac);
	if(ifname && ifmac) {
	  SFLMacAddress mac;
	  memset(&mac, 0, sizeof(mac));
	  if(hexToBinary((u_char *)ifmac, mac.mac, 6) == 6) {
	    SFLAdaptor *ad = adaptorByMac(sp, &mac);
	    if(ad == NULL) {
	      ad = nioAdaptorNew(ifname, mac.mac, 0);
	      UTHashAdd(sp->adaptorsByMac, ad, NO);
	    }
	    adaptorListAdd(state->interfaces, ad);
	    // mark it as a vm/container device
	    ADAPTOR_NIO(ad)->vm_or_container = YES;
	    // clear the mark so we don't free it
	    ad->marked = NO;
	  }
	}
      }
      else if(domain_xml_path_equal(n, "disk", "devices", "domain", NULL)) {
	// need both a path and a dev before we will accept it
	char *disk_path=NULL,*disk_dev=NULL;
	domain_xml_disk(n, &disk_path, &disk_dev);
	if(disk_path && disk_dev) {
	  strArrayAdd(state->volumes, (char *)disk_path);
	  strArrayAdd(state->disks, (char *)disk_dev);
	}
      }
      else if(n->children) domain_xml_node(sp, n->children, state);
    }
  }


  /*_________________---------------------------__________________
    _________________    configVMs              __________________
    -----------------___________________________------------------
  */

  void configVMs_VRT(HSP *sp) {
    if(sp->virConn == NULL) {
      // no libvirt connection
      return;
    }
    int num_domains = virConnectNumOfDomains(sp->virConn);
    if(num_domains == -1) {
      myLog(LOG_ERR, "virConnectNumOfDomains() returned -1");
      return;
    }
    int *domainIds = (int *)my_calloc(num_domains * sizeof(int));
    if(virConnectListDomains(sp->virConn, domainIds, num_domains) != num_domains) {
      my_free(domainIds);
      return;
    }
    for(int i = 0; i < num_domains; i++) {
      int domId = domainIds[i];
      virDomainPtr domainPtr = virDomainLookupByID(sp->virConn, domId);
      if(domainPtr) {
	char uuid[16];
	virDomainGetUUID(domainPtr, (u_char *)uuid);
	HSPVMState *state = getVM(sp, uuid, VMTYPE_VRT, agentCB_getCounters_VRT_request);
	state->marked = NO;
	state->created = NO;
	// remember the domId, which might have changed (if vm rebooted)
	state->domId = domId;
	// reset the information that we are about to refresh
	adaptorListMarkAll(state->interfaces);
	strArrayReset(state->volumes);
	strArrayReset(state->disks);
	// get the XML descr - this seems more portable than some of
	// the newer libvert API calls,  such as those to list interfaces
	char *xmlstr = virDomainGetXMLDesc(domainPtr, 0 /*VIR_DOMAIN_XML_SECURE not allowed for read-only */);
	if(xmlstr == NULL) {
	  myLog(LOG_ERR, "virDomainGetXMLDesc(domain=%u, 0) failed", domId);
	}
	else {
	  // parse the XML to get the list of interfaces and storage nodes
	  xmlDoc *doc = xmlParseMemory(xmlstr, strlen(xmlstr));
	  if(doc) {
	    xmlNode *rootNode = xmlDocGetRootElement(doc);
	    domain_xml_node(sp, rootNode, state);
	    xmlFreeDoc(doc);
	  }
	  free(xmlstr); // allocated by virDomainGetXMLDesc()
	}
	xmlCleanupParser();
	virDomainFree(domainPtr);
	// fully delete and free the marked adaptors - some may return if
	// they are still present in the global-namespace list,  but
	// we have to do this here in case one of these was discovered
	// and allocated just for this VM.
	deleteMarkedAdaptors_adaptorList(sp, state->interfaces);
	adaptorListFreeMarked(state->interfaces);
      }
    }
    // remember the number of domains we found
    sp->num_domains = num_domains;
    my_free(domainIds);
  }

#endif /* HSP_VRT */
#if defined(__cplusplus)
} /* extern "C" */
#endif

