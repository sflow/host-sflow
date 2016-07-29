/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <kstat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/sockio.h>
#include <libdlpi.h>
#if (HSP_SOLARIS >= 5011)
#include "ifaddrs.h"
#endif

  extern int debug;

  /*________________---------------------------__________________
    ________________        readVLANs          __________________
    ----------------___________________________------------------
  */
  void readVLANs(HSP *sp)
  {
    // dladm show-link?
    ; // noop for now
  }

  /*________________---------------------------__________________
    ________________  setAddressPriorities     __________________
    ----------------___________________________------------------
    Ideally we would do this as we go along,  but since the vlan
    info is spliced in separately we have to wait for that and
    then set the priorities for the whole list.
  */
  void setAddressPriorities(HSP *sp)
  {
    for(uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
      SFLAdaptor *adaptor = sp->adaptorList->adaptors[i];
      if(adaptor && adaptor->userData) {
	HSPAdaptorNIO *adaptorNIO = (HSPAdaptorNIO *)adaptor->userData;
	adaptorNIO->ipPriority = agentAddressPriority(sp,
						      &adaptorNIO->ipAddr,
						      adaptorNIO->vlan,
						      adaptorNIO->loopback);
      }
    }
  }
  
  /*________________---------------------------__________________
    ________________     readMacAddress        __________________
    ----------------___________________________------------------
  */

  int readMacAddress(char *devName, u_char *buf, int bufLen) {
    // we can only call dlpi_open() with root privileges.  So only try to get
    // the MAC address if we are still root.  We could cache the dlpi handle
    // for each interface as another field in the adaptorNIO structure, but in
    // practice it seems unlikely that the MAC address will change without
    // a reboot of the host,  so it's OK to only read it at the start.  If a
    // new interface somehow appears then it will just be instantiated without
    // a MAC.
    if(getuid() != 0) {
      return NO;
    }
    
    size_t macaddrlen = DLPI_PHYSADDR_MAX;
    int copied = 0;
    char macaddr[DLPI_PHYSADDR_MAX];
    dlpi_handle_t dh;
    if (DLPI_SUCCESS != dlpi_open(devName, &dh, 0)) {
      myLog(LOG_ERR, "device %s dlpi_open failed : %s", devName, strerror(errno));
      return 0;
    }
    // opened OK
    if (DLPI_SUCCESS != dlpi_get_physaddr(dh, DL_CURR_PHYS_ADDR, macaddr, &macaddrlen)) {
      myLog(LOG_ERR, "device %s dlpi_get_physaddr failed :%s", devName, strerror(errno));
    }
    if(macaddrlen <= bufLen) {
      memcpy(buf, macaddr, macaddrlen);
      copied = macaddrlen;
    }
    dlpi_close(dh);
    return copied;
  }
  

  /*________________---------------------------__________________
    ________________     readInterfaces        __________________
    ----------------___________________________------------------
  */
#if (HSP_SOLARIS >= 5011)
  int readInterfaces_getifaddrs(HSP *sp)
  {
    struct ifaddrs *ifap = NULL;
    int interfaces_found = 0;
    
    if(getifaddrs(&ifap) != 0) {
      myLog(LOG_ERR, "getifaddrs() failed : %s", strerror(errno));
      return 0;
    }
    for(struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {
      int up = (ifa->ifa_flags & IFF_UP) ? 1 : 0;
      int loopback = (ifa->ifa_flags & IFF_LOOPBACK) ? 1: 0;
      int promisc = (ifa->ifa_flags & IFF_PROMISC) ? 1 : 0;
      int bond_master = 0; // (ifa->ifa_flags & IFF_MASTER) ? 1 : 0;
	
      if(debug) myLog(LOG_INFO, "ifa_name=%s up=%d loopback=%d", ifa->ifa_name, up, loopback);
	
      if(up == 0) continue;
      interfaces_found++;

      // try to get the MAC
      u_char *macptr = NULL;
      u_char macAddr[6];
      if(readMacAddress(ifa->ifa_name, macAddr, 6)) {
	macptr = macAddr;
      }

      // find or create the "adaptor" entry for this dev
      SFLAdaptor *adaptor = adaptorListAdd(sp->adaptorList, ifa->ifa_name, macptr, sizeof(HSPAdaptorNIO));
			
      // this flag might belong in the adaptorNIO struct
      adaptor->promiscuous = promisc;
			
      // remember some useful flags in the userData structure
      HSPAdaptorNIO *adaptorNIO = (HSPAdaptorNIO *)adaptor->userData;
      adaptorNIO->loopback = loopback;
      adaptorNIO->bond_master = bond_master;
      adaptorNIO->vlan = HSP_VLAN_ALL; // may be modified below

      // we don't expect to read counters from this device - it's
      // really just there to learn the IP address/MAC addresses
      adaptorNIO->forCounters = NO;

      SFLAddress addr = { 0 };

      if (AF_INET == ifa->ifa_addr->sa_family) {
	struct sockaddr_in *s = (struct sockaddr_in *)ifa->ifa_addr;
	addr.type = SFLADDRESSTYPE_IP_V4;
	addr.address.ip_v4.addr = s->sin_addr.s_addr;
      }
      else if(AF_INET6 == ifa->ifa_addr->sa_family) {
	struct sockaddr_in6 *s = (struct sockaddr_in6 *)ifa->ifa_addr;
	addr.type = SFLADDRESSTYPE_IP_V6;
	memcpy(&addr.address.ip_v6.addr, &s->sin6_addr, 16);
      }
      EnumIPSelectionPriority ipPriority = agentAddressPriority(sp,
								&addr,
								adaptorNIO->vlan,
								adaptorNIO->loopback);
      if(adaptor->marked ||
	 ipPriority > adaptorNIO->ipPriority) {
	adaptorNIO->ipAddr = addr;
	adaptorNIO->ipPriority = ipPriority;

	if(debug) {
	  char buf[51];
	  myLog(LOG_INFO, "interface: %s family: %d IP: %s priority: %d",
		ifa->ifa_name,
		ifa->ifa_addr->sa_family,
		inet_ntop(ifa->ifa_addr->sa_family, &adaptorNIO->ipAddr.address, buf, 50),
		ipPriority);
	}
      }
	
      // clear the mark so we don't free it below
      adaptor->marked = NO; 
    }

    // clean up
    freeifaddrs(ifap);

    if(debug) myLog(LOG_INFO, "found (and unmarked) %d interfaces via getifaddrs", interfaces_found);

    return interfaces_found;
  }
#endif


  int readInterfaces_lifreq(HSP *sp)
  {
    int interfaces_found = 0;
    struct lifnum ln;
    struct lifconf lc;
    struct lifreq rq;
    int i, nFd;
    int up, loopback, promisc, bond_master;
    nFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (nFd >= 0)
      {
        ln.lifn_family = AF_INET;
        ln.lifn_flags = 0;
        if (ioctl(nFd, SIOCGLIFNUM, &ln) == 0) {
	  lc.lifc_family = AF_INET;
	  lc.lifc_flags = 0;
	  lc.lifc_len = sizeof(struct lifreq) * ln.lifn_count;
	  lc.lifc_buf = (caddr_t)my_calloc(lc.lifc_len);
	  if (ioctl(nFd, SIOCGLIFCONF, &lc) == 0) {
	    if(debug > 2) myLog(LOG_INFO, "ln.lifn_count = %u", ln.lifn_count);
	    for (i = 0; i < ln.lifn_count; i++) {
	      strcpy(rq.lifr_name, lc.lifc_req[i].lifr_name);
	      myLog(LOG_INFO, "interface: %s", rq.lifr_name);
	      if (ioctl(nFd, SIOCGLIFFLAGS, &rq) == 0) {
		if(debug) myLog(LOG_INFO, "interface:%s flags=%x",
				rq.lifr_name,
				rq.lifr_index);
		up = (rq.lifr_flags & IFF_UP) ? 1 : 0;
		loopback = (rq.lifr_flags & IFF_LOOPBACK) ? 1: 0;
		promisc = (rq.lifr_flags & IFF_PROMISC) ? 1 : 0;
		// TODO: No IFF_MASTER so set to 0
		bond_master = 0;
		if(up == 0) continue;
		interfaces_found++;
	      
		// get MAC if we can
		u_char *macptr = NULL;
		u_char macAddr[6];
		if(readMacAddress(rq.lifr_name, macAddr, 6)) {
		  macptr = macAddr;
		}

		// find or create the "adaptor" entry for this dev
		SFLAdaptor *adaptor = adaptorListAdd(sp->adaptorList, rq.lifr_name, macptr, sizeof(HSPAdaptorNIO));
			
		// clear the mark so we don't free it below
		adaptor->marked = NO; 
			
		// this flag might belong in the adaptorNIO struct
		adaptor->promiscuous = promisc;
			
		// remember some useful flags in the userData structure
		HSPAdaptorNIO *adaptorNIO = (HSPAdaptorNIO *)adaptor->userData;
		adaptorNIO->loopback = loopback;
		adaptorNIO->bond_master = bond_master;
		adaptorNIO->vlan = HSP_VLAN_ALL; // may be modified below
		adaptorNIO->forCounters = NO;

		if (ioctl(nFd, SIOCGLIFINDEX, &rq) == 0) {
		  if(debug) myLog(LOG_INFO, "interface: %s ifIndex=%d",
				  rq.lifr_name,
				  rq.lifr_index);
		  adaptor->ifIndex = rq.lifr_index;
		}

		if (ioctl(nFd, SIOCGLIFADDR, &rq) == 0) {
		  char buf[51];
			  
		  if (AF_INET == rq.lifr_addr.ss_family) {
		    struct sockaddr_in *s = (struct sockaddr_in *)&rq.lifr_addr;
		    adaptorNIO->ipAddr.type = SFLADDRESSTYPE_IP_V4;
		    adaptorNIO->ipAddr.address.ip_v4.addr = s->sin_addr.s_addr;
		  }
		  else if(AF_INET6 == rq.lifr_addr.ss_family) {
		    /* I think we have to do the whole thing with an IPv6 raw socket
		       before we can get an IPv6 address this way,  so this will
		       probably not work.  Better to use getifaddrs() if we can. */
		    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&rq.lifr_addr;
		    adaptorNIO->ipAddr.type = SFLADDRESSTYPE_IP_V6;
		    memcpy(&adaptorNIO->ipAddr.address.ip_v6.addr, &s->sin6_addr, 16);
		  }
		  if(debug) {
		    myLog(LOG_INFO, "lifreq interface: %s family: %d IP: %s",
			  rq.lifr_name,
			  rq.lifr_addr.ss_family,
			  inet_ntop(rq.lifr_addr.ss_family, &adaptorNIO->ipAddr.address, buf, 51));
		  }
		}
	      }
	    }
	  }
	  
	  my_free(lc.lifc_buf);
	}
        close(nFd);
      }
    
    if(debug) myLog(LOG_INFO, "found (and unmarked) %d interfaces via lifrec", interfaces_found);
    return interfaces_found;
  }


  int readInterfaces_kstat(HSP *sp)
  {
    int noErr = 1;
    kstat_ctl_t *kc = NULL;
    kstat_t *ksp;
#ifndef KSNAME_BUFFER_SIZE
#define KSNAME_BUFFER_SIZE 32
#endif
    char devName[KSNAME_BUFFER_SIZE];
    int interfaces_found = 0;

    int fd = socket (PF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
      myLog(LOG_ERR, "error opening socket: %d (%s)\n", errno, strerror(errno));
      noErr = 0;
    }
    struct lifreq lifr;
    memset(&lifr, 0, sizeof(lifr));
	
    if (noErr) {
      kc = kstat_open();
      if (NULL == kc) {
	noErr = 0;
	myLog(LOG_ERR, "readInterfaces kstat_open failed");
      }
    }

    if (noErr) {
      for (ksp = kc->kc_chain; NULL != ksp; ksp = ksp->ks_next) {
	// Look for kstats of class "net"
	if (ksp->ks_class
	    && ksp->ks_module
	    && ksp->ks_name
	    && !strncmp(ksp->ks_class, "net", 3)) {

	  if(debug > 2) {
	    myLog(LOG_INFO, "ksp class=%s, module=%s name=%s",
		  ksp->ks_class ?: "NULL",
		  ksp->ks_module ?: "NULL",
		  ksp->ks_name ?: "NULL");
	  }

#ifndef KSNAME_BUFFER_SIZE
#define KSNAME_BUFFER_SIZE 32
#endif
	  int includeDev = NO;

          // Concatenate the module name and instance number to create device name
	  snprintf(devName, KSNAME_BUFFER_SIZE, "%s%d", ksp->ks_module, ksp->ks_instance);


#if (HSP_SOLARIS >= 5011)
          // on solaris 11 we collect name=phys, module!=aggr,vnic for counter purposes.
          // and don't use any of the others for counters.
          if(my_strequal(ksp->ks_name, "phys")
             && !my_strequal(ksp->ks_module, "aggr") 
             && !my_strequal(ksp->ks_module, "vnic")) {
	    includeDev = YES;
          }
#else
	  // If device name equals the kstat's name, then we have a kstat the describes the device. 
	  if (!strncmp(ksp->ks_name, devName, KSNAME_BUFFER_SIZE)) {
            includeDev = YES;
          }
#endif
          if(includeDev == NO) continue;

	  // since we now rely on getifaddrs or lifrec to learn about IP/MAC details,
	  // we are only interested in collecting interfaces to get counters-from here.

	  // find or create the "adaptor" entry for this dev
	  SFLAdaptor *adaptor = adaptorListAdd(sp->adaptorList, devName, NULL, sizeof(HSPAdaptorNIO));
		
	  // clear the mark so we don't free it below
	  adaptor->marked = NO; 
	  interfaces_found++;
			    
	  // remember some useful flags in the userData structure
	  HSPAdaptorNIO *adaptorNIO = (HSPAdaptorNIO *)adaptor->userData;
	  adaptorNIO->forCounters = YES;
	  adaptorNIO->vlan = HSP_VLAN_ALL; // may be modified below
		
#if 0
	  kstat_t *ksp_tmp;
	  kstat_named_t *knp;
	  ksp_tmp = kstat_lookup(kc, ksp->ks_module, ksp->ks_instance, "mac");
	  if (NULL == ksp_tmp) {
	    myLog(LOG_ERR, "kstat_lookup error (module: %s, inst: %d, name: mac): %s",
		  ksp->ks_module, ksp->ks_instance, strerror(errno));
	  }
	  else {
	    if (-1 == kstat_read(kc, ksp_tmp, NULL)) {
	      myLog(LOG_ERR, "kstat_read error (module: %s, name: %s, class: %s): %s",
		    ksp->ks_module, ksp->ks_name, ksp->ks_class, strerror(errno));
	    }
	    else {
	      knp = kstat_data_lookup(ksp_tmp, "ifspeed");
	      if(knp) {
		adaptor->ifSpeed = knp->value.ui64;
	      }
	      knp = kstat_data_lookup(ksp_tmp, "link_up");
	      if(knp) {
		myLog(LOG_INFO, "kstat link_up = %d", knp->value.ui32);
	      }
	      
	      uint32_t direction = 0;
	      knp = kstat_data_lookup(ksp_tmp, "link_duplex");
	      if(knp) {
		// The full-duplex and half-duplex values are reversed between the
		// comment in sflow.h and link_duplex man page.
		if (knp->value.ui32 == 1)
		  direction = 2;
		else if (knp->value.ui32 == 2)
		  direction = 1;
		adaptor->ifDirection = direction;
	      }
	    }
	  }
#endif
	}
      }
    }

    // clean up
    if(kc) kstat_close(kc);
    if(fd > 0) close(fd);
    return interfaces_found;
  }


  int readInterfaces(HSP *sp) {
    if(sp->adaptorList == NULL)
      sp->adaptorList = adaptorListNew();
    else
      adaptorListMarkAll(sp->adaptorList);

#if (HSP_SOLARIS >= 5011)
    readInterfaces_getifaddrs(sp);
#else
    readInterfaces_lifreq(sp);
#endif

    readInterfaces_kstat(sp);

    // now remove and free any that are still marked
    adaptorListFreeMarked(sp->adaptorList);

    // check in case any of the survivors are specific
    // to a particular VLAN
    readVLANs(sp);

    // now that we have the evidence gathered together, we can
    // set the L3 address priorities (used for auto-selecting
    // the sFlow-agent-address if requrired to by the config.
    setAddressPriorities(sp);
    if(debug) myLog(LOG_INFO, "found %d adaptors", sp->adaptorList->num_adaptors);

    return sp->adaptorList->num_adaptors;
  }


  
#if defined(__cplusplus)
} /* extern "C" */
#endif
