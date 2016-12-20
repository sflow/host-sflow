/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>


  /*________________---------------------------__________________
    ________________  setAddressPriorities     __________________
    ----------------___________________________------------------
    Ideally we would do this as we go along,  but since the vlan
    info is spliced in separately we have to wait for that and
    then set the priorities for the whole list.
  */
  void setAddressPriorities(HSP *sp)
  {
    myDebug(1, "setAddressPriorities");
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByName, adaptor) {
      HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
      adaptorNIO->ipPriority = agentAddressPriority(sp,
						    &adaptorNIO->ipAddr,
						    adaptorNIO->vlan,
						    adaptorNIO->loopback);
    }
  }

/*________________---------------------------__________________
  ________________      HSPDevTypeName       __________________
  ----------------___________________________------------------
*/

  const char *devTypeName(EnumHSPDevType devType) {
    switch(devType) {
    case HSPDEV_OTHER: return "OTHER";
    case HSPDEV_PHYSICAL: return "PHYSICAL";
    case HSPDEV_VETH: return "VETH";
    case HSPDEV_VIF: return "VIF";
    case HSPDEV_OVS: return "OVS";
    case HSPDEV_BRIDGE: return "BRIDGE";
    default: break;
    }
    return "<out of range>";
  }

  /*________________---------------------------__________________
    ________________      readInterfaces       __________________
    ----------------___________________________------------------
  */

  int readInterfaces(HSP *sp, bool full_discovery,  uint32_t *p_added, uint32_t *p_removed, uint32_t *p_cameup, uint32_t *p_wentdown, uint32_t *p_changed)
  {
    uint32_t ad_added=0, ad_removed=0, ad_cameup=0, ad_wentdown=0, ad_changed=0;

    UTHash *newLocalIP = UTHASH_NEW(SFLAddress, address.ip_v4, UTHASH_DFLT);
    UTHash *newLocalIP6 = UTHASH_NEW(SFLAddress, address.ip_v6, UTHASH_DFLT);

    { SFLAdaptor *ad;  UTHASH_WALK(sp->adaptorsByName, ad) ad->marked = YES; }

    // Walk the interfaces and collect the non-loopback interfaces so that we
    // have a list of MAC addresses for each interface (usually only 1).

    struct ifaddrs *ifap;
    getifaddrs(&ifap);
    uint32_t ifIndex=0;
    for(struct ifaddrs *ifp = ifap; ifp; ifp = ifp->ifa_next) {
      char *devName = ifp->ifa_name;

      if(devName == NULL) continue;
      devName = trimWhitespace(devName);
      int devNameLen = my_strlen(devName);
      if(devNameLen == 0 || devNameLen >= IFNAMSIZ) continue;

      // Get the flags for this interface
      int up = (ifp->ifa_flags & IFF_UP) ? YES : NO;
      int loopback = (ifp->ifa_flags & IFF_LOOPBACK) ? YES : NO;
      int address_family = ifp->ifa_addr->sa_family;
      int promisc = (ifp->ifa_flags & IFF_PROMISC) ? YES : NO;
      //int bond_master = (ifp->ifa_flags & IFF_MASTER) ? YES : NO;
      //int bond_slave = (ifp->ifa_flags & IFF_SLAVE) ? YES : NO;

      // read MAC
      u_char macBytes[6];
      memcpy(macBytes, &ifp->ifa_addr->sa_data, 6);
      if(macBytes[0] == 0
	 && macBytes[1] == 0
	 && macBytes[2] == 0
	 && macBytes[3] == 0
	 && macBytes[4] == 0
	 && macBytes[5] == 0)
	continue;
      int gotMac = YES;

      // Try and get the ifIndex for this interface
      // TODO: could take a digest of the MAC if we want it to be more predictable?
      ++ifIndex;

      // for now just assume that each interface has only one MAC.  It's not clear how we can
      // learn multiple MACs this way anyhow.  It seems like there is just one per ifr record.
      // find or create a new "adaptor" entry
      SFLAdaptor *adaptor = nioAdaptorNew(devName, (gotMac ? macBytes : NULL), ifIndex);
    
      bool addAdaptorToHT = YES;
      SFLAdaptor *existing = adaptorByName(sp, devName);
      if(existing
	 && adaptorEqual(adaptor, existing)) {
	// no change - use existing object
	adaptorFree(adaptor);
	adaptor = existing;
	addAdaptorToHT = NO;
      }
    
      // clear the mark so we don't free it below
      adaptor->marked = NO;

      // this flag might belong in the adaptorNIO struct
      adaptor->promiscuous = promisc;

      // remember some useful flags in the userData structure
      HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
      if(adaptorNIO->up != up) {
	if(up) {
	  ad_cameup++;
	}
	else ad_wentdown++;
	myDebug(1, "adaptor %s %s",
		adaptor->deviceName,
		up ? "came up" : "went down");
      }
      adaptorNIO->up = up;
      adaptorNIO->loopback = loopback;
      //adaptorNIO->bond_master = bond_master;
      //adaptorNIO->bond_slave = bond_slave;

      // Try to get the IP address for this interface
      if(address_family == AF_INET) {
	struct sockaddr_in *s = (struct sockaddr_in *)ifp->ifa_addr;
	// IP addr is now s->sin_addr
	adaptorNIO->ipAddr.type = SFLADDRESSTYPE_IP_V4;
	adaptorNIO->ipAddr.address.ip_v4.addr = s->sin_addr.s_addr;
	// add to localIP hash too
	if(UTHashGet(newLocalIP, &adaptorNIO->ipAddr) == NULL) {
	  SFLAddress *addrCopy = my_calloc(sizeof(SFLAddress));
	  *addrCopy = adaptorNIO->ipAddr;
	  UTHashAdd(newLocalIP, addrCopy);
	}
      }
      //else if (address_family == AF_INET6) {
      //struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ifp->ifa_addr;
      // IP6 addr is now s->sin6_addr;
      //myDebug(1, "got IPv6 address");
      // TODO: read it in
      //      }

      char buf[51];
      myDebug(1, "interface %s IP address: %s", devName, SFLAddress_print(&adaptorNIO->ipAddr, buf, 50));

      if(full_discovery) {
	// allow modules to supply additional info on this adaptor
	// (and influence ethtool data-gathering).  We broadcast this
	// but it only really makes sense to receive it on the POLL_BUS
	EVEventTxAll(sp->rootModule, HSPEVENT_INTF_READ, &adaptor, sizeof(adaptor));
	// use ethtool to get info about direction/speed and more
	// if(read_ethtool_info(sp, &ifr, fd, adaptor) == YES) ad_changed++;
      }

      if(addAdaptorToHT) {
	ad_added++;
	adaptorAddOrReplace(sp->adaptorsByName, adaptor);
	// add to "all namespaces" collections too
	if(gotMac) adaptorAddOrReplace(sp->adaptorsByMac, adaptor);
	if(ifIndex) adaptorAddOrReplace(sp->adaptorsByIndex, adaptor);
      }

    }
    freeifaddrs(ifap);
  
    // now remove and free any that are still marked
    ad_removed = deleteMarkedAdaptors(sp, sp->adaptorsByName, YES);

    // check in case any of the survivors are specific
    // to a particular VLAN
    // TODO: readVLANs(sp);

    // now that we have the evidence gathered together, we can
    // set the L3 address priorities (used for auto-selecting
    // the sFlow-agent-address if requrired to by the config.
    setAddressPriorities(sp);

    if(p_added) *p_added = ad_added;
    if(p_removed) *p_removed = ad_removed;
    if(p_cameup) *p_cameup = ad_cameup;
    if(p_wentdown) *p_wentdown = ad_wentdown;
    if(p_changed) *p_changed = ad_changed;

    // swap in new localIP lookup tables
    UTHash *oldLocalIP = sp->localIP;
    UTHash *oldLocalIP6 = sp->localIP6;
    sp->localIP = newLocalIP;
    sp->localIP6 = newLocalIP6;
    if(oldLocalIP) {
      SFLAddress *ad;
      UTHASH_WALK(oldLocalIP, ad)
	my_free(ad);
      UTHashFree(oldLocalIP);
    }
    if(oldLocalIP6) {
      SFLAddress *ad;
      UTHASH_WALK(oldLocalIP6, ad)
	my_free(ad);
      UTHashFree(oldLocalIP6);
    }
  
    return sp->adaptorsByName->entries;
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
