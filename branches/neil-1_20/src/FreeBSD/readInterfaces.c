/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <ifaddrs.h>

  extern int debug;
    
  static void
  find_mac(char *name, u_char *dest)
  {
    size_t			len;
    char			*buf;
    unsigned char		*ptr;
    struct if_msghdr	*ifm;
    struct sockaddr_dl	*sdl;
    int mib[6] = { CTL_NET, AF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, 0 };

    if ((mib[5] = if_nametoindex(name)) == 0) {
      return;
    }
  
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
      return;
    }
  
    buf = my_calloc(len);
	
    if (sysctl(mib, 6, buf, &len, NULL, 0) >= 0) {
      ifm = (struct if_msghdr *)buf;
      sdl = (struct sockaddr_dl *)(ifm + 1);
      ptr = (unsigned char *)LLADDR(sdl);
      memcpy(dest, ptr, 6);
    }

    my_free(buf);
  }

#if 0
  /*________________---------------------------__________________
    ________________    updateAdaptorNIO       __________________
    ----------------___________________________------------------
  */

  static HSPAdaptorNIO *extractOrCreateAdaptorNIO(HSPAdaptorNIOList *nioList, char *deviceName)
  {
    HSPAdaptorNIO *adaptor = NULL;
    for(int i = 0; i < nioList->num_adaptors; i++) {
      adaptor = nioList->adaptors[i];
      if(adaptor && !strcmp(adaptor->deviceName, deviceName)) {
	// take it out of the array and return it
	nioList->adaptors[i] = NULL;
	return adaptor;
      }
    }
    // not found, create a new one
    adaptor = (HSPAdaptorNIO *)my_calloc(sizeof(HSPAdaptorNIO));
    adaptor->deviceName = strdup(deviceName);
    return adaptor;
  }

  void freeAdaptorNIOs(HSPAdaptorNIOList *nioList)
  {
    for(int i = 0; i < nioList->num_adaptors; i++) {
      HSPAdaptorNIO *adaptor = nioList->adaptors[i];
      if(adaptor) {
	free(adaptor->deviceName);
	free(adaptor);
      }
    }
    free(nioList->adaptors);
    nioList->adaptors = NULL;
    nioList->num_adaptors = 0;
  }

  static void updateAdaptorNIO(HSP *sp)
  {
    uint32_t N = sp->adaptorList->num_adaptors;
    // space for new list
    HSPAdaptorNIO **new_list = (HSPAdaptorNIO **)my_calloc(N * sizeof(HSPAdaptorNIO *));
    // move pre-existing ones across,  or create new ones if necessary
    for(int i = 0; i < N; i++) {
      new_list[i] = extractOrCreateAdaptorNIO(&sp->adaptorNIOList, sp->adaptorList->adaptors[i]->deviceName);
    }
    // free old ones we don't need any more
    freeAdaptorNIOs(&sp->adaptorNIOList);
    // and move the new list into place
    sp->adaptorNIOList.adaptors = new_list;
    sp->adaptorNIOList.num_adaptors = N;
    sp->adaptorNIOList.last_update = 0;
    return;
  }
#endif

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
	adaptorNIO->ipPriority = agentAddressPriority(&adaptorNIO->ipAddr,
						      adaptorNIO->vlan,
						      adaptorNIO->loopback);
      }
    }
  }

  /*________________---------------------------__________________
    ________________      readInterfaces       __________________
    ----------------___________________________------------------
  */

  int readInterfaces(HSP *sp)
  {
    
    char *a;
    u_char dest_mac[6];
    struct sockaddr_in *foo;
    if(sp->adaptorList == NULL) sp->adaptorList = adaptorListNew();
    else adaptorListMarkAll(sp->adaptorList);
    
    // Walk the interfaces and collect the non-loopback interfaces so that we
    // have a list of MAC addresses for each interface (usually only 1).
    //
    // May need to come back and run a variation of this where we supply
    // a domain and collect the virtual interfaces for that domain in a
    // similar way.  It looks like we do that by just parsing the numbers
    // out of the interface name.
    
    struct ifaddrs *ifap;
    
    getifaddrs(&ifap);
    for(struct ifaddrs *ifp = ifap; ifp; ifp = ifp->ifa_next) {
      char *devName = ifp->ifa_name;
      if(devName) {
	devName = trimWhitespace(devName);
	// Get the flags for this interface
	int up = (ifp->ifa_flags & IFF_UP) ? YES : NO;
	int loopback = (ifp->ifa_flags & IFF_LOOPBACK) ? YES : NO;
	int promisc =  (ifp->ifa_flags & IFF_PROMISC) ? YES : NO;
	int address_family = ifp->ifa_addr->sa_family;
	if(debug > 1) {
	  myLog(LOG_INFO, "reading interface %s (up=%d, loopback=%d, family=%d)",
		devName,
		up,
		loopback,
		address_family);
	}
	//int hasBroadcast = (ifp->ifa_flags & IFF_BROADCAST);
	//int pointToPoint = (ifp->ifa_flags & IFF_POINTOPOINT);
	
	if(up && !loopback && address_family == AF_INET) {
	  
	  /***** THE NEW WAY ******/
	  
	  find_mac(devName,&dest_mac[0]);
	  SFLAdaptor *adaptor = adaptorListAdd(sp->adaptorList, devName, 
					       (u_char *)&dest_mac,
					       sizeof(HSPAdaptorNIO)); 

	  // clear the mark so we don't free it below
	  adaptor->marked = NO;
	  
	  // this flag might belong in the adaptorNIO struct
	  adaptor->promiscuous = promisc;

	  // remember some useful flags in the userData structure
	  HSPAdaptorNIO *adaptorNIO = (HSPAdaptorNIO *)adaptor->userData;
	  adaptorNIO->loopback = loopback;
	  // adaptorNIO->bond_master = bond_master;
	  adaptorNIO->vlan = HSP_VLAN_ALL; // may be modified below
	  
	  address_family = ifp->ifa_addr->sa_family;
	  
	  if(debug > 1) {
	    myLog(LOG_INFO, "Device: %s",devName);
	    myLog(LOG_INFO, "Address family: %d",address_family);
	  }
	  
	  foo = (struct sockaddr_in *)&ifp->ifa_addr;
	  if (address_family == AF_INET) {
	    
	    a=(char *)&(ifp->ifa_addr->sa_data);
	    a++; a++; // Yep... it really is 2 bytes over 
	    // Only IPV4 below ....
	    adaptorNIO->ipAddr.type = SFLADDRESSTYPE_IP_V4;
	    memcpy(&adaptorNIO->ipAddr.address.ip_v4.addr, a, 4);
	    if(debug > 1) {
	      myLog(LOG_INFO, "My IP address = %d.%d.%d.%d", a[0], a[1], a[2], a[3]);
	    }
	  }
	}	  
      }
    }

    // now remove and free any that are still marked
    adaptorListFreeMarked(sp->adaptorList);

  // now that we have the evidence gathered together, we can
  // set the L3 address priorities (used for auto-selecting
  // the sFlow-agent-address if requrired to by the config.
  setAddressPriorities(sp);

    freeifaddrs(ifap);

    return sp->adaptorList->num_adaptors;
    
  }
  
#if defined(__cplusplus)
} /* extern "C" */
#endif
