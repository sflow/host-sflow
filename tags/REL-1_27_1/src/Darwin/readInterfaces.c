/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#include "hsflowd.h"

#include <ifaddrs.h>

extern int debug;
    
/*________________---------------------------__________________
  ________________    freeAdaptors           __________________
  ----------------___________________________------------------
*/

void freeAdaptors(HSP *sp)
{
  if(sp->adaptorList) {
    for(uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
      free(sp->adaptorList->adaptors[i]);
    }
    free(sp->adaptorList);
    sp->adaptorList = NULL;
  }
}

  
/*________________---------------------------__________________
  ________________    newAdaptorList         __________________
  ----------------___________________________------------------
*/

void newAdaptorList(HSP *sp)
{
  freeAdaptors(sp);
  sp->adaptorList = (SFLAdaptorList *)my_calloc(sizeof(SFLAdaptorList));
  sp->adaptorList->capacity = 4; // will grow if necessary
  sp->adaptorList->adaptors = (SFLAdaptor **)my_calloc(sp->adaptorList->capacity * sizeof(SFLAdaptor *));
  sp->adaptorList->num_adaptors = 0;
}

  
/*________________---------------------------__________________
  ________________    trimWhitespace         __________________
  ----------------___________________________------------------
*/

static char *trimWhitespace(char *str)
{
  char *end;
  
  // Trim leading space
  while(isspace(*str)) str++;
  
  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && isspace(*end)) end--;
  
  // Write new null terminator
  *(end+1) = 0;
  
  return str;
}

/*________________---------------------------__________________
  ________________      readInterfaces       __________________
  ----------------___________________________------------------
*/

int readInterfaces(HSP *sp)
{
  newAdaptorList(sp);

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
      if(up && !loopback && address_family == AF_LINK) {
	// for now just assume that each interface has only one MAC.  It's not clear how we can
	// learn multiple MACs this way anyhow.  It seems like there is just one per ifr record.
	// create a new "adaptor" entry
	SFLAdaptor *adaptor = (SFLAdaptor *)my_calloc(sizeof(SFLAdaptor) + (1 * sizeof(SFLMacAddress)));
	memcpy(adaptor->macs[0].mac, &ifp->ifa_addr->sa_data, 6);
	adaptor->num_macs = 1;
	adaptor->deviceName = strdup(devName);
	
	// Try and get the ifIndex for this interface
	// if(ioctl(fd,SIOCGIFINDEX, &ifr) != 0) {
	// only complain about this if we are debugging
	//if(debug) {
	//myLog(LOG_ERR, "device %s Get SIOCGIFINDEX failed : %s",
	//devName,
	//strerror(errno));
	//}
	//}
	//else {
	//adaptor->ifIndex = ifr.ifr_ifindex;
	//}
	       
	// Try to get the IP address for this interface
/* 	if(ioctl(fd,SIOCGIFADDR, &ifr) != 0) { */
/* 	  // only complain about this if we are debugging */
/* 	  if(debug) { */
/* 	    myLog(LOG_ERR, "device %s Get SIOCGIFADDR failed : %s", */
/* 		  devName, */
/* 		  strerror(errno)); */
/* 	  } */
/* 	} */
/* 	else { */
/* 	  if (ifr.ifr_addr.sa_family == AF_INET) { */
/* 	    struct sockaddr_in *s = (struct sockaddr_in *)&ifr.ifr_addr; */
/* 	    // IP addr is now s->sin_addr */
/* 	    adaptor->ipAddr.addr = s->sin_addr.s_addr; */
/* 	  } */
/* 	  //else if (ifr.ifr_addr.sa_family == AF_INET6) { */
/* 	  // not sure this ever happens - on a linux system IPv6 addresses */
/* 	  // are picked up from /proc/net/if_inet6 */
/* 	  // struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ifr.ifr_addr; */
/* 	  // IP6 addr is now s->sin6_addr; */
/* 	  //} */
/* 	} */
	
	// add it to the list
	sp->adaptorList->adaptors[sp->adaptorList->num_adaptors] = adaptor;
	if(++sp->adaptorList->num_adaptors == sp->adaptorList->capacity)  {
	  // grow
	  sp->adaptorList->capacity *= 2;
	  sp->adaptorList->adaptors = (SFLAdaptor **)my_realloc(sp->adaptorList->adaptors,
								sp->adaptorList->capacity * sizeof(SFLAdaptor *));
	}
      }
    }
  }
  freeifaddrs(ifap);
  return sp->adaptorList->num_adaptors;
}
  
#if defined(__cplusplus)
} /* extern "C" */
#endif
