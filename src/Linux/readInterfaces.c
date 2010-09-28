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
  ________________    updateAdaptorNIO       __________________
  ----------------___________________________------------------
*/

static HSPAdaptorNIO *findOrCreateAdaptorNIO(HSPAdaptorNIOList *nioList, char *deviceName)
{
  HSPAdaptorNIO *adaptor = NULL;
  for(int i = 0; i < nioList->num_adaptors; i++) {
    adaptor = nioList->adaptors[i];
    if(adaptor && !strcmp(adaptor->deviceName, deviceName)) {
      nioList->adaptors[i] = NULL;
      return adaptor;
    }
  }
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
    new_list[i] = findOrCreateAdaptorNIO(&sp->adaptorNIOList, sp->adaptorList->adaptors[i]->deviceName);
  }
  // free old ones we don't need any more
  freeAdaptorNIOs(&sp->adaptorNIOList);
  // and move the new list into place
  sp->adaptorNIOList.adaptors = new_list;
  sp->adaptorNIOList.num_adaptors = N;
  sp->adaptorNIOList.last_update = 0;
  return;
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
  
  int fd = socket (PF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    fprintf (stderr, "error opening socket: %d (%s)\n", errno, strerror(errno));
    return 0;
  }

  FILE *procFile = fopen("/proc/net/dev", "r");
  if(procFile) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    // limit the number of chars we will read from each line
    // (there can be more than this - fgets will chop for us)
#define MAX_PROC_LINE_CHARS 80
    char line[MAX_PROC_LINE_CHARS];
    while(fgets(line, MAX_PROC_LINE_CHARS, procFile)) {
      // the device name is always the token before the ":"
      char *devName = strtok(line, ":");
      if(devName) {
	devName = trimWhitespace(devName);
	if(devName && strlen(devName) < IFNAMSIZ) {
	  // we set the ifr_name field to make our queries
	  strcpy(ifr.ifr_name, devName);

	  if(debug > 1) {
	    myLog(LOG_INFO, "reading interface %s", devName);
	  }

	  // Get the flags for this interface
	  if(ioctl(fd,SIOCGIFFLAGS, &ifr) != 0) {
	    myLog(LOG_ERR, "device %s Get SIOCGIFFLAGS failed : %s",
		  devName,
		  strerror(errno));
	  }
	  else {
	    int up = (ifr.ifr_flags & IFF_UP) ? YES : NO;
	    int loopback = (ifr.ifr_flags & IFF_LOOPBACK) ? YES : NO;
	    //int hasBroadcast = (ifr.ifr_flags & IFF_BROADCAST);
	    //int pointToPoint = (ifr.ifr_flags & IFF_POINTOPOINT);
	    if(up && !loopback) {
	      
	       // Get the MAC Address for this interface
	      if(ioctl(fd,SIOCGIFHWADDR, &ifr) != 0) {
		myLog(LOG_ERR, "device %s Get SIOCGIFHWADDR failed : %s",
		      devName,
		      strerror(errno));
	      }
	      else {
		// for now just assume that each interface has only one MAC.  It's not clear how we can
		// learn multiple MACs this way anyhow.  It seems like there is just one per ifr record.
		// create a new "adaptor" entry
		SFLAdaptor *adaptor = (SFLAdaptor *)my_calloc(sizeof(SFLAdaptor) + (1 * sizeof(SFLMacAddress)));
		memcpy(adaptor->macs[0].mac, &ifr.ifr_hwaddr.sa_data, 6);
		adaptor->num_macs = 1;
		adaptor->deviceName = strdup(devName);

		// Try and get the ifIndex for this interface
		if(ioctl(fd,SIOCGIFINDEX, &ifr) != 0) {
		  // only complain about this if we are debugging
		  if(debug) {
		    myLog(LOG_ERR, "device %s Get SIOCGIFINDEX failed : %s",
			  devName,
			  strerror(errno));
		  }
		}
		else {
		  adaptor->ifIndex = ifr.ifr_ifindex;
		}
	       
		// Try to get the IP address for this interface
		if(ioctl(fd,SIOCGIFADDR, &ifr) != 0) {
		  // only complain about this if we are debugging
		  if(debug) {
		    myLog(LOG_ERR, "device %s Get SIOCGIFADDR failed : %s",
			  devName,
			  strerror(errno));
		  }
		}
		else {
		  if (ifr.ifr_addr.sa_family == AF_INET) {
		    struct sockaddr_in *s = (struct sockaddr_in *)&ifr.ifr_addr;
		    // IP addr is now s->sin_addr
		    adaptor->ipAddr.addr = s->sin_addr.s_addr;
		  }
		  //else if (ifr.ifr_addr.sa_family == AF_INET6) {
		  // not sure this ever happens - on a linux system IPv6 addresses
		  // are picked up from /proc/net/if_inet6
		  // struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ifr.ifr_addr;
		  // IP6 addr is now s->sin6_addr;
		  //}
		}
		
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
	}
      }
    }
    fclose(procFile);
  }
  
  close (fd);

  updateAdaptorNIO(sp);
  
  return sp->adaptorList->num_adaptors;
}
  
#if defined(__cplusplus)
} /* extern "C" */
#endif
