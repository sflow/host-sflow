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
  sp->adaptorList = (SFLAdaptorList *)malloc(sizeof(SFLAdaptorList));
  sp->adaptorList->capacity = 4; // will grow if necessary
  sp->adaptorList->adaptors = (SFLAdaptor **)malloc(sp->adaptorList->capacity * sizeof(SFLAdaptor *));
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

	  // Get the flags for this interface
	  if(ioctl(fd,SIOCGIFFLAGS, &ifr) != 0) perror("Get SIOCGIFFLAGS failed\n");
	  else {
	    int up = (ifr.ifr_flags & IFF_UP) ? YES : NO;
	    int loopback = (ifr.ifr_flags & IFF_LOOPBACK) ? YES : NO;
	    //int hasBroadcast = (ifr.ifr_flags & IFF_BROADCAST);
	    //int pointToPoint = (ifr.ifr_flags & IFF_POINTOPOINT);
	    if(up && !loopback) {
	      
	       // Get the MAC Address for this interface
	       if(ioctl(fd,SIOCGIFHWADDR, &ifr) != 0) perror("Get SIOCGIFHWADDR failed");
	      else {
		// for now just assume that each interface has only one MAC.  It's not clear how we can
		// learn multiple MACs this way anyhow.  It seems like there is just one per ifr record.
		// create a new "adaptor" entry
		SFLAdaptor *adaptor = (SFLAdaptor *)calloc(1, sizeof(SFLAdaptor) + (1 * sizeof(SFLMacAddress)));
		memcpy(adaptor->macs[0].mac, &ifr.ifr_hwaddr.sa_data, 6);
		adaptor->num_macs = 1;
		adaptor->deviceName = strdup(devName);

		// Try and get the ifIndex for this interface
		if(ioctl(fd,SIOCGIFINDEX, &ifr) != 0) {
		  perror("Get SIOCGIFINDEX failed");
		}
		else {
		  adaptor->ifIndex = ifr.ifr_ifindex;
		}
	       
		// Get the IP address for this interface
		if(ioctl(fd,SIOCGIFADDR, &ifr) != 0) perror("Get SIOCGIFADDR failed");
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
		  sp->adaptorList->adaptors = (SFLAdaptor **)realloc(sp->adaptorList->adaptors,
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

  return sp->adaptorList->num_adaptors;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif
