/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>

extern int debug;
    
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

/*________________---------------------------__________________
  ________________      readInterfaces       __________________
  ----------------___________________________------------------
*/

int readInterfaces(HSP *sp)
{

	char *a;
	struct sockaddr_in *foo;
  if(sp->adaptorList == NULL) sp->adaptorList = adaptorListNew();
  else adaptorListReset(sp->adaptorList);

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

	SFLAdaptor *adaptor = adaptorListAdd(sp->adaptorList, devName, 
	  (u_char *)&(ifp->ifa_addr->sa_data)); 
	adaptor->promiscuous = promisc;

        address_family = ifp->ifa_addr->sa_family;

#if defined(MORE_DEBUG)
	printf("Device: %s\n",devName);
	printf("Address family: %d\n",address_family);
#endif

	foo = (struct sockaddr_in *)&ifp->ifa_addr;
        if (address_family == AF_INET) {

	   a=(char *)&(ifp->ifa_addr->sa_data);
	   a++; a++;            // Yep... it really is 2 bytes over 
				// Only IPV4 below ....
           adaptor->ipAddr.addr = *((unsigned int *)a);

#if defined(MORE_DEBUG)
printf("My addr \n");
	   a=(char *)&(ifp->ifa_addr->sa_data);
	   a++;
	   a++;
	   printf("%d ",*a);
	   a++;
	   printf("%d ",*a);
	   a++;
	   printf("%d ",*a);
	   a++;
	   printf("%d \n",*a);
#endif
        }
       }

     }
   }
   updateAdaptorNIO(sp);
   freeifaddrs(ifap);
   return sp->adaptorList->num_adaptors;
 
}
  
#if defined(__cplusplus)
} /* extern "C" */
#endif
