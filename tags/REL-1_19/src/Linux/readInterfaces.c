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
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/if_vlan.h>

extern int debug;


#if 0

/*________________---------------------------__________________
  ________________      readVLAN             __________________
  ----------------___________________________------------------

Rejected this way of looking up the VLAN because is was not
portable back to Linux 2.4 kernels,  and because the /proc/net/vlan
approach seemed more stable and portable.
*/
  int32_t readVLAN(char *devName, int fd)
  {
    // check in case it is just a sub-interface with a VLAN tag
    // that we should ignore to avoid double-counting.  We'll still
    // allow it through in case we are doing ULOG sampling and we
    // want to record flows/counters against this interface.
    int32_t vlan = HSP_VLAN_ALL;
    // for some reason if_vlan.h has only 24 characters set aside
    // for the device name, and no #define to capture that (like
    // IFNAMSIZ above)
#define HSP_VLAN_IFNAMSIZ 24
    if(my_strlen(devName) < HSP_VLAN_IFNAMSIZ) {
      struct vlan_ioctl_args vlargs;
      vlargs.cmd = GET_VLAN_VID_CMD;
      strcpy(vlargs.device1, devName);
      if(ioctl(fd, SIOCGIFVLAN, &vlargs) != 0) {
	if(debug) {
	  myLog(LOG_ERR, "device %s Get SIOCGIFVLAN failed : %s",
		devName,
		strerror(errno));
	}
      }
      else {
	vlan = vlargs.u.VID;
	if(debug) {
	  myLog(LOG_INFO, "device %s is vlan interface for vlan %u",
		devName,
		vlan);
	}
      }
    }
    return vlan;
  }

#endif

  // limit the number of chars we will read from each line
  // in /proc/net/dev and /prov/net/vlan/config
  // (there can be more than this - fgets will chop for us)
#define MAX_PROC_LINE_CHARS 160


/*________________---------------------------__________________
  ________________      readVLANs            __________________
  ----------------___________________________------------------
*/

  void readVLANs(HSP *sp)
  {
    // mark interfaces that are specific to a VLAN
    FILE *procFile = fopen("/proc/net/vlan/config", "r");
    if(procFile) {
      char line[MAX_PROC_LINE_CHARS];
      int lineNo = 0;
      while(fgets(line, MAX_PROC_LINE_CHARS, procFile)) {
	// expect lines of the form "<device> VID: <vlan> ..."
	// (with a header line on the first row)
	char devName[MAX_PROC_LINE_CHARS];
	int vlan;
	++lineNo;
	if(lineNo > 1 && sscanf(line, "%s | %d", devName, &vlan) == 2) {
	  SFLAdaptor *adaptor = adaptorListGet(sp->adaptorList, trimWhitespace(devName));
	  if(adaptor && adaptor->userData &&
	     vlan >= 0 && vlan < 4096) {
	    HSPAdaptorNIO *niostate = (HSPAdaptorNIO *)adaptor->userData;
	    niostate->vlan = vlan;
	    if(debug) myLog(LOG_INFO, "adaptor %s has 802.1Q vlan %d", devName, vlan);
	  }
	}
      }
      fclose(procFile);
    }
  }

/*________________---------------------------__________________
  ________________      readInterfaces       __________________
  ----------------___________________________------------------
*/

int readInterfaces(HSP *sp)
{
  if(sp->adaptorList == NULL) sp->adaptorList = adaptorListNew();
  else adaptorListMarkAll(sp->adaptorList);

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
    char line[MAX_PROC_LINE_CHARS];
    while(fgets(line, MAX_PROC_LINE_CHARS, procFile)) {
      if(debug) myLog(LOG_INFO, "/proc/net/dev line: %s", line);
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
	    int promisc =  (ifr.ifr_flags & IFF_PROMISC) ? YES : NO;
	    int bond_master = (ifr.ifr_flags & IFF_MASTER) ? YES : NO;
	    //int hasBroadcast = (ifr.ifr_flags & IFF_BROADCAST);
	    //int pointToPoint = (ifr.ifr_flags & IFF_POINTOPOINT);

	    // used to igore loopback interfaces here, but now those
	    // are filtered at the point where we roll together the
	    // counters.
	    if(up) {
	      
	       // Get the MAC Address for this interface
	      if(ioctl(fd,SIOCGIFHWADDR, &ifr) != 0) {
		myLog(LOG_ERR, "device %s Get SIOCGIFHWADDR failed : %s",
		      devName,
		      strerror(errno));
	      }

	      // for now just assume that each interface has only one MAC.  It's not clear how we can
	      // learn multiple MACs this way anyhow.  It seems like there is just one per ifr record.
	      // find or create a new "adaptor" entry
	      SFLAdaptor *adaptor = adaptorListAdd(sp->adaptorList, devName, (u_char *)&ifr.ifr_hwaddr.sa_data, sizeof(HSPAdaptorNIO));

	      // clear the mark so we don't free it below
	      adaptor->marked = NO;

	      // this flag might belong in the adaptorNIO struct
	      adaptor->promiscuous = promisc;

	      // remember some useful flags in the userData structure
	      HSPAdaptorNIO *adaptorNIO = (HSPAdaptorNIO *)adaptor->userData;
	      adaptorNIO->loopback = loopback;
	      adaptorNIO->bond_master = bond_master;
	      adaptorNIO->vlan = HSP_VLAN_ALL; // may be modified below

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
	      
	      // Try to get the ethtool info for this interface so we can infer the
	      // ifDirection and ifSpeed. Learned from openvswitch (http://www.openvswitch.org).
	      struct ethtool_cmd ecmd = { 0 };
	      ecmd.cmd = ETHTOOL_GSET;
	      ifr.ifr_data = (char *)&ecmd;
	      if(ioctl(fd, SIOCETHTOOL, &ifr) == 0) {
		adaptor->ifDirection = ecmd.duplex ? 1 : 2;
		uint64_t ifSpeed_mb = ecmd.speed;
		// ethtool_cmd_speed(&ecmd) is available in newer systems and uses the
		// speed_hi field too,  but we would need to run autoconf-style
		// tests to see if it was there and we are trying to avoid that.
		if(ifSpeed_mb == (uint16_t)-1 ||
		   ifSpeed_mb == (uint32_t)-1) {
		  // unknown
		  adaptor->ifSpeed = 0;
		}
		else {
		  adaptor->ifSpeed = ifSpeed_mb * 1000000;
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

  // now remove and free any that are still marked
  adaptorListFreeMarked(sp->adaptorList);

  // check in case any of the survivors are specific
  // to a particular VLAN
  readVLANs(sp);

  return sp->adaptorList->num_adaptors;
}
  
#if defined(__cplusplus)
} /* extern "C" */
#endif
