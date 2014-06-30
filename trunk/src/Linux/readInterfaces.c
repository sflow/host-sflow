/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "hsflow_ethtool.h"

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
      if(ioctl(fd, SIOCGIFVLAN, &vlargs) < 0) {
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
  ________________  setAddressPriorities     __________________
  ----------------___________________________------------------
  Ideally we would do this as we go along,  but since the vlan
  info is spliced in separately we have to wait for that and
  then set the priorities for the whole list.
*/
  void setAddressPriorities(HSP *sp)
  {
    if(debug) myLog(LOG_INFO, "setAddressPriorities");
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
  ________________  readIPv6Addresses        __________________
  ----------------___________________________------------------
*/

#if 0
  static u_int remap_proc_net_if_inet6_scope(u_int scope)
  {
    // for reasons not yet understood, the scope field in /proc/net/if_inet6
    // does not correspond to the values we expected to see.  (I think it
    // might actually be the sin6_scope that you would write into a v6 socket
    // to talk to that address,  but I don't know for sure,  or why that
    // would need to be different anyway).
    // This function tries to map the scope field back into familiar
    // territory again.
    switch(scope) {
    case 0x40: return 0x5; // site
    case 0x20: return 0x2; // link
    case 0x10: return 0x1; // interface
    case 0x00: return 0xe; // global
    }
    // if it's something else,  then just leave it unchanged.  Not sure
    // what you get here for scope = admin or org.
    return scope;
  }
#endif

  void readIPv6Addresses(HSP *sp)
  {
    FILE *procFile = fopen("/proc/net/if_inet6", "r");
    if(procFile) {
      char line[MAX_PROC_LINE_CHARS];
      int lineNo = 0;
      while(fgets(line, MAX_PROC_LINE_CHARS, procFile)) {
	// expect lines of the form "<address> <netlink_no> <prefix_len(HEX)> <scope(HEX)> <flags(HEX)> <deviceName>
	// (with a header line on the first row)
	char devName[MAX_PROC_LINE_CHARS];
	u_char addr[MAX_PROC_LINE_CHARS];
	u_int devNo, maskBits, scope, flags;
	++lineNo;
	if(sscanf(line, "%s %x %x %x %x %s",
		  addr,
		  &devNo,
		  &maskBits,
		  &scope,
		  &flags,
		  devName) == 6) {
	  if(debug) {
	    myLog(LOG_INFO, "adaptor %s has v6 address %s with scope 0x%x",
		  devName,
		  addr,
		  scope);
	  }
	  SFLAdaptor *adaptor = adaptorListGet(sp->adaptorList, trimWhitespace(devName));
	  if(adaptor && adaptor->userData) {
	    HSPAdaptorNIO *niostate = (HSPAdaptorNIO *)adaptor->userData;
	    SFLAddress v6addr;
	    v6addr.type = SFLADDRESSTYPE_IP_V6;
	    if(hexToBinary(addr, v6addr.address.ip_v6.addr, 16) == 16) {
	      // we interpret the scope from the address now
	      // scope = remap_proc_net_if_inet6_scope(scope);
	      EnumIPSelectionPriority ipPriority = agentAddressPriority(sp,
									&v6addr,
									niostate->vlan,
									niostate->loopback);
	      if(ipPriority > niostate->ipPriority) {
		// write this in as the preferred sflow-agent-address for this adaptor
		niostate->ipAddr = v6addr;
		niostate->ipPriority = ipPriority;
	      }
	    }
	  }
	}
      }
      fclose(procFile);
    }
  }

#if (HSP_ETHTOOL_STATS || HSF_DOCKER)
/*________________---------------------------__________________
  ________________  staticStringsIndexOf     __________________
  ----------------___________________________------------------
*/

  static int staticStringsIndexOf(const char **strings, char *search) {
    for(int ss = 0; strings[ss]; ss++) {
      if(my_strequal((char *)strings[ss],search)) return ss;
    }
    return -1;
  }
#endif
	    

/*________________---------------------------__________________
  ________________    read_ethtool_info      __________________
  ----------------___________________________------------------
  return true if something changed
*/
  static int read_ethtool_info(struct ifreq *ifr, int fd, SFLAdaptor *adaptor)
  {
    // Try to get the ethtool info for this interface so we can infer the
    // ifDirection and ifSpeed. Learned from openvswitch (http://www.openvswitch.org).
    int changed = NO;
    struct ethtool_cmd ecmd = { 0 };
    ecmd.cmd = ETHTOOL_GSET;
    ifr->ifr_data = (char *)&ecmd;
    if(ioctl(fd, SIOCETHTOOL, ifr) >= 0) {
      uint32_t direction = ecmd.duplex ? 1 : 2;
      if(direction != adaptor->ifDirection) {
	changed = YES;
      }
      adaptor->ifDirection = direction;
      uint64_t ifSpeed_mb = ecmd.speed;
      // ethtool_cmd_speed(&ecmd) is available in newer systems and uses the
      // speed_hi field too,  but we would need to run autoconf-style
      // tests to see if it was there and we are trying to avoid that.
      if(ifSpeed_mb == (uint16_t)-1 ||
	 ifSpeed_mb == (uint32_t)-1) {
	// unknown
	if(adaptor->ifSpeed != 0) {
	  changed = YES;
	}
	adaptor->ifSpeed = 0;
      }
      else {
	uint64_t ifSpeed_bps = ifSpeed_mb * 1000000;
	if(adaptor->ifSpeed != ifSpeed_bps) {
	  changed = YES;
	}
	adaptor->ifSpeed = ifSpeed_bps;
      }
#if (HSP_ETHTOOL_STATS || HSF_DOCKER)
      // see if the ethtool stats block can give us multicast/broadcast counters too
      HSPAdaptorNIO *adaptorNIO = (HSPAdaptorNIO *)adaptor->userData;
      adaptorNIO->et_nfound=0;
      struct {
	struct ethtool_sset_info ssi;
	uint32_t data;
      } sset_info;
      memset(&sset_info, 0, sizeof(sset_info));
      sset_info.ssi.cmd = ETHTOOL_GSSET_INFO;
      sset_info.ssi.sset_mask = (uint64_t)1 << ETH_SS_STATS;
      ifr->ifr_data = (char *)&sset_info;
      if(ioctl(fd, SIOCETHTOOL, ifr) >= 0) {
	if(sset_info.ssi.sset_mask) {
	  adaptorNIO->et_nctrs = sset_info.data;
	  if(adaptorNIO->et_nctrs) {
	    struct ethtool_gstrings *ctrNames;
	    uint32_t bytes = sizeof(*ctrNames) + (adaptorNIO->et_nctrs * ETH_GSTRING_LEN);
	    ctrNames = (struct ethtool_gstrings *)my_calloc(bytes);
	    ctrNames->cmd = ETHTOOL_GSTRINGS;
	    ctrNames->string_set = ETH_SS_STATS;
	    ctrNames->len = adaptorNIO->et_nctrs;
	    ifr->ifr_data = (char *)ctrNames;
	    if(ioctl(fd, SIOCETHTOOL, ifr) >= 0) {
	      // copy out one at a time to make sure we have null-termination
	      char cname[ETH_GSTRING_LEN+1];
	      cname[ETH_GSTRING_LEN] = '\0';
	      for(int ii=0; ii < adaptorNIO->et_nctrs; ii++) {
		memcpy(cname, &ctrNames->data[ii * ETH_GSTRING_LEN], ETH_GSTRING_LEN);
		if(debug) myLog(LOG_INFO, "ethtool counter %s is at index %d", cname, ii);
		// then see if this is one of the ones we want,
		// and record the index if it is.
#ifdef HSP_ETHTOOL_STATS
		if(staticStringsIndexOf(HSP_ethtool_mcasts_in_names, cname) != -1) {
		  adaptorNIO->et_idx_mcasts_in = ii+1;
		  adaptorNIO->et_nfound++;
		}
		else if(staticStringsIndexOf(HSP_ethtool_mcasts_out_names, cname) != -1) {
		  adaptorNIO->et_idx_mcasts_out = ii+1;
		  adaptorNIO->et_nfound++;
		}
		else if(staticStringsIndexOf(HSP_ethtool_bcasts_in_names, cname) != -1) {
		  adaptorNIO->et_idx_bcasts_in = ii+1;
		  adaptorNIO->et_nfound++;
		}
		else if(staticStringsIndexOf(HSP_ethtool_bcasts_out_names, cname) != -1) {
		  adaptorNIO->et_idx_bcasts_out = ii+1;
		  adaptorNIO->et_nfound++;
		}
#endif
#ifdef HSF_DOCKER
		if(staticStringsIndexOf(HSP_ethtool_peer_ifindex_names, cname) != -1) {
		  // Now go ahead and make the call to get the peer_ifindex.
		  struct ethtool_stats *et_stats = (struct ethtool_stats *)my_calloc(bytes);
		  et_stats->cmd = ETHTOOL_GSTATS;
		  et_stats->n_stats = adaptorNIO->et_nctrs;
		  ifr->ifr_data = (char *)et_stats;
		  if(ioctl(fd, SIOCETHTOOL, ifr) >= 0) {
		    adaptorNIO->peer_ifIndex = et_stats->data[ii];
		    if(debug) myLog(LOG_INFO, "Interface %s (ifIndex=%u) has peer_ifindex=%u", 
				    adaptor->deviceName,
				    adaptor->ifIndex,
				    adaptorNIO->peer_ifIndex);
		  }
		}
#endif
	      }
	    }
	    my_free(ctrNames);
	  }
	}
      }
#endif
    }
    return changed;
  }

/*________________---------------------------__________________
  ________________      readInterfaces       __________________
  ----------------___________________________------------------
*/

  int readInterfaces(HSP *sp, uint32_t *p_added, uint32_t *p_removed, uint32_t *p_cameup, uint32_t *p_wentdown, uint32_t *p_changed)
{
  uint32_t ad_added=0, ad_removed=0, ad_cameup=0, ad_wentdown=0, ad_changed=0;
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
    int lineNo = 0;
    while(fgets(line, MAX_PROC_LINE_CHARS, procFile)) {
      if(lineNo++ < 2) continue; // skip headers
      // the device name is always the first token before the ":"
      char buf[MAX_PROC_LINE_CHARS];
      char *p = line;
      char *devName = parseNextTok(&p, " \t:", NO, '\0', NO, buf, MAX_PROC_LINE_CHARS);
      if(devName && my_strlen(devName) < IFNAMSIZ) {
	devName = trimWhitespace(devName);
	if(devName && strlen(devName) < IFNAMSIZ) {
	  // we set the ifr_name field to make our queries
	  strncpy(ifr.ifr_name, devName, sizeof(ifr.ifr_name));

	  if(debug > 1) {
	    myLog(LOG_INFO, "reading interface %s", devName);
	  }

	  // Get the flags for this interface
	  if(ioctl(fd,SIOCGIFFLAGS, &ifr) < 0) {
	    myLog(LOG_ERR, "device %s Get SIOCGIFFLAGS failed : %s",
		  devName,
		  strerror(errno));
	  }
	  else {
	    int up = (ifr.ifr_flags & IFF_UP) ? YES : NO;
	    int loopback = (ifr.ifr_flags & IFF_LOOPBACK) ? YES : NO;
	    int promisc =  (ifr.ifr_flags & IFF_PROMISC) ? YES : NO;
	    int bond_master = (ifr.ifr_flags & IFF_MASTER) ? YES : NO;
	    int bond_slave = (ifr.ifr_flags & IFF_SLAVE) ? YES : NO;
	    //int hasBroadcast = (ifr.ifr_flags & IFF_BROADCAST);
	    //int pointToPoint = (ifr.ifr_flags & IFF_POINTOPOINT);

	    // used to ignore loopback interfaces here, and interfaces
	    // that are currently marked down, but now those are
	    // filtered at the point where we roll together the
	    // counters, or build the list for export
	      
	    // Get the MAC Address for this interface
	    if(ioctl(fd,SIOCGIFHWADDR, &ifr) < 0) {
	      myLog(LOG_ERR, "device %s Get SIOCGIFHWADDR failed : %s",
		    devName,
		    strerror(errno));
	    }
	    
	    // for now just assume that each interface has only one MAC.  It's not clear how we can
	    // learn multiple MACs this way anyhow.  It seems like there is just one per ifr record.
	    // find or create a new "adaptor" entry
	    SFLAdaptor *adaptor = adaptorListGet(sp->adaptorList, devName);
	    if(adaptor == NULL) {
	      ad_added++;
	      adaptor = adaptorListAdd(sp->adaptorList, devName, (u_char *)&ifr.ifr_hwaddr.sa_data, sizeof(HSPAdaptorNIO));
	    }
	    
	    // clear the mark so we don't free it below
	    adaptor->marked = NO;
	    
	    // this flag might belong in the adaptorNIO struct
	    adaptor->promiscuous = promisc;
	    
	    // remember some useful flags in the userData structure
	    HSPAdaptorNIO *adaptorNIO = (HSPAdaptorNIO *)adaptor->userData;
	    if(adaptorNIO->up != up) {
	      if(up) ad_cameup++;
	      else ad_wentdown++;
	      if(debug) {
		myLog(LOG_INFO, "adaptor %s %s",
		      adaptor->deviceName,
		      up ? "came up" : "went down");
	      }
	    }
	    adaptorNIO->up = up;
	    adaptorNIO->loopback = loopback;
	    adaptorNIO->bond_master = bond_master;
	    adaptorNIO->bond_slave = bond_slave;
	    adaptorNIO->vlan = HSP_VLAN_ALL; // may be modified below
#ifdef HSP_SWITCHPORT_REGEX
	    if(regexec(&sp->swp_regex, devName, 0, NULL, 0) == 0) {
	      adaptorNIO->switchPort = YES;
	    }
#endif
	    // Try and get the ifIndex for this interface
	    if(ioctl(fd,SIOCGIFINDEX, &ifr) < 0) {
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
	    if(ioctl(fd,SIOCGIFADDR, &ifr) < 0) {
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
		adaptorNIO->ipAddr.type = SFLADDRESSTYPE_IP_V4;
		adaptorNIO->ipAddr.address.ip_v4.addr = s->sin_addr.s_addr;
	      }
	      //else if (ifr.ifr_addr.sa_family == AF_INET6) {
	      // not sure this ever happens - on a linux system IPv6 addresses
	      // are picked up from /proc/net/if_inet6
	      // struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ifr.ifr_addr;
	      // IP6 addr is now s->sin6_addr;
	      //}
	    }

	    // use ethtool to get info about direction/speed and more
	    if(read_ethtool_info(&ifr, fd, adaptor) == YES) {
	      ad_changed++;
	    }
	  }
	}
      }
    }
    fclose(procFile);
  }
  
  close (fd);

  // now remove and free any that are still marked
  ad_removed = adaptorListFreeMarked(sp->adaptorList);

  // check in case any of the survivors are specific
  // to a particular VLAN
  readVLANs(sp);

  // now that we have the evidence gathered together, we can
  // set the L3 address priorities (used for auto-selecting
  // the sFlow-agent-address if requrired to by the config.
  setAddressPriorities(sp);

  // now we can read IPv6 addresses too - they come from a
  // different place. Depending on the address priorities this
  // may cause the adaptor's best-choice ipAddress to be
  // overwritten.
  readIPv6Addresses(sp);

  if(p_added) *p_added = ad_added;
  if(p_removed) *p_removed = ad_removed;
  if(p_cameup) *p_cameup = ad_cameup;
  if(p_wentdown) *p_wentdown = ad_wentdown;
  if(p_changed) *p_changed = ad_changed;

  return sp->adaptorList->num_adaptors;
}

#ifdef HSF_DOCKER

/*________________---------------------------__________________
  ________________   containerLinkCB         __________________
  ----------------___________________________------------------
  
expecting lines of the form:
VNIC: <ifindex> <device> <mac>
*/

  static int containerLinkCB(void *magic, char *line) {
    HSPVMState *vm = (HSPVMState *)magic;
    if(debug) myLog(LOG_INFO, "containerLinkCB: line=<%s>", line);
    char deviceName[HSF_DOCKER_MAX_LINELEN];
    char macStr[HSF_DOCKER_MAX_LINELEN];
    uint32_t ifIndex;
    if(sscanf(line, "VNIC: %u %s %s", &ifIndex, deviceName, macStr) == 3) {
      u_char mac[6];
      if(hexToBinary((u_char *)macStr, mac, 6) == 6) {
	SFLAdaptor *adaptor = adaptorListGet(vm->interfaces, deviceName);
	if(adaptor == NULL) {
	  adaptor = adaptorListAdd(vm->interfaces, deviceName, mac, sizeof(HSPAdaptorNIO));
	}
	// set ifIndex
	adaptor->ifIndex = ifIndex;
	// clear the mark so we don't free it below
	adaptor->marked = NO;
      }
    }
    return YES;
  }

/*________________---------------------------__________________
  ________________   readContainerInterfaces __________________
  ----------------___________________________------------------
*/

//#ifndef CLONE_NEWNET
//#define CLONE_NEWNET 0x40000000	/* New network namespace (lo, device, names sockets, etc) */
//#endif
  
  //  static int my_setns(int fd, int nstype) {
  //    return syscall(__NR_setns, fd, nstype);
  // }

  int readContainerInterfaces(HSP *sp, HSPVMState *vm)  {
    if(!vm->container) return 0;
    pid_t nspid = vm->container->pid;
    if(debug) myLog(LOG_INFO, "readContainerInterfaces: pid=%u", nspid);
    if(nspid == 0) return 0;

    // do the dirty work after a fork, so we can just exit afterwards,
    // same as they do in "ip netns exec"
    int pfd[2];
    if(pipe(pfd) == -1) {
      myLog(LOG_ERR, "pipe() failed : %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    pid_t cpid;
    if((cpid = fork()) == -1) {
      myLog(LOG_ERR, "fork() failed : %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    if(cpid == 0) {
      // in child
      close(pfd[0]);   // close read-end
      dup2(pfd[1], 1); // stdout -> write-end
      dup2(pfd[1], 2); // stderr -> write-end
      close(pfd[1]);
      
      // open /proc/<nspid>/ns/net
      char topath[HSF_DOCKER_MAX_FNAME_LEN+1];
      snprintf(topath, HSF_DOCKER_MAX_FNAME_LEN, "/proc/%u/ns/net", nspid);
      int nsfd = open(topath, O_RDONLY | O_CLOEXEC);
      if(nsfd < 0) {
	fprintf(stderr, "cannot open %s : %s", topath, strerror(errno));
	exit(EXIT_FAILURE);
      }
      
      /* set network namespace
	 CLONE_NEWNET means nsfd must refer to a network namespace
      */
      if(setns(nsfd, CLONE_NEWNET) < 0) {
	fprintf(stderr, "seting network namespace failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }
      
      /* From "man 2 unshare":  This flag has the same effect as the clone(2)
	 CLONE_NEWNS flag. Unshare the mount namespace, so that the calling
	 process has a private copy of its namespace which is not shared with
	 any other process. Specifying this flag automatically implies CLONE_FS
	 as well. Use of CLONE_NEWNS requires the CAP_SYS_ADMIN capability. */
      if(unshare(CLONE_NEWNS) < 0) {
	fprintf(stderr, "seting network namespace failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }

      int fd = socket(PF_INET, SOCK_DGRAM, 0);
      if(fd < 0) {
	fprintf(stderr, "error opening socket: %d (%s)\n", errno, strerror(errno));
	return 0;
      }

      FILE *procFile = fopen("/proc/net/dev", "r");
      if(procFile) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	char line[MAX_PROC_LINE_CHARS];
	int lineNo = 0;
	while(fgets(line, MAX_PROC_LINE_CHARS, procFile)) {
	  if(lineNo++ < 2) continue; // skip headers
	  char buf[MAX_PROC_LINE_CHARS];
	  char *p = line;
	  char *devName = parseNextTok(&p, " \t:", NO, '\0', NO, buf, MAX_PROC_LINE_CHARS);
	  if(devName && my_strlen(devName) < IFNAMSIZ) {
	    strncpy(ifr.ifr_name, devName, sizeof(ifr.ifr_name));
	    // Get the flags for this interface
	    if(ioctl(fd,SIOCGIFFLAGS, &ifr) < 0) {
	      fprintf((stderr, "container device %s Get SIOCGIFFLAGS failed : %s",
		       devName,
		       strerror(errno));
	    }
	    else {
	      int up = (ifr.ifr_flags & IFF_UP) ? YES : NO;
	      int loopback = (ifr.ifr_flags & IFF_LOOPBACK) ? YES : NO;

	      if(up && !loopback) {
		// try to get ifIndex next, because we only care about
		// ifIndex and MAC when looking at container interfaces
		if(ioctl(fd,SIOCGIFINDEX, &ifr) < 0) {
		  // only complain about this if we are debugging
		  if(debug) {
		    fprintf(stderr, "container device %s Get SIOCGIFINDEX failed : %s",
			  devName,
			  strerror(errno));
		  }
		}
		else {
		  int ifIndex = ifr.ifr_ifindex;
		  
		  // Get the MAC Address for this interface
		  if(ioctl(fd,SIOCGIFHWADDR, &ifr) < 0) {
		    if(debug) {
		      fprint(stderr, "device %s Get SIOCGIFHWADDR failed : %s",
			     devName,
			     strerror(errno));
		    }
		  }
		  else {
		    u_char macStr[13];
		    printHex((u_char *)&ifr.ifr_hwaddr.sa_data, 6, macStr, 12, NO);
		    // send this info back up the pipe to my my parent
		    printf("VNIC: %u %s %s\n", ifIndex, devName, macStr);
		  }
		}
	      }
	    }
	  }
	}
      }

      // don't even bother to close file-descriptors,  just bail
      exit(0);
      
    }
    else {
      // in parent
      close(pfd[1]); // close write-end
      // read from read-end
      FILE *ovs;
      if((ovs = fdopen(pfd[0], "r")) == NULL) {
	myLog(LOG_ERR, "readContainerInterfaces: fdopen() failed : %s", strerror(errno));
	return 0;
      }
      char line[MAX_PROC_LINE_CHARS];
      while(fgets(line, MAX_PROC_LINE_CHARS, ovs)) containerLinkCB(vm, line);
      fclose(ovs);
      wait(NULL); // block here until child is done
    }

    return vm->interfaces->num_adaptors;
  }

#endif	

#if defined(__cplusplus)
} /* extern "C" */
#endif
