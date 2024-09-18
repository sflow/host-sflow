/* This software is distributed under the following license:
 * http://sflow.net/license.html
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

#if (__GLIBC__ >= 2 && __GLIBC_MINOR__ >= 3)
#include <ifaddrs.h> // for getifaddrs(3)
#endif

  // limit the number of chars we will read from each line
  // in /proc/net/dev and /prov/net/vlan/config
  // (there can be more than this - my_readline will chop for us)
#define MAX_PROC_LINE_CHARS 320

/*________________---------------------------__________________
  ________________      readVLANs            __________________
  ----------------___________________________------------------
*/

  void readVLANs(HSP *sp)
  {
    EVMod *mod = sp->rootModule;
    // mark interfaces that are specific to a VLAN
    FILE *procFile = fopen(PROCFS_STR "/net/vlan/config", "r");
    if(procFile) {
      char line[MAX_PROC_LINE_CHARS];
      int lineNo = 0;
      int truncated;
      while(my_readline(procFile, line, MAX_PROC_LINE_CHARS, &truncated) != EOF) {
	// expect lines of the form "<device> VID: <vlan> ..."
	// (with a header line on the first row)
	char devName[MAX_PROC_LINE_CHARS];
	int vlan;
	++lineNo;
	if(lineNo > 1 && sscanf(line, "%s | %d", devName, &vlan) == 2) {
	  uint32_t devLen = my_strnlen(devName, MAX_PROC_LINE_CHARS-1);
	  char *trimmed = trimWhitespace(devName, devLen);
	  if (trimmed) {
	    SFLAdaptor *adaptor = adaptorByName(sp,  trimmed);
	    if(adaptor &&
	       vlan >= 0 && vlan < 4096) {
	      ADAPTOR_NIO(adaptor)->vlan = vlan;
	      EVDebug(mod, 1, "adaptor %s has 802.1Q vlan %d", devName, vlan);
	    }
	  }
	}
      }
      fclose(procFile);
    }
  }

  /*________________---------------------------__________________
    ________________       local IPs           __________________
    ----------------___________________________------------------
  */

  static bool addLocalIP(HSP *sp, UTHash *ht, SFLAddress *addr, char *dev) {
    HSPLocalIP searchIP = { .ipAddr = *addr };
    HSPLocalIP *lip = UTHashGet(ht, &searchIP);
    bool added = NO;
    if(lip == NULL) {
      lip = localIPNew(addr, dev);
      UTHashAdd(ht, lip);
      lip->discoveryIndex = UTHashN(ht);
      added = YES;
    }
    else {
      // keep the set of all devs this address was seen on
      // in case one of them is the preferred one for agent
      // address selection.
      if(!strArrayContains(lip->devs, dev))
	strArrayAdd(lip->devs, dev);
    }
    return added;
  }

  static void freeLocalIPs(UTHash *ht) {
    HSPLocalIP *lip;
    UTHASH_WALK(ht, lip)
      localIPFree(lip);
    UTHashFree(ht);
  }


  /*________________---------------------------__________________
    ________________     readL3Addresses       __________________
    ----------------___________________________------------------
  */

    
  static int readL3Addresses(HSP *sp, UTHash *localIP, UTHash *localIP6)
  {
    EVMod *mod = sp->rootModule;
    int addresses_added = 0;
    // getifaddrs(3) first appeared in glibc 2.3
    // and first included v6 addresses in 2.3.3
#if (__GLIBC__ >= 2 && __GLIBC_MINOR__ >= 3)
    struct ifaddrs *ifap = NULL;

    
    if(getifaddrs(&ifap) != 0) {
      EVDebug(mod, 1, "readL3Addresses: getifaddrs() failed : %s", strerror(errno));
      return 0;
    }
    for(struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {
      bool up = (ifa->ifa_flags & IFF_UP) ? YES : NO;
      bool loopback = (ifa->ifa_flags & IFF_LOOPBACK) ? YES: NO;
      bool promisc = (ifa->ifa_flags & IFF_PROMISC) ? YES : NO;
      bool bond_master = (ifa->ifa_flags & IFF_MASTER) ? YES : NO;
      bool bond_slave = (ifa->ifa_flags & IFF_SLAVE) ? YES : NO;

      EVDebug(mod, 1, "readL3Addresses: ifa_name=%s up=%d loopback=%d promisc=%d bond(master=%u,slave=%u)",
	      ifa->ifa_name,
	      up,
	      loopback,
	      promisc,
	      bond_master,
	      bond_slave);
	
      if(up == 0)
	continue;
      if(ifa->ifa_addr == NULL)
	continue;

      SFLAdaptor *adaptor = adaptorByName(sp, ifa->ifa_name);
      if(adaptor == NULL) {
	EVDebug(mod, 1, "readL3Addreses: ignoring IP address for unknown device: %s", ifa->ifa_name);
	continue;
      }
      
      SFLAddress addr = { 0 };
      UTHash *addrHT = NULL;
      switch(ifa->ifa_addr->sa_family) {
      case AF_INET:
	{
	  struct sockaddr_in *s = (struct sockaddr_in *)ifa->ifa_addr;
	  addr.type = SFLADDRESSTYPE_IP_V4;
	  addr.address.ip_v4.addr = s->sin_addr.s_addr;
	  addrHT = localIP;
	}
	break;
      case AF_INET6:
	{
	  struct sockaddr_in6 *s = (struct sockaddr_in6 *)ifa->ifa_addr;
	  addr.type = SFLADDRESSTYPE_IP_V6;
	  memcpy(&addr.address.ip_v6.addr, &s->sin6_addr, 16);
	  addrHT = localIP6;
	}
	break;
      case AF_PACKET:
	// counters accessible under here (see linux/if_link.h), but it seems
	// better to read them from /proc, ethtool or Netlink.
	break;
      default:
	EVDebug(mod, 1, "readL3Addresses: unexpected family = %u", ifa->ifa_addr->sa_family);
	break;
      }
      
      if(addrHT) {
	char ipbuf[51];
	EVDebug(mod, 1, "readL3Addresses: found=%s\n", SFLAddress_print(&addr, ipbuf, 50));
	if(addLocalIP(sp, addrHT, &addr, ifa->ifa_name))
	  addresses_added++;
      }
    }

    // clean up
    freeifaddrs(ifap);

    EVDebug(mod, 1, "readL3Addresses: found %u extra L3 addresses", addresses_added);

#endif
    return addresses_added;
  }

/*________________---------------------------__________________
  ________________  readIPv6Addresses        __________________
  ----------------___________________________------------------
*/

  static int readIPv6Addresses(HSP *sp, UTHash *addrHT)
  {
    EVMod *mod = sp->rootModule;
    int addresses_added = 0;
    FILE *procFile = fopen(PROCFS_STR "/net/if_inet6", "r");
    if(procFile) {
      char line[MAX_PROC_LINE_CHARS];
      int lineNo = 0;
      int truncated;
      while(my_readline(procFile, line, MAX_PROC_LINE_CHARS, &truncated) != EOF) {
	// expect lines of the form "<address> <netlink_no> <prefix_len(HEX)> <scope(HEX)> <flags(HEX)> <deviceName>
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

	  EVDebug(mod, 1, "adaptor %s has v6 address %s with scope 0x%x",
		devName,
		addr,
		scope);

	  uint32_t devLen = my_strnlen(devName, MAX_PROC_LINE_CHARS-1);
	  char *trimmed = trimWhitespace(devName, devLen);
	  if(trimmed) {
	    SFLAdaptor *adaptor = adaptorByName(sp, trimmed);
	    if(adaptor) {
	      SFLAddress v6addr;
	      v6addr.type = SFLADDRESSTYPE_IP_V6;
	      if(hexToBinary(addr, v6addr.address.ip_v6.addr, 16) == 16) {
		if(addLocalIP(sp, addrHT, &v6addr, adaptor->deviceName))
		  addresses_added++;
	      }
	    }
	  }
	}
      }
      fclose(procFile);
    }
    return addresses_added;
  }

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

/*________________---------------------------__________________
  ________________   ethtool_num_counters    __________________
  ----------------___________________________------------------
*/

  static int ethtool_num_counters(struct ifreq *ifr, int fd)
  {
#ifdef ETHTOOL_GSSET_INFO
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
	return sset_info.data > 0 ? sset_info.data : 0;
      }
    }
#else
    struct ethtool_drvinfo drvinfo;
    drvinfo.cmd = ETHTOOL_GDRVINFO;
    ifr->ifr_data = (char *)&drvinfo;
    if(ioctl(fd, SIOCETHTOOL, ifr) >= 0) {
      return drvinfo.n_stats > 0 ? drvinfo.n_stats : 0;
    }
#endif
    return 0;
  }

#ifdef ETHTOOL_GLINKSETTINGS

/*________________-----------------------------__________________
  ________________  ethtool_get_GLINKSETTINGS  __________________
  ----------------_____________________________------------------
*/

/* New local definitions needed for updated  ethtool ioctl, ripped from upstream ethtool  */
#define ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NU32	(SCHAR_MAX)
#define ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NBITS	(32 * ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NU32)
#define ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NBYTES (4 * ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NU32)
#define ETHTOOL_DECLARE_LINK_MODE_MASK(name) uint32_t name[ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NU32]

  struct ethtool_link_usettings {
    struct {
      __u8 transceiver;
    } deprecated;
    struct ethtool_link_settings base;
    struct {
      ETHTOOL_DECLARE_LINK_MODE_MASK(supported);
      ETHTOOL_DECLARE_LINK_MODE_MASK(advertising);
      ETHTOOL_DECLARE_LINK_MODE_MASK(lp_advertising);
    } link_modes;
  };

  static bool ethtool_get_GLINKSETTINGS(HSP *sp, struct ifreq *ifr, int fd, SFLAdaptor *adaptor, bool *sysCallOK)
  {
    // Try to get the ethtool info for this interface so we can infer the
    // ifDirection and ifSpeed. Learned from openvswitch (http://www.openvswitch.org).
    bool changed = NO;
    (*sysCallOK) = NO;
    int err;
    struct {
      struct ethtool_link_settings req;
      __u32 link_mode_data[3 * ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NU32];
    } ecmd;

    /* Handshake with kernel to determine number of words for link
     * mode bitmaps. When requested number of bitmap words is not
     * the one expected by kernel, the latter returns the integer
     * opposite of what it is expecting. We request length 0 below
     * (aka. invalid bitmap length) to get this info.
     */
    memset(&ecmd, 0, sizeof(ecmd));
    ecmd.req.cmd = ETHTOOL_GLINKSETTINGS;
    ifr->ifr_data = (void *)&ecmd;
    err = ioctl(fd, SIOCETHTOOL, ifr);
    if (err == 0) {
      /* see above: we expect a strictly negative value from kernel.
       */
      if (ecmd.req.link_mode_masks_nwords >= 0
          || ecmd.req.cmd != ETHTOOL_GLINKSETTINGS) {
	return NO;
      }
      /* got the real ecmd.req.link_mode_masks_nwords,
       * now send the real request
       */
      ecmd.req.cmd = ETHTOOL_GLINKSETTINGS;
      ecmd.req.link_mode_masks_nwords = -ecmd.req.link_mode_masks_nwords;
      err = ioctl(fd, SIOCETHTOOL, ifr);
      if (err < 0) {
	return NO;
      }

      // indicate to caller that this has worked
      (*sysCallOK) = YES;

      uint32_t direction = ecmd.req.duplex ? 1 : 2;
      if(direction != adaptor->ifDirection) {
	changed = YES;
      }
      adaptor->ifDirection = direction;
      uint64_t ifSpeed_mb = ecmd.req.speed;
      // ethtool_cmd_speed(&ecmd) is available in newer systems and uses the
      // speed_hi field too,  but we would need to run autoconf-style
      // tests to see if it was there and we are trying to avoid that.
      if(ifSpeed_mb == (uint16_t)-1 ||
	 ifSpeed_mb == (uint32_t)-1) {
        // unknown
        if(adaptor->ifSpeed != 0) {
          changed = YES;
        }
        setAdaptorSpeed(sp, adaptor, 0, "ETHTOOL_GLINKSETTINGS1");
      }
      else {
        uint64_t ifSpeed_bps = ifSpeed_mb * 1000000;
        if(adaptor->ifSpeed != ifSpeed_bps) {
          changed = YES;
        }
        setAdaptorSpeed(sp, adaptor, ifSpeed_bps, "ETHTOOL_GLINKSETTINGS2");
      }
    }
    return changed;
  }

#endif /* ETHTOOL_GLINKSETTINGS */

#ifdef ETHTOOL_GSET
/*________________--------------------------__________________
  ________________  ethtool_get_GSET        __________________
  ----------------__________________________------------------
*/

  static bool ethtool_get_GSET(HSP *sp, struct ifreq *ifr, int fd, SFLAdaptor *adaptor)
  {
    // Try to get the ethtool info for this interface so we can infer the
    // ifDirection and ifSpeed. Learned from openvswitch (http://www.openvswitch.org).
    int changed = NO;
    struct ethtool_cmd ecmd_legacy = { 0 };
    ecmd_legacy.cmd = ETHTOOL_GSET;
    ifr->ifr_data = (char *)&ecmd_legacy;
    if(ioctl(fd, SIOCETHTOOL, ifr) >= 0) {
      uint32_t direction = ecmd_legacy.duplex ? 1 : 2;
      if(direction != adaptor->ifDirection) {
	changed = YES;
      }
      adaptor->ifDirection = direction;
      uint64_t ifSpeed_mb = ecmd_legacy.speed;
      // ethtool_cmd_speed(&ecmd_legacy) is available in newer systems and uses the
      // speed_hi field too,  but we would need to run autoconf-style
      // tests to see if it was there and we are trying to avoid that.
      if(ifSpeed_mb == (uint16_t)-1 ||
	 ifSpeed_mb == (uint32_t)-1) {
	// unknown
	if(adaptor->ifSpeed != 0) {
	  changed = YES;
	}
	setAdaptorSpeed(sp, adaptor, 0, "ETHTOOL_GSET1");
      }
      else {
	uint64_t ifSpeed_bps = ifSpeed_mb * 1000000;
	if(adaptor->ifSpeed != ifSpeed_bps) {
	  changed = YES;
	}
	setAdaptorSpeed(sp, adaptor, ifSpeed_bps, "ETHTOOL_GSET2");
      }
    }
    return changed;
  }

#endif /* ETHTOOL_GSET */

#if ( HSP_OPTICAL_STATS && ETHTOOL_GMODULEINFO )

/*________________---------------------------__________________
  ________________  ethtool_get_GMODULEINFO  __________________
  ----------------___________________________------------------
*/
  static bool ethtool_get_GMODULEINFO(HSP *sp, struct ifreq *ifr, int fd, SFLAdaptor *adaptor) {
    EVMod *mod = sp->rootModule;
    /* avoid re-testing this every time in case it is slow */
    HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
    // optical data
#ifdef HSP_TEST_QSFP
    adaptorNIO->modinfo_type = ETH_MODULE_SFF_8436;
    adaptorNIO->modinfo_len = ETH_MODULE_SFF_8436_LEN;
    adaptorNIO->ethtool_GMODULEINFO = NO;
#endif
    if(adaptorNIO->ethtool_GMODULEINFO) {
      adaptorNIO->ethtool_GMODULEINFO = NO;
      struct ethtool_modinfo modinfo = { 0 };
      modinfo.cmd = ETHTOOL_GMODULEINFO;
      ifr->ifr_data = (char *)&modinfo;
      if(ioctl(fd, SIOCETHTOOL, ifr) >= 0) {
	EVDebug(mod, 1, "ETHTOOL_GMODULEINFO %s succeeded eeprom_len = %u eeprom_type=%u",
	      adaptor->deviceName,
	      modinfo.eeprom_len,
	      modinfo.type);
	adaptorNIO->modinfo_len = modinfo.eeprom_len;
	adaptorNIO->modinfo_type = modinfo.type;
	return YES;
      }
      else {
	EVDebug(mod, 1, "ETHTOOL_GMODULEINF0 %s failed : %s",
		adaptor->deviceName,
		strerror(errno));
      }
    }
    return NO;
  }
#endif /* HSP_OPTICAL_STATS && ETHTOOL_GMODULEINFO */


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
  ________________  ethtool_get_GDRVINFO     __________________
  ----------------___________________________------------------
*/

  static bool ethtool_get_GDRVINFO(HSP *sp, struct ifreq *ifr, int fd, SFLAdaptor *adaptor)
  {
    // set device type from ethtool driver info - could also have gone
    // to /sys/class/net/<device>/.
    HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
    struct ethtool_drvinfo drvinfo;
    drvinfo.cmd = ETHTOOL_GDRVINFO;
    ifr->ifr_data = (char *)&drvinfo;
    if(ioctl(fd, SIOCETHTOOL, ifr) >= 0) {
      EnumHSPDevType devType = HSPDEV_OTHER;
      if(!strncasecmp(drvinfo.driver, "bridge", strlen("bridge")))
	devType = HSPDEV_BRIDGE;
      else if(!strncasecmp(drvinfo.driver, "veth", strlen("veth")))
	devType = HSPDEV_VETH;
      else if(!strncasecmp(drvinfo.driver, "vif", strlen("vif")))
	devType = HSPDEV_VIF;
      else if(!strncasecmp(drvinfo.driver, "openvswitch", strlen("openvswitch")))
	devType = HSPDEV_OVS;
      else if(strncasecmp(drvinfo.driver, "e1000", strlen("e1000")))
	devType = HSPDEV_PHYSICAL;
      else if(my_strlen(drvinfo.bus_info))
	devType = HSPDEV_PHYSICAL;

      if(adaptorNIO->devType != devType) {
	adaptorNIO->devType = devType;
	return YES;
      }
    }
    return NO;
  }

/*________________---------------------------__________________
  ________________  ethtool_get_GSTATS       __________________
  ----------------___________________________------------------
*/

  static void ethtool_get_GSTATS(HSP *sp, struct ifreq *ifr, int fd, SFLAdaptor *adaptor)
  {
    EVMod *mod = sp->rootModule;
    // see if the ethtool stats block can give us multicast/broadcast counters too
    HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
    adaptorNIO->et_nctrs = ethtool_num_counters(ifr, fd);
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
	adaptorNIO->et_found = 0;
	for(int ii=0; ii < adaptorNIO->et_nctrs; ii++) {
	  memcpy(cname, &ctrNames->data[ii * ETH_GSTRING_LEN], ETH_GSTRING_LEN);
	  EVDebug(mod, 3, "ethtool counter %s is at index %d", cname, ii);
	  // then see if this is one of the ones we want,
	  // and record the index if it is.
	  if(staticStringsIndexOf(HSP_ethtool_mcasts_in_names, cname) != -1) {
	    adaptorNIO->et_idx_mcasts_in = ii+1;
	    adaptorNIO->et_found |= HSP_ETCTR_MC_IN;
	  }
	  else if(staticStringsIndexOf(HSP_ethtool_mcasts_out_names, cname) != -1) {
	    adaptorNIO->et_idx_mcasts_out = ii+1;
	    adaptorNIO->et_found |= HSP_ETCTR_MC_OUT;
	  }
	  else if(staticStringsIndexOf(HSP_ethtool_bcasts_in_names, cname) != -1) {
	    adaptorNIO->et_idx_bcasts_in = ii+1;
	    adaptorNIO->et_found |= HSP_ETCTR_BC_IN;
	    }
	  else if(staticStringsIndexOf(HSP_ethtool_bcasts_out_names, cname) != -1) {
	    adaptorNIO->et_idx_bcasts_out = ii+1;
	    adaptorNIO->et_found |= HSP_ETCTR_BC_OUT;
	  }
	  if(staticStringsIndexOf(HSP_ethtool_peer_ifindex_names, cname) != -1) {
	    // Now go ahead and make the call to get the peer_ifindex. This should
	    // work for veth pairs. If the container's device is a macvlan then it's
	    // peer ifIndex will be reported as 0.
	    // Understanding where a macvlan connects to can be
	    // gleaned from a netlink call to RTM_GETLINK,  where the IFLA_LINK
	    // attribute should have the ifIndex of the interface that the macvlan
	    // is on.  See https://github.com/jbenc/plotnetcfg.  However we don't
	    // really need that information to correctly model a macvlan setup as
	    // an sFlow bridge,  so we don't even try to get it here.
	      struct ethtool_stats *et_stats = (struct ethtool_stats *)my_calloc(bytes);
	      et_stats->cmd = ETHTOOL_GSTATS;
	      et_stats->n_stats = adaptorNIO->et_nctrs;
	      ifr->ifr_data = (char *)et_stats;
	      if(ioctl(fd, SIOCETHTOOL, ifr) >= 0) {
		adaptor->peer_ifIndex = et_stats->data[ii];
		adaptorAddOrReplace(sp->adaptorsByPeerIndex, adaptor, "byPeerIndex");
		EVDebug(mod, 1, "Interface %s (ifIndex=%u) has peer_ifindex=%u",
			adaptor->deviceName,
			adaptor->ifIndex,
			adaptor->peer_ifIndex);
	      }
	      my_free(et_stats);
	  }
	}
      }
      my_free(ctrNames);
    }
  }

/*________________---------------------------__________________
  ________________  read_ethtool_info        __________________
  ----------------___________________________------------------
*/

  static bool read_ethtool_info(HSP *sp, struct ifreq *ifr, int fd, SFLAdaptor *adaptor)
  {
    bool changed = NO;
    HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);

    if(nio->ethtool_GDRVINFO) {
      changed |= ethtool_get_GDRVINFO(sp, ifr, fd, adaptor);
    }

#if ( HSP_OPTICAL_STATS && ETHTOOL_GMODULEINFO )
    if(nio->ethtool_GMODULEINFO) {
      changed |= ethtool_get_GMODULEINFO(sp, ifr, fd, adaptor);
    }
#endif

    // GLINKSETTINGS should eventually take over from GSET
    bool glinkSettingsOK = NO;
#ifdef ETHTOOL_GLINKSETTINGS
    if(nio->ethtool_GLINKSETTINGS) {
      changed |= ethtool_get_GLINKSETTINGS(sp, ifr, fd, adaptor, &glinkSettingsOK);
    }
#endif

#ifdef ETHTOOL_GSET
    // But fall back on GSET if the GLINKSETTINGS syscall fails (e.g. Debian 9)
    if(glinkSettingsOK==NO && nio->ethtool_GSET) {
      changed |= ethtool_get_GSET(sp, ifr, fd, adaptor);
    }
#endif

    if(nio->ethtool_GSTATS) {
      ethtool_get_GSTATS(sp, ifr, fd, adaptor);
    }
    return changed;
  }


/*________________---------------------------__________________
  ________________   detectInterfaceChange   __________________
  ----------------___________________________------------------
  Check for any change to the set of interface.  This can be used
  to trigger a more extensive re-read of the interface state.
  Currently it won't detect changes such as a new interface
  being added,  and it won't detect changes in MAC/IP/VLAN.  We
  could add checks for all those things but the risk is that we
  end up doing too much work.  By keeping this light we can call
  it more frequently,  however listening for interface changes via
  netlink will probably work better for this.
*/

  bool detectInterfaceChange(HSP *sp)
  {
    EVMod *mod = sp->rootModule;
    int fd = socket (PF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
      fprintf (stderr, "error opening socket: %d (%s)\n", errno, strerror(errno));
      return 0;
    }
    SFLAdaptor *changed = NULL;
    SFLAdaptor *ad;
    UTHASH_WALK(sp->adaptorsByName, ad) {
      EVDebug(mod, 3, "detectInterfaceChange: testing %s", ad->deviceName);
      struct ifreq ifr;
      memset(&ifr, 0, sizeof(ifr));
      strncpy(ifr.ifr_name, ad->deviceName, IFNAMSIZ-1);
      if(ioctl(fd,SIOCGIFFLAGS, &ifr) < 0) {
	EVDebug(mod, 1, "device %s Get SIOCGIFFLAGS failed : %s",
		ad->deviceName,
		strerror(errno));
	changed = ad;
	break;
      }
      int up = (ifr.ifr_flags & IFF_UP) ? YES : NO;
      int loopback = (ifr.ifr_flags & IFF_LOOPBACK) ? YES : NO;
      int bond_master = (ifr.ifr_flags & IFF_MASTER) ? YES : NO;
      int bond_slave = (ifr.ifr_flags & IFF_SLAVE) ? YES : NO;
      HSPAdaptorNIO *nio = ADAPTOR_NIO(ad);
      if(nio->up != up
	 || nio->loopback != loopback
	 || nio->bond_master != bond_master
	 || nio->bond_slave != bond_slave) {
	changed = ad;
	break;
      }
    }
    close (fd);
    if(changed)
      EVDebug(mod, 1, "detectInterfaceChange: found change in %s", changed->deviceName);
    return (changed != NULL);
  }

/*________________---------------------------__________________
  ________________      readInterfaces       __________________
  ----------------___________________________------------------
*/

  int readInterfaces(HSP *sp, bool full_discovery,  uint32_t *p_added, uint32_t *p_removed, uint32_t *p_cameup, uint32_t *p_wentdown, uint32_t *p_changed)
  {
    EVMod *mod = sp->rootModule;

    if(full_discovery)
      EVEventTxAll(mod, HSPEVENT_INTFS_START, NULL, 0);

    uint32_t ad_added=0, ad_removed=0, ad_cameup=0, ad_wentdown=0, ad_changed=0;

  // keep v4 and v6 separate to simplify HT logic
  UTHash *newLocalIP = UTHASH_NEW(HSPLocalIP, ipAddr.address.ip_v4, UTHASH_DFLT);
  UTHash *newLocalIP6 = UTHASH_NEW(HSPLocalIP, ipAddr.address.ip_v6, UTHASH_DFLT);

  // mark-and-sweep. Mark all existing adaptors (that are managed by this mod)
  {
    SFLAdaptor *ad;
    UTHASH_WALK(sp->adaptorsByName, ad)
      if(ad->marked == mod->id)
	markAdaptor(ad);
  }

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

  FILE *procFile = fopen(PROCFS_STR "/net/dev", "r");
  if(procFile) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    char line[MAX_PROC_LINE_CHARS];
    int lineNo = 0;
    int truncated;
    while(my_readline(procFile, line, MAX_PROC_LINE_CHARS, &truncated) != EOF) {
      if(lineNo++ < 2) continue; // skip headers
      // the device name is always the first token before the ":"
      char buf[MAX_PROC_LINE_CHARS];
      char *p = line;
      char *devName = parseNextTok(&p, " \t:", NO, '\0', YES, buf, MAX_PROC_LINE_CHARS);
      if(devName == NULL) continue;
      int devNameLen = my_strlen(devName);
      if(devNameLen == 0 || devNameLen >= IFNAMSIZ) continue;
      // we set the ifr_name field to make our queries
      strncpy(ifr.ifr_name, devName, IFNAMSIZ-1);

      EVDebug(mod, 3, "reading interface %s", devName);

      // Get the flags for this interface
      if(ioctl(fd,SIOCGIFFLAGS, &ifr) < 0) {
	// Can get here if the interface was just removed under our feet.
	myLog(LOG_INFO, "device %s Get SIOCGIFFLAGS failed : %s",
	      devName,
	      strerror(errno));
	continue;
      }

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

      // Try and get the MAC Address for this interface
      u_char macBytes[6];
      int gotMac = NO;
      if(ioctl(fd,SIOCGIFHWADDR, &ifr) < 0) {
	myLog(LOG_INFO, "device %s Get SIOCGIFHWADDR failed : %s",
	      devName,
	      strerror(errno));
      }
      else {
	memcpy(macBytes, (u_char *)&ifr.ifr_hwaddr.sa_data, 6);
	gotMac = YES;
      }

      // Try and get the ifIndex for this interface
      uint32_t ifIndex = 0;
      if(ioctl(fd,SIOCGIFINDEX, &ifr) < 0) {
	// only complain about this if we are debugging
	EVDebug(mod, 1, "device %s Get SIOCGIFINDEX failed : %s",
		devName,
		strerror(errno));
      }
      else {
	ifIndex = ifr.ifr_ifindex;
      }

      // find existing adaptor by name.  We use adaptorsByName as the primary lookup here
      // assuming that every interface has a unique, non-empty name. We treat this as being
      // the same interface if it appears with the same name, ifIndex and MAC as last time.
      // Otherwise a new adaptor object is inserted. Any previous adaptor objects that are not
      // found in this way are deleted (from all lookup tables) using the mark-and-sweep
      // mechanism.

      // for now just assume that each interface has only one MAC.  It's not clear how we can
      // learn multiple MACs this way anyhow.  It seems like there is just one per ifr record.
      // find or create a new "adaptor" entry
      SFLAdaptor *adaptor = nioAdaptorNew(mod, devName, (gotMac ? macBytes : NULL), ifIndex);

      bool addAdaptorToHT = YES;

      SFLAdaptor *existing = adaptorByName(sp, devName);
      if(existing
	 && adaptorEqual(adaptor, existing)) {
	// found by name, and no change to (name,ifIndex,MAC), so use existing object
	// note that attributes such as peer_ifIndex may differ here, but they may not
	// have been looked up yet.
	adaptorFree(adaptor);
	// this adaptor is going to survive
	adaptor = existing;
	// reset the mark so we don't free it below
	unmarkAdaptor(adaptor);
	// indicate that it is already in the lookup tables
	addAdaptorToHT = NO;
      }

      // this flag might belong in the adaptorNIO struct
      adaptor->promiscuous = promisc;

      // remember some useful flags in the userData structure
      HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
      if(adaptorNIO->up != up) {
	if(up) {
	  ad_cameup++;
	  // trigger test for module eeprom data
	  adaptorNIO->ethtool_GMODULEINFO = YES;
	}
	else ad_wentdown++;
	EVDebug(mod, 1, "adaptor %s %s",
		adaptor->deviceName,
		up ? "came up" : "went down");
      }
      adaptorNIO->up = up;

      // make sure we notice changes
      if(adaptorNIO->loopback != loopback
	 || adaptorNIO->bond_master != bond_master
	 || adaptorNIO->bond_slave != bond_slave)
	ad_changed++;

      adaptorNIO->loopback = loopback;
      adaptorNIO->bond_master = bond_master;
      adaptorNIO->bond_slave = bond_slave;

      // Try to get the IP address for this interface
      if(ioctl(fd,SIOCGIFADDR, &ifr) < 0) {
	// only complain about this if we are debugging
	EVDebug(mod, 1, "device %s Get SIOCGIFADDR failed : %s",
		devName,
		strerror(errno));
      }
      else {
	if (ifr.ifr_addr.sa_family == AF_INET) {
	  struct sockaddr_in *s = (struct sockaddr_in *)&ifr.ifr_addr;
	  // IP addr is now s->sin_addr
	  adaptorNIO->ipAddr.type = SFLADDRESSTYPE_IP_V4;
	  adaptorNIO->ipAddr.address.ip_v4.addr = s->sin_addr.s_addr;
	  // add to localIP hash too
	  addLocalIP(sp, newLocalIP, &adaptorNIO->ipAddr, adaptor->deviceName);
	}
	//else if (ifr.ifr_addr.sa_family == AF_INET6) {
	// not sure this ever happens - on a linux system IPv6 addresses
	// are picked up from /proc/net/if_inet6
	// struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ifr.ifr_addr;
	// IP6 addr is now s->sin6_addr;
	//}
      }

      if(full_discovery) {
	// allow modules to supply additional info on this adaptor
	// (and influence ethtool data-gathering).  We broadcast this
	// but it only really makes sense to receive it on the POLL_BUS
	EVEventTxAll(sp->rootModule, HSPEVENT_INTF_READ, &adaptor, sizeof(adaptor));
	if(adaptorNIO->changed_external) {
	  // notice the change here, then reset it
	  // for the next cycle.  So any external change
	  // between now and then will be noticed.
	  ad_changed++;
	  adaptorNIO->changed_external = NO;
	}
	// TODO: need flag in adaptor to indicate that something changed - so we
	// can increment ad_changed here.
	// use ethtool to get info about direction/speed, peer_ifIndex and more
	if(read_ethtool_info(sp, &ifr, fd, adaptor) == YES) {
	  ad_changed++;
	}
      }

      if(addAdaptorToHT) {
	// it is a new adaptor name or the mac or ifindex appeared to change.
	// That could mean it is a new interface, or it could mean something
	// more subtle such as that the interface was renamed, or given a new
	// ifIndex or MAC.  Either way, this is a newly allocated adaptor
	// object that needs to be inserted into the lookup tables.
	ad_added++;
	adaptorAddOrReplace(sp->adaptorsByName, adaptor, "byName");
	// add to "all namespaces" collections too.
	if(gotMac) adaptorAddOrReplace(sp->adaptorsByMac, adaptor, "byMac");
	if(ifIndex) adaptorAddOrReplace(sp->adaptorsByIndex, adaptor, "byIndex");
      }

    }
    fclose(procFile);
  }

  close (fd);

  // now remove and free any that are still marked
  ad_removed = deleteMarkedAdaptors(sp, sp->adaptorsByName, YES);

  // check in case any of the survivors are specific
  // to a particular VLAN
  readVLANs(sp);

  // sweep for additional layer3 addresses
  readL3Addresses(sp, newLocalIP, newLocalIP6);
  readIPv6Addresses(sp, newLocalIP6);

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
  if(oldLocalIP)
    freeLocalIPs(oldLocalIP);
  if(oldLocalIP6)
    freeLocalIPs(oldLocalIP6);

  if(full_discovery)
      EVEventTxAll(mod, HSPEVENT_INTFS_END, NULL, 0);

  return sp->adaptorsByName->entries;
}

/*________________---------------------------__________________
  ________________   isLocalAddress          __________________
  ----------------___________________________------------------
*/
  bool isLocalAddress(HSP *sp, SFLAddress *addr) {
    UTHash *localHT = (addr->type == SFLADDRESSTYPE_IP_V6)
      ? sp->localIP6
      : sp->localIP;
    HSPLocalIP search = { .ipAddr = *addr };
    return (UTHashGet(localHT, &search) != NULL);
  }
  

#if defined(__cplusplus)
} /* extern "C" */
#endif
