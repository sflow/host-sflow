/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>
#include <linux/types.h>
#include <sys/prctl.h>
#include <sched.h>

#include "hsflowd.h"

  // limit the number of chars we will read from each line
  // (there can be more than this - my_readline will chop for us)
#define MAX_PROC_LINE_CHARS 320
#define HSP_VNIC_MAX_FNAME_LEN 255
#define HSP_VNIC_MAX_LINELEN 512

  /*________________---------------------------__________________
    ________________        vnicCB             __________________
    ----------------___________________________------------------
    
    expecting lines of the form:
    VNIC: <ifindex> <device> <mac> <ipv4> <ipv6> <nspid>
  */

  static int vnicCB(EVMod *mod, HSPVMState *vm, char *line, HSPVnicIPCB ipCB) {
    EVDebug(mod, 1, "linkCB: line=<%s>", line);
    char deviceName[HSP_VNIC_MAX_LINELEN];
    char macStr[HSP_VNIC_MAX_LINELEN];
    char ipStr[HSP_VNIC_MAX_LINELEN];
    char ip6Str[HSP_VNIC_MAX_LINELEN];
    uint32_t ifIndex;
    uint32_t nspid;
    if(sscanf(line, "VNIC: %u %s %s %s %s %u", &ifIndex, deviceName, macStr, ipStr, ip6Str, &nspid) == 6) {
      SFLMacAddress mac = {};
      if(hexToBinary((u_char *)macStr, mac.mac, 6) == 6) {
	// adaptor deviceName and ifIndex are not very helpful here because
	// they are private to the namespace of the container (and the ifIndex is
	// NOT globally unique) so the mapping we are harvesting here is really
	// MAC,IP <-> nspid.
	SFLAddress ipAddr = { };
	SFLAddress ip6Addr = { };
	bool gotV4 = parseNumericAddress(ipStr, NULL, &ipAddr, PF_INET);
	gotV4 = gotV4 && !SFLAddress_isZero(&ipAddr);
	bool gotV6 = parseNumericAddress(ip6Str, NULL, &ip6Addr, PF_INET6);
	gotV6 = gotV6 && !SFLAddress_isZero(&ip6Addr); 
	if(gotV4 || gotV6) {
	  // Can use this to associate traffic with this container/pod
	  // if this address appears in sampled packet header as
	  // outer or inner IP
	  if(gotV6) {
	    ipCB(mod, vm, &mac, &ip6Addr, nspid);
	  }
	  if(gotV4) {
	    // ADAPTOR_NIO(adaptor)->ipAddr = ipAddr;
	    ipCB(mod, vm, &mac, &ipAddr, nspid);
	  }
	}
      }
    }
    return YES;
  }

/*________________---------------------------__________________
  ________________    readVNICInterfaces     __________________
  ----------------___________________________------------------
*/

#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0) || (__GLIBC__ <= 2 && __GLIBC_MINOR__ < 14))
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000	/* New network namespace (lo, device, names sockets, etc) */
#endif

#define MY_SETNS(fd, nstype) syscall(__NR_setns, fd, nstype)
#else
#define MY_SETNS(fd, nstype) setns(fd, nstype)
#endif


  int readVNICInterfaces(EVMod *mod, HSPVMState *vm, uint32_t nspid, HSPVnicIPCB ipCB)  {
    struct stat myNS;
    EVDebug(mod, 2, "readVNICInterfaces: pid=%u", nspid);
    if(nspid == 0)
      return 0;

    // learn my own namespace inode from /proc/self/ns/net
    if(stat("/proc/self/ns/net", &myNS) == 0) {
      EVDebug(mod, 1, "my namespace dev.inode == %lu.%lu",
	      myNS.st_dev,
	      myNS.st_ino);
    }
    else {
      myLog(LOG_ERR, "stat(/proc/self/ns/net) failed : %s", strerror(errno));
      return 0;
    }
    
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
      char topath[HSP_VNIC_MAX_FNAME_LEN+1];
      snprintf(topath, HSP_VNIC_MAX_FNAME_LEN, PROCFS_STR "/%u/ns/net", nspid);
      int nsfd = open(topath, O_RDONLY | O_CLOEXEC);
      if(nsfd < 0) {
	fprintf(stderr, "cannot open %s : %s", topath, strerror(errno));
	exit(EXIT_FAILURE);
      }

      struct stat statBuf;
      if(fstat(nsfd, &statBuf) == 0) {
	EVDebug(mod, 2, "vm namespace dev.inode == %lu.%lu", statBuf.st_dev, statBuf.st_ino);
	if(statBuf.st_dev == myNS.st_dev
	   && statBuf.st_ino == myNS.st_ino) {
	  EVDebug(mod, 1, "skip my own namespace");
	  close(nsfd);
	  exit(0);
	}
      }

      /* set network namespace
	 CLONE_NEWNET means nsfd must refer to a network namespace
      */
      if(MY_SETNS(nsfd, CLONE_NEWNET) < 0) {
	fprintf(stderr, "seting network namespace failed: %s", strerror(errno));
	close(nsfd);
	exit(EXIT_FAILURE);
      }

      /* From "man 2 unshare":  This flag has the same effect as the clone(2)
	 CLONE_NEWNS flag. Unshare the mount namespace, so that the calling
	 process has a private copy of its namespace which is not shared with
	 any other process. Specifying this flag automatically implies CLONE_FS
	 as well. Use of CLONE_NEWNS requires the CAP_SYS_ADMIN capability. */
      if(unshare(CLONE_NEWNS) < 0) {
	fprintf(stderr, "seting network namespace failed: %s", strerror(errno));
	close(nsfd);
	exit(EXIT_FAILURE);
      }

      int fd = socket(PF_INET, SOCK_DGRAM, 0);
      if(fd < 0) {
	fprintf(stderr, "error opening socket: %d (%s)\n", errno, strerror(errno));
	close(nsfd);
	exit(EXIT_FAILURE);
      }

      // first build lookup from device name to IPv6 address, since we can't get that
      // using SIOCGIFADDR below.
      // Note: getIfAddrs() is another option but it doesn't provide the locally visible
      // MAC address.  In fact the MAC is the main reason we have to switch namespaces here,
      // otherwise we could just read from /proc/<nspid>/net/dev and /proc/<nspid>/net/if_inet6.
      typedef struct {
	char *ifName;
	SFLAddress ip6;
      } HSPIfNameToV6;
      
      UTHash *v6Addrs = UTHASH_NEW(HSPIfNameToV6, ifName, UTHASH_SKEY);
      FILE *procV6 = fopen(PROCFS_STR "/net/if_inet6", "r");
      if(procV6) {
	char line[MAX_PROC_LINE_CHARS];
	int truncated;
	while(my_readline(procV6, line, MAX_PROC_LINE_CHARS, &truncated) != EOF) {
	  // expect lines of the form "<address> <netlink_no> <prefix_len(HEX)> <scope(HEX)> <flags(HEX)> <deviceName>
	  // (with a header line on the first row)
	  char devName[MAX_PROC_LINE_CHARS];
	  u_char addr[MAX_PROC_LINE_CHARS];
	  u_int devNo, maskBits, scope, flags;
	  if(sscanf(line, "%s %x %x %x %x %s",
		    addr,
		    &devNo,
		    &maskBits,
		    &scope,
		    &flags,
		    devName) == 6) {
	    
	    uint32_t devLen = my_strnlen(devName, MAX_PROC_LINE_CHARS-1);
	    char *trimmed = trimWhitespace(devName, devLen);
	    if(trimmed) {
	      SFLAddress v6addr;
	      v6addr.type = SFLADDRESSTYPE_IP_V6;
	      if(hexToBinary(addr, v6addr.address.ip_v6.addr, 16) == 16) {
		if(!SFLAddress_isLinkLocal(&v6addr)
		   && !SFLAddress_isLoopback(&v6addr)) {
		  HSPIfNameToV6 *v6Entry = my_calloc(sizeof(HSPIfNameToV6));
		  v6Entry->ifName = my_strdup(trimmed);
		  v6Entry->ip6 = v6addr;
		  UTHashAdd(v6Addrs, v6Entry);
		}
	      }
	    }
	  }
	}
	fclose(procV6);
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
	  char buf[MAX_PROC_LINE_CHARS];
	  char *p = line;
	  char *devName = parseNextTok(&p, " \t:", NO, '\0', NO, buf, MAX_PROC_LINE_CHARS);
	  if(devName && my_strlen(devName) < IFNAMSIZ) {
	    strncpy(ifr.ifr_name, devName, sizeof(ifr.ifr_name)-1);
	    // Get the flags for this interface
	    if(ioctl(fd,SIOCGIFFLAGS, &ifr) < 0) {
	      fprintf(stderr, "pod device %s Get SIOCGIFFLAGS failed : %s",
		      devName,
		      strerror(errno));
	    }
	    else {
	      int up = (ifr.ifr_flags & IFF_UP) ? YES : NO;
	      int loopback = (ifr.ifr_flags & IFF_LOOPBACK) ? YES : NO;

	      if(up && !loopback) {
		// try to get ifIndex next, because we only care about
		// ifIndex and MAC when looking at pod interfaces
		if(ioctl(fd,SIOCGIFINDEX, &ifr) < 0) {
		  // only complain about this if we are debugging
		  EVDebug(mod, 1, "pod device %s Get SIOCGIFINDEX failed : %s",
			  devName,
			  strerror(errno));
		}
		else {
		  int ifIndex = ifr.ifr_ifindex;
		  SFLAddress ipAddr = { .type = SFLADDRESSTYPE_IP_V4 };
		  SFLAddress ip6Addr = { .type = SFLADDRESSTYPE_IP_V6 };

		  // see if we can get an IP address
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
		      ipAddr.address.ip_v4.addr = s->sin_addr.s_addr;
		    }
		  }

		  // possibly add a v6 addr
		  HSPIfNameToV6 search = { .ifName = devName };
		  HSPIfNameToV6 *v6Entry = UTHashGet(v6Addrs, &search);
		  if(v6Entry)
		    ip6Addr = v6Entry->ip6;

		  // Get the MAC Address for this interface
		  if(ioctl(fd,SIOCGIFHWADDR, &ifr) < 0) {
		    EVDebug(mod, 1, "device %s Get SIOCGIFHWADDR failed : %s",
			      devName,
			      strerror(errno));
		  }
		  else {
		    u_char macStr[13];
		    printHex((u_char *)&ifr.ifr_hwaddr.sa_data, 6, macStr, 12, NO);
		    char ipStr[64];
		    SFLAddress_print(&ipAddr, ipStr, 64);
		    char ip6Str[64]; // (from a second-hand store...)
		    SFLAddress_print(&ip6Addr, ip6Str, 64);
		    // send this info back up the pipe to my my parent
		    printf("VNIC: %u %s %s %s %s %u\n", ifIndex, devName, macStr, ipStr, ip6Str, nspid);
		  }

		}
	      }
	    }
	  }
	}
	fclose(procFile);
      }
      close(fd);
      close(nsfd);
      exit(0);
    }
    else {
      // in parent
      close(pfd[1]); // close write-end
      // read from read-end
      FILE *ovs;
      if((ovs = fdopen(pfd[0], "r")) == NULL) {
	myLog(LOG_ERR, "readVNICInterfaces: fdopen() failed : %s", strerror(errno));
	close(pfd[0]);
	return 0;
      }
      char line[MAX_PROC_LINE_CHARS];
      int truncated;
      while(my_readline(ovs, line, MAX_PROC_LINE_CHARS, &truncated) != EOF)
	vnicCB(mod, vm, line, ipCB);
      fclose(ovs);
      wait(NULL); // block here until child is done
    }

    return vm->interfaces->num_adaptors;
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
