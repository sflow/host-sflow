/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <kstat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/sockio.h>
#include <libdlpi.h>

extern int debug;

/*________________---------------------------__________________
  ________________        readVLANs          __________________
  ----------------___________________________------------------
*/
void readVLANs(HSP *sp)
{
	// dladm show-link?
	; // noop for now
}

/*________________---------------------------__________________
  ________________      readInterfaces       __________________
  ----------------___________________________------------------
*/

int readInterfaces(HSP *sp)
{
	int noErr = 1;
	kstat_ctl_t *kc;
	kstat_t *ksp, *ksp_tmp;
	kstat_named_t *knp;
#ifndef KSNAME_BUFFER_SIZE
#define KSNAME_BUFFER_SIZE 32
#endif
	char devName[KSNAME_BUFFER_SIZE];

	if(sp->adaptorList == NULL)
		sp->adaptorList = adaptorListNew();
	else
		adaptorListMarkAll(sp->adaptorList);

	// Walk the interfaces and collect the non-loopback interfaces so that we
	// have a list of MAC addresses for each interface (usually only 1).
  
	int fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf (stderr, "error opening socket: %d (%s)\n", errno, strerror(errno));
		noErr = 0;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	
	if (noErr) {
		kc = kstat_open();
		if (NULL == kc) {
			noErr = 0;
			myLog(LOG_ERR, "readInterfaces kstat_open failed");
		}
	}

	int up, loopback, promisc, bond_master;
	if (noErr) {
		for (ksp = kc->kc_chain; NULL != ksp; ksp = ksp->ks_next) {
			// Look for kstats of class "net"
			if (!strncmp(ksp->ks_class, "net", 3)) {
#ifndef KSNAME_BUFFER_SIZE
#define KSNAME_BUFFER_SIZE 32
#endif
				// Concatenate the module name and instance number to create device name
				snprintf(devName, KSNAME_BUFFER_SIZE, "%s%d", ksp->ks_module, ksp->ks_instance);
				// If device name equals the kstat's name, then we have a kstat the describes the
				// device.  Don't count loopback.
				if (!strncmp(ksp->ks_name, devName, KSNAME_BUFFER_SIZE) && strcmp(ksp->ks_name, "lo0")) {
					strncpy(ifr.ifr_name, devName, strlen(devName));
					if (0 != ioctl(fd, SIOCGIFFLAGS, &ifr)) {
						myLog(LOG_ERR, "device %s Get SIOCGIFFLAGS failed : %s", devName, strerror(errno));
					} else {
						up = (ifr.ifr_flags & IFF_UP) ? 1 : 0;
						loopback = (ifr.ifr_flags & IFF_LOOPBACK) ? 1: 0;
						promisc = (ifr.ifr_flags & IFF_PROMISC) ? 1 : 0;
						// TODO: No IFF_MASTER so set to 0
						bond_master = 0;

						if (up) {
							int macaddrlen = DLPI_PHYSADDR_MAX;
							char macaddr[DLPI_PHYSADDR_MAX];
							dlpi_handle_t dh;
							if (DLPI_SUCCESS != dlpi_open(devName, &dh, 0)) {
								myLog(LOG_ERR, "device %s dlpi_open failed : %s", devName, strerror(errno));
							} else {
								if (DLPI_SUCCESS != dlpi_get_physaddr(dh, DL_CURR_PHYS_ADDR, macaddr, &macaddrlen)) {
									myLog(LOG_ERR, "device %s dlpi_get_physaddr failed :%s", devName, strerror(errno));
								} 
								dlpi_close(dh);

							}

							// for now just assume that each interface has only one MAC.  It's not clear how we can
							// learn multiple MACs this way anyhow.  It seems like there is just one per ifr record.
							// find or create a new "adaptor" entry
							SFLAdaptor *adaptor = adaptorListAdd(sp->adaptorList, devName, (u_char*)macaddr, sizeof(HSPAdaptorNIO));
							// clear the mark so we don't free it below
							adaptor->marked = NO; 

							// this flag might belong in the adaptorNIO struct
							adaptor->promiscuous = promisc;

							// remember some useful flags in the userData structure
							HSPAdaptorNIO *adaptorNIO = (HSPAdaptorNIO *)adaptor->userData;
							adaptorNIO->loopback = loopback;
							adaptorNIO->bond_master = bond_master;
							adaptorNIO->vlan = HSP_VLAN_ALL; // may be modified below
				
							if (0 != ioctl(fd, SIOCGIFINDEX, &ifr)) {
								myLog(LOG_ERR, "device %s Get SIOCGIFINDEX failed : %s", devName, strerror(errno));
							} else {
								adaptor->ifIndex = ifr.ifr_index;
							}

							if (0 != ioctl(fd, SIOCGIFADDR, &ifr)) {
								myLog(LOG_ERR, "device %s Get SIOCGIFADDR failed : %s", devName, strerror(errno));
							} else {
								if (AF_INET == ifr.ifr_addr.sa_family) {
									struct sockaddr_in *s = (struct sockaddr_in*)&ifr.ifr_addr;
									adaptor->ipAddr.addr = s->sin_addr.s_addr;
								}
							}
							
							ksp_tmp = kstat_lookup(kc, ksp->ks_module, ksp->ks_instance, "mac");
							if (NULL == ksp_tmp) {
								myLog(LOG_ERR, "kstat_lookup error (module: %s, inst: %d, name: mac): %s",
									ksp->ks_module, ksp->ks_instance, strerror(errno));
							} else {
								if (-1 == kstat_read(kc, ksp_tmp, NULL)) {
									myLog(LOG_ERR, "kstat_read error (module: %s, name: %s, class: %s): %s",
										ksp->ks_module, ksp->ks_name, ksp->ks_class, strerror(errno));
								} else {

									knp = kstat_data_lookup(ksp_tmp, "ifspeed");
									adaptor->ifSpeed = knp->value.ui64;

									uint32_t direction = 0;
									knp = kstat_data_lookup(ksp_tmp, "link_duplex");
									// The full-duplex and half-duplex values are reversed between the
									// comment in sflow.h and link_duplex man page.
									if (knp->value.ui32 == 1)
										direction = 2;
									else if (knp->value.ui32 == 2)
										direction = 1;
									adaptor->ifDirection = direction;
								}
							} 

						}
					}
				}
			}
		}
	}

	kstat_close(kc);

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
