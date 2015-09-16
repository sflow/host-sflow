/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

  extern int debug;
  
#ifdef HSF_CUMULUS
  /*_________________---------------------------__________________
    _________________    readOneIntFile         __________________
    -----------------___________________________------------------
    function to read an ASCII integer from a file
  */
  
  static int readOneIntFile(char *path, uint64_t *p_ans) {
    int found = 0;
    FILE *intFile = fopen(path, "r");
    if(intFile) {
      found = fscanf(intFile, "%"SCNu64, p_ans);
      fclose(intFile);
    }
    return found;
  }

  /*_________________---------------------------__________________
    _________________    readBroadcomCounters   __________________
    -----------------___________________________------------------
    Called to get latest counters
  */
  
  int readBroadcomCounters(HSP *sp, SFLBCM_tables *bcm) {
    uint64_t scratch64;
    uint64_t mode;

#define HSF_BCM_FILES "/cumulus/switchd/run/"

    struct stat statBuf;
    if(stat(HSF_BCM_FILES, &statBuf) == -1) {
      // don't include this structure at all if none of the data is there,
      // which happens on "VX" virtual switches.
      return NO;
    }

    // hosts
    if(readOneIntFile(HSF_BCM_FILES "route_info/host/count", &scratch64)) bcm->bcm_host_entries = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "route_info/host/max", &scratch64)) bcm->bcm_host_entries_max = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "route_info/host/count_v4", &scratch64)) bcm->bcm_ipv4_neighbors = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "route_info/host/count_v6", &scratch64)) bcm->bcm_ipv6_neighbors = scratch64;

    // routing tables
    if(!readOneIntFile(HSF_BCM_FILES "route_info/route/mode", &mode)) {
      if(debug) myLog(LOG_INFO, "cannot read route-table mode");
    }
    if(mode == 1) {
      // (v4-v6, long-v6)
      if(readOneIntFile(HSF_BCM_FILES "route_info/route/count_0", &scratch64)) bcm->bcm_ipv4_ipv6_entries = scratch64;
      if(readOneIntFile(HSF_BCM_FILES "route_info/route/max_0", &scratch64)) bcm->bcm_ipv4_ipv6_entries_max = scratch64;

      if(readOneIntFile(HSF_BCM_FILES "route_info/route/count_1", &scratch64)) bcm->bcm_long_ipv6_entries = scratch64;
      if(readOneIntFile(HSF_BCM_FILES "route_info/route/max_1", &scratch64)) bcm->bcm_long_ipv6_entries_max = scratch64;
    }
    else if(mode == 2) {
      // (v4, v6)
      if(readOneIntFile(HSF_BCM_FILES "route_info/route/count_0", &scratch64)) bcm->bcm_ipv4_entries = scratch64;
      if(readOneIntFile(HSF_BCM_FILES "route_info/route/max_0", &scratch64)) bcm->bcm_ipv4_entries_max = scratch64;

      if(readOneIntFile(HSF_BCM_FILES "route_info/route/count_1", &scratch64)) bcm->bcm_ipv6_entries = scratch64;
      if(readOneIntFile(HSF_BCM_FILES "route_info/route/max_1", &scratch64)) bcm->bcm_ipv6_entries_max = scratch64;
    }

    // total routes
    if(readOneIntFile(HSF_BCM_FILES "route_info/route/count_total", &scratch64)) bcm->bcm_total_routes = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "route_info/route/max_total", &scratch64)) bcm->bcm_total_routes_max = scratch64;

    // ECMP nexthops
    if(readOneIntFile(HSF_BCM_FILES "route_info/ecmp_nh/count", &scratch64)) bcm->bcm_ecmp_nexthops = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "route_info/ecmp_nh/max", &scratch64)) bcm->bcm_ecmp_nexthops_max = scratch64;

    // MACs
    if(readOneIntFile(HSF_BCM_FILES "route_info/mac/count", &scratch64)) bcm->bcm_mac_entries = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "route_info/mac/max", &scratch64)) bcm->bcm_mac_entries_max = scratch64;

    // ACL ingress (entries, counters, meters, slices)
    if(readOneIntFile(HSF_BCM_FILES "acl_info/ingress/entries", &scratch64)) bcm->bcm_acl_ingress_entries = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "acl_info/ingress/entries_total", &scratch64)) bcm->bcm_acl_ingress_entries_max = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "acl_info/ingress/counters", &scratch64)) bcm->bcm_acl_ingress_counters = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "acl_info/ingress/counters_total", &scratch64)) bcm->bcm_acl_ingress_counters_max = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "acl_info/ingress/meters", &scratch64)) bcm->bcm_acl_ingress_meters = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "acl_info/ingress/meters_total", &scratch64)) bcm->bcm_acl_ingress_meters_max = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "acl_info/ingress/slices", &scratch64)) bcm->bcm_acl_ingress_slices = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "acl_info/ingress/slices_total", &scratch64)) bcm->bcm_acl_ingress_slices_max = scratch64;

    // ACL egress (entries, counters, meters, slices)
    if(readOneIntFile(HSF_BCM_FILES "acl_info/egress/entries", &scratch64)) bcm->bcm_acl_egress_entries = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "acl_info/egress/entries_total", &scratch64)) bcm->bcm_acl_egress_entries_max = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "acl_info/egress/counters", &scratch64)) bcm->bcm_acl_egress_counters = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "acl_info/egress/counters_total", &scratch64)) bcm->bcm_acl_egress_counters_max = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "acl_info/egress/meters", &scratch64)) bcm->bcm_acl_egress_meters = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "acl_info/egress/meters_total", &scratch64)) bcm->bcm_acl_egress_meters_max = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "acl_info/egress/slices", &scratch64)) bcm->bcm_acl_egress_slices = scratch64;
    if(readOneIntFile(HSF_BCM_FILES "acl_info/egress/slices_total", &scratch64)) bcm->bcm_acl_egress_slices_max = scratch64;
    
    return YES;
  }

#endif /* HSF_CUMULUS */

#if defined(__cplusplus)
} /* extern "C" */
#endif

