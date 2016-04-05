/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#ifndef HSFLOW_ETHTOOL_H
#define HSFLOW_ETHTOOL_H 1

#if defined(__cplusplus)
extern "C" {
#endif

#ifdef HSP_ETHTOOL_STATS
  static const char *HSP_ethtool_mcasts_in_names[] = {
    "HwIfInMcastPkts",
    "receive-multicast-packet",
    NULL
  };
  static const char *HSP_ethtool_mcasts_out_names[] = {
    "HwIfOutMcastPkts",
    "tx-multicast-packets",
    NULL
  };
  static const char *HSP_ethtool_bcasts_in_names[] = {
    "HwIfInBcastPkts",
    "receive-broadcast-packet",
    NULL
  };
  static const char *HSP_ethtool_bcasts_out_names[] = {
    "HwIfOutBcastPkts",
    "tx-broadcast-packets",
    NULL
  };
#endif

#ifdef HSP_DOCKER
  static const char *HSP_ethtool_peer_ifindex_names[] = {
    "peer_ifindex",
    NULL
  };
#endif

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* HSFLOW_ETHTOOL_H */

