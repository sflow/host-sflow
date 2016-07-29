/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#ifndef HSFLOW_ETHTOOL_H
#define HSFLOW_ETHTOOL_H 1

#if defined(__cplusplus)
extern "C" {
#endif

  static const char *HSP_ethtool_mcasts_in_names[] = {
    "HwIfInMcastPkts",
    "receive-multicast-packet",
    "rx_mcast_packets", // os10
    NULL
  };
  static const char *HSP_ethtool_mcasts_out_names[] = {
    "HwIfOutMcastPkts",
    "tx-multicast-packets",
    "tx_mcast_packets", // os10
    NULL
  };
  static const char *HSP_ethtool_bcasts_in_names[] = {
    "HwIfInBcastPkts",
    "receive-broadcast-packet",
    "rx_bcast_packets", // os10
    NULL
  };
  static const char *HSP_ethtool_bcasts_out_names[] = {
    "HwIfOutBcastPkts",
    "tx-broadcast-packets",
    "tx_bcast_packets", // os10
    NULL
  };
  static const char *HSP_ethtool_peer_ifindex_names[] = {
    "peer_ifindex",
    NULL
  };

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* HSFLOW_ETHTOOL_H */

