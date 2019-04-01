/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#ifndef UTIL_NETLINK_H
#define UTIL_NETLINK_H 1

#if defined(__cplusplus)
extern "C" {
#endif

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>
#include <pwd.h>

#include "util.h"

#define HSP_READNL_RCV_BUF 8192
#define HSP_READNL_BATCH 100

  // Kernel TCP states. /include/net/tcp_states.h
  typedef enum {
       TCP_ESTABLISHED = 1,
       TCP_SYN_SENT,
       TCP_SYN_RECV,
       TCP_FIN_WAIT1,
       TCP_FIN_WAIT2,
       TCP_TIME_WAIT,
       TCP_CLOSE,
       TCP_CLOSE_WAIT,
       TCP_LAST_ACK,
       TCP_LISTEN,
       TCP_CLOSING 
  } EnumKernelTCPState;

  char *UTNLDiag_sockid_print(struct inet_diag_sockid *sockid);

  int UTNLDiag_open(void);

  int UTNLDiag_send(int sockfd, void *req, int req_len, bool dump, uint32_t seqNo);

  typedef void (*UTNLDiagCB)(void *magic, int sockFd, uint32_t seqNo, struct inet_diag_msg *diag_msg, int rtalen);
  void UTNLDiag_recv(void *magic, int sockFd, UTNLDiagCB diagCB);

  int UTNLGeneric_open(uint32_t mod_id);

  int UTNLGeneric_send(int sockfd, uint32_t mod_id, int type, int cmd, int req_type, void *req, int req_len, uint32_t seqNo);
  
#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* UTIL_NETLINK_H */
