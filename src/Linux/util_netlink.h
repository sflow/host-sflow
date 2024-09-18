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
  bool UTNLDiag_sockid_normalize(struct inet_diag_sockid *sockid);

  int UTNLDiag_open(void);

  int UTNLDiag_send(int sockfd, void *req, int req_len, bool dump, uint32_t seqNo);

  typedef void (*UTNLDiagCB)(void *magic, int sockFd, uint32_t seqNo, struct inet_diag_msg *diag_msg, int rtalen);
  void UTNLDiag_recv(void *magic, int sockFd, UTNLDiagCB diagCB);

  int UTNLGeneric_open(uint32_t mod_id);

  uint32_t UTNLGeneric_pid(uint32_t mod_id);

  int UTNLGeneric_send(int sockfd, uint32_t mod_id, int type, int cmd, int req_type, void *req, int req_len, uint32_t seqNo);

  int UTNLRoute_open(uint32_t mod_id, bool nonBlocking, size_t bufferSize);
  int UTNLRoute_send(int sockfd, uint32_t mod_id, uint32_t ifIndex, uint field, uint32_t seqNo);
  int UTNLRoute_recv(int sockfd, uint field, uint32_t *pIfIndex, char *resultBuf, uint *pResultLen);

  int UTNLUsersock_open(uint32_t mod_id);

  // linux/netlink.h defines struct nlattr but doesn't provide the walking macros NLA_OK, NLA_NEXT.
  // rtnetlink.h provides RTA_OK, RTA_NEXT macros.
  // nfnetlink_compat.h provides NFA_OK, NFA_NEXT macros.
  // genetlink.h does not provide walking macros.
  // libnl provides its own framework.
  // So anticipating that eventually there will be a clean way to include just the struct nlattr
  // walking macros for netlink (i.e. without having to link libnl) we will define them here with
  // a UT prefix:

#define UTNLA_OK(nla,len)	((len) > 0 && (nla)->nla_len >= sizeof(struct nlattr) \
	&& (nla)->nla_len <= (len))
#define UTNLA_NEXT(nla,attrlen)	((attrlen) -= NLA_ALIGN((nla)->nla_len), \
	(struct nlattr *)(((char *)(nla)) + NLA_ALIGN((nla)->nla_len)))
#define UTNLA_LENGTH(len)	(NLA_ALIGN(sizeof(struct nlattr)) + (len))
#define UTNLA_SPACE(len)	NLA_ALIGN(UTNLA_LENGTH(len))
#define UTNLA_DATA(nla)   ((void *)(((char *)(nla)) + UTNLA_LENGTH(0)))
#define UTNLA_PAYLOAD(nla) ((int)((nla)->nla_len) - UTNLA_LENGTH(0))

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* UTIL_NETLINK_H */
