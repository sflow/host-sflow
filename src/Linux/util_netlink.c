/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "util_netlink.h"

  /*_________________---------------------------__________________
    _________________      UTNLDiag_send        __________________
    -----------------___________________________------------------
  */

  int UTNLDiag_send(int sockfd, void *req, int req_len, bool dump, uint32_t seqNo) {
    struct nlmsghdr nlh = { };
    nlh.nlmsg_len = NLMSG_LENGTH(req_len);
    nlh.nlmsg_flags = NLM_F_REQUEST;
    if(dump)
      nlh.nlmsg_flags |= NLM_F_DUMP;
    nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    nlh.nlmsg_seq = seqNo;

    struct iovec iov[2] = {
      { .iov_base = &nlh, .iov_len = sizeof(nlh) },
      { .iov_base = req,  .iov_len = req_len }
    };

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct msghdr msg = { .msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = iov, .msg_iovlen = 2 };
    return sendmsg(sockfd, &msg, 0);
  }

  /*_________________---------------------------__________________
    _________________     UTNLDiag_recv         __________________
    -----------------___________________________------------------
  */

  void UTNLDiag_recv(void *magic, int sockFd, UTNLDiagCB diagCB)
  {
    uint8_t recv_buf[HSP_READNL_RCV_BUF];
    int batch = 0;
    if(sockFd > 0) {
      for( ; batch < HSP_READNL_BATCH; batch++) {
	int numbytes = recv(sockFd, recv_buf, sizeof(recv_buf), 0);
	if(numbytes <= 0)
	  break;
	struct nlmsghdr *nlh = (struct nlmsghdr*) recv_buf;
	while(NLMSG_OK(nlh, numbytes)){
	  if(nlh->nlmsg_type == NLMSG_DONE)
	    break;
	  if(nlh->nlmsg_type == NLMSG_ERROR){
            struct nlmsgerr *err_msg = (struct nlmsgerr *)NLMSG_DATA(nlh);
	    // Frequently see:
	    // "device or resource busy" (especially with NLM_F_DUMP set)
	    // "netlink error" (IPv6 but connection not established)
	    // so only log when debugging:
	    myDebug(1, "Error in netlink message: %d : %s", err_msg->error, strerror(-err_msg->error));
	    break;
	  }
	  struct inet_diag_msg *diag_msg = (struct inet_diag_msg*) NLMSG_DATA(nlh);
	  int rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));
	  (*diagCB)(magic, sockFd, nlh->nlmsg_seq, diag_msg, rtalen);
	  nlh = NLMSG_NEXT(nlh, numbytes);
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________       fcntl utils         __________________
    -----------------___________________________------------------
  */
  static void setNonBlocking(int fd) {
    // set the socket to non-blocking
    int fdFlags = fcntl(fd, F_GETFL);
    fdFlags |= O_NONBLOCK;
    if(fcntl(fd, F_SETFL, fdFlags) < 0) {
      myLog(LOG_ERR, "fcntl(O_NONBLOCK) failed: %s", strerror(errno));
    }
  }

  static void setCloseOnExec(int fd) {
    // make sure it doesn't get inherited, e.g. when we fork a script
    int fdFlags = fcntl(fd, F_GETFD);
    fdFlags |= FD_CLOEXEC;
    if(fcntl(fd, F_SETFD, fdFlags) < 0) {
      myLog(LOG_ERR, "fcntl(F_SETFD=FD_CLOEXEC) failed: %s", strerror(errno));
    }
  }

  /*_________________---------------------------__________________
    _________________    UTNLDiag_open          __________________
    -----------------___________________________------------------
  */

  int UTNLDiag_open(void) {
    // open the netlink monitoring socket
    int nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG);
    if(nl_sock < 0) {
      myLog(LOG_ERR, "nl_sock open failed: %s", strerror(errno));
      return -1;
    }
    setNonBlocking(nl_sock);
    setCloseOnExec(nl_sock);
    return nl_sock;
  }

  /*_________________---------------------------__________________
    _________________    UTNLGeneric_pid        __________________
    -----------------___________________________------------------
    choose a 32-bit id that is likely to be unique even if more
    than one module in this process wants to bind a netlink socket
  */

  static uint32_t UTNLGeneric_pid(uint32_t mod_id) {
    return (mod_id << 16) | getpid();
  }

  /*_________________---------------------------__________________
    _________________    UTNLGeneric_open       __________________
    -----------------___________________________------------------
  */

  int UTNLGeneric_open(uint32_t mod_id) {
    int nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if(nl_sock < 0) {
      myLog(LOG_ERR, "nl_sock open failed: %s", strerror(errno));
      return -1;
    }

    // bind to a suitable id
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK,
			      .nl_pid = UTNLGeneric_pid(mod_id) };
    if(bind(nl_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
      myLog(LOG_ERR, "UTNLGeneric_open: bind failed: %s", strerror(errno));

    setNonBlocking(nl_sock);
    setCloseOnExec(nl_sock);
    return nl_sock;
  }

  /*_________________---------------------------__________________
    _________________      UTNLGeneric_send     __________________
    -----------------___________________________------------------
  */

  int UTNLGeneric_send(int sockfd, uint32_t mod_id, int type, int cmd, int req_type, void *req, int req_len, uint32_t seqNo) {
    struct nlmsghdr nlh = { };
    struct genlmsghdr ge = { };
    struct nlattr attr = { };
    int req_footprint = NLMSG_ALIGN(req_len);

    attr.nla_len = sizeof(attr) + req_len;
    attr.nla_type = req_type;

    ge.cmd = cmd;
    ge.version = 1;

    nlh.nlmsg_len = NLMSG_LENGTH(req_footprint + sizeof(attr) + sizeof(ge));
    nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh.nlmsg_type = type;
    nlh.nlmsg_seq = seqNo;
    nlh.nlmsg_pid = UTNLGeneric_pid(mod_id);

    struct iovec iov[4] = {
      { .iov_base = &nlh,  .iov_len = sizeof(nlh) },
      { .iov_base = &ge,   .iov_len = sizeof(ge) },
      { .iov_base = &attr, .iov_len = sizeof(attr) },
      { .iov_base = req,   .iov_len = req_footprint }
    };

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct msghdr msg = { .msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = iov, .msg_iovlen = 4 };
    return sendmsg(sockfd, &msg, 0);
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif
