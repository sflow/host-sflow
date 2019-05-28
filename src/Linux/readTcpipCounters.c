/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

  // make sure we read whole lines at a time
#define MAX_PROC_LINE_CHARS 2048

  /*_________________---------------------------__________________
    _________________    parseCounterArray      __________________
    -----------------___________________________------------------
  */

  static int parseCounterArray(char *str, uint32_t *counters, int n) {
    char *p = str;
    int ff = 0;
    for(; ff < n; ff++) {
      char buf[MAX_PROC_LINE_CHARS];
      char *var = parseNextTok(&p, " \t", NO, 0, NO, buf, MAX_PROC_LINE_CHARS);
      // stop if we reach the end of the line - or if something was not a number
      if(var == NULL) {
	// no more tokens
	break;
      }
      char *end = NULL;
      long val = strtol(var, &end, 0);
      if(end == var) {
	// nothing was consumed - it wasn't a number
	break;
      }
      counters[ff] = (uint32_t)val;
    }
    return ff;
  }

  /*_________________---------------------------__________________
    _________________    readTcpipCounters      __________________
    -----------------___________________________------------------
  */

  int readTcpipCounters(HSP *sp, SFLHost_ip_counters *c_ip, SFLHost_icmp_counters *c_icmp, SFLHost_tcp_counters *c_tcp, SFLHost_udp_counters *c_udp) {
    int count = 0;
    FILE *procFile;
    char line[MAX_PROC_LINE_CHARS];

    procFile= fopen("/proc/net/snmp", "r");
    if(procFile) {
      int truncated;
      while(my_readline(procFile, line, MAX_PROC_LINE_CHARS, &truncated) != EOF) {
	char *p = line;
	char buf[MAX_PROC_LINE_CHARS];
	char *var = parseNextTok(&p, " \t", NO, 0, NO, buf, MAX_PROC_LINE_CHARS);
	if(strcmp(var, "Ip:") == 0) {
	  count += parseCounterArray(p, (uint32_t *)c_ip, SFLHOST_NUM_IP_COUNTERS);
	}
	else if(strcmp(var, "Icmp:") == 0) {
	  count += parseCounterArray(p, (uint32_t *)c_icmp, SFLHOST_NUM_ICMP_COUNTERS);
	}
	else if(strcmp(var, "Tcp:") == 0) {
	  count += parseCounterArray(p, (uint32_t *)c_tcp, SFLHOST_NUM_TCP_COUNTERS);
	}
	else if(strcmp(var, "Udp:") == 0) {
	  count += parseCounterArray(p, (uint32_t *)c_udp, SFLHOST_NUM_UDP_COUNTERS);
	}
      }
      fclose(procFile);
    }
    return (count > 0);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
