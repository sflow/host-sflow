/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
  extern int debug;

#ifdef HSP_DOCKER

#define HSP_DOCKER_MAX_STATS_LINELEN 512


  /*_________________---------------------------__________________
    _________________     readCgroupCounters    __________________
    -----------------___________________________------------------
  */
  
  static int readCgroupCounters(char *cgroup, char *longId, char *fname, int nvals, HSFNameVal *nameVals, int multi) {
    int found = 0;

    char statsFileName[HSP_DOCKER_MAX_FNAME_LEN+1];
#ifdef HSP_SYSTEM_SLICE
    snprintf(statsFileName, HSP_DOCKER_MAX_FNAME_LEN, "/sys/fs/cgroup/%s/system.slice/docker-%s.scope/%s",
	     cgroup,
	     longId,
	     fname);
#else
    snprintf(statsFileName, HSP_DOCKER_MAX_FNAME_LEN, "/sys/fs/cgroup/%s/docker/%s/%s",
	     cgroup,
	     longId,
	     fname);
#endif
    FILE *statsFile = fopen(statsFileName, "r");
    if(statsFile == NULL) {
      if(debug > 1) {
	myLog(LOG_INFO, "cannot open %s : %s", statsFileName, strerror(errno));
      }
    }
    else {
      char line[HSP_DOCKER_MAX_STATS_LINELEN];
      char var[HSP_DOCKER_MAX_STATS_LINELEN];
      uint64_t val64;
      char *fmt = multi ?
	"%*s %s %"SCNu64 :
	"%s %"SCNu64 ;
      while(fgets(line, HSP_DOCKER_MAX_STATS_LINELEN, statsFile)) {
	if(found == nvals && !multi) break;
	if(sscanf(line, fmt, var, &val64) == 2) {
	  for(int ii = 0; ii < nvals; ii++) {
	    char *nm = nameVals[ii].nv_name;
	    if(nm == NULL) break; // null name is double-check
	    if(strcmp(var, nm) == 0)  {
	      nameVals[ii].nv_found = YES;
	      nameVals[ii].nv_val64 += val64;
	      found++;
	    }
	  }
        }
      }
      fclose(statsFile);
    }
    return (found > 0);
  }

  /*_________________---------------------------__________________
    _________________  readContainerCounters    __________________
    -----------------___________________________------------------
  */
  
  int readContainerCounters(char *cgroup, char *longId, char *fname, int nvals, HSFNameVal *nameVals) {
    return readCgroupCounters(cgroup, longId, fname, nvals, nameVals, 0);
  }

  /*_________________-----------------------------__________________
    _________________  readContainerCountersMulti __________________
    -----------------_____________________________------------------
    Variant where the stats file has per-device numbers that need to be summed.
    The device id is assumed to be the first space-separated token on each line.
*/
  
  int readContainerCountersMulti(char *cgroup, char *longId, char *fname, int nvals, HSFNameVal *nameVals) {
    return readCgroupCounters(cgroup, longId, fname, nvals, nameVals, 1);
  }

#endif /* HSP_DOCKER */

#if defined(__cplusplus)
} /* extern "C" */
#endif

