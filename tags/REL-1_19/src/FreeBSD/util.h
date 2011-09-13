/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#ifndef UTIL_H
#define UTIL_H 1

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <syslog.h>

#include <sys/types.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h> // for PRIu64 etc.
#include <stdlib.h>

#include <sys/wait.h>
#include <ctype.h> // for isspace() etc.
#include "pthread.h"

#define YES 1
#define NO 0

#include "sflow.h" // for SFLAddress, SFLAdaptorList...

  // sysctl
  int getSys64(char *field, uint64_t *val64p);
  int getSys32(char *field, uint32_t *val32p);

  // addressing
  int lookupAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family);
  int hexToBinary(u_char *hex, u_char *bin, uint32_t binLen);
  int printHex(const u_char *a, int len, u_char *buf, int bufLen, int prefix);
  int parseUUID(char *str, char *uuid);
  int printUUID(const u_char *a, u_char *buf, int bufLen);
  
  // logger
  void myLog(int syslogType, char *fmt, ...);

  // allocation
  void *my_calloc(size_t bytes);
  void *my_realloc(void *ptr, size_t bytes);
  void my_free(void *ptr);

  // mutual-exclusion semaphores
  static inline int lockOrDie(pthread_mutex_t *sem) {
    if(sem && pthread_mutex_lock(sem) != 0) {
      myLog(LOG_ERR, "failed to lock semaphore!");
      exit(EXIT_FAILURE);
    }
    return YES;
  }

  static inline int releaseOrDie(pthread_mutex_t *sem) {
    if(sem && pthread_mutex_unlock(sem) != 0) {
      myLog(LOG_ERR, "failed to unlock semaphore!");
      exit(EXIT_FAILURE);
    }
    return YES;
  }

#define STRINGIFY(Y) #Y
#define STRINGIFY_DEF(D) STRINGIFY(D)

#define DYNAMIC_LOCAL(VAR) VAR
#define SEMLOCK_DO(_sem) for(int DYNAMIC_LOCAL(_ctrl)=1; DYNAMIC_LOCAL(_ctrl) && lockOrDie(_sem); DYNAMIC_LOCAL(_ctrl)=0, releaseOrDie(_sem))

  // string utils
  char *trimWhitespace(char *str);
  void setStr(char **fieldp, char *str);

  // sleep
  void my_usleep(uint32_t microseconds);
  void my_usleep_fd(uint32_t microseconds, int fd);

  // SFLAdaptorList
  SFLAdaptorList *adaptorListNew();
  void adaptorListReset(SFLAdaptorList *adList);
  void adaptorListFree(SFLAdaptorList *adlist);
  SFLAdaptor *adaptorListGet(SFLAdaptorList *adList, char *dev);
  SFLAdaptor *adaptorListAdd(SFLAdaptorList *adList, char *dev, u_char *macBytes);

  // file utils
  int truncateOpenFile(FILE *fptr);

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* UTIL_H */

