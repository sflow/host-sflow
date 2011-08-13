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
#include <sys/socket.h>
#include <syslog.h>
#include <assert.h>

#include <sys/types.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h> // for PRIu64 etc.
#include "malloc.h" // for malloc_stats()

#include <sys/wait.h>
#include <ctype.h> // for isspace() etc.
#include "pthread.h"

#include "sys/syscall.h" /* just for gettid() */
#define MYGETTID (pid_t)syscall(SYS_gettid)

#define YES 1
#define NO 0

#include "sflow.h" // for SFLAddress, SFLAdaptorList...

  // addressing
  int lookupAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family);
  int hexToBinary(u_char *hex, u_char *bin, uint32_t binLen);
  int printHex(const u_char *a, int len, u_char *buf, int bufLen, int prefix);
  int parseUUID(char *str, char *uuid);
  int printUUID(const u_char *a, u_char *buf, int bufLen);
  
  // logger
  void myLog(int syslogType, char *fmt, ...);

  // OS allocation
  void *my_os_calloc(size_t bytes);
  void *my_os_realloc(void *ptr, size_t bytes);
  void my_os_free(void *ptr);

  // realm allocation (buffer recycling)
  void *UTHeapQNew(size_t len);
  void *UTHeapQReAlloc(void *buf, size_t newSiz);
  void UTHeapQFree(void *buf);
  void UTHeapQKeep(void *buf);

#define SYS_CALLOC calloc
#define SYS_REALLOC realloc
#define SYS_FREE free

#ifdef UTHEAP
#define my_calloc UTHeapQNew
#define my_realloc UTHeapQReAlloc
#define my_free UTHeapQFree
#else
#define my_calloc my_os_calloc
#define my_realloc my_os_realloc
#define my_free my_os_free
#endif

  // safer string fns
  uint32_t my_strnlen(const char *s, uint32_t max);
  uint32_t my_strlen(const char *s);
  char *my_strdup(char *str);
  int my_strnequal(char *s1, char *s2, uint32_t max);
  int my_strequal(char *s1, char *s2);

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

  // string array
  typedef struct _UTStringArray {
    char **strs;
    uint32_t n;
    uint32_t capacity;
    int8_t sorted;
  } UTStringArray;

  UTStringArray *strArrayNew();
  void strArrayAdd(UTStringArray *ar, char *str);
  void strArrayReset(UTStringArray *ar);
  void strArrayFree(UTStringArray *ar);
  char **strArray(UTStringArray *ar);
  uint32_t strArrayN(UTStringArray *ar);
  char *strArrayAt(UTStringArray *ar, int i);
  void strArraySort(UTStringArray *ar);
  char *strArrayStr(UTStringArray *ar, char *start, char *quote, char *delim, char *end);
  int strArrayEqual(UTStringArray *ar1, UTStringArray *ar2);
  int strArrayIndexOf(UTStringArray *ar, char *str);

  // string utils
  char *trimWhitespace(char *str);

  // sleep
  void my_usleep(uint32_t microseconds);
  void my_usleep_fd(uint32_t microseconds, int fd);

  // calling execve()
  typedef int (*UTExecCB)(void *magic, char *line);
  int myExec(void *magic, char **cmd, UTExecCB lineCB, char *line, size_t lineLen);

  // SFLAdaptorList
  SFLAdaptorList *adaptorListNew();
  void adaptorListReset(SFLAdaptorList *adList);
  void adaptorListFree(SFLAdaptorList *adList);
  void adaptorListMarkAll(SFLAdaptorList *adList);
  void adaptorListFreeMarked(SFLAdaptorList *adList);
  SFLAdaptor *adaptorListGet(SFLAdaptorList *adList, char *dev);
  SFLAdaptor *adaptorListAdd(SFLAdaptorList *adList, char *dev, u_char *macBytes, size_t userDataSize);

  // file utils
  int truncateOpenFile(FILE *fptr);

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* UTIL_H */

