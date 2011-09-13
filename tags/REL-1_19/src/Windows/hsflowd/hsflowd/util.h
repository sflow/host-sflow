/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#ifndef UTIL_H
#define UTIL_H 1

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <sys/types.h>

#include <ctype.h> // for isspace() etc.

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
#define LOG_EMERG 0
#define LOG_ALERT 1
#define LOG_CRIT 2
#define LOG_ERR 3
#define LOG_WARNING 4
#define LOG_NOTICE 5
#define LOG_INFO 6
#define LOG_DEBUG 7
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
  uint64_t UTHeapQTotal(void);

#define SYS_CALLOC calloc
#define SYS_REALLOC realloc
#define SYS_FREE free

#define UTHEAP 1

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

#define STRINGIFY(Y) #Y
#define STRINGIFY_DEF(D) STRINGIFY(D)

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

  void readAddresses(void);

  // file utils
  int truncateOpenFile(FILE *fptr);

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* UTIL_H */

