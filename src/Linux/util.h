/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#ifndef UTIL_H
#define UTIL_H 1

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h> // for PRIu64 etc.

#include <sys/wait.h>
#include <ctype.h> // for isspace() etc.
#include "pthread.h"

#include <sys/time.h> // for timeradd()

#include "sys/syscall.h" /* just for gettid() */
#define MYGETTID (pid_t)syscall(SYS_gettid)

#include <arpa/inet.h> // for inet_ntop()

#include <regex.h> // for regcomp, regexec

  // adopt a reasonable integer type for "bool" that
  // does not threaten alignment too much and can also be
  // declared in structure fields as 1-bit flags
  // such as "bool flag:1" where space-saving is called for.
  typedef uint32_t bool;
#define YES 1
#define NO 0

#include "sflow.h" // for SFLAddress, SFLAdaptorList...

  // addressing
  bool lookupAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family);
  bool parseNumericAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family);
  int hexToBinary(u_char *hex, u_char *bin, uint32_t binLen);
  int printHex(const u_char *a, int len, u_char *buf, int bufLen, int prefix);
  int parseUUID(char *str, char *uuid);
  int printUUID(const u_char *a, u_char *buf, int bufLen);
  uint32_t hashUUID(char *uuid);
  bool isZeroUUID(char *uuid);

  int printSpeed(const uint64_t speed, char *buf, int bufLen);

  // logger
  void myLogv(int syslogType, char *fmt, va_list args);
  void myLog(int syslogType, char *fmt, ...);
  // expose composable logging calls too
  void myLogv2(int level, bool end, int syslogType, char *fmt, va_list args);
  void myLog2(int level, bool end, int syslogType, char *fmt, ...);
  void setDebug(int level);
  int getDebug(void);
  void setDebugOut(FILE *out);
  FILE *getDebugOut(void);
  void setDebugLimit(long byteLimit);
  long getDebugLimit(void);
  int debug(int level);
  void myDebug(int level, char *fmt, ...);
  void setDaemon(bool yesno);
  bool getDaemon(void);

  // OS allocation
  void *my_os_calloc(size_t bytes);
  void *my_os_realloc(void *ptr, size_t bytes);
  void my_os_free(void *ptr);

#define SYS_CALLOC calloc
#define SYS_REALLOC realloc
#define SYS_FREE free

#ifdef UTHEAP
  // realm allocation (buffer recycling)
  void UTHeapInit(void);
  void *UTHeapQNew(size_t len);
  void *UTHeapQReAlloc(void *buf, size_t newSiz);
  void UTHeapQFree(void *buf);
  void UTHeapGC(void);

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
  char *my_strdup(const char *str);
  int my_strnequal(const char *s1, const char *s2, uint32_t max);
  int my_strequal(const char *s1, const char *s2);
  uint32_t my_strhash(const char *str);
  uint32_t my_binhash(const char *bytes, const uint32_t len);
  int my_readline(FILE *ff, char *buf, uint32_t len, int *p_truncated);

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
  char *trimWhitespace(char *str, uint32_t len);
  void setStr(char **fieldp, char *str);

  // string buffer
  typedef struct _UTStrBuf {
    char *buf;
    size_t len;
    size_t cap;
  } UTStrBuf;

#define UTSTRBUF_LEN(_b) (_b)->len
#define UTSTRBUF_STR(_b) (_b)->buf
#define UTSTRBUF_START 64
  UTStrBuf *UTStrBuf_new(void);
  void UTStrBuf_need(UTStrBuf *buf, size_t len);
  void UTStrBuf_append(UTStrBuf *buf, char *str);
  void UTStrBuf_append_n(UTStrBuf *buf, char *str, size_t len);
  int UTStrBuf_printf(UTStrBuf *buf, char *fmt, ...);
  void UTStrBuf_reset(UTStrBuf *buf);
  size_t UTStrBuf_snip_prefix(UTStrBuf *buf, size_t prefix);
  void UTStrBuf_chomp(UTStrBuf *buf);
  UTStrBuf *UTStrBuf_wrap(char *str);
  char *UTStrBuf_unwrap(UTStrBuf *buf);
  UTStrBuf *UTStrBuf_copy(UTStrBuf *from);
  void UTStrBuf_free(UTStrBuf *buf);

  // string array
  typedef struct _UTStringArray {
    char **strs;
    uint32_t n;
    uint32_t capacity;
    bool sorted;
  } UTStringArray;

  UTStringArray *strArrayNew(void);
  void strArrayAdd(UTStringArray *ar, char *str);
  void strArrayInsert(UTStringArray *ar, int i, char *str);
  void strArrayReset(UTStringArray *ar);
  void strArrayFree(UTStringArray *ar);
  char **strArray(UTStringArray *ar);
  uint32_t strArrayN(UTStringArray *ar);
  char *strArrayAt(UTStringArray *ar, int i);
  void strArraySort(UTStringArray *ar);
  char *strArrayStr(UTStringArray *ar, char *start, char *quote, char *delim, char *end);
  int strArrayEqual(UTStringArray *ar1, UTStringArray *ar2);
  int strArrayIndexOf(UTStringArray *ar, char *str);
  bool strArrayContains(UTStringArray *ar, char *str);

  // obj array
  typedef struct _UTArray {
    void **objs;
    uint32_t n;
    uint32_t cap;
    uint32_t options;
    uint32_t dbins;
    pthread_mutex_t *sync;
  } UTArray;

#define UTARRAY_DFLT 0
#define UTARRAY_SYNC 1
#define UTARRAY_PACK 2
  UTArray *UTArrayNew(int flags);
  uint32_t UTArrayAdd(UTArray *ar, void *obj);
  uint32_t UTArrayAddAll(UTArray *ar, UTArray *add);
  void UTArrayPut(UTArray *ar, void *obj, int i);
  bool UTArrayDel(UTArray *ar, void *obj);
  void *UTArrayDelAt(UTArray *ar, int i);
  void UTArrayPack(UTArray *ar);
  void UTArrayReset(UTArray *ar);
  void UTArrayFree(UTArray *ar);
  uint32_t UTArrayN(UTArray *ar);
  void *UTArrayAt(UTArray *ar, int i);
  void UTArrayPush(UTArray *ar, void *obj);
  void *UTArrayPop(UTArray *ar);
  uint32_t UTArraySnapshot(UTArray *ar, uint32_t buf_n, void *buf);
#define UTARRAY_WALK(ar, obj) for(uint32_t _ii=0; _ii<UTArrayN(ar); _ii++) if(((obj)=(typeof(obj))UTArrayAt((ar), _ii)))

  // tokenizer
  char *parseNextTok(char **str, char *sep, int delim, char quot, int trim, char *buf, int buflen);

  // sleep
  void my_usleep(uint32_t microseconds);

  // calling execve()
  typedef int (*UTExecCB)(void *magic, char *line);
  int myExec(void *magic, char **cmd, UTExecCB lineCB, char *line, size_t lineLen, int *pstatus);

  // SFLAdaptor
  SFLAdaptor *adaptorNew(char *dev, u_char *macBytes, size_t userDataSize, uint32_t ifIndex);
  int adaptorEqual(SFLAdaptor *ad1, SFLAdaptor *ad2);
  void adaptorFree(SFLAdaptor *ad);
  int adaptorInstances(void);

  void markAdaptor(SFLAdaptor *ad);
  bool adaptorIsMarked(SFLAdaptor *ad);
  void unmarkAdaptor(SFLAdaptor *ad);

  // SFLAdaptorList
  SFLAdaptorList *adaptorListNew(void);
  void adaptorListReset(SFLAdaptorList *adList);
  void adaptorListFree(SFLAdaptorList *adList);
#define SFLADAPTOR_MARK_DEL 0x80000000
  void adaptorListMarkAll(SFLAdaptorList *adList);
  int adaptorListFreeMarked(SFLAdaptorList *adList);
  SFLAdaptor *adaptorListGet(SFLAdaptorList *adList, char *dev);
  SFLAdaptor *adaptorListGet_ifIndex(SFLAdaptorList *adList, uint32_t ifIndex);
  void adaptorListAdd(SFLAdaptorList *adList, SFLAdaptor *adaptor);
#define ADAPTORLIST_WALK(al, ad) for(uint32_t _ii = 0; _ii < (al)->num_adaptors; _ii++) if(((ad)=(al)->adaptors[_ii]))

  // file utils
  int UTTruncateOpenFile(FILE *fptr);
  int UTFileExists(char *path);

  // sockets
  typedef union _UTSockAddr {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
  } UTSockAddr;

  void UTSocketRcvbuf(int fd, int requested);
  int UTSocketUDP(char *bindaddr, int family, uint16_t port, int bufferSize);
  int UTUnixDomainSocket(char *path);

  // SFLAddress utils
  char *SFLAddress_print(SFLAddress *addr, char *buf, size_t len);
  int SFLAddress_equal(SFLAddress *addr1, SFLAddress *addr2);
  int SFLAddress_isLoopback(SFLAddress *addr);
  int SFLAddress_isZero(SFLAddress *addr);
  int SFLAddress_isSelfAssigned(SFLAddress *addr);
  int SFLAddress_isRFC1918(SFLAddress *addr);
  int SFLAddress_isLinkLocal(SFLAddress *addr);
  int SFLAddress_isUniqueLocal(SFLAddress *addr);
  int SFLAddress_isMulticast(SFLAddress *addr);
  int SFLAddress_isClassE(SFLAddress *addr);
  void SFLAddress_mask(SFLAddress *addr, SFLAddress *mask);
  int SFLAddress_maskEqual(SFLAddress *addr, SFLAddress *mask, SFLAddress *compare);
  int SFLAddress_parseCIDR(char *str, SFLAddress *addr, SFLAddress *mask, uint32_t *maskBits);

  int isAllZero(u_char *buf, int len);
  int isZeroMAC(SFLMacAddress *mac);
  char *SFLMacAddress_print(SFLMacAddress *addr, char *buf, size_t len);

  // UTHash
  typedef struct _UTHash {
    void **bins;
    pthread_mutex_t *sync;
    uint32_t f_offset;
    uint32_t f_len;
    uint32_t cap;
    uint32_t entries;
    uint32_t dbins;
    uint32_t options;
  } UTHash;

#define UTHASH_DFLT 0
#define UTHASH_SKEY 1
#define UTHASH_SYNC 2
#define UTHASH_IDTY 4
  UTHash *UTHashNew(uint32_t f_offset, uint32_t f_len, uint32_t options);
#define UTHASH_NEW(t,f,o) UTHashNew(offsetof(t, f), sizeof(((t *)0)->f), (o))
  void UTHashFree(UTHash *oh);
  void *UTHashAdd(UTHash *oh, void *obj);
  void *UTHashGet(UTHash *oh, void *obj);
  void *UTHashGetOrAdd(UTHash *oh, void *obj);
  void *UTHashDel(UTHash *oh, void *obj);
  void *UTHashDelKey(UTHash *oh, void *obj);
  void UTHashReset(UTHash *oh);
  uint32_t UTHashN(UTHash *oh);
  void *UTHashNext(UTHash *oh, uint32_t *pCursor);

#define UTHASH_DBIN (void *)-1

#define UTHASH_WALK(oh, obj) for(uint32_t _ii=0; _ii<oh->cap; _ii++) if(((obj)=(typeof(obj))oh->bins[_ii]) && (obj) != UTHASH_DBIN)

  regex_t *UTRegexCompile(char *pattern_str);
  int UTRegexExtractInt(regex_t *rx, char *str, int nvals, int *val1, int *val2, int *val3);

// UTQ: doubly-linked list (requires *prev and *next fields in elements)

#define UTQ(type)      \
  struct {	       \
    type *head;	       \
    type *tail;	       \
  }

#define UTQ_HEAD(q) (q).head
#define UTQ_TAIL(q) (q).tail
#define UTQ_EMPTY(q) ((q).head == NULL)
#define UTQ_CLEAR(q) do { (q).head = NULL; (q).tail = NULL; } while(0)

#define UTQ_ADD_HEAD(q, obj)			\
  do {						\
    (obj)->next = (q).head;			\
    (obj)->prev = NULL;				\
    if((q).head) (q).head->prev = (obj);	\
    else {					\
      (q).tail = (obj);				\
      (q).head = (obj);				\
    }						\
  } while(0)

#define UTQ_ADD_TAIL(q, obj)			\
  do {						\
    if((q).tail) {				\
      (q).tail->next = obj;			\
      (obj)->prev = (q).tail;			\
    }						\
    else {					\
      (q).head = obj;				\
      (obj)->prev = NULL;			\
    }						\
    (q).tail = obj;				\
    (obj)->next = NULL;				\
  } while(0)

#define UTQ_INSERTAFTER(q, obj, after)			\
  do {							\
    (obj)->next = (after)->next;			\
    (obj)->prev = (after);				\
    if((after)->next) (after)->next->prev = (obj);	\
    else (q).tail = (obj);				\
    (after)->next = (obj);				\
  } while(0)

#define UTQ_REMOVE(q, obj)				\
  do {							\
    if((obj)->prev) (obj)->prev->next = (obj)->next;	\
    else (q).head = (obj)->next;			\
    if((obj)->next) (obj)->next->prev = (obj)->prev;	\
    else (q).tail = (obj)->prev;			\
    (obj)->next = (obj)->prev = NULL;			\
  } while(0)

#define UTQ_REMOVE_HEAD(q, result)		\
  do {						\
    result = (q).head;				\
    UTQ_REMOVE(q, result);			\
  } while(0)

#define UTQ_REMOVE_TAIL(q, result)		\
  do {						\
    result = (q).tail;				\
    UTQ_REMOVE(q, result);			\
  } while(0)

#define UTQ_WALK(q, ptr) for((ptr)=(q).head; (ptr); (ptr)=(ptr)->next)
  
#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* UTIL_H */
