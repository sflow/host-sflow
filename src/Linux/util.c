/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include "util.h"

  static int debugLevel = 0;
  static bool daemonFlag = YES;
  static FILE *debugOut = NULL;
  static long debugLimit = 0;

  /*________________---------------------------__________________
    ________________       UTStrBuf            __________________
    ----------------___________________________------------------
  */

  static void UTStrBuf_nul_terminate(UTStrBuf *buf) {
    buf->buf[buf->len] = '\0';
  }

  UTStrBuf *UTStrBuf_new() {
    UTStrBuf *buf = (UTStrBuf *)my_calloc(sizeof(UTStrBuf));
    buf->cap = UTSTRBUF_START;
    buf->buf = my_calloc(buf->cap);
    UTStrBuf_nul_terminate(buf);
    return buf;
  }

  static void UTStrBuf_grow(UTStrBuf *buf) {
    buf->cap <<= 2;
    char *newbuf = (char *)my_calloc(buf->cap);
    memcpy(newbuf, buf->buf, buf->len);
    my_free(buf->buf);
    buf->buf = newbuf;
  }

  void UTStrBuf_need(UTStrBuf *buf, size_t len) {
    while((buf->len + len + 1) >= buf->cap) UTStrBuf_grow(buf);
  }

  void UTStrBuf_append_n(UTStrBuf *buf, char *str, size_t len) {
    if(len) {
      UTStrBuf_need(buf, len+1);
      memcpy(buf->buf + buf->len, str, len);
      buf->len += len;
      UTStrBuf_nul_terminate(buf);
    }
  }

  void UTStrBuf_append(UTStrBuf *buf, char *str) {
    UTStrBuf_append_n(buf, str, my_strlen(str));
  }

  int UTStrBuf_printf(UTStrBuf *buf, char *fmt, ...) {
    int ans = 0;
    va_list args;
    va_start(args, fmt);
    // vsnprintf will tell you what space it *would* need
    int needed = vsnprintf(NULL, 0, fmt, args);
    if(needed > 0) {
      UTStrBuf_need(buf, needed+1);
      va_start(args, fmt);
      ans = vsnprintf(buf->buf + buf->len, needed+1, fmt, args);
      buf->len += needed;
    }
    return ans;
  }

  size_t UTStrBuf_snip_prefix(UTStrBuf *buf, size_t prefix) {
    if(buf->len <= prefix) {
      buf->len = 0;
    }
    else {
      buf->len -= prefix;
      memmove(buf->buf, buf->buf + prefix, buf->len);
    }
    UTStrBuf_nul_terminate(buf);
    return buf->len;
  }

  void UTStrBuf_chomp(UTStrBuf *buf) {
    char *p = buf->buf + buf->len - 1;
    if(*p == 13) {
      *p-- = '\0'; // CR
      buf->len--;
    }
    else if(*p == 10) {
      *p-- = '\0'; // LF
      buf->len--;
      if(*p == 13) {
	*p-- = '\0'; // CRLF
	buf->len--;
      }
    }
  }

  void UTStrBuf_reset(UTStrBuf *buf) {
    buf->len = 0;
    UTStrBuf_nul_terminate(buf);
  }
  
  UTStrBuf *UTStrBuf_wrap(char *str) {
    UTStrBuf *buf = UTStrBuf_new();
    UTStrBuf_append(buf, str);
    return buf;
  }

  UTStrBuf *UTStrBuf_copy(UTStrBuf *from) {
    UTStrBuf *buf = UTStrBuf_new();
    UTStrBuf_append_n(buf, UTSTRBUF_STR(from), UTSTRBUF_LEN(from));
    return buf;
  }

  char *UTStrBuf_unwrap(UTStrBuf *buf) {
    char *ans = buf->buf;
    my_free(buf);
    return ans;
  }

  void UTStrBuf_free(UTStrBuf *buf) {
    if(buf->buf) my_free(buf->buf);
    my_free(buf);
  }

  /*_________________---------------------------__________________
    _________________        logging            __________________
    -----------------___________________________------------------
  */

  void setDebugOut(FILE *out) {
    debugOut = out;
  }

  FILE *getDebugOut(void) {
    return debugOut ?: stdout;
  }

  void setDebugLimit(long byteLimit) {
    debugLimit = byteLimit;
  }

  long getDebugLimit(void) {
    return debugLimit;
  }

  void myLogv2(int level, bool end, int syslogType, char *fmt, va_list args) {
    if(level
       || daemonFlag==NO) {
      FILE *out = getDebugOut();
      if(debugLimit == 0
	 || (ftell(out) < debugLimit)) {
	vfprintf(out, fmt, args);
	if(end)
	  fprintf(out, "\n");
      }
    }
    else
      vsyslog(syslogType, fmt, args);
  }

  void myLogv(int syslogType, char *fmt, va_list args) {
    myLogv2(debugLevel, YES, syslogType, fmt, args);
  }

  void myLog2(int level, bool end, int syslogType, char *fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    myLogv2(level, end, syslogType, fmt, args);
  }
    
  void myLog(int syslogType, char *fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    myLogv2(debugLevel, YES, syslogType, fmt, args);
  }

  void setDebug(int level) {
    debugLevel = level;
  }

  int getDebug() {
    return debugLevel;
  }

  int debug(int level) {
    return (debugLevel >= level);
  }

  void myDebug(int level, char *fmt, ...)
  {
    if(debug(level)) {
      myLog2(level, NO, LOG_DEBUG, "dbg%d:", level);
      va_list args;
      va_start(args, fmt);
      myLogv2(level, YES, LOG_DEBUG, fmt, args);
    }
  }

  void setDaemon(bool yesno) {
    daemonFlag = yesno;
  }

  bool getDaemon() {
    return daemonFlag;
  }


  /*_________________---------------------------__________________
    _________________       my_os_allocation    __________________
    -----------------___________________________------------------
  */

  void *my_os_calloc(size_t bytes)
  {
#ifdef UTHEAP
    myDebug(4, "my_os_calloc(%u)", bytes);
#endif
    void *mem = SYS_CALLOC(1, bytes);
    if(mem == NULL) {
      myLog(LOG_ERR, "calloc() failed : %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    return mem;
  }

  void *my_os_realloc(void *ptr, size_t bytes)
  {
#ifdef UTHEAP
    myDebug(4, "my_os_realloc(%u)", bytes);
#endif
    void *mem = SYS_REALLOC(ptr, bytes);
    if(mem == NULL) {
      myLog(LOG_ERR, "realloc() failed : %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    return mem;
  }

  void my_os_free(void *ptr)
  {
    if(ptr) SYS_FREE(ptr);
  }

#ifdef UTHEAP

  /*_________________---------------------------------------__________________
    _________________  Realm allocation (buffer recycling)  __________________
    -----------------_______________________________________------------------
  */

  typedef union _UTHeapHeader {
    uint64_t hdrBits64[2];     // force sizeof(UTBufferHeader) == 128bits to ensure alignment
    union _UTHeapHeader *nxt;  // valid when in linked list waiting to be reallocated
    struct {                   // valid when buffer being used - store bookkeeping info here
      uint32_t realmIdx;
      uint32_t queueIdx;
    } h;
  } UTHeapHeader;

  static UTHeapHeader *UTHeapQHdr(void *buf) {
    return (UTHeapHeader *)buf - 1;
  }

  typedef struct _UTHeapRealm {
#define UT_MAX_BUFFER_Q 32
    UTHeapHeader *bufferLists[UT_MAX_BUFFER_Q];
    pid_t realmIdx;
    uint32_t totalAllocatedBytes;
  } UTHeapRealm;

  // separate realm for each thread
  static __thread UTHeapRealm utRealm;

  static uint32_t UTHeapQSize(void *buf) {
    UTHeapHeader *utBuf = UTHeapQHdr(buf);
    return (1 << utBuf->h.queueIdx) - sizeof(UTHeapHeader);
  }

  /*_________________---------------------------__________________
    _________________         UTHeapQNew        __________________
    -----------------___________________________------------------
    Variable-length, recyclable
  */

  void *UTHeapQNew(size_t len) {
    // initialize the realm so that we can trap on any cross-thread
    // allocation activity.
    if(utRealm.realmIdx == 0) {
      utRealm.realmIdx = MYGETTID;
    }
    // take it up to the nearest power of 2, including room for my header
    // but make sure it is at least 16 bytes (queue 4), so we always have
    // 128-bit alignment (just in case it is needed)
    int queueIdx = 4;
    for(int l = (len + 15) >> 4; l > 0; l >>= 1) queueIdx++;
    UTHeapHeader *utBuf = (UTHeapHeader *)utRealm.bufferLists[queueIdx];
    if(utBuf) {
      // peel it off
      utRealm.bufferLists[queueIdx] = utBuf->nxt;
    }
    else {
      // allocate a new one
      utBuf = (UTHeapHeader *)my_os_calloc(1<<queueIdx);
      utRealm.totalAllocatedBytes += (1<<queueIdx);
    }
    // remember the details so we know what to do on free (overwriting the nxt pointer)
    utBuf->h.realmIdx = utRealm.realmIdx;
    utBuf->h.queueIdx = queueIdx;
    // return a pointer to just after the header
    return (char *)utBuf + sizeof(UTHeapHeader);
  }

  /*_________________---------------------------__________________
    _________________    foreign thread free    __________________
    -----------------___________________________------------------
  */

  static struct {
    UTHeapHeader *foreign;
    pthread_mutex_t *sync_foreign;
    uint32_t n_foreign;
  } UTHeap;

  // call once at startup
  void UTHeapInit() {
    if(UTHeap.sync_foreign == NULL) {
      UTHeap.sync_foreign = (pthread_mutex_t *)SYS_CALLOC(1, sizeof(pthread_mutex_t));
      pthread_mutex_init(UTHeap.sync_foreign, NULL);
      UTHeap.n_foreign = 0;
    }
  }

  // each thread should call this periodically
  void UTHeapGC(void)
  {
    if(UTHeap.n_foreign) {
      SEMLOCK_DO(UTHeap.sync_foreign) {
	for(UTHeapHeader *utBuf = UTHeap.foreign, *prev = NULL; utBuf; ) {
	  UTHeapHeader *nextBuf = utBuf->nxt;
	  if(utBuf->h.realmIdx == utRealm.realmIdx) {
	    // this one is mine - recycle and unlink
	    myDebug(1, "UTHeapGC: realm %u foreign free (n=%u)", utRealm.realmIdx, UTHeap.n_foreign);
	    UTHeapQFree(utBuf);
	    if(prev) prev->nxt = nextBuf;
	    else UTHeap.foreign = nextBuf;
	    UTHeap.n_foreign--;
	  }
	  else prev = utBuf;
	  utBuf = nextBuf;
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    UTHeapQFree            __________________
    -----------------___________________________------------------
  */

  void UTHeapQFree(void *buf)
  {
    UTHeapHeader *utBuf = UTHeapQHdr(buf);
    if(utBuf->h.realmIdx == utRealm.realmIdx) {
      // read the queue index before we overwrite it
      uint16_t queueIdx = utBuf->h.queueIdx;
      memset(utBuf, 0, 1 << queueIdx);
      // put it back on the queue
      utBuf->nxt = (UTHeapHeader *)(utRealm.bufferLists[queueIdx]);
      utRealm.bufferLists[queueIdx] = utBuf;
    }
    else {
      // foreign realm - queue it for the owner to recycle.  Could
      // improve this to use a separate mutex and queue for each
      // realm if we ever find that there is performance pressure.
      SEMLOCK_DO(UTHeap.sync_foreign) {
	utBuf->nxt = UTHeap.foreign;
	UTHeap.foreign = utBuf;
	UTHeap.n_foreign++;
      }
    }
  }

  /*_________________---------------------------__________________
    _________________      UTHeapQReAlloc       __________________
    -----------------___________________________------------------
  */

  void *UTHeapQReAlloc(void *buf, size_t newSiz)
  {
    if(buf == NULL)
      return UTHeapQNew(newSiz);
    size_t siz = UTHeapQSize(buf);
    if(newSiz <= siz)
      return buf;
    void *newBuf = UTHeapQNew(newSiz);
    memcpy(newBuf, buf, siz);
    UTHeapQFree(buf);
    return newBuf;
  }

#endif /* UTHEAP */

  /*_________________---------------------------__________________
    _________________     hashing               __________________
    -----------------___________________________------------------
    Don't expose this directly, so we can swap them out easily for
    alternatives if we want to.
  */

#define FNV_PRIME_32 16777619
#define FNV_OFFSET_32 2166136261U
  static uint32_t hash_fnv1a(const char *s, const uint32_t len)
  {
    uint32_t hash = FNV_OFFSET_32;
    for(uint32_t i = 0; i < len; i++) {
      hash ^= (s[i]);
      hash *= FNV_PRIME_32;
    }
    return hash;
  }

  #if 0
  // See "64-bit to 32-bit hash functions"
  // https://gist.github.com/badboy/6267743
  static uint32_t hash6432shift(uint64_t h) {
    h = (~h) + (h << 18);
    h ^= (h >> 31);
    h *= 21;
    h ^= (h >> 11);
    h += (h << 6);
    h ^= (h >> 22);
    return (uint32_t) h;
  }
  #endif

  /*_________________---------------------------__________________
    _________________     safe string fns       __________________
    -----------------___________________________------------------
  */

#define UT_DEFAULT_MAX_STRLEN 65535

  uint32_t my_strnlen(const char *s, uint32_t max) {
    uint32_t i;
    if(s == NULL) return 0;
    for(i = 0; i < max; i++) if(s[i] == '\0') return i;
    return max;
  }

  uint32_t my_strlen(const char *s) {
    return my_strnlen(s, UT_DEFAULT_MAX_STRLEN);
  }

  char *my_strdup(const char *str)
  {
    if(str == NULL) return NULL;
    uint32_t len = my_strlen(str);
    char *newStr = (char *)my_calloc(len+1);
    memcpy(newStr, str, len);
    return newStr;
  }

  int my_strnequal(const char *s1, const char *s2, uint32_t max) {
    if(s1 == s2) return YES;
    if(s1 == NULL || s2 == NULL) return NO;
    uint32_t len1 = my_strnlen(s1, max);
    uint32_t len2 = my_strnlen(s2, max);
    if(len1 != len2) return NO;
    return (memcmp(s1, s2, len1) == 0);
  }

  int my_strequal(const char *s1, const char *s2) {
    return my_strnequal(s1, s2, UT_DEFAULT_MAX_STRLEN);
  }

  uint32_t my_strhash(const char *str) {
    return hash_fnv1a(str, my_strlen(str));
  }

  uint32_t my_binhash(const char *bytes, const uint32_t len) {
    return hash_fnv1a(bytes, len);
  }

  int my_readline(FILE *ff, char *buf, uint32_t len, int *p_truncated) {
    // read up to len-1 chars from line, but consume the whole line.
    // return number of characters read (0 for empty line), or EOF if file
    // was already at EOF. Always null-terminate the buffer. Indicate
    // number of truncated characters with the pointer provided.
    int ch;
    uint32_t count=0;
    bool atEOF=YES;
    bool bufOK=(buf != NULL
		&& len > 1);
    if(p_truncated)
      *p_truncated = 0;
    while((ch = getc(ff)) != EOF) {
      atEOF = NO;
      // EOL on CR, LF or CRLF
      if(ch == 10 || ch == 13) {
	if(ch == 13) {
	  // peek for CRLF
	  if((ch = getc(ff)) != 10)
	    ungetc(ch, ff);
	}
	break;
      }
      if(bufOK
	 && count < (len-1))
	buf[count++] = ch;
      else if(p_truncated)
	(*p_truncated)++;
    }
    if(bufOK)
      buf[count] = '\0';
    return atEOF ? EOF : count;
  }

  /*_________________---------------------------__________________
    _________________     setStr                __________________
    -----------------___________________________------------------
  */

  void setStr(char **fieldp, char *str) {
    if(*fieldp) my_free(*fieldp);
    (*fieldp) = my_strdup(str);
  }

/*________________---------------------------__________________
  ________________    trimWhitespace         __________________
  ----------------___________________________------------------
*/

  char *trimWhitespace(char *str, uint32_t len)
  {
    // NULL -> NULL
    if(str == NULL)
      return NULL;
    
    // "" -> NULL
    if(len == 0
       || *str == '\0')
      return NULL;
    
    char *end = str + len - 1;

    // Trim leading space
    while(isspace(*str)) {
      // also return NULL for a string with only spaces in it
      // (don't want that condition to slip through unnoticed)
      if(++str > end)
	return NULL;
    }

    // Trim trailing space
    while(end > str
	  && isspace(*end))
      end--;

    // Write new null terminator
    *(end+1) = 0;

    return str;
  }

  /*_________________---------------------------__________________
    _________________     string array          __________________
    -----------------___________________________------------------
  */

  UTStringArray *strArrayNew() {
    return (UTStringArray *)my_calloc(sizeof(UTStringArray));
  }

  static void strArrayGrowthCheck(UTStringArray *ar, int i) {
    if(ar->capacity <= i) {
      uint32_t oldBytes = ar->capacity * sizeof(char *);
      ar->capacity = i + 16;
      uint32_t newBytes = ar->capacity * sizeof(char *);
      char **newArray = (char **)my_calloc(newBytes);
      if(ar->strs) {
	memcpy(newArray, ar->strs, oldBytes);
	my_free(ar->strs);
      }
      ar->strs = newArray;
    }
  }

   void strArrayAdd(UTStringArray *ar, char *str) {
    ar->sorted = NO;
    strArrayGrowthCheck(ar, ar->n);
    if(ar->strs[ar->n]) my_free(ar->strs[ar->n]);
    ar->strs[ar->n++] = my_strdup(str);
  }

  void strArrayInsert(UTStringArray *ar, int i, char *str) {
    ar->sorted = NO;
    strArrayGrowthCheck(ar, i);
    if(ar->strs[i]) my_free(ar->strs[i]);
    ar->strs[i] = my_strdup(str);
    if(i >= ar->n) ar->n = i+1;
  }

   void strArrayReset(UTStringArray *ar) {
    ar->sorted = NO;
    for(uint32_t i = 0; i < ar->n; i++) {
      if(ar->strs[i]) {
	my_free(ar->strs[i]);
	ar->strs[i] = NULL;
      }
    }
    ar->n = 0;
  }

   void strArrayFree(UTStringArray *ar) {
    strArrayReset(ar);
    if(ar->strs) my_free(ar->strs);
    my_free(ar);
  }

   char **strArray(UTStringArray *ar) {
    return ar->strs;
  }

   uint32_t strArrayN(UTStringArray *ar) {
    return ar->n;
  }

   char *strArrayAt(UTStringArray *ar, int i) {
     return(i < ar->n) ? ar->strs[i] : NULL;
  }

  static int mysortcmp(const void *p1, const void* p2) {
    char *s1 = *(char **)p1;
    char *s2 = *(char **)p2;
    if(s1 == s2) return 0;
    if(s1 == NULL) return -1;
    if(s2 == NULL) return 1;
    return strcmp(s1, s2);
  }

   void strArraySort(UTStringArray *ar) {
    qsort(ar->strs, ar->n, sizeof(char *), mysortcmp);
    ar->sorted = YES;
  }

  char *strArrayStr(UTStringArray *ar, char *start, char *quote, char *delim, char *end) {
    UTStrBuf *buf = UTStrBuf_new();
    if(start) UTStrBuf_append(buf, start);
    for(uint32_t i = 0; i < ar->n; i++) {
      if(i && delim) UTStrBuf_append(buf, delim);
      char *str = ar->strs[i];
      if(str) {
	if(quote) UTStrBuf_append(buf, quote);
	UTStrBuf_append(buf, str);
	if(quote) UTStrBuf_append(buf, quote);
      }
    }
    if(end) UTStrBuf_append(buf, end);
    return UTStrBuf_unwrap(buf);
  }

   int strArrayEqual(UTStringArray *ar1, UTStringArray *ar2) {
    if(ar1->n != ar2->n) return NO;
    for(int i = 0; i < ar1->n; i++) {
      char *s1 = ar1->strs[i];
      char *s2 = ar2->strs[i];
      if(!my_strequal(s1, s2)) return NO;
    }
    return YES;
  }

  int strArrayIndexOf(UTStringArray *ar, char *str) {
    //if(ar->sorted) {
    //  char **ptr = (char **)bsearch(&str, ar->strs, ar->n, sizeof(char *), mysortcmp);
    //  return ptr ? (ptr - ar->strs) : 0;
    //}
    //else
    for(int i = 0; i < ar->n; i++) {
      if(my_strequal(str, ar->strs[i])) return i;
    }
    return -1;
  }

  bool strArrayContains(UTStringArray *ar, char *str) {
    return (strArrayIndexOf(ar, str) >= 0);
  }

  static int isSeparator(char ch, char *separators) {
    if(separators == NULL) return NO;
    for(char *sep = separators; (*sep) != '\0'; sep++)
      if((*sep) == ch) return YES;
    return NO;
  }

  char *parseNextTok(char **str, char *sep, int delim, char quot, int trim, char *buf, int buflen)
  {
    if(str == NULL) return NULL;

    char *a = (*str);

    if(a == NULL) {
      // We hit EOS last time and indicated it by setting *str to NULL.
      // Last time we may have returned an empty string to indicate a
      // trailing delimiter (or the whole input was ""). This time
      // we terminate for sure.
      return NULL;
    }

    // initialize buffer to empty string
    buf[0] = '\0';

    if(a[0] == '\0') {
      // return the empty string and make sure we terminate next time
      *str = NULL;
      return buf;
    }

    int buflast = buflen-1;
    int len = 0;

    if(delim && isSeparator(a[0], sep)) {
      // leading delimiter, so don't advance - just allow an
      // empty-string token to be generated.  The delimiter
      // will be consumed below
    }
    else {
      if(!delim) {
	// skip separators
	while(a[0] != '\0' && isSeparator(a[0], sep)) a++;
      }
      if(a[0] == quot) {
	a++; // consume leading quote
	while(a[0] != '\0') {
	  if(a[0] == quot) {
	    a++; // consume it
	    if(a[0] != quot) break; // quotquot -> quot
	  }
	  if(len < buflast) buf[len++] = a[0];
	  a++;
	}
      }
      else {
	while(a[0] != '\0' && !isSeparator(a[0], sep)) {
	  if(len < buflast) buf[len++] = a[0];
	  a++;
	}
      }
    }
    buf[len] = '\0';

    if(!delim) {
      // skip separators again - in case there are no more tokens
      // and this takes us all the way to EOS
      while(a[0] != '\0' && isSeparator(a[0], sep)) a++;
    }

    if(a[0] == '\0') {
      // at EOS, so indicate to the caller that there are no more tokens after this one
      *str = NULL;
    }
    else {
      if(delim) {
	// since we got a token, we need
	// to consume the trailing delimiter if it is there
	if(isSeparator(a[0], sep)) a++;
	// this may mean we are at EOS now, but that implies
	// there is one more (empty-string) token,  so it's
	// correct.
      }
      *str = a;
    }

    return trim ? trimWhitespace(buf, len) : buf;
  }

  /*_________________---------------------------__________________
    _________________        obj array          __________________
    -----------------___________________________------------------
  */

  UTArray *UTArrayNew(int flags) {
    UTArray *ar = (UTArray *)my_calloc(sizeof(UTArray));
    ar->options = flags;
    if(flags & UTARRAY_SYNC) {
      ar->sync = (pthread_mutex_t *)my_calloc(sizeof(pthread_mutex_t));
      pthread_mutex_init(ar->sync, NULL);
    }
    return ar;
  }

  static void arrayGrowthCheck(UTArray *ar, int i) {
    if(ar->cap <= i) {
      uint32_t oldBytes = ar->cap * sizeof(void *);
      // stay two slots under the powers of 2 to make
      // it easier for the allocator to avoid waste
      ar->cap += 2;
      while(ar->cap <= (i+2)) ar->cap *= 2;
      ar->cap -= 2;
      uint32_t newBytes = ar->cap * sizeof(void *);
      void **newArray = (void **)my_calloc(newBytes);
      if(ar->objs) {
	memcpy(newArray, ar->objs, oldBytes);
	my_free(ar->objs);
      }
      ar->objs = newArray;
    }
  }

  static void arrayDeleteCheck(UTArray *ar) {
    ar->dbins++;
    if(ar->options & UTARRAY_PACK
       // used to have more efficient "lazy" pack like this:
       // && ar->n > 8
       // && ar->dbins > (ar->n >> 1)
       // but it's easier if UTARRAY_PACK means "always packed"
       // because less likely to be thrown off by "holes" in
       // the array.  Can revist if efficiency is neeeded.
       )
      UTArrayPack(ar);
  }
    
  uint32_t UTArrayAdd(UTArray *ar, void *obj) {
    int offset = -1;
    SEMLOCK_DO(ar->sync) {
      arrayGrowthCheck(ar, ar->n);
      offset = ar->n;
      ar->objs[ar->n++] = obj;
    }
    return offset;
  }

  uint32_t UTArrayAddAll(UTArray *ar, UTArray *add) {
    SEMLOCK_DO(ar->sync) {
      arrayGrowthCheck(ar, (ar->n + add->n));
      for(int ii = 0; ii < add->n; ii++)
	ar->objs[ar->n++] = add->objs[ii];
    }
    return ar->n;
  }

  void *UTArrayDelAt(UTArray *ar, int i) {
    void *obj = NULL;
    SEMLOCK_DO(ar->sync) {
      if(i < ar->n) {
	obj = ar->objs[i];
	ar->objs[i] = NULL;
	arrayDeleteCheck(ar);
      }
    }
    return obj;
  }

  void UTArrayPush(UTArray *ar, void *obj) {
    UTArrayAdd(ar, obj);
  }

  void *UTArrayPop(UTArray *ar) {
    void *obj = NULL;
    SEMLOCK_DO(ar->sync) {
      if(ar->n > 0) {
	ar->n--;
	obj = ar->objs[ar->n];
	ar->objs[ar->n] = NULL;
      }
    }
    return obj;
  }

  bool UTArrayDel(UTArray *ar, void *obj) {
    bool ans = NO;
    SEMLOCK_DO(ar->sync) {
      for(uint32_t i = 0; i < ar->n; i++) {
	if(ar->objs[i] == obj) {
	  ar->objs[i] = NULL;
	  arrayDeleteCheck(ar);
	  ans = YES;
	  break;
	}
      }
    }
    return ans;
  }

  void UTArrayPut(UTArray *ar, void *obj, int i) {
    SEMLOCK_DO(ar->sync) {
      arrayGrowthCheck(ar, i);
      ar->objs[i] = obj;
      if(i >= ar->n) ar->n = i+1;
    }
  }

  void UTArrayPack(UTArray *ar) {
    SEMLOCK_DO(ar->sync) {
      int found = 0;
      for(uint32_t i = 0; i < ar->n; i++) {
	void *obj = ar->objs[i];
	if(obj) {
	  ar->objs[i] = NULL;
	  ar->objs[found++] = obj;
	}
      }
      ar->dbins = 0;
      ar->n = found;
    }
  }

  void UTArrayReset(UTArray *ar) {
    SEMLOCK_DO(ar->sync) {
      for(uint32_t i = 0; i < ar->n; i++)
	ar->objs[i] = NULL;
      ar->n = 0;
      ar->dbins = 0;
    }
  }

  void UTArrayFree(UTArray *ar) {
    if(ar->sync) {
      UTArrayReset(ar);
      my_free(ar->sync);
    }
    if(ar->objs) my_free(ar->objs);
    my_free(ar);
  }

  uint32_t UTArrayN(UTArray *ar) {
    return ar->n;
  }

  void *UTArrayAt(UTArray *ar, int i) {
    return ((i < ar->n)
	    ? ar->objs[i]
	    : NULL);
  }

  /*________________---------------------------__________________
    ________________       lookupAddress       __________________
    ----------------___________________________------------------
  */

  static bool parseOrResolveAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family, int numeric)
  {
    struct addrinfo *info = NULL;
    struct addrinfo hints = { 0 };
    hints.ai_socktype = SOCK_DGRAM; // constrain this so we don't get lots of answers
    hints.ai_family = family; // PF_INET, PF_INET6 or 0
    if(numeric) {
      hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    }
    int err = getaddrinfo(name, NULL, &hints, &info);
    if(err) {
      myDebug(1, "getaddrinfo() failed: %s", gai_strerror(err));
      switch(err) {
      case EAI_NONAME: break;
      case EAI_NODATA: break;
      case EAI_AGAIN: break; // loop and try again?
      default: myLog(LOG_ERR, "getaddrinfo() error: %s", gai_strerror(err)); break;
      }
      return NO;
    }

    if(info == NULL) return NO;

    if(info->ai_addr) {
      // answer is now in info - a linked list of answers with sockaddr values.
      // extract the address we want from the first one. $$$ should perhaps
      // traverse the list and look for an IPv4 address since that is more
      // likely to work?
      switch(info->ai_family) {
      case PF_INET:
	{
	  struct sockaddr_in *ipsoc = (struct sockaddr_in *)info->ai_addr;
	  memset(addr, 0, sizeof(*addr)); // avoid artifacts in unused bytes
	  addr->type = SFLADDRESSTYPE_IP_V4;
	  addr->address.ip_v4.addr = ipsoc->sin_addr.s_addr;
	  if(sa)
	    memcpy(sa, info->ai_addr, info->ai_addrlen);
	}
	break;
      case PF_INET6:
	{
	  struct sockaddr_in6 *ip6soc = (struct sockaddr_in6 *)info->ai_addr;
	  memset(addr, 0, sizeof(*addr)); // avoid artifacts in unused bytes
	  addr->type = SFLADDRESSTYPE_IP_V6;
	  memcpy(&addr->address.ip_v6, &ip6soc->sin6_addr, 16);
	  if(sa)
	    memcpy(sa, info->ai_addr, info->ai_addrlen);
	}
	break;
      default:
	myLog(LOG_ERR, "get addrinfo: unexpected address family: %d", info->ai_family);
	return NO;
	break;
      }
    }
    // free the dynamically allocated data before returning
    freeaddrinfo(info);
    return YES;
  }

  bool lookupAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family)
  {
    return parseOrResolveAddress(name, sa, addr, family, NO);
  }

  bool parseNumericAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family)
  {
    return parseOrResolveAddress(name, sa, addr, family, YES);
  }

  /*________________---------------------------__________________
    ________________     hex2bin, bin2hex      __________________
    ----------------___________________________------------------
  */

  static u_char hex2bin(u_char c)
  {
    return (isdigit(c) ? (c)-'0': ((toupper(c))-'A')+10)  & 0xf;
  }

  static u_char bin2hex(int nib)
  {
    return (nib < 10) ? ('0' + nib) : ('A' - 10 + nib);
  }

/*_________________---------------------------__________________
  _________________   printHex, hexToBinary   __________________
  -----------------___________________________------------------
*/

  int printHex(const u_char *a, int len, u_char *buf, int bufLen, int prefix)
  {
    int b = 0;
    if(prefix) {
      buf[b++] = '0';
      buf[b++] = 'x';
    }
    for(int i = 0; i < len; i++) {
      if(b > (bufLen - 2)) return 0; // must be room for 2 characters
      u_char byte = a[i];
      buf[b++] = bin2hex(byte >> 4);
      buf[b++] = bin2hex(byte & 0x0f);
    }

    // add NUL termination
    buf[b] = '\0';

    return b;
  }

  int hexToBinary(u_char *hex, u_char *bin, uint32_t binLen)
  {
    // read from hex into bin, up to max binLen chars, return number written
    u_char *h = hex;
    u_char *b = bin;
    u_char c;
    uint32_t i = 0;

    while((c = *h++) != '\0') {
      if(isxdigit(c)) {
	u_char val = hex2bin(c);
	if(isxdigit(*h)) {
	  c = *h++;
	  val = (val << 4) | hex2bin(c);
	}
	*b++ = val;
	if(++i >= binLen) return i;
      }
      else if(c != '.' &&
	      c != '-' &&
	      c != ':') { // allow a variety of byte-separators
	return i;
      }
    }
    return i;
  }

/*_________________---------------------------__________________
  _________________   parseUUID, printUUID    __________________
  -----------------___________________________------------------
*/

  int parseUUID(char *str, char *uuid)
  {
    if(hexToBinary((u_char *)str, (u_char *)uuid, 16) != 16) return NO;
    return YES;
  }

  int printUUID(const u_char *a, u_char *buf, int bufLen)
  {
    int b = 0;
    b += printHex(a, 4, buf, bufLen, NO);
    buf[b++] = '-';
    b += printHex(a + 4, 2, buf + b, bufLen - b, NO);
    buf[b++] = '-';
    b += printHex(a + 6, 2, buf + b, bufLen - b, NO);
    buf[b++] = '-';
    b += printHex(a + 8, 2, buf + b, bufLen - b, NO);
    buf[b++] = '-';
    b += printHex(a + 10, 6, buf + b, bufLen - b, NO);

    // should really be lowercase hex - fix that here
    for(int i = 0; i < b; i++) buf[i] = tolower(buf[i]);

    // add NUL termination
    buf[b] = '\0';

    return b;
  }

  uint32_t hashUUID(char *uuid) {
    return hash_fnv1a(uuid, 16);
  }

  bool isZeroUUID(char *uuid) {
    for(int ii = 0; ii < 16; ii++)
      if(uuid[ii]) return NO;
    return YES;
  }

  /*_________________---------------------------__________________
    _________________     printSpeed            __________________
    -----------------___________________________------------------
  */

  int printSpeed(const uint64_t speed, char *buf, int bufLen)
  {
    // this print may have a truncating effect,  e.g. if the speed
    // were somthing like 10000001.  However as long as we are just
    // using it to match config options then it's OK.
    snprintf(buf, bufLen, "%"PRIu64, speed);
    int digits = my_strlen(buf);
    int chop = 0;
    int mult = '\0';
    if(digits > 12) {
      mult = 'T';
      chop = 12;
    }
    else if(digits > 9) {
      mult = 'G';
      chop = 9;
    }
    else if(digits > 6) {
      mult = 'M';
      chop = 6;
    }
    else if(digits > 3) {
      mult = 'K';
      chop = 3;
    }
    if(chop) {
      digits -= chop;
      buf[digits++] = mult;
      buf[digits] = '\0';
    }
    return digits;
  }

  /*_________________---------------------------__________________
    _________________     my_usleep             __________________
    -----------------___________________________------------------
  */

  void my_usleep(uint32_t microseconds) {
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = microseconds;
    int max_fd = 0;
    int nfds = select(max_fd + 1,
		      (fd_set *)NULL,
		      (fd_set *)NULL,
		      (fd_set *)NULL,
		      &timeout);
    // may return prematurely if a signal was caught, in which case nfds will be
    // -1 and errno will be set to EINTR.  If we get any other error, abort.
    if(nfds < 0 && errno != EINTR) {
      myLog(LOG_ERR, "select() returned %d : %s", nfds, strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  /*_________________---------------------------__________________
    _________________     myExec                __________________
    -----------------___________________________------------------

    like popen(), but more secure coz the shell doesn't get
    to "reimagine" the args.
  */

  int myExec(void *magic, char **cmd, UTExecCB lineCB, char *line, size_t lineLen, int *pstatus)
  {
    int ans = YES;
    int pfd[2];
    pid_t cpid;
    if(pipe(pfd) == -1) {
      myLog(LOG_ERR, "pipe() failed : %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    if((cpid = fork()) == -1) {
      myLog(LOG_ERR, "fork() failed : %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    if(cpid == 0) {
      // in child
      while(close(pfd[0]) == -1 && errno == EINTR);   // close read-end
      while(dup2(pfd[1], 1) == -1 && errno == EINTR); // stdout -> write-end
      while(dup2(pfd[1], 2) == -1 && errno == EINTR); // stderr -> write-end
      while(close(pfd[1]) == -1 && errno == EINTR); // clean up
      // By merging stdout and stderr we make it easier to read the data back
      // but it does mean the caller has to be able to tell the difference between
      // the expected lines of stdout and an error message. See EVBusExec() for a
      // more thorough treatment.
      if(execv(cmd[0], cmd) == -1) {
	myLog(LOG_ERR, "execv(%s,...) failed : errno=%d (%s)", cmd[0], errno, strerror(errno));
	exit(EXIT_FAILURE);
      }
    }
    else {
      // in parent
      while(close(pfd[1]) == -1 && errno == EINTR); // close write-end
      // read from read-end
      FILE *ovs;
      if((ovs = fdopen(pfd[0], "r")) == NULL) {
	myLog(LOG_ERR, "fdopen() failed : %s", strerror(errno));
	exit(EXIT_FAILURE);
      }
      int truncated;
      while(my_readline(ovs, line, lineLen, &truncated) != EOF) {
	myDebug(2, "myExec input> <%s>%s", line, truncated ? " TRUNCATED":"");
	if((*lineCB)(magic, line) == NO) {
	  myDebug(2, "myExec callback returned NO");
	  ans = NO;
	  break;
	}
      }
      fclose(ovs);
      // block here until child is done.
      waitpid(cpid, pstatus, 0);
    }
    return ans;
  }

  /*________________---------------------------__________________
    ________________      adaptor              __________________
    ----------------___________________________------------------
  */

  static __thread int th_n_adaptors=0;
  
  SFLAdaptor *adaptorNew(char *dev, u_char *macBytes, size_t userDataSize, uint32_t ifIndex) {
    SFLAdaptor *ad = (SFLAdaptor *)my_calloc(sizeof(SFLAdaptor));
    ad->deviceName = my_strdup(dev);
    ad->ifIndex = ifIndex;
    ad->userData = my_calloc(userDataSize);
    if(macBytes) {
      memcpy(ad->macs[0].mac, macBytes, 6);
      ad->num_macs = 1;
    }
    th_n_adaptors++;
    return ad;
  }

  int adaptorEqual(SFLAdaptor *ad1, SFLAdaptor *ad2) {
    // must have the same name, ifIndex and MAC
    if(ad1 == ad2) return YES;
    if(ad1 == NULL || ad2 == NULL) return NO;
    if(ad1->ifIndex != ad2->ifIndex) return NO;
    if(ad1->num_macs != ad2->num_macs) return NO;
    if(ad1->num_macs && memcmp(ad1->macs[0].mac, ad2->macs[0].mac, 6)) return NO;
    return (my_strequal(ad1->deviceName, ad2->deviceName));
  }

  void adaptorFree(SFLAdaptor *ad)
  {
    if(ad) {
      if(ad->deviceName) my_free(ad->deviceName);
      if(ad->userData) my_free(ad->userData);
      my_free(ad);
      th_n_adaptors--;
    }
  }

  int adaptorInstances(void) {
    return th_n_adaptors;
  }

  /*________________---------------------------__________________
    ________________      adaptorList          __________________
    ----------------___________________________------------------
  */

  SFLAdaptorList *adaptorListNew()
  {
    SFLAdaptorList *adList = (SFLAdaptorList *)my_calloc(sizeof(SFLAdaptorList));
    adList->capacity = 2; // will grow if necessary
    adList->adaptors = (SFLAdaptor **)my_calloc(adList->capacity * sizeof(SFLAdaptor *));
    adList->num_adaptors = 0;
    return adList;
  }

  void adaptorListReset(SFLAdaptorList *adList)
  {
    for(uint32_t i = 0; i < adList->num_adaptors; i++) {
      if(adList->adaptors[i]) {
	adaptorFree(adList->adaptors[i]);
	adList->adaptors[i] = NULL;
      }
    }
    adList->num_adaptors = 0;
  }

  void adaptorListFree(SFLAdaptorList *adList)
  {
    adaptorListReset(adList);
    my_free(adList->adaptors);
    my_free(adList);
  }

  void markAdaptor(SFLAdaptor *ad)  {
    ad->marked |= SFLADAPTOR_MARK_DEL;
  }

  bool adaptorIsMarked(SFLAdaptor *ad)  {
    return (ad->marked & SFLADAPTOR_MARK_DEL) == SFLADAPTOR_MARK_DEL;
  }

  void unmarkAdaptor(SFLAdaptor *ad)  {
    ad->marked &= ~SFLADAPTOR_MARK_DEL;
  }
  
  void adaptorListMarkAll(SFLAdaptorList *adList)
  {
    SFLAdaptor *ad;
    ADAPTORLIST_WALK(adList, ad)
      markAdaptor(ad);
  }

  int adaptorListFreeMarked(SFLAdaptorList *adList)
  {
    uint32_t removed = 0;
    for(uint32_t i = 0; i < adList->num_adaptors; i++) {
      SFLAdaptor *ad = adList->adaptors[i];
      if(ad
	 && adaptorIsMarked(ad)) {
	adaptorFree(ad);
	adList->adaptors[i] = NULL;
	removed++;
      }
    }
    if(removed > 0) {
      uint32_t found = 0;
      // now pack the array and update the num_adaptors count
      for(uint32_t i = 0; i < adList->num_adaptors; i++) {
	SFLAdaptor *ad = adList->adaptors[i];
	if(ad) adList->adaptors[found++] = ad;
      }
      // cross-check
      if((found + removed) != adList->num_adaptors) {
	myLog(LOG_ERR, "adaptorListFreeMarked: found(%u) + removed(%u) != num_adaptors(%u)",
	      found,
	      removed,
	      adList->num_adaptors);
      }
      adList->num_adaptors = found;
    }
    return (int)removed;
  }

  SFLAdaptor *adaptorListGet(SFLAdaptorList *adList, char *dev)
  {
    SFLAdaptor *ad;
    ADAPTORLIST_WALK(adList, ad)
      if(my_strequal(ad->deviceName, dev)) return ad;
    return NULL;
  }

  SFLAdaptor *adaptorListGet_ifIndex(SFLAdaptorList *adList, uint32_t ifIndex)
  {
    SFLAdaptor *ad;
    ADAPTORLIST_WALK(adList, ad)
      if(ifIndex == ad->ifIndex) return ad;
    return NULL;
  }

  void adaptorListAdd(SFLAdaptorList *adList, SFLAdaptor *adaptor)
  {
    if(adaptorListGet(adList, adaptor->deviceName)) {
      myLog(LOG_ERR, "ERROR: adaptor %s already in list", adaptor->deviceName);
      return;
    }
    if(adList->num_adaptors == adList->capacity) {
      // grow
      adList->capacity *= 2;
      adList->adaptors = (SFLAdaptor **)my_realloc(adList->adaptors, adList->capacity * sizeof(SFLAdaptor *));
    }
    adList->adaptors[adList->num_adaptors++] = adaptor;
  }

  /*________________---------------------------__________________
    ________________     UTTruncateOpenFile     __________________
    ----------------___________________________------------------
  */

  int UTTruncateOpenFile(FILE *fptr)   {
    int fd = fileno(fptr);
    if(fd == -1) {
      myLog(LOG_ERR, "truncateOpenFile(): fileno() failed : %s", strerror(errno));
      return NO;
    }
    if(ftruncate(fd, lseek(fd, 0, SEEK_CUR)) != 0) {
      myLog(LOG_ERR, "truncateOpenFile(): ftruncate() failed : %s", strerror(errno));
      return NO;
    }
    return YES;
  }

  /*________________---------------------------__________________
    ________________     UTFileExists          __________________
    ----------------___________________________------------------
  */

  int UTFileExists(char *path) {
    struct stat statBuf;
    return (stat(path, &statBuf) == 0);
  }

  /*________________---------------------------__________________
    ________________      SFLAddress utils     __________________
    ----------------___________________________------------------
  */

  char *SFLAddress_print(SFLAddress *addr, char *buf, size_t len) {
    return (char *)inet_ntop(addr->type == SFLADDRESSTYPE_IP_V6 ? AF_INET6 : AF_INET,
			     &addr->address,
			     buf,
			     len);
  }

  // TODO: replace "int" with "bool" where appropriate

  int SFLAddress_equal(SFLAddress *addr1, SFLAddress *addr2) {
    if(addr1 == addr2) return YES;
    if(addr1 ==NULL ||addr2 == NULL) return NO;
    if(addr1->type != addr2->type) return NO;
    if(addr1->type == SFLADDRESSTYPE_IP_V6) {
      return (memcmp(addr1->address.ip_v6.addr, addr2->address.ip_v6.addr, 16) == 0);
    }
    else {
      return (addr1->address.ip_v4.addr == addr2->address.ip_v4.addr);
    }
  }

  int SFLAddress_isLoopback(SFLAddress *addr) {
    if(addr->type == SFLADDRESSTYPE_IP_V6) {
      // for IPv6, loopback is always ::1
      uint32_t *x = (uint32_t *)addr->address.ip_v6.addr;
      return (x[0] == 0 &&
	      x[1] == 0 &&
	      x[2] == 0 &&
	      ntohl(x[3]) == 1);
    }
    else {
      // for IPv4, it's 127.0.0.0/8
      char *a = (char *)&(addr->address.ip_v4.addr);
      return a[0] == 127;
    }
  }

  int SFLAddress_isZero(SFLAddress *addr) {
    if(addr->type == SFLADDRESSTYPE_IP_V6) {
      uint32_t *x = (uint32_t *)addr->address.ip_v6.addr;
      return (x[0] == 0 &&
	      x[1] == 0 &&
	      x[2] == 0 &&
	      x[3] == 0);
    }
    else {
      return (addr->address.ip_v4.addr == 0);
    }
  }

  int SFLAddress_isSelfAssigned(SFLAddress *addr) {
    if(addr->type == SFLADDRESSTYPE_IP_V4) {
      // for IPv4, it's 169.254.*
      u_char *a = (u_char *)&(addr->address.ip_v4.addr);
      return (a[0] == 169 &&
	      a[1] == 254);
    }
    return NO;
  }

  int SFLAddress_isRFC1918(SFLAddress *addr) {
    if(addr->type == SFLADDRESSTYPE_IP_V4) {
      u_char *a = (u_char *)&(addr->address.ip_v4.addr);
      if(a[0] == 10 // 10.0.0.0/8
	 || (a[0] == 192 && a[1] == 168) // 192.168.0.0/16
	 || (a[0] == 172 && (a[1] & 0xF0) == 16)) // 172.16.0.0/12
	return YES;
    }
    return NO;
  }

  int SFLAddress_isLinkLocal(SFLAddress *addr) {
    if(addr->type == SFLADDRESSTYPE_IP_V6) {
      // FE80::/10
      return(addr->address.ip_v6.addr[0] == 0xFE &&
	     (addr->address.ip_v6.addr[1] & 0xC0) == 0x80);
    }
    return NO;
  }

  int SFLAddress_isUniqueLocal(SFLAddress *addr) {
    if(addr->type == SFLADDRESSTYPE_IP_V6) {
      // FC00::/7
      return((addr->address.ip_v6.addr[0] & 0xFE) == 0xFC);
    }
    return NO;
  }

  int SFLAddress_isMulticast(SFLAddress *addr) {
    if(addr->type == SFLADDRESSTYPE_IP_V6) {
      // FF00::/8
      return(addr->address.ip_v6.addr[0] == 0xFF);
    }
    else {
      // 224.0.0.0/4
      u_char *a = (u_char *)&(addr->address.ip_v4.addr);
      return ((a[0] & 0xF0) == 224);
    }
    return NO;
  }

  int SFLAddress_isClassE(SFLAddress *addr) {
    if(addr->type == SFLADDRESSTYPE_IP_V6) {
      // TODO: is there a 'do not use' block in IPv6?
      // If changes are made here be sure to apply
      // in agentAddressPriority() fn.
      return NO;
    }
    else {
      // 240.0.0.0/4
      u_char *a = (u_char *)&(addr->address.ip_v4.addr);
      return ((a[0] & 0xF0) == 240);
    }
    return NO;
  }

  void SFLAddress_mask(SFLAddress *addr, SFLAddress *mask) {
    if((mask->type = addr->type) == SFLADDRESSTYPE_IP_V6) {
      for(int ii = 0; ii < 16; ii++) {
	addr->address.ip_v6.addr[ii] &= mask->address.ip_v6.addr[ii];
      }
    }
    else {
      addr->address.ip_v4.addr &= mask->address.ip_v4.addr;
    }
  }

  int SFLAddress_maskEqual(SFLAddress *addr, SFLAddress *mask, SFLAddress *compare) {

    if(addr->type != compare->type) {
      return NO;
    }

    if(addr->type == SFLADDRESSTYPE_IP_V6) {
      for(int ii = 0; ii < 16; ii++) {
	if((addr->address.ip_v6.addr[ii] & mask->address.ip_v6.addr[ii]) != (compare->address.ip_v6.addr[ii] & mask->address.ip_v6.addr[ii])) return NO;
      }
      return YES;
    }
    else {
      return ((addr->address.ip_v4.addr & mask->address.ip_v4.addr) == (compare->address.ip_v4.addr & mask->address.ip_v4.addr));
    }
  }

  static int maskToMaskBits(uint32_t maskaddr)
  {
    int mbits = 0;
    uint32_t mask = ntohl(maskaddr);
    if(mask > 0) {
      mbits = 32;
      while((mask & 1) == 0) {
	mbits--;
	mask >>= 1;
      }
    }
    return mbits;
  }

  static uint32_t maskBitsToMask(uint32_t mbits)
  {
    if(mbits == 0) return 0;
    return ~((1 << (32 - (mbits))) - 1);
  }

  static uint32_t SFLAddress_maskToMaskBits(SFLAddress *mask) {
    if(mask->type == SFLADDRESSTYPE_IP_V6) {
      uint32_t *ii = (uint32_t *)mask->address.ip_v6.addr;
    return (maskToMaskBits(ii[0]) +
	    maskToMaskBits(ii[1]) +
	    maskToMaskBits(ii[2]) +
	    maskToMaskBits(ii[3]));
    }
    else {
      return maskToMaskBits(mask->address.ip_v4.addr);
    }
  }

  static void SFLAddress_maskBitsToMask(uint32_t bits, SFLAddress *mask) {
    if(mask->type == SFLADDRESSTYPE_IP_V4) {
      mask->address.ip_v4.addr = htonl(maskBitsToMask(bits));
    }
    else {
      memset(mask->address.ip_v6.addr, 0, 16);
      uint32_t *ii = (uint32_t *)mask->address.ip_v6.addr;
      int quad = 0;
      while(bits >= 32) {
	ii[quad++] = 0xFFFFFFFF;
	bits -= 32;
      }
      if(bits) ii[quad] = htonl(maskBitsToMask(bits));
    }
  }

  int SFLAddress_parseCIDR(char *str, SFLAddress *addr, SFLAddress *mask, uint32_t *maskBits) {
    if(str == NULL) return NO;
    int len = my_strlen(str);
    int slash = strcspn(str, "/");
    if(len == 0 || slash == 0 || slash >= len) {
      return NO;
    }
    // temporarily blat in a '\0'
    str[slash] = '\0';
    int ok = lookupAddress(str, NULL, addr, 0);
    str[slash] = '/';
    if(ok == NO) return NO;

    // after the slash we can find a mask address or just mask-bits
    int maskAsAddress = NO;
    for(int ii = slash + 1; ii < len; ii++) {
      if(str[ii] == '.' || str[ii] == ':') {
	maskAsAddress = YES;
	break;
      }
    }
    if(maskAsAddress) {
      if(lookupAddress(str + slash + 1, NULL, mask, 0) == NO) {
	return NO;
      }
      *maskBits = SFLAddress_maskToMaskBits(mask);
    }
    else {
      *maskBits = strtol(str + slash + 1, NULL, 0);
      mask->type = addr->type;
      SFLAddress_maskBitsToMask(*maskBits, mask);
    }

    // more checks
    if(addr->type != mask->type) {
      return NO;
    }
    if(addr->type == SFLADDRESSTYPE_IP_V4 && *maskBits > 32) {
      return NO;
    }
    if(addr->type == SFLADDRESSTYPE_IP_V6 && *maskBits > 128) {
      return NO;
    }

    // apply mask to myself
    SFLAddress_mask(addr, mask);

    return YES;
  }

  int isAllZero(u_char *buf, int len) {
    for(int ii = 0; ii < len; ii++) {
      if(buf[ii] != 0) return NO;
    }
    return YES;
  }

  int isZeroMAC(SFLMacAddress *mac) {
    return isAllZero(mac->mac, 6);
  }

  char *SFLMacAddress_print(SFLMacAddress *addr, char *buf, size_t len) {
    printHex(addr->mac, 6, (u_char *)buf, len, NO);
    return buf;
  }

  /*________________---------------------------__________________
    ________________        UTHash             __________________
    ----------------___________________________------------------
    A simple open-hash for structures, where the key is a field
    in the structure - either fixed-length (up to 64-bits) or
    a null-terminated string.  Added this for looking up the
    same SFLAdaptor objects by name, ifIndex, peerIfIndex  and MAC,
    but it's used in other places too.
    Uses linear probing:
    http://www.cs.rmit.edu.au/online/blackboard/chapter/05/documents/contribute/chapter/05/linear-probing.html
    entries can be deleted during a walk.
  */

#define UTHASH_INIT 8 // must be power of 2

#define UTHASH_BYTES(oh) ((oh)->cap * sizeof(void *))

  UTHash *UTHashNew(uint32_t f_offset, uint32_t f_len, uint32_t options) {
    UTHash *oh = (UTHash *)my_calloc(sizeof(UTHash));
    oh->options = options;
    if(options & UTHASH_SYNC) {
      oh->sync = (pthread_mutex_t *)my_calloc(sizeof(pthread_mutex_t));
      pthread_mutex_init(oh->sync, NULL);
    }
    oh->cap = UTHASH_INIT;
    oh->bins = my_calloc(UTHASH_BYTES(oh));
    oh->f_offset = (options & (UTHASH_IDTY)) ? 0 : f_offset;
    oh->f_len = (options & (UTHASH_SKEY|UTHASH_IDTY)) ? 0 : f_len;
    return oh;
  }

  static void *hashAdd(UTHash *oh, void *obj);

  static void hashRebuild(UTHash *oh, bool bigger) {
    uint32_t old_cap = oh->cap;
    void **old_bins = oh->bins;
    if(bigger) oh->cap *= 2;
    oh->bins = my_calloc(UTHASH_BYTES(oh));
    oh->entries = 0;
    oh->dbins = 0;
    for(uint32_t ii = 0; ii < old_cap; ii++)
      if(old_bins[ii] && old_bins[ii] != UTHASH_DBIN)
	hashAdd(oh, old_bins[ii]);
    my_free(old_bins);
  }

  static uint32_t hashHash(UTHash *oh, void *obj) {
    char *f = (char *)obj + oh->f_offset;
    if(oh->f_len) return hash_fnv1a(f, oh->f_len);
    else if(oh->options & UTHASH_IDTY) return (uint32_t)((uint64_t)obj);
    return my_strhash(*(char **)f);
  }

  static bool hashEqual(UTHash *oh, void *obj1, void *obj2) {
    char *f1 = (char *)obj1 + oh->f_offset;
    char *f2 = (char *)obj2 + oh->f_offset;
    return (oh->f_len)
      ? (!memcmp(f1, f2, oh->f_len))
      : ((oh->options & UTHASH_IDTY)
	 ? (obj1 == obj2)
	 : my_strequal(*(char **)f1, *(char **)f2));
  }

  // oh->cap is always a power of 2, so we can just mask the bits
#define UTHASH_WRAP(oh, pr) ((pr) & ((oh)->cap - 1))

static uint32_t hashSearch(UTHash *oh, void *obj, void **found) {
    uint32_t probe = hashHash(oh, obj);
    int32_t dbin = -1;
    probe = UTHASH_WRAP(oh, probe);
    for( ; oh->bins[probe]; probe=UTHASH_WRAP(oh,probe+1)) {
      void *entry = oh->bins[probe];
      if(entry == UTHASH_DBIN) {
	// remember first dbin
	if(dbin == -1)  dbin = probe;
	else if(dbin == probe) break; // all the way around!
      }
      else if(hashEqual(oh, obj, entry)) {
	(*found) = entry;
	return probe;
      }
    }
    // not found - reuse the dbin if we encountered one
    (*found) = NULL;
    return (dbin == -1) ? probe : dbin;
  }

  static void *hashAdd(UTHash *oh, void *obj) {
    if(obj == NULL) return NULL;
    // make sure there is room so the search cannot fail
    if(oh->entries >= (oh->cap >> 1))
      hashRebuild(oh, YES);
    // search for obj or empty slot
    void *found = NULL;
    uint32_t idx = hashSearch(oh, obj, &found);
    // put it here
    oh->bins[idx] = obj;
    if(!found) oh->entries++;
    // return what was there before
    return found;
  }

  void *UTHashAdd(UTHash *oh, void *obj) {
    void *overwritten;
    SEMLOCK_DO(oh->sync) {
      overwritten = hashAdd(oh, obj);
    }
    return overwritten;
  }

  void *UTHashGet(UTHash *oh, void *obj) {
    if(obj == NULL) return NULL;
    void *found = NULL;
    SEMLOCK_DO(oh->sync) {
      hashSearch(oh, obj, &found);
    }
    return found;
  }

  void *UTHashGetOrAdd(UTHash *oh, void *obj) {
    if(obj == NULL) return NULL;
    void *found = NULL;
    SEMLOCK_DO(oh->sync) {
      hashSearch(oh, obj, &found);
      if(!found)
	hashAdd(oh, obj);
    }
    return found;
  }

  static void *hashDelete(UTHash *oh, void *obj, bool identity) {
    if(obj == NULL) return NULL;
    void *found = NULL;
    SEMLOCK_DO(oh->sync) {
      int idx = hashSearch(oh, obj, &found);
      if (found
	  && (found == obj
	      || identity == NO)) {
	oh->bins[idx] = UTHASH_DBIN;
	oh->entries--;
	if(++oh->dbins >= (oh->cap >> 1))
	  hashRebuild(oh, NO);
      }
    }
    return found;
  }

  void *UTHashDel(UTHash *oh, void *obj) {
    // delete this particular object
    return hashDelete(oh, obj, YES);
  }

  void *UTHashDelKey(UTHash *oh, void *obj) {
    // delete whatever is stored under this key
    return hashDelete(oh, obj, NO);
  }

  void UTHashReset(UTHash *oh) {
    memset(oh->bins, 0, UTHASH_BYTES(oh));
    oh->entries = 0;
    oh->dbins = 0;
   }

  uint32_t UTHashN(UTHash *oh) {
    return oh->entries;
  }

  void UTHashFree(UTHash *oh) {
    if(oh == NULL) return;
    my_free(oh->bins);
    if(oh->sync) my_free(oh->sync);
    my_free(oh);
  }

  // Cursor walk. Start from 0.
  // Ordering will be scrambled if HT grows.
  void *UTHashNext(UTHash *oh, uint32_t *pCursor) {
    uint32_t csr = *pCursor;
    // skip over NULLs and DBINS
    while(csr < oh->cap
	  && (oh->bins[csr] == UTHASH_DBIN
	      || oh->bins[csr] == NULL))
      csr++;
    // check for end (can also be off-end if HT was reset)
    if(csr >= oh->cap) {
      // don't advance cursor any further
      *pCursor = csr;
      return NULL;
    }
    else {
      void *obj = oh->bins[csr];
      // advance cursor
      *pCursor = csr + 1;
      return obj;
    }
  }
  
  /*_________________---------------------------__________________
    _________________   socket handling         __________________
    -----------------___________________________------------------
  */
  
  void UTSocketRcvbuf(int fd, int requested) {
    int rcvbuf=0;
    socklen_t rcvbufsiz = sizeof(rcvbuf);
    if(getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &rcvbufsiz) < 0) {
      myLog(LOG_ERR, "UTSocketRcvbuf: getsockopt(SO_RCVBUF) failed: %s", strerror(errno));
    }
    myDebug(1, "UTSocketRcvbuf: socket buffer current=%d", rcvbuf);
    if(rcvbuf < requested) {
      // want more: submit the request
      rcvbuf = requested;
      if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
	myLog(LOG_ERR, "UTSocketRcvbuf: setsockopt(SO_RCVBUF=%d) failed: %s",
	      requested, strerror(errno));
      }
      // see what we actually got
      rcvbufsiz = sizeof(rcvbuf);
      if(getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &rcvbufsiz) < 0) {
	myLog(LOG_ERR, "UTSocketRcvbuf: getsockopt(SO_RCVBUF) failed: %s", strerror(errno));
      }
      myDebug(1, "UTSocketRcvbuf: socket buffer requested=%d received=%d", requested, rcvbuf);
    }
  }

  int UTSocketUDP(char *bindaddr, int family, uint16_t port, int bufferSize)
  {
    struct sockaddr_in myaddr_in = { 0 };
    struct sockaddr_in6 myaddr_in6 = { 0 };
    SFLAddress loopbackAddress = { 0 };
    int soc = 0;

    // create socket
    if((soc = socket(family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
      myLog(LOG_ERR, "error opening socket: %s", strerror(errno));
      return 0;
    }

    // set the socket to non-blocking
    int fdFlags = fcntl(soc, F_GETFL);
    fdFlags |= O_NONBLOCK;
    if(fcntl(soc, F_SETFL, fdFlags) < 0) {
      myLog(LOG_ERR, "fcntl(O_NONBLOCK) failed: %s", strerror(errno));
      close(soc);
      return 0;
    }

    // make sure it doesn't get inherited, e.g. when we fork a script
    fdFlags = fcntl(soc, F_GETFD);
    fdFlags |= FD_CLOEXEC;
    if(fcntl(soc, F_SETFD, fdFlags) < 0) {
      myLog(LOG_ERR, "ULOG fcntl(F_SETFD=FD_CLOEXEC) failed: %s", strerror(errno));
    }

    // lookup bind address
    struct sockaddr *psockaddr = (family == PF_INET6) ?
      (struct sockaddr *)&myaddr_in6 :
      (struct sockaddr *)&myaddr_in;
    if(lookupAddress(bindaddr, psockaddr, &loopbackAddress, family) == NO) {
      myLog(LOG_ERR, "error resolving <%s> : %s", bindaddr, strerror(errno));
      close(soc);
      return 0;
    }

    // bind
    if(family == PF_INET6) myaddr_in6.sin6_port = htons(port);
    else myaddr_in.sin_port = htons(port);
    if(bind(soc,
	    psockaddr,
	    (family == PF_INET6) ?
	    sizeof(myaddr_in6) :
	    sizeof(myaddr_in)) == -1) {
      myLog(LOG_ERR, "bind(%s) failed: %s", bindaddr, strerror(errno));
      close(soc);
      return 0;
    }

    // increase receiver buffer size - but only if the requested size
    // is larger than we already got (sysctl net.core.rmem_default)
    UTSocketRcvbuf(soc, bufferSize);

    return soc;
  }

  int UTUnixDomainSocket(char *path) {
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(fd == -1) {
      myLog(LOG_ERR, "UTUnixDomainSocket - socket() failed: %s", strerror(errno));
      return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);
    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
      myLog(LOG_ERR, "UTUnixDomainSocket(%s) - connect() failed: %s",
	    path,
	    strerror(errno));
      close(fd);
      return -1;
    }
    return fd;
  }

  /*_________________---------------------------__________________
    _________________          regex            __________________
    -----------------___________________________------------------
  */

  regex_t *UTRegexCompile(char *pattern_str) {
    regex_t *rx = (regex_t *)my_calloc(sizeof(regex_t));
    int err = regcomp(rx, pattern_str, REG_EXTENDED | REG_NEWLINE);
    if(err != 0) {
      char errbuf[101];
      myLog(LOG_ERR, "regcomp(%s) failed: %s", pattern_str, regerror(err, rx, errbuf, 100));
      my_free(rx);
      return NULL;
    }
    return rx;
  }

  static int extract_int(char *str, int start, int end) {
    int len = end - start;
    if(start >= 0
       && len > 0
       && len < 16) {
      char extraction[16];
      memcpy(extraction, str + start, len);
      extraction[len] = '\0';
      return strtol(extraction, NULL, 0);
    }
    return -1;
  }

  int UTRegexExtractInt(regex_t *rx, char *str, int nvals, int *val1, int *val2, int *val3) {
    regmatch_t valMatch[4];
    if(regexec(rx, str, nvals+1, valMatch, 0) == 0) {
      if(val1
	 && nvals >= 1) *val1 = extract_int(str, valMatch[1].rm_so, valMatch[1].rm_eo);
      if(val2
	 && nvals >= 2) *val2 = extract_int(str, valMatch[2].rm_so, valMatch[2].rm_eo);
      if(val3
	 && nvals >= 3) *val3 = extract_int(str, valMatch[3].rm_so, valMatch[3].rm_eo);
      return YES;
    }
    return NO;
  }

#if defined(__cplusplus)
}  /* extern "C" */
#endif
