/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "util.h"

  int debug = 0;
  int daemonize = 0;

  /*________________---------------------------__________________
    ________________       UTStrBuf            __________________
    ----------------___________________________------------------
  */

  UTStrBuf *UTStrBuf_new(size_t cap) {
    UTStrBuf *buf = (UTStrBuf *)my_calloc(sizeof(UTStrBuf));
    buf->buf = my_calloc(cap);
    buf->cap = cap;
    return buf;
  }

  void UTStrBuf_grow(UTStrBuf *buf) {
    buf->cap <<= 2;
    char *newbuf = (char *)my_calloc(buf->cap);
    memcpy(newbuf, buf->buf, buf->len);
    my_free(buf->buf);
    buf->buf = newbuf;
  }

  static void UTStrBuf_need(UTStrBuf *buf, size_t len) {
    while((buf->len + len + 1) >= buf->cap) UTStrBuf_grow(buf);
  }

  void UTStrBuf_append(UTStrBuf *buf, char *str) {
    int len = my_strlen(str);
    UTStrBuf_need(buf, len);
    memcpy(buf->buf + buf->len, str, len);
    buf->len += len;
  }

  int UTStrBuf_printf(UTStrBuf *buf, char *fmt, ...) {
    int ans;
    va_list args;
    va_start(args, fmt);
    // vsnprintf will tell you what space it *would* need
    int needed = vsnprintf(NULL, 0, fmt, args);
    UTStrBuf_need(buf, needed+1);
    va_start(args, fmt);
    ans =vsnprintf(buf->buf + buf->len, needed+1, fmt, args);
    buf->len += needed;
    return ans;
  }

  char *UTStrBuf_unwrap(UTStrBuf *buf) {
    char *ans = buf->buf;
    my_free(buf);
    return ans;
  }

  /*_________________---------------------------__________________
    _________________        logging            __________________
    -----------------___________________________------------------
  */

  void myLog(int syslogType, char *fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    if(debug && !daemonize) {
      vfprintf(stderr, fmt, args);
      fprintf(stderr, "\n");
    }
    else vsyslog(syslogType, fmt, args);
  }


  /*_________________---------------------------__________________
    _________________       my_os_allocation    __________________
    -----------------___________________________------------------
  */

  void *my_os_calloc(size_t bytes)
  {
    if(debug) myLog(LOG_INFO, "my_os_calloc(%u)", bytes);
    void *mem = SYS_CALLOC(1, bytes);
    if(mem == NULL) {
      myLog(LOG_ERR, "calloc() failed : %s", strerror(errno));
      if(debug) malloc_stats();
      exit(EXIT_FAILURE);
    }
    return mem;
  }

  void *my_os_realloc(void *ptr, size_t bytes)
  {
    if(debug) myLog(LOG_INFO, "my_os_realloc(%u)", bytes);
    void *mem = SYS_REALLOC(ptr, bytes);
    if(mem == NULL) {
      myLog(LOG_ERR, "realloc() failed : %s", strerror(errno));
      if(debug) malloc_stats();
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
      uint16_t refCount;
#define UT_MAX_REFCOUNT 0xFFFF
      uint16_t queueIdx;
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
    utBuf->h.refCount = 1;
    utBuf->h.queueIdx = queueIdx;
    // return a pointer to just after the header
    return (char *)utBuf + sizeof(UTHeapHeader);
  }


  /*_________________---------------------------__________________
    _________________    UTHeapQFree            __________________
    -----------------___________________________------------------
  */

  void UTHeapQFree(void *buf)
  {
    UTHeapHeader *utBuf = UTHeapQHdr(buf);
    int rc = utBuf->h.refCount;
    assert(rc != 0);
    assert(utBuf->h.realmIdx == utRealm.realmIdx);
    // UT_MAX_REFCOUNT => immortality
    if(rc != UT_MAX_REFCOUNT) {
      // decrement the ref count
      if(--rc != 0) {
	// not zero yet, so just write back the decremented refcount
	utBuf->h.refCount = rc;
      }
      else {
	// reference count reached zero, so it's time to free this buffer for real
	// read the queue index before we overwrite it
	uint16_t queueIdx = utBuf->h.queueIdx;
	memset(utBuf, 0, 1 << queueIdx);
	// put it back on the queue
	utBuf->nxt = (UTHeapHeader *)(utRealm.bufferLists[queueIdx]);
	utRealm.bufferLists[queueIdx] = utBuf;
      }
    }
  }

  /*_________________---------------------------__________________
    _________________      UTHeapQReAlloc       __________________
    -----------------___________________________------------------
  */

  void *UTHeapQReAlloc(void *buf, size_t newSiz)
  {
    size_t siz = UTHeapQSize(buf);
    if(newSiz <= siz) return buf;
    void *newBuf = UTHeapQNew(newSiz);
    memcpy(newBuf, buf, siz);
    UTHeapQFree(buf);
    return newBuf;
  }

  /*_________________---------------------------__________________
    _________________      UTHeapQKeep          __________________
    -----------------___________________________------------------
  */

  void UTHeapQKeep(void *buf)
  {
    // might even need to grab the semaphore for this operation too?
    UTHeapHeader *utBuf = UTHeapQHdr(buf);
    assert(utBuf->h.refCount > 0);
    assert(utBuf->h.realmIdx == utRealm.realmIdx);
    if(++utBuf->h.refCount == 0) utBuf->h.refCount = UT_MAX_REFCOUNT;
  }

#endif /* UTHEAP */

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

  char *my_strdup(char *str)
  {
    if(str == NULL) return NULL;
    uint32_t len = my_strlen(str);
    char *newStr = (char *)my_calloc(len+1);
    memcpy(newStr, str, len);
    return newStr;
  }
   
  int my_strnequal(char *s1, char *s2, uint32_t max) {
    if(s1 == s2) return YES;
    if(s1 == NULL || s2 == NULL) return NO;
    uint32_t len1 = my_strnlen(s1, max);
    uint32_t len2 = my_strnlen(s2, max);
    if(len1 != len2) return NO;
    return (memcmp(s1, s2, len1) == 0);
  }
   
  int my_strequal(char *s1, char *s2) {
    return my_strnequal(s1, s2, UT_DEFAULT_MAX_STRLEN);
  }
  
  uint32_t my_strhash(char *str)
  {
    /* hash function from the great Dan Bernstein */
    uint32_t hash = 5381;
    if(str == NULL) return hash;
    int c;
    while ((c = *str++) != '\0') hash = hash * 33 ^ c;
    return hash;
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

  char *trimWhitespace(char *str)
  {
    char *end;
    
    // Trim leading space
    while(isspace(*str)) str++;
    
    // Trim trailing space
    end = str + strlen(str) - 1;
    while(end > str && isspace(*end)) end--;
    
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
    return ar->strs[i];
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
    UTStrBuf *buf = UTStrBuf_new(256);
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
    
    return trim ? trimWhitespace(buf) : buf;
  }

  /*________________---------------------------__________________
    ________________       lookupAddress       __________________
    ----------------___________________________------------------
  */

  static int parseOrResolveAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family, int numeric)
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
      if(debug) myLog(LOG_INFO, "getaddrinfo() failed: %s", gai_strerror(err));
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
	  addr->type = SFLADDRESSTYPE_IP_V4;
	  addr->address.ip_v4.addr = ipsoc->sin_addr.s_addr;
	  if(sa) memcpy(sa, info->ai_addr, info->ai_addrlen);
	}
	break;
      case PF_INET6:
	{
	  struct sockaddr_in6 *ip6soc = (struct sockaddr_in6 *)info->ai_addr;
	  addr->type = SFLADDRESSTYPE_IP_V6;
	  memcpy(&addr->address.ip_v6, &ip6soc->sin6_addr, 16);
	  if(sa) memcpy(sa, info->ai_addr, info->ai_addrlen);
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

  int lookupAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family)
  {
    return parseOrResolveAddress(name, sa, addr, family, NO);
  }

  int parseNumericAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family)
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

  int myExec(void *magic, char **cmd, UTExecCB lineCB, char *line, size_t lineLen)
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
      close(pfd[0]);   // close read-end
      dup2(pfd[1], 1); // stdout -> write-end
      dup2(pfd[1], 2); // stderr -> write-end
      close(pfd[1]);
      // exec program
      char *env[] = { NULL };
      if(execve(cmd[0], cmd, env) == -1) {
	myLog(LOG_ERR, "execve() failed : errno=%d (%s)", errno, strerror(errno));
	exit(EXIT_FAILURE);
      }
    }
    else {
      // in parent
      close(pfd[1]); // close write-end
      // read from read-end
      FILE *ovs;
      if((ovs = fdopen(pfd[0], "r")) == NULL) {
	myLog(LOG_ERR, "fdopen() failed : %s", strerror(errno));
	exit(EXIT_FAILURE);
      }
      while(fgets(line, lineLen, ovs)) {
	if(debug > 1) myLog(LOG_INFO, "myExec input> <%s>", line);
	if((*lineCB)(magic, line) == NO) {
	  if(debug > 1) myLog(LOG_INFO, "myExec callback returned NO");
	  ans = NO;
	  break;
	}
      }
      fclose(ovs);
      wait(NULL); // block here until child is done
    }
    return ans;
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

  static void adaptorFree(SFLAdaptor *ad)
  {
    if(ad) {
      if(ad->deviceName) my_free(ad->deviceName);
      if(ad->userData) my_free(ad->userData);
      my_free(ad);
    }
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

  void adaptorListMarkAll(SFLAdaptorList *adList)
  {
    for(uint32_t i = 0; i < adList->num_adaptors; i++) {
      SFLAdaptor *ad = adList->adaptors[i];
      if(ad) ad->marked = YES;
    }
  }

  int adaptorListFreeMarked(SFLAdaptorList *adList)
  {
    uint32_t removed = 0;
    for(uint32_t i = 0; i < adList->num_adaptors; i++) {
      SFLAdaptor *ad = adList->adaptors[i];
      if(ad && ad->marked) {
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
    for(uint32_t i = 0; i < adList->num_adaptors; i++) {
      SFLAdaptor *ad = adList->adaptors[i];
      if(ad && my_strequal(ad->deviceName, dev)) {
	// return the one that was already there
	return ad;
      }
    }
    return NULL;
  }

  SFLAdaptor *adaptorListAdd(SFLAdaptorList *adList, char *dev, u_char *macBytes, size_t userDataSize)
  {
    SFLAdaptor *ad = adaptorListGet(adList, dev);
    if(ad == NULL) {
      ad = (SFLAdaptor *)my_calloc(sizeof(SFLAdaptor));
      ad->deviceName = my_strdup(dev);
      ad->userData = my_calloc(userDataSize);
      
      if(adList->num_adaptors == adList->capacity) {
	// grow
	adList->capacity *= 2;
	adList->adaptors = (SFLAdaptor **)my_realloc(adList->adaptors, adList->capacity * sizeof(SFLAdaptor *));
      }
      adList->adaptors[adList->num_adaptors++] = ad;
      if(macBytes) {
	memcpy(ad->macs[0].mac, macBytes, 6);
	ad->num_macs = 1;
      }
    }
    return ad;
  }
    
  /*________________---------------------------__________________
    ________________      truncateOpenFile     __________________
    ----------------___________________________------------------
  */

  int truncateOpenFile(FILE *fptr)
  {
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
    ________________      SFLAddress utils     __________________
    ----------------___________________________------------------
  */

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
  
  int SFLAddress_isSelfAssigned(SFLAddress *addr) {
    if(addr->type == SFLADDRESSTYPE_IP_V4) {
      // for IPv4, it's 169.254.*
      u_char *a = (u_char *)&(addr->address.ip_v4.addr);
      return (a[0] == 169 &&
	      a[1] == 254);
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
      if(buf[len] != 0) return NO;
    }
    return YES;
  }

  int isZeroMAC(SFLMacAddress *mac) {
    return isAllZero(mac->mac, 6);
  }


#if defined(__cplusplus)
}  /* extern "C" */
#endif
