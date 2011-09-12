/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "util.h"

  int debug = 0;

  /*_________________---------------------------__________________
    _________________        logging            __________________
    -----------------___________________________------------------
  */

  void myLog(int syslogType, char *fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    if(debug) {
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

   void strArrayAdd(UTStringArray *ar, char *str) {
    ar->sorted = NO;
    if(ar->capacity <= ar->n) {
      uint32_t oldBytes = ar->capacity * sizeof(char *);
      ar->capacity = ar->n + 16;
      uint32_t newBytes = ar->capacity * sizeof(char *);
      char **newArray = (char **)my_calloc(newBytes);
      if(ar->strs) {
	memcpy(newArray, ar->strs, oldBytes);
	my_free(ar->strs);
      }
      ar->strs = newArray;
    }
    if(ar->strs[ar->n]) my_free(ar->strs[ar->n]);
    ar->strs[ar->n++] = my_strdup(str);
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
    size_t strbufLen = 256;
    char *strbuf = NULL;
    FILE *f_strbuf;
    if((f_strbuf = open_memstream(&strbuf, &strbufLen)) == NULL) {
      myLog(LOG_ERR, "error in open_memstream: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    if(start) fputs(start, f_strbuf);
    for(uint32_t i = 0; i < ar->n; i++) {
      if(i && delim) fputs(delim, f_strbuf);
      char *str = ar->strs[i];
      if(str) {
	if(quote) fputs(quote, f_strbuf);
	fputs(str, f_strbuf);
	if(quote) fputs(quote, f_strbuf);
      }
    }
    if(end) fputs(end, f_strbuf);
    fclose(f_strbuf);
    return strbuf;
  }

   int strArrayEqual(UTStringArray *ar1, UTStringArray *ar2) {
    if(ar1->n != ar2->n) return NO;
    for(int i = 0; i < ar1->n; i++) {
      char *s1 = ar1->strs[i];
      char *s2 = ar2->strs[i];
      if((s1 != s2)
	 && (s1 == NULL || s2 == NULL || strcmp(s1, s2))) return NO;
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
      char *instr = ar->strs[i];
      if(str == instr) return i;
      if(str && instr && !strcmp(str, instr)) return i;
    }
    return -1;
  } 

  /*________________---------------------------__________________
    ________________       lookupAddress       __________________
    ----------------___________________________------------------
  */

  int lookupAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family)
  {
    struct addrinfo *info = NULL;
    struct addrinfo hints = { 0 };
    hints.ai_socktype = SOCK_DGRAM; // constrain this so we don't get lots of answers
    hints.ai_family = family; // PF_INET, PF_INET6 or 0
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
      // extract the address we want from the first one.
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
    _________________     my_usleep_fd          __________________
    -----------------___________________________------------------
    variant that returns early if there is activity on the supplied file descriptor
  */
  
  void my_usleep_fd(uint32_t microseconds, int fd) {
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = microseconds;
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    int max_fd = fd;
    int nfds = select(max_fd + 1,
		      &readfds,
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

  void adaptorListFreeMarked(SFLAdaptorList *adList)
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
  }
  
  SFLAdaptor *adaptorListGet(SFLAdaptorList *adList, char *dev)
  {
    for(uint32_t i = 0; i < adList->num_adaptors; i++) {
      SFLAdaptor *ad = adList->adaptors[i];
      if(ad && ad->deviceName && !strcmp(ad->deviceName, dev)) {
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
    
#if defined(__cplusplus)
}  /* extern "C" */
#endif
