/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "util.h"

extern int debug;

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
  }


  /*_________________---------------------------__________________
    _________________       my_os_allocation    __________________
    -----------------___________________________------------------
  */

  void *my_os_calloc(size_t bytes)
  {
     myLog(LOG_INFO, "my_os_calloc(%u)", bytes);
    void *mem = SYS_CALLOC(1, bytes);
    if(mem == NULL) {
      myLog(LOG_ERR, "calloc() failed : %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    return mem;
  }

  void *my_os_realloc(void *ptr, size_t bytes)
  {
    myLog(LOG_INFO, "my_os_realloc(%u)", bytes);
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
    uint32_t realmIdx;
    uint32_t totalAllocatedBytes;
  } UTHeapRealm;

  // separate realm for each thread
static __declspec(thread) UTHeapRealm utRealm;
  
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
      // utRealm.realmIdx = MYGETTID; $$$
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
   /*________________---------------------------__________________
    _________________      UTHeapQTotal         __________________
    -----------------___________________________------------------
  */

  uint64_t UTHeapQTotal(void)
  {
    return utRealm.totalAllocatedBytes;
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
	my_free(adList->adaptors[i]->deviceName);
	my_free(adList->adaptors[i]);
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

  SFLAdaptor *adaptorListAdd(SFLAdaptorList *adList, char *dev, u_char *macBytes)
  {
    SFLAdaptor *ad = adaptorListGet(adList, dev);
    if(ad == NULL) {
      ad = (SFLAdaptor *)my_calloc(sizeof(SFLAdaptor));
      ad->deviceName = my_strdup(dev);
    }
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
    return ad;
  }
    

    
#if defined(__cplusplus)
}  /* extern "C" */
#endif
