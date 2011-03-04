/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "util.h"
#include <sys/sysctl.h>


  int debug = 0;

    
  /*________________---------------------------__________________
    ________________      getSys64             __________________
    ----------------___________________________------------------
  */

  int getSys64(char *field, uint64_t *val64p) {
    size_t len = sizeof(*val64p);
    if(sysctlbyname(field, val64p, &len, NULL, 0) != 0) {
      myLog(LOG_ERR, "sysctl(%s) failed : %s", field, strerror(errno));
      return NO;
    }
    if(len == 4) {
      uint32_t val32;
      memcpy (&val32, val64p, 4);
      *val64p = (uint64_t)val32;
    }
    return YES;
  }
    
  /*________________---------------------------__________________
    ________________      getSys32             __________________
    ----------------___________________________------------------
  */

  int getSys32(char *field, uint32_t *val32p) {
    size_t len = sizeof(*val32p);
    if(sysctlbyname(field, val32p, &len, NULL, 0) != 0) {
      myLog(LOG_ERR, "sysctl(%s) failed : %s", field, strerror(errno));
      return NO;
    }
    return YES;
  }

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
    _________________       my_calloc           __________________
    -----------------___________________________------------------
  */
  
  void *my_calloc(size_t bytes)
  {
    void *mem = calloc(1, bytes);
    if(mem == NULL) {
      myLog(LOG_ERR, "calloc() failed : %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    return mem;
  }

  void *my_realloc(void *ptr, size_t bytes)
  {
    void *mem = realloc(ptr, bytes);
    if(mem == NULL) {
      myLog(LOG_ERR, "realloc() failed : %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    return mem;
  }
  
  void my_free(void *ptr)
  {
    if(ptr) free(ptr);
  }
    
  /*_________________---------------------------__________________
    _________________     setStr                __________________
    -----------------___________________________------------------
  */
  
  void setStr(char **fieldp, char *str) {
    if(*fieldp) my_free(*fieldp);
    (*fieldp) = str ? strdup(str) : NULL;
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
      case EAI_AGAIN: break; // loop and try again?
      default: myLog(LOG_ERR, "getaddrinfo() error: %s", gai_strerror(err)); break;
      }
      return NO;
    }
  
    if(info == NULL) 
      {
        myLog(LOG_ERR, "getaddrinfo() error2: ");
	return NO;
      }
  
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
          myLog(LOG_ERR, "Setting type");
	  addr->type = SFLADDRESSTYPE_IP_V6;
          myLog(LOG_ERR, "Setting address");
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
      ad->deviceName = strdup(dev);
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
} /* extern "C" */
#endif

