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

// #define HSP_USE_GETADAPTERSADDRESSES 

#ifdef HSP_USE_GETADAPTERSADDRESSES
  /* experimental code to read address information that includes IPv4 and IPv6 addresses */

#include <winsock2.h>
#include <iphlpapi.h>

/* Link with Iphlpapi.lib */
#pragma comment(lib, "IPHLPAPI.lib")

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

#define MALLOC(x) my_calloc(x)
#define FREE(x) my_free(x)

void readAddresses()
{

    /* Declare and initialize variables */

    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    unsigned int i = 0;

    // Set the flags to pass to GetAdaptersAddresses
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

    // default to unspecified address family (both)
    ULONG family = AF_UNSPEC;

    LPVOID lpMsgBuf = NULL;

    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 0;
    ULONG Iterations = 0;

    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
    PIP_ADAPTER_ANYCAST_ADDRESS pAnycast = NULL;
    PIP_ADAPTER_MULTICAST_ADDRESS pMulticast = NULL;
    IP_ADAPTER_DNS_SERVER_ADDRESS *pDnServer = NULL;
    IP_ADAPTER_PREFIX *pPrefix = NULL;


    printf("Calling GetAdaptersAddresses function with family = ");
    if (family == AF_INET)
        printf("AF_INET\n");
    if (family == AF_INET6)
        printf("AF_INET6\n");
    if (family == AF_UNSPEC)
        printf("AF_UNSPEC\n\n");

    // Allocate a 15 KB buffer to start with.
    outBufLen = WORKING_BUFFER_SIZE;

    do {

        pAddresses = (IP_ADAPTER_ADDRESSES *) MALLOC(outBufLen);
        if (pAddresses == NULL) {
            printf
                ("Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
            exit(1);
        }

        dwRetVal =
            GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            FREE(pAddresses);
            pAddresses = NULL;
        } else {
            break;
        }

        Iterations++;

    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

    if (dwRetVal == NO_ERROR) {
        // If successful, output some information from the data we received
        pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            printf("\tLength of the IP_ADAPTER_ADDRESS struct: %ld\n",
                   pCurrAddresses->Length);
            printf("\tIfIndex (IPv4 interface): %u\n", pCurrAddresses->IfIndex);
            printf("\tAdapter name: %s\n", pCurrAddresses->AdapterName);

            pUnicast = pCurrAddresses->FirstUnicastAddress;
            if (pUnicast != NULL) {
                for (i = 0; pUnicast != NULL; i++)
                    pUnicast = pUnicast->Next;
                printf("\tNumber of Unicast Addresses: %d\n", i);
            } else
                printf("\tNo Unicast Addresses\n");

            pAnycast = pCurrAddresses->FirstAnycastAddress;
            if (pAnycast) {
                for (i = 0; pAnycast != NULL; i++)
                    pAnycast = pAnycast->Next;
                printf("\tNumber of Anycast Addresses: %d\n", i);
            } else
                printf("\tNo Anycast Addresses\n");

            pMulticast = pCurrAddresses->FirstMulticastAddress;
            if (pMulticast) {
                for (i = 0; pMulticast != NULL; i++)
                    pMulticast = pMulticast->Next;
                printf("\tNumber of Multicast Addresses: %d\n", i);
            } else
                printf("\tNo Multicast Addresses\n");

            pDnServer = pCurrAddresses->FirstDnsServerAddress;
            if (pDnServer) {
                for (i = 0; pDnServer != NULL; i++)
                    pDnServer = pDnServer->Next;
                printf("\tNumber of DNS Server Addresses: %d\n", i);
            } else
                printf("\tNo DNS Server Addresses\n");

            printf("\tDNS Suffix: %wS\n", pCurrAddresses->DnsSuffix);
            printf("\tDescription: %wS\n", pCurrAddresses->Description);
            printf("\tFriendly name: %wS\n", pCurrAddresses->FriendlyName);

            if (pCurrAddresses->PhysicalAddressLength != 0) {
                printf("\tPhysical address: ");
                for (i = 0; i < (int) pCurrAddresses->PhysicalAddressLength;
                     i++) {
                    if (i == (pCurrAddresses->PhysicalAddressLength - 1))
                        printf("%.2X\n",
                               (int) pCurrAddresses->PhysicalAddress[i]);
                    else
                        printf("%.2X-",
                               (int) pCurrAddresses->PhysicalAddress[i]);
                }
            }
            printf("\tFlags: %ld\n", pCurrAddresses->Flags);
            printf("\tMtu: %lu\n", pCurrAddresses->Mtu);
            printf("\tIfType: %ld\n", pCurrAddresses->IfType);
            printf("\tOperStatus: %ld\n", pCurrAddresses->OperStatus);
            printf("\tIpv6IfIndex (IPv6 interface): %u\n",
                   pCurrAddresses->Ipv6IfIndex);
            printf("\tZoneIndices (hex): ");
            for (i = 0; i < 16; i++)
                printf("%lx ", pCurrAddresses->ZoneIndices[i]);
            printf("\n");

            printf("\tTransmit link speed: %I64u\n", pCurrAddresses->TransmitLinkSpeed);
            printf("\tReceive link speed: %I64u\n", pCurrAddresses->ReceiveLinkSpeed);

            pPrefix = pCurrAddresses->FirstPrefix;
            if (pPrefix) {
                for (i = 0; pPrefix != NULL; i++)
                    pPrefix = pPrefix->Next;
                printf("\tNumber of IP Adapter Prefix entries: %d\n", i);
            } else
                printf("\tNumber of IP Adapter Prefix entries: 0\n");

            printf("\n");

            pCurrAddresses = pCurrAddresses->Next;
        }
    } else {
        printf("Call to GetAdaptersAddresses failed with error: %d\n",
               dwRetVal);
        if (dwRetVal == ERROR_NO_DATA)
            printf("\tNo addresses were found for the requested parameters\n");
        else {

            if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 
                    NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),   
                    // Default language
                    (LPTSTR) & lpMsgBuf, 0, NULL)) {
                printf("\tError: %s", lpMsgBuf);
                LocalFree(lpMsgBuf);
                if (pAddresses)
                    FREE(pAddresses);
                exit(1);
            }
        }
    }

    if (pAddresses) {
        FREE(pAddresses);
    }
}
    
#endif /* HSP_USE_GETADAPTERSADDRESSES */
#if defined(__cplusplus)
}  /* extern "C" */
#endif
