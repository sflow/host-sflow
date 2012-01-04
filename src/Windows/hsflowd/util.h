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
#include <WbemIdl.h>

#define FORMATTED_GUID_LEN 50 //also formatted UUID len excl NULL

#include "sflow.h" // for SFLAddress, SFLAdaptorList...

//Adds obj to the head of the singly linked list referenced by linkedlist.
//Changes linkedlist to point to obj at the head of the list.
#define ADD_TO_LIST(linkedlist, obj) \
	do { \
	obj->nxt = linkedlist; \
	linkedlist = obj; \
	} while(0)

// addressing
int hexToBinary(u_char *hex, u_char *bin, uint32_t binLen);
int wchexToBinary(wchar_t *hex, u_char *bin, uint32_t length);
int printHex(const u_char *a, int len, u_char *buf, int bufLen, BOOL prefix);
BOOL parseUUID(char *str, char *uuid);
int printUUID(const u_char *a, u_char *buf, int bufLen);
BOOL guidToString(wchar_t *guid, u_char *guidStr, int guidStrLen); 
  
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

// string copy fns
char *my_strdup(char *str);
wchar_t *my_wcsdup(wchar_t *str);
char *my_wcstombs(wchar_t *wcstr);

#define STRINGIFY(Y) #Y
#define STRINGIFY_DEF(D) STRINGIFY(D)

//wide character string array and functions
typedef struct {
	wchar_t ** strings;
	uint32_t n;
	uint32_t capacity;
	BOOL sorted;
} WcsArray;

WcsArray *wcsArrayNew();
void wcsArrayAdd(WcsArray *wcsArray, wchar_t *str);
void wcsArrayReset(WcsArray *wcsArray);
void wcsArrayFree(WcsArray *wcsArray);
uint32_t wcsArrayIndexOf(WcsArray *wcsArray, wchar_t *str);

//WMI functions
HRESULT connectToWMI(BSTR path, IWbemServices **pNamespace);
HRESULT associatorsOf(IWbemServices *pNamespace, IWbemClassObject *classObj, 
					   wchar_t *assocClass, wchar_t *endClass, wchar_t *resultRole,
					   IEnumWbemClassObject **resultEnum);
void cleanCounterName(wchar_t *name);

/**
 * Call back function to free userData. Frees any allocated memory
 * and the userData structure itself.
 */
typedef void (*freeUserData_t)(void *userData);

// SFLAdaptorList
SFLAdaptorList *adaptorListNew();
void adaptorListReset(SFLAdaptorList *adList, freeUserData_t freeUserData);
void adaptorListFree(SFLAdaptorList *adList, freeUserData_t freeUserData);
void adaptorListMarkAll(SFLAdaptorList *adList);
void adaptorListFreeMarked(SFLAdaptorList *adList, freeUserData_t freeUserData);
SFLAdaptor *adaptorListGet(SFLAdaptorList *adList, char *dev);
SFLAdaptor *adaptorListAdd(SFLAdaptorList *adList, char *dev, u_char *macBytes, size_t userDataSize);

BOOL truncateOpenFile(FILE *fptr);

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* UTIL_H */

