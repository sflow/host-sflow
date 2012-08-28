/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#ifndef VERSION_H
#define VERSION_H 1

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

#ifndef VERSION_MAJOR
#define VERSION_MAJOR 1
#endif

#ifndef VERSION_MINOR
#define VERSION_MINOR 0
#endif

#ifndef VERSION_REVISION
#define VERSION_REVISION 0
#endif

#define VER_FILE_VERSION VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION
#define VER_FILE_VERSION_STR STRINGIZE(VERSION_MAJOR) "." \
							 STRINGIZE(VERSION_MINOR) "." \
							 STRINGIZE(VERSION_REVISION)

#define VER_COMPANY_NAME_STR "Host sFlow Project"
#define VER_PRODUCTNAME_STR "Host sFlow Agent"
#define VER_PRODUCT_VERSION VER_FILE_VERSION
#define VER_PRODUCT_VERSION_STR VER_FILE_VERSION_STR
#define VER_COPYRIGHT_STR "Copyright (C) 2010 - 2012"
 
#ifdef _DEBUG
  #define VER_VER_DEBUG VS_FF_DEBUG
#else
  #define VER_VER_DEBUG 0
#endif
 
#define VER_FILEOS VOS_NT_WINDOWS32
#define VER_FILEFLAGS VER_VER_DEBUG

#endif
