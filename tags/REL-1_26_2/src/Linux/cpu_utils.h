/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#ifndef CPU_UTILS_H
#define CPU_UTILS_H 1

#if defined(__cplusplus)
extern "C" {
#endif

#include <linux/param.h> // for HZ

#define JIFFY_TO_MS(i) (((i) * 1000L) / HZ)

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* CPU_UTILS_H */

