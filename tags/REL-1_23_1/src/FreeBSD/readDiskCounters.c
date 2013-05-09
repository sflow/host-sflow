/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#include <sys/mount.h>
#include <sys/statvfs.h> // for statvfs
#include <paths.h>
#include <devstat.h>
#include <limits.h>
#include <kvm.h>
#include <sys/param.h>
#include <sys/sysctl.h>

  extern int debug;

  /*
   * A big thanks to Ganglia for all of the libmetrics code !!! 
   */

#define MAXNAMELEN 256
 
  /*_________________---------------------------__________________
    _________________     check vfs name        __________________
    -----------------___________________________------------------
  */
#define VFCF_NONLOCAL   (VFCF_NETWORK|VFCF_SYNTHETIC|VFCF_LOOPBACK)
  static int skipvfs = 1;
  
  static int checkvfsname(const char *vfsname, const char **vfslist)
  {
    if (vfslist == NULL) return (0);
    while (*vfslist != NULL) {
      if (strcmp(vfsname, *vfslist) == 0)
	return (skipvfs);
      ++vfslist;
    }
    return (!skipvfs);
  }
  
  /*_________________---------------------------__________________
    _________________     regetmntinfo          __________________
    -----------------___________________________------------------
  */
  static size_t regetmntinfo(struct statfs **mntbufp, long mntsize, const char **vfslist)
  {
    int i, j;
    struct statfs *mntbuf;
    
    if (vfslist == NULL)
      return (getmntinfo(mntbufp, MNT_WAIT));
    
    mntbuf = *mntbufp;
    for (j = 0, i = 0; i < mntsize; i++) {
      if (checkvfsname(mntbuf[i].f_fstypename, vfslist))
	continue;
      (void)statfs(mntbuf[i].f_mntonname,&mntbuf[j]);
      j++;
    }
    return (j);
  }

  /*_________________---------------------------__________________
    _________________     makenetvfslist        __________________
    -----------------___________________________------------------
  */
  static char *
  makenetvfslist(void)
  {
    char *str = NULL, *strptr, **listptr = NULL;
    size_t slen;
    int cnt = 0;
    int i;

#if __FreeBSD_version > 500000
    struct xvfsconf *xvfsp, *keep_xvfsp = NULL;
    size_t buflen;
    int maxvfsconf;

    if (sysctlbyname("vfs.conflist", NULL, &buflen, NULL, 0) < 0) {
      printf("sysctl(vfs.conflist)");
      goto done;
    }
    keep_xvfsp = xvfsp = malloc(buflen);
    if (xvfsp == NULL) {
      printf("malloc failed");
      goto done;
    }
    if (sysctlbyname("vfs.conflist", xvfsp, &buflen, NULL, 0) < 0) {
      printf("sysctl(vfs.conflist)");
      goto done;
    }
    maxvfsconf = buflen / sizeof(struct xvfsconf);

    if ((listptr = malloc(sizeof(char*) * maxvfsconf)) == NULL) {
      printf("malloc failed");
      goto done;
    }

    cnt = 0;
    for (i = 0; i < maxvfsconf; i++, xvfsp++) {
      if (xvfsp->vfc_typenum == 0)
	continue;
      if (xvfsp->vfc_flags & VFCF_NONLOCAL)
	continue;

      listptr[cnt] = strdup(xvfsp->vfc_name);
      if (listptr[cnt] == NULL) {
	printf("malloc failed");
	goto done;
      }
      cnt++;
    }
#else
    int mib[3], maxvfsconf;
    size_t miblen;
    struct ovfsconf *ptr;

    mib[0] = CTL_VFS; mib[1] = VFS_GENERIC; mib[2] = VFS_MAXTYPENUM;
    miblen=sizeof(maxvfsconf);
    if (sysctl(mib, (unsigned int)(sizeof(mib) / sizeof(mib[0])),
	       &maxvfsconf, &miblen, NULL, 0)) {
      printf("sysctl failed");
      goto done;
    }

    if ((listptr = malloc(sizeof(char*) * maxvfsconf)) == NULL) {
      printf("malloc failed");
      goto done;
    }

    cnt = 0;
    while ((ptr = getvfsent()) != NULL && cnt < maxvfsconf) {
      if (ptr->vfc_flags & VFCF_NONLOCAL)
	continue;

      listptr[cnt] = strdup(ptr->vfc_name);
      if (listptr[cnt] == NULL) {
	printf("malloc failed");
	goto done;
      }
      cnt++;
    }
#endif

    if (cnt == 0)
      goto done;
    /*
     * Count up the string lengths, we need a extra byte to hold
     * the between entries ',' or the NUL at the end.
     */
    slen = 0;
    for (i = 0; i < cnt; i++)
      slen += strlen(listptr[i]);
    /* for ',' */
    slen += cnt - 1;
    /* Add 3 for initial "no" and the NUL. */
    slen += 3;

    if ((str = malloc(slen)) == NULL) {
      printf("malloc failed");
      goto done;
    }

    str[0] = 'n';
    str[1] = 'o';
    for (i = 0, strptr = str + 2; i < cnt; i++) {
      if (i > 0)
	*strptr++ = ',';
      strcpy(strptr, listptr[i]);
      strptr += strlen(listptr[i]);
    }
    *strptr = '\0';

  done:
#if __FreeBSD_version > 500000
    if (keep_xvfsp != NULL)
      free(keep_xvfsp);
#endif
    if (listptr != NULL) {
      for(i = 0; i < cnt && listptr[i] != NULL; i++)
	free(listptr[i]);
      free(listptr);
    }
    return (str);

  }

  /*_________________---------------------------__________________
    _________________     makevfslist           __________________
    -----------------___________________________------------------
  */
  static const char **
  makevfslist(fslist)
       char *fslist;
  {
    const char **av;
    int i;
    char *nextcp;

    if (fslist == NULL)
      return (NULL);
    if (fslist[0] == 'n' && fslist[1] == 'o') {
      fslist += 2;
      skipvfs = 0;
    }
    for (i = 0, nextcp = fslist; *nextcp; nextcp++)
      if (*nextcp == ',')
	i++;
    if ((av = malloc((size_t)(i + 2) * sizeof(char *))) == NULL) {
      printf("malloc failed");
      return (NULL);
    }
    nextcp = fslist;
    i = 0;
    av[i++] = nextcp;
    while ((nextcp = strchr(nextcp, ',')) != NULL) {
      *nextcp++ = '\0';
      av[i++] = nextcp;
    }
    av[i++] = NULL;
    return (av);
  }


  /*_________________---------------------------__________________
    _________________     find_disk_space       __________________
    -----------------___________________________------------------
  */
  static float
  find_disk_space(uint64_t *total, uint64_t *tot_avail)
  {
    struct statfs *mntbuf;
    const char *fstype;
    const char **vfslist;
    char *netvfslist;
    size_t i, mntsize;
    size_t used, availblks;
    float pct;
    float most_full = 0.0;

    *total = 0;
    *tot_avail = 0;

    fstype = "ufs";

    netvfslist = makenetvfslist();
    vfslist = makevfslist(netvfslist);
    mntsize = getmntinfo(&mntbuf, MNT_NOWAIT);
    mntsize = regetmntinfo(&mntbuf, mntsize, vfslist);
    for (i = 0; i < mntsize; i++) {
      if ((mntbuf[i].f_flags & MNT_IGNORE) == 0) {
	used = mntbuf[i].f_blocks - mntbuf[i].f_bfree;
	availblks = mntbuf[i].f_bavail + used;
	pct = (availblks == 0 ? 100.0 :
	       (double)used / (double)availblks * 100.0);
	if (pct > most_full)
	  most_full = pct;
	*total += (mntbuf[i].f_blocks * mntbuf[i].f_bsize);
	*tot_avail += (mntbuf[i].f_bavail * mntbuf[i].f_bsize);
      }
    }
    free(vfslist);
    free(netvfslist);

    return most_full;
  }

  /*_________________---------------------------__________________
    _________________     readDiskCounters      __________________
    -----------------___________________________------------------
  */
  
  int readDiskCounters(HSP *sp, SFLHost_dsk_counters *dsk) 
  {
    int gotData = NO;
    struct statinfo stats;
    struct devinfo  dinfo;
    kvm_t *kd = NULL;
    struct devstat  dev;
  
    memset(&stats, 0, sizeof(stats));
    memset(&dinfo, 0, sizeof(dinfo));
    /* Clear out any old stats */
    dsk->bytes_read = 0;
    dsk->bytes_written  = 0;
    dsk->reads = 0;
    dsk->writes = 0;
    dsk->read_time = 0;
    dsk->write_time = 0;
  
    stats.dinfo = &dinfo;
    if (devstat_getdevs(kd, &stats) == -1) {
      if(debug) myLog(LOG_ERR, "devstat_getdevs() failed");
    }
    else {
      for(int i = 0; i < (stats.dinfo)->numdevs; i++) {
	dev = (stats.dinfo)->devices[i];
	dsk->bytes_read += dev.bytes[DEVSTAT_READ];
	dsk->bytes_written += dev.bytes[DEVSTAT_WRITE];
	dsk->reads += dev.operations[DEVSTAT_READ];
	dsk->writes += dev.operations[DEVSTAT_WRITE];
	dsk->read_time += dev.duration[DEVSTAT_READ].sec;
	dsk->write_time += dev.duration[DEVSTAT_WRITE].sec;
      }
      free((stats.dinfo)->mem_ptr);
    
      /* Now find the disk space total and free */
      dsk->part_max_used = find_disk_space(&dsk->disk_total, &dsk->disk_free);
      gotData = YES;
    }
    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif

