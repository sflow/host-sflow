/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <kstat.h>
#include <sys/sysinfo.h>
#include <sys/swap.h>


  /*_________________---------------------------__________________
    _________________     readMemoryCounters    __________________
    -----------------___________________________------------------
  */
  
int readMemoryCounters(SFLHost_mem_counters *mem) {
	int gotData = NO;

	kstat_ctl_t *kc;
	kstat_t *ksp = NULL;
	kstat_named_t *knp;

	kc = kstat_open();
	if (NULL == kc) {
		myLog(LOG_ERR, "readMemoryCounters kstat_open() failed");
	}

	if (NULL != kc) {
		ksp = kstat_lookup(kc, "unix", -1, "system_pages");
		if (NULL == ksp) {
			myLog(LOG_ERR, "kstat_lookup error (unix:*:system_pages:*)");
		}
	}

	if (NULL != ksp) {
		if (-1 == kstat_read(kc, ksp, NULL)) {
			myLog(LOG_ERR, "kstat_read error (module: %s, name: %s, class: %s)",
				ksp->ks_module, ksp->ks_name, ksp->ks_class);
		} else {
			gotData = YES;
			// mem_total
			knp = kstat_data_lookup(ksp, "pagestotal");
			mem->mem_total = (uint64_t)knp->value.ui32 * (uint64_t)sysconf(_SC_PAGESIZE);

			// mem_free
			knp = kstat_data_lookup(ksp, "pagesfree");
			mem->mem_free = (uint64_t)knp->value.ui32 * (uint64_t)sysconf(_SC_PAGESIZE);

			// mem_shared
			// Ganglia's libmertrics sets this to 0
			mem->mem_shared = 0;

			// mem_buffers
			// Ganglia's libmertrics sets this to 0
			mem->mem_buffers = 0;

			// mem_cached
			// Ganglia's libmertrics sets this to 0
			mem->mem_cached = 0;

			struct anoninfo anon;
			if (-1 != swapctl(SC_AINFO, &anon)) {
				// swap_total
				mem->swap_total = (uint64_t)anon.ani_max * (uint64_t)sysconf(_SC_PAGESIZE);

				// swap_free
				mem->swap_free = (uint64_t)(anon.ani_max - anon.ani_resv) * (uint64_t)sysconf(_SC_PAGESIZE);
			}

			cpu_stat_t cpu_stat;
			int cpu_id = sysconf(_SC_NPROCESSORS_ONLN);

			uint32_t pgpgin = 0;
			uint32_t pgpgout = 0;
			uint32_t pgswapin = 0;
			uint32_t pgswapout = 0;

			int i, n;
#ifndef KSNAME_BUFFER_SIZE
#define KSNAME_BUFFER_SIZE 32
#endif
			char ks_name[KSNAME_BUFFER_SIZE];
			for (i = 0; cpu_id > 0; i++) {
				n = p_online(i, P_STATUS);
				if (1 == n || (-1 == n && EINVAL == errno)) {
					continue;
				}

				snprintf(ks_name, KSNAME_BUFFER_SIZE, "cpu_stat%d", i);
				cpu_id--;

				ksp = kstat_lookup(kc, "cpu_stat", i, ks_name);
				if (NULL == ksp) {
					myLog(LOG_ERR, "kstat_lookup error (module: %s, name: %s, class: %s)",
						ksp->ks_module, ksp->ks_name, ksp->ks_class);
					continue;
				} 

				if (-1 == kstat_read(kc, ksp, &cpu_stat)) {
					myLog(LOG_ERR, "kstat_read error (module: %s, name: %s, class: %s",
						ksp->ks_module, ksp->ks_name, ksp->ks_class);
					continue;
				}

				pgpgin += cpu_stat.cpu_vminfo.pgpgin;
				pgpgout += cpu_stat.cpu_vminfo.pgpgout;
				pgswapin += cpu_stat.cpu_vminfo.pgswapin;
				pgswapout += cpu_stat.cpu_vminfo.pgswapout;

			}

			// page_in
			mem->page_in = pgpgin;
			// page_out
			mem->page_out = pgpgout;
			// swap_in
			mem->swap_in = pgswapin;
			// swap_out
			mem->swap_out = pgswapout;	
		}
	}

	kstat_close(kc);
	return gotData;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif

