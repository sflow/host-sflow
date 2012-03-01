/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "hypervSwitch.h"
#include <ShlObj.h>
#include <Shlwapi.h>
#include <fcntl.h>
#include <io.h>

#define instanceMutexName "Global\\hsflowd-{0C4FB5D9-641D-428C-8216-950962E608E0}"

//globals
int debug = LOG_ERR;
FILE *logFile = stderr;

SERVICE_STATUS ServiceStatus; 
SERVICE_STATUS_HANDLE hStatus = 0; 

static BOOL isService = TRUE;
static char *logFilename = NULL;

//foward declarations
void  ServiceMain(int argc, char** argv); 
void  ControlHandler(DWORD request); 


/*_________________---------------------------__________________
  _________________     agent callbacks       __________________
  -----------------___________________________------------------
*/

static void *agentCB_alloc(void *magic, SFLAgent *agent, size_t bytes)
{
	return my_calloc(bytes);
}

static int agentCB_free(void *magic, SFLAgent *agent, void *obj)
{
	my_free(obj);
	return 0;
}

static void agentCB_error(void *magic, SFLAgent *agent, char *msg)
{
	myLog(LOG_ERR,"agentCB_error: %s",msg);	  
}

  
static void agentCB_sendPkt(void *magic, SFLAgent *agent, SFLReceiver *receiver, u_char *pkt, uint32_t pktLen)
{
	HSP *sp = (HSP *)magic;
	size_t socklen = 0;
	SOCKET fd = 0, result = 0;
	HSPCollector *coll;

	for (coll = sp->sFlow->collectors; coll; coll=coll->nxt) {
		switch(coll->ipAddr.type) {
		case SFLADDRESSTYPE_IP_V4:
			{
				struct sockaddr_in *sa = (struct sockaddr_in *)&(coll->sendSocketAddr);
				socklen = sizeof(struct sockaddr_in);
				sa->sin_family = AF_INET;
				sa->sin_port = htons(coll->udpPort);
				fd = sp->socket4;
			}
			break;
		case SFLADDRESSTYPE_IP_V6:
			{
				struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&(coll->sendSocketAddr);
				socklen = sizeof(struct sockaddr_in6);
				sa6->sin6_family = AF_INET6;
				sa6->sin6_port = htons(coll->udpPort);
				fd = sp->socket6;
			}
			break;
		}

		if (socklen && fd > 0) {
			result = sendto(fd, (const char *)pkt, pktLen, 0,
						    (struct sockaddr *)&coll->sendSocketAddr,
							(int)socklen);
			if (result == -1 && errno != EINTR) {
				if (LOG_ERR <= debug) {
					int sockerr = WSAGetLastError();
					myLog(LOG_ERR,"agentCB_sendPacket: sendto error code: %d", sockerr);
				}
			}
			if (result == 0) {
				myLog(LOG_ERR, "agentCB_sendPacket: socket sendto returned 0: %s", strerror(errno));
			}
		}
	}
}

/**
 * Callback function used when counters are to be exported.
 * Queues the poller so that counter polling can be interleaved with sample
 * export and sample export not starved while exporting counters
 */
void agentCB_getCounters(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
	HSP *sp = (HSP *)poller->magic;
	HSPPollerQ *pollerQ = (HSPPollerQ *)my_calloc(sizeof(HSPPollerQ));
	pollerQ->magic = magic;
	pollerQ->poller = poller;
	//we don't save cs because this is allocated on the stack of the calling function.
	//we'll have to allocate a new cs on the stack when we come to service the
	//counter poll request later
	if (sp->pollerQTail != NULL) {
		sp->pollerQTail->nxt = pollerQ;
	}
	sp->pollerQTail = pollerQ;
	if (sp->pollerQHead == NULL) {
		sp->pollerQHead = sp->pollerQTail;
	}
}

/**
 * Gathers all the physical host counters and writes them to the poller.
 */
void getCounters_host(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
	SFLCounters_sample_element hidElem = { 0 };
	SFLCounters_sample_element nioElem = { 0 };
	SFLCounters_sample_element cpuElem = { 0 };
	SFLCounters_sample_element memElem = { 0 };
	SFLCounters_sample_element dskElem = { 0 };
	SFLCounters_sample_element adaptorsElem = { 0 };
	SFLCounters_sample_element vNodeElem = { 0 };

	HSP *sp = (HSP *)poller->magic;

	hidElem.tag = SFLCOUNTERS_HOST_HID;
	hidElem.counterBlock.host_hid = sp->host_hid; // structure copy
	SFLADD_ELEMENT(cs, &hidElem);
    // host Net I/O
	nioElem.tag = SFLCOUNTERS_HOST_NIO;
	if (readNioCounters(sp, &nioElem.counterBlock.host_nio)) {
		SFLADD_ELEMENT(cs, &nioElem);
	}
	// host cpu counters
	cpuElem.tag = SFLCOUNTERS_HOST_CPU;
	readCpuCounters(&cpuElem.counterBlock.host_cpu);
	SFLADD_ELEMENT(cs, &cpuElem);

    // host memory counters
	memElem.tag = SFLCOUNTERS_HOST_MEM;
	if (readMemoryCounters(&memElem.counterBlock.host_mem)) {
		SFLADD_ELEMENT(cs, &memElem);
	}
	// host I/O counters
    dskElem.tag = SFLCOUNTERS_HOST_DSK;
    readDiskCounters(&dskElem.counterBlock.host_dsk);
	SFLADD_ELEMENT(cs, &dskElem);

	// include the adaptor list
	adaptorsElem.tag = SFLCOUNTERS_ADAPTORS;
	adaptorsElem.counterBlock.adaptors = sp->adaptorList;
	SFLADD_ELEMENT(cs, &adaptorsElem);

	//virt_node if hyper-v is present
	//Since the root partition sees all the memory and CPUs we can just use the
	//physical counters for the host.
	if (sp->hyperV) {
		vNodeElem.tag = SFLCOUNTERS_HOST_VRT_NODE;
		SFLHost_vrt_node_counters vNode = vNodeElem.counterBlock.host_vrt_node;
		vNode.mhz = cpuElem.counterBlock.host_cpu.cpu_speed;
		vNode.cpus = cpuElem.counterBlock.host_cpu.cpu_num;
		vNode.memory = memElem.counterBlock.host_mem.mem_total;
		vNode.memory_free = memElem.counterBlock.host_mem.mem_free;
		vNode.num_domains = sp->num_partitions;
		SFLADD_ELEMENT(cs, &vNodeElem);
	}
	sfl_poller_writeCountersSample(poller, cs);
	myLog(LOG_INFO, "UTHeap totalAllocatedBytes = %I64u", UTHeapQTotal());
}

  /*_________________---------------------------__________________
    _________________       tick                __________________
    -----------------___________________________------------------
  */
  
static void tick(HSP *sp) 
{
	if (sp->clk%5 == 0) {
		calcLoad();
	}
	if ((sp->clk % HSP_REFRESH_PORTS) == 0  && HSP_FILTER_ACTIVE(sp->filter)) {
			readFilterSwitchPorts(sp);
	}
	if (sp->refreshVms || (sp->clk % HSP_REFRESH_VMS) == 0) {
		sp->refreshVms = FALSE;
		if (HSP_FILTER_ACTIVE(sp->filter) || sp->hyperV) {
			//it would be better to do this only when we detect a switch port change.
			//However, we need the vm friendly names to be current and changes to
			//friendly names will not be detected by the filter.
			//We also need to handle the case where there is no filter or the filter
			//is not installed in all the switches.
			readVms(sp);
		}
	}
	if (sp->nio_polling_secs && (sp->clk % sp->nio_polling_secs) == 0) {
		updateNioCounters(sp);
	}
	if (sp->vmStoreInvalid) {
		writeGuidStore(sp->vmStore, sp->f_vmStore);
		sp->vmStoreInvalid = FALSE;
	}
	if (sp->portStoreInvalid) {
		writeGuidStore(sp->portStore, sp->f_portStore);
		sp->portStoreInvalid = FALSE;
	}
	if ((sp->clk % HSP_REFRESH_ADAPTORS) == 0) {
		readInterfaces(sp, false);
	}
	sfl_agent_tick(sp->sFlow->agent, sp->clk);
}

  /*_________________---------------------------__________________
    _________________         initAgent         __________________
    -----------------___________________________------------------
  */
  
static BOOL initAgent(HSP *sp)
{
	time_t now;
	HSPCollector *collector;
	SFLReceiver *receiver;
	uint32_t receiverIndex;
	SFLDataSource_instance dsi;
	uint32_t pollingInterval;
	HSPSFlow *sf = sp->sFlow;
	WSADATA WSAData;
	int WSARes = 0;

	myLog(LOG_INFO,"creating sfl agent\n");
	if (sf->collectors == NULL) {
		myLog(LOG_ERR,"No collectors defined\n");
		return FALSE;
	}
	assert(sf->agentIP.type);

	WORD word = MAKEWORD(2, 2);
	WSARes = WSAStartup(word,&WSAData);
	if (WSARes != 0) {
		myLog(LOG_ERR,"WSAStartup failed: %d",WSARes);
		exit(WSARes);
	}
	// open the sockets if not open already - one for v4 and another for v6
    if (sp->socket4 <= 0) {
		if ((sp->socket4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
			myLog(LOG_ERR,"socket error");
		}
	}
	if (sp->socket6 <= 0) {
		if ((sp->socket6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
			myLog(LOG_ERR,"socket error");
		}
	}
	time(&now);
	sf->agent = (SFLAgent *)my_calloc(sizeof(SFLAgent));
	sfl_agent_init(sf->agent,
				   &sf->agentIP,
				   sf->subAgentId,
				   now,
				   now,
				   sp,
				   agentCB_alloc,
				   agentCB_free,
				   agentCB_error,
				   agentCB_sendPkt);
	// just one receiver - we are serious about making this lightweight for now
	collector = sf->collectors;
	receiver = sfl_agent_addReceiver(sf->agent);
	receiverIndex = HSP_SFLOW_RECEIVER_INDEX;
    
	// set the default receiver owner string
	sfl_receiver_set_sFlowRcvrOwner(receiver, "HyperV sFlow Agent");
    
	// set the timeout to infinity
	sfl_receiver_set_sFlowRcvrTimeout(receiver, 0xFFFFFFFF);

	// receiver address/port - set it for the first collector,  but
	// actually we'll send the same feed to all collectors.  This step
	// may not be necessary at all when we are using the sendPkt callback.
	sfl_receiver_set_sFlowRcvrAddress(receiver, &collector->ipAddr);
	sfl_receiver_set_sFlowRcvrPort(receiver, collector->udpPort);
    
	pollingInterval = sf->sFlowSettings ? sf->sFlowSettings->pollingInterval : SFL_DEFAULT_POLLING_INTERVAL;
	// add a single poller to represent the whole physical host
	if (pollingInterval > 0) {
		// ds_class = <physicalEntity>, ds_index = <my physical>, ds_instance = 0
		SFL_DS_SET(dsi, SFL_DSCLASS_PHYSICAL_ENTITY, HSP_DEFAULT_PHYSICAL_DSINDEX, 0);  
		sf->poller = sfl_agent_addPoller(sf->agent, &dsi, sp, agentCB_getCounters);
		sfl_poller_set_sFlowCpInterval(sf->poller, pollingInterval);
		sfl_poller_set_sFlowCpReceiver(sf->poller, receiverIndex);
	}
    return TRUE;
}

/**
 * Removes all instances of the counter poller from the list of queued pollers
 * without fulfilling the counter poll requests.
 * This is required when a counter poller is removed when there are pending 
 * counter poll requests.
 */
void removeQueuedPoller(HSP *sp, SFLPoller *poller)
{
	HSPPollerQ *pollerQPrev = NULL;
	HSPPollerQ *pollerQNxt = sp->pollerQHead;
	while (pollerQNxt != NULL) {
		if (pollerQNxt->poller == poller) {
			if (pollerQPrev == NULL) {
				sp->pollerQHead = pollerQNxt->nxt;
				my_free(pollerQNxt);
				pollerQNxt = sp->pollerQHead;
			} else {
				pollerQPrev->nxt = pollerQNxt->nxt;
				my_free(pollerQNxt);
				pollerQNxt = pollerQPrev->nxt;
			}
		} else {
			pollerQPrev = pollerQNxt;
			pollerQNxt = pollerQPrev->nxt;
		}
	}
	sp->pollerQTail = pollerQPrev;
}

/**
 * Removes the queued poller at the head of the queue, uses the
 * poller's dsClass to determine which set of counters are to be
 * polled: 
 * SFL_DSCLASS_PHYSICAL_ENTITY = physical host counters
 * SFL_DSCLASS_IFINDEX = switch port counters
 * SFL_DSCLASS_LOGICAL_ENTITY = vm counters
 * then calls the appropriate function to assemble and export the counters.
 * Updates the queue head and tail pointers.
 */
void processQueuedPoller(HSP *sp)
{
	if (sp->pollerQHead != NULL) {
		HSPPollerQ *pollerQ = sp->pollerQHead;
		sp->pollerQHead = pollerQ->nxt;
		pollerQ->nxt = NULL;
		if (sp->pollerQHead == NULL) {
			sp->pollerQTail = NULL;
		}
		uint32_t dsClass = SFL_DS_CLASS(pollerQ->poller->dsi);
		SFL_COUNTERS_SAMPLE_TYPE cs;
		memset(&cs, 0, sizeof(cs));
		switch (dsClass) {
			case SFL_DSCLASS_PHYSICAL_ENTITY:
				getCounters_host(pollerQ->magic, pollerQ->poller, &cs);
				break;
			case SFL_DSCLASS_IFINDEX:
				getCounters_interface(pollerQ->magic, pollerQ->poller, &cs);
				break;
			case SFL_DSCLASS_LOGICAL_ENTITY:
				getCounters_vm(pollerQ->magic, pollerQ->poller, &cs);
				break;
		}
		my_free(pollerQ);
	}
}

/*_________________---------------------------__________________
  _________________       freeSFlow           __________________
  -----------------___________________________------------------
*/

static void freeSFlow(HSPSFlow *sf)
{
	HSPCollector *coll;
	if (sf == NULL) return;
	if (sf->sFlowSettings) {
		my_free(sf->sFlowSettings);
	}
	if (sf->agent) {
		sfl_agent_release(sf->agent);
	}
	for (coll = sf->collectors; coll; ) {
		HSPCollector *nextColl = coll->nxt;
		my_free(coll);
		coll = nextColl;
	}
	if (sf->agentDevice) {
		my_free(sf->agentDevice);
	}
	my_free(sf);
}

static bool initialiseDir(wchar_t *path, wchar_t *dirName)
{
	PathAppendW(path, dirName);
	DWORD attributes = GetFileAttributesW(path);
	if (INVALID_FILE_ATTRIBUTES == attributes) {
		DWORD error = GetLastError();
		if (ERROR_FILE_NOT_FOUND == error ||
			ERROR_PATH_NOT_FOUND == error) {
			error = CreateDirectoryW(path, NULL);
			if (!SUCCEEDED(error)) {
				myLog(LOG_ERR, "initialiseDir: cannot create directory %S", path);
				return false;
			}
		} else {
			myLog(LOG_ERR, "initialiseDir: invalid directory %S error=0x%x", path, error);
			return false;
		}
	} else if ((FILE_ATTRIBUTE_DIRECTORY & attributes) != FILE_ATTRIBUTE_DIRECTORY) {
		myLog(LOG_ERR, "initialiseDir: invalid directory %S attributes=0x%x", path, attributes);
		return false;
	}
	return true;
}

static bool initialiseProgramDataDir(wchar_t *path, size_t pathLen)
{
	PWSTR programData;
	if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, NULL, &programData))) {
		wcscpy_s(path, pathLen, programData);
		CoTaskMemFree(programData);
		if (initialiseDir(path, HSP_PUBLISHER)) {
			return initialiseDir(path, HSP_PRODUCT_NAME);
		}
	}
	return false;
}

static bool initialiseProgramDataFiles(HSP *sp, wchar_t *programDataDir)
{
	size_t dirLen = wcsnlen(programDataDir, MAX_PATH);
	size_t fnLen = dirLen+wcslen(HSP_DEFAULT_VMSTORE)+1;
	wchar_t *vmStoreFile = (wchar_t *)my_calloc(sizeof(wchar_t)*fnLen);
	wcscpy_s(vmStoreFile, fnLen, programDataDir);
	PathAppendW(vmStoreFile, HSP_DEFAULT_VMSTORE);
	sp->vmStoreFile = vmStoreFile;
	HANDLE fileHandle;
	if ((fileHandle = CreateFileW(vmStoreFile, 
								  GENERIC_READ | GENERIC_WRITE, 
								  FILE_SHARE_WRITE, NULL,
								  OPEN_ALWAYS, 
								  FILE_ATTRIBUTE_NORMAL, 
								  NULL)) == INVALID_HANDLE_VALUE) {
		myLog(LOG_ERR, "initialiseProgramDataFiles: cannot open VM store file %S\n", vmStoreFile);
		return false;
	} else {
		int cHandle = _open_osfhandle((long)fileHandle, _O_RDWR | _O_TEXT);
		sp->f_vmStore = _fdopen(cHandle, "r+t");
	}
	fnLen = dirLen+wcslen(HSP_DEFAULT_PORTSTORE)+1;
	wchar_t *portStoreFile = (wchar_t *)my_calloc(sizeof(wchar_t)*fnLen);
	wcscpy_s(portStoreFile, fnLen, programDataDir);
	PathAppendW(portStoreFile, HSP_DEFAULT_PORTSTORE);
	sp->portStoreFile = portStoreFile;
	if ((fileHandle = CreateFileW(portStoreFile, 
								  GENERIC_READ | GENERIC_WRITE,
								  FILE_SHARE_WRITE, NULL,
								  OPEN_ALWAYS, 
								  FILE_ATTRIBUTE_NORMAL, 
								  NULL)) == INVALID_HANDLE_VALUE) {
		myLog(LOG_ERR, "initialiseProgramDataFiles: cannot open VM store file %S\n", portStoreFile);
		return false;
	} else {
		int cHandle = _open_osfhandle((long)fileHandle, _O_RDWR | _O_TEXT);
		sp->f_portStore = _fdopen(cHandle, "r+t");
	}
	return true;
}

VOID usage(char *prog)
{
	fprintf(stderr, "%s: usage: hsflowd.exe [-v[v]] [-l logFile]\n", prog);
	exit(1);
}

void main(int argc, char *argv[])
{ 
	for (int arg = 1; arg < argc; arg++) {
		if (strcmp(argv[arg], "-v") == 0) {
			debug = LOG_NOTICE;
		} else if (strcmp(argv[arg], "-vv") == 0) {
			debug = LOG_INFO;
        }  else if (strcmp(argv[arg], "-l") == 0) {
            if (arg < argc-1) {
                logFilename = argv[++arg];
            } else {
                usage(argv[0]);
			}
		} else {
            // Unknown parameter
            usage(argv[0]);
        }
    }
    SERVICE_TABLE_ENTRY ServiceTable[2];
	ServiceTable[0].lpServiceName = HSP_SERVICE_NAME;
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

    ServiceTable[1].lpServiceName = NULL;
    ServiceTable[1].lpServiceProc = NULL;
    if (0 == StartServiceCtrlDispatcher(ServiceTable)) { //else ServiceMain is called by the dispatcher
		if (ERROR_FAILED_SERVICE_CONTROLLER_CONNECT == GetLastError()){
			//invoked from the commandline.  
			//Turn on debug output at debug level defined by commandline.
			isService = FALSE;
			ServiceMain(0, NULL);
		}
	}
}


void ServiceMain(int argc, char** argv) 
{ 
	ServiceStatus.dwServiceType        = SERVICE_WIN32; 
	ServiceStatus.dwCurrentState       = SERVICE_START_PENDING; 
	ServiceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ServiceStatus.dwWin32ExitCode      = 0; 
	ServiceStatus.dwServiceSpecificExitCode = 0; 
	ServiceStatus.dwCheckPoint         = 0;
	ServiceStatus.dwWaitHint           = 0;
	if (isService) {
		hStatus = RegisterServiceCtrlHandler(HSP_SERVICE_NAME, 
											 (LPHANDLER_FUNCTION)ControlHandler); 

		if (hStatus == 0) 
		{ 
			return; 
		}
	}
	// Test for only one instance is running
	HANDLE mutex = CreateMutex(NULL, TRUE, instanceMutexName);
	DWORD err = GetLastError();
	if (mutex != NULL && err == ERROR_ALREADY_EXISTS ||
		mutex == NULL && err == ERROR_ACCESS_DENIED) {
			// Mutex found, so another instance is running
		if (hStatus != 0) {
			ServiceStatus.dwCurrentState = SERVICE_STOPPED;
			ServiceStatus.dwWin32ExitCode = ERROR_SINGLE_INSTANCE_APP;
			SetServiceStatus(hStatus, &ServiceStatus);
		} else {
			myLog(LOG_ERR, "%s.ServiceMain: only one instance can run, existing instance found", HSP_SERVICE_NAME);
		}
		return;
	} else {
		ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
		if (hStatus != 0) {
			// We are the first instance, report the running status to SCM. 
			SetServiceStatus (hStatus, &ServiceStatus);
		}
	}
	wchar_t programDataDir[MAX_PATH];
	if (!initialiseProgramDataDir(programDataDir, MAX_PATH)) {
		*programDataDir = NULL;
	}
	char mbcLogFilename[MAX_PATH];
	if (isService && *programDataDir != NULL) {
		//set the log file name to the default.
		size_t dirLen = 0;
		if (0 == wcstombs_s(&dirLen, mbcLogFilename, MAX_PATH, programDataDir, wcslen(programDataDir))) {
			PathAppend(mbcLogFilename, HSP_DEFAULT_LOGFILE);
			logFilename = mbcLogFilename;
		} else {
			logFilename = NULL;
		}
	}
	if (logFilename != NULL) {
        // Logging on
     	errno_t error = fopen_s(&logFile, logFilename, "wt");
        if (error != 0) {
			logFile = stderr;
			myLog(LOG_ERR, "%s.ServiceMain: could not open log file %s: error %d\n", HSP_SERVICE_NAME, logFilename, error);
        }
		logFilename = NULL;
    }
	myLog(debug, "-------------Starting %s %s--------------", HSP_SERVICE_NAME, HSP_VERSION);
	fflush(logFile);

	HSP sp = { 0 };
	// look up host-id fields at startup only (hostname
	// may change dynamically so will have to revisit this $$$)
	sp.host_hid.hostname.str = (char *)my_calloc(SFL_MAX_HOSTNAME_CHARS+1);
	sp.host_hid.os_release.str = (char *)my_calloc(SFL_MAX_OSRELEASE_CHARS+1);
	readHidCounters(&sp, &sp.host_hid);
	
	sp.nio_polling_secs = HSP_NIO_POLLING_SECS_32BIT;

	readInterfaces(&sp, TRUE);
	if (!readConfig(&sp)) {
		myLog(LOG_ERR, "%s.ServiceMain: invalid configuration", HSP_SERVICE_NAME);
		if (hStatus != 0) {
			ServiceStatus.dwCurrentState = SERVICE_STOPPED;
			ServiceStatus.dwWin32ExitCode = ERROR_INVALID_PARAMETER;
			SetServiceStatus(hStatus, &ServiceStatus);
		}
		return;
	}
	sp.hyperV = testForHyperv();
	if (sp.hyperV) {
		myLog(debug, "%s.ServiceMain Hyper-V services are running", HSP_SERVICE_NAME);
		if (programDataDir == NULL || !initialiseProgramDataFiles(&sp, programDataDir)) {
			myLog(LOG_ERR, "%s.ServiceMain: cannot initialise switch port and VM state files", HSP_SERVICE_NAME);
			if (hStatus != 0) {
				ServiceStatus.dwCurrentState = SERVICE_STOPPED;
				ServiceStatus.dwWin32ExitCode = ERROR_FILE_NOT_FOUND;
				SetServiceStatus(hStatus, &ServiceStatus);
			}
			return;
		}
		readGuidStore(sp.f_vmStore, sp.vmStoreFile, &sp.vmStore, &sp.maxDsIndex);
		readGuidStore(sp.f_portStore, sp.portStoreFile, &sp.portStore, &sp.maxIfIndex);
	}
	openFilter(&sp); //try to initialise the sFlow filter for sampling
	initAgent(&sp);

	// initialize the clock so we can detect second boundaries
	sp.clk = time(NULL);
 
    // main loop
	BOOL dataAvailable = true;
	uint32_t currReadNum = 0;
    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING && dataAvailable)
	{
		// check for second boundaries and generate ticks for the sFlow library
		time_t now = time(NULL);
		if ((now < sp.clk) || (now - sp.clk) > HSP_MAX_TICKS) {
			// avoid a busy-loop of ticks if time jumps
			myLog(LOG_INFO, "%s.ServiceMain: time jump detected", HSP_SERVICE_NAME);
			sp.clk = now - 1;
		}
		while (sp.clk < now) { //only happens on second boundary
			//start critical
			if (sp.sFlow->sFlowSettings) {
				// update polling interval here if config has changed.
				tick(&sp);
			}
			//end critical
			sp.clk++;
		}
		DWORD result;
		//process a queued counter poller
		processQueuedPoller(&sp);
		//timeout is set so that we loop around checking for ticks and samples
		//several times/s.
		//calculate timeout 200 if the counter poller queue is empty, 0 otherwise
		DWORD timeout = sp.pollerQHead == NULL ? HSP_TIMEOUT : 0;
		if (HSP_FILTER_ACTIVE(sp.filter)) {
			result = WaitForSingleObject(sp.filter.overlaps[currReadNum].hEvent, 
										 timeout);
			if (result == WAIT_OBJECT_0) {
				dataAvailable = sp.filter.overlaps[currReadNum].Internal == ERROR_SUCCESS;
				if (dataAvailable && sp.filter.overlaps[currReadNum].InternalHigh > 0) {
					//process the sample info in sp.filter.buffers[currReadNum]
					readPackets(&sp, sp.filter.buffers[currReadNum]);
				}
				// Re-queue this read
				queueRead(sp.filter.dev,
					      sp.filter.buffers[currReadNum], 
					      sizeof(sp.filter.buffers[currReadNum]), 
						  &sp.filter.overlaps[currReadNum]);
				//set the next buffer to read
				currReadNum = (currReadNum+1)%numConcurrentReads;
			}
		} else {
			Sleep(timeout);
		}
	}
    return; 
}

// Control handler function
void ControlHandler(DWORD request) 
{ 
    switch(request) 
    { 
        case SERVICE_CONTROL_STOP: 

            ServiceStatus.dwWin32ExitCode = 0; 
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED; 
            SetServiceStatus (hStatus, &ServiceStatus);
            return; 
 
        case SERVICE_CONTROL_SHUTDOWN: 

            ServiceStatus.dwWin32ExitCode = 0; 
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED; 
            SetServiceStatus (hStatus, &ServiceStatus);
            return; 
        
        default:
            break;
    } 
 
    // Report current status
    SetServiceStatus (hStatus,  &ServiceStatus);
 
    return; 
} 

#if defined(__cplusplus)
} /* extern "C" */
#endif