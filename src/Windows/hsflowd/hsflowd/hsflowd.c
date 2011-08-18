/* Copyright (c) 2009 InMon Corp. ALL RIGHTS RESERVED */
/* License: http://www.inmon.com/products/virtual-probe/license.php */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#define SLEEP_TIME 1000

//globals
int debug = 0;
uint64_t tick_count = 0;
SERVICE_STATUS ServiceStatus; 
SERVICE_STATUS_HANDLE hStatus; 
 
void  ServiceMain(int argc, char** argv); 
void  ControlHandler(DWORD request); 
int InitService();


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
    int fd = 0, result = 0;
	HSPCollector *coll;

    for(coll = sp->sFlow->collectors; coll; coll=coll->nxt) {

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

    if(socklen && fd > 0) {
		result = sendto(fd,
			    (const char *)pkt,
			    pktLen,
			    0,
			    (struct sockaddr *)&coll->sendSocketAddr,
			    socklen);
	if(result == -1 && errno != EINTR) {
	  if(debug){
		  int sockerr = WSAGetLastError();
		  myLog(LOG_ERR,"sendto error code: %d",sockerr);
	  }
	}
	if(result == 0) {
	  myLog(LOG_ERR, "socket sendto returned 0: %s", strerror(errno));
	}
      }
    }
  }

  void agentCB_getCounters(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
	SFLCounters_sample_element hidElem;
	SFLCounters_sample_element nioElem;
	SFLCounters_sample_element cpuElem;
	SFLCounters_sample_element memElem;
	SFLCounters_sample_element dskElem;
	SFLCounters_sample_element adaptorsElem;

	HSP *sp = (HSP *)poller->magic;
	
    memset(&hidElem, 0, sizeof(hidElem));
    hidElem.tag = SFLCOUNTERS_HOST_HID;
	hidElem.counterBlock.host_hid = sp->host_hid; // structure copy
    SFLADD_ELEMENT(cs, &hidElem);

    // host Net I/O
    memset(&nioElem, 0, sizeof(nioElem));
    nioElem.tag = SFLCOUNTERS_HOST_NIO;
    if(readNioCounters(sp, &nioElem.counterBlock.host_nio)) {
      SFLADD_ELEMENT(cs, &nioElem);
    }
	
    // host cpu counters
    memset(&cpuElem, 0, sizeof(cpuElem));
    cpuElem.tag = SFLCOUNTERS_HOST_CPU;
    if(readCpuCounters(&cpuElem.counterBlock.host_cpu)) {
      SFLADD_ELEMENT(cs, &cpuElem);
    }

    // host memory counters
    memset(&memElem, 0, sizeof(memElem));
    memElem.tag = SFLCOUNTERS_HOST_MEM;
    if(readMemoryCounters(&memElem.counterBlock.host_mem)) {
      SFLADD_ELEMENT(cs, &memElem);
    }

    // host I/O counters
    memset(&dskElem, 0, sizeof(dskElem));
    dskElem.tag = SFLCOUNTERS_HOST_DSK;
    if(readDiskCounters(&dskElem.counterBlock.host_dsk)) {
      SFLADD_ELEMENT(cs, &dskElem);
    }

    // include the adaptor list
    memset(&adaptorsElem, 0, sizeof(adaptorsElem));
    adaptorsElem.tag = SFLCOUNTERS_ADAPTORS;
    adaptorsElem.counterBlock.adaptors = sp->adaptorList;
    SFLADD_ELEMENT(cs, &adaptorsElem);

    sfl_poller_writeCountersSample(poller, cs);
	myLog(LOG_INFO, "UTHeap totalAllocatedBytes = %I64u", UTHeapQTotal());
  }

  /*_________________---------------------------__________________
    _________________       tick                __________________
    -----------------___________________________------------------
  */
  
  static void tick(HSP *sp) {
    if(tick_count++%5==0)
		calcLoad();
	if(sp->nio_polling_secs && (sp->clk % sp->nio_polling_secs) == 0) {
			updateNioCounters(sp);
	}
	sfl_agent_tick(sp->sFlow->agent, sp->clk);
  }

    /*_________________---------------------------__________________
    _________________         initAgent         __________________
    -----------------___________________________------------------
  */
  
  static int initAgent(HSP *sp)
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

    myLog(LOG_ERR,"creating sfl agent\n");

    if(sf->collectors == NULL) {
	  myLog(LOG_ERR,"No collectors defined\n");
      return NO;
    }

    assert(sf->agentIP.type);

	WSARes = WSAStartup(MAKEWORD(2, 2),&WSAData);
    if(WSARes != 0){
		myLog(LOG_ERR,"WSAStartup failed: %d",WSARes);
		exit(WSARes);
	}
    // open the sockets if not open already - one for v4 and another for v6
    if(sp->socket4 <= 0) {
      if((sp->socket4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		  myLog(LOG_ERR,"socket error");
    }
    if(sp->socket6 <= 0) {
      if((sp->socket6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		  myLog(LOG_ERR,"socket error");
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
    receiverIndex = 1;
    
    // claim the receiver slot
    sfl_receiver_set_sFlowRcvrOwner(receiver, "Virtual Switch sFlow Probe");
    
    // set the timeout to infinity
    sfl_receiver_set_sFlowRcvrTimeout(receiver, 0xFFFFFFFF);

    // receiver address/port - set it for the first collector,  but
    // actually we'll send the same feed to all collectors.  This step
    // may not be necessary at all when we are using the sendPkt callback.
    sfl_receiver_set_sFlowRcvrAddress(receiver, &collector->ipAddr);
    sfl_receiver_set_sFlowRcvrPort(receiver, collector->udpPort);
    
    pollingInterval = sf->sFlowSettings ? sf->sFlowSettings->pollingInterval : SFL_DEFAULT_POLLING_INTERVAL;
    
    // add a single poller to represent the whole physical host
    
    SFL_DS_SET(dsi, 2, 1, 0);  // ds_class = <physicalEntity>, ds_index = 1, ds_instance = 0
    sf->poller = sfl_agent_addPoller(sf->agent, &dsi, sp, agentCB_getCounters);
    sfl_poller_set_sFlowCpInterval(sf->poller, pollingInterval);
    sfl_poller_set_sFlowCpReceiver(sf->poller, receiverIndex);
    
    // add poller instances for each virtual machine $$$
    
    return YES;
  }


  /*_________________---------------------------__________________
    _________________       freeSFlow           __________________
    -----------------___________________________------------------
  */

  static void freeSFlow(HSPSFlow *sf)
  {
	HSPCollector *coll;

    if(sf == NULL) return;
    if(sf->sFlowSettings) my_free(sf->sFlowSettings);
    if(sf->agent) sfl_agent_release(sf->agent);
    for(coll = sf->collectors; coll; ) {
      HSPCollector *nextColl = coll->nxt;
      my_free(coll);
      coll = nextColl;
    }
    my_free(sf);
  }


void main() 
{ 

    SERVICE_TABLE_ENTRY ServiceTable[2];
    ServiceTable[0].lpServiceName = "hsflowd";
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

    ServiceTable[1].lpServiceName = NULL;
    ServiceTable[1].lpServiceProc = NULL;
    if(0 == StartServiceCtrlDispatcher(ServiceTable)){
		if(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT == GetLastError()){
			//invoked from the commandline.  turn on debug output.
			debug = 1;
			ServiceMain(0,NULL);
		}
	}
}


void ServiceMain(int argc, char** argv) 
{ 
	HSP sp;

	memset(&sp,0,sizeof(sp));
	sp.configFile = "";
	sp.pidFile = "";
 
    ServiceStatus.dwServiceType        = SERVICE_WIN32; 
    ServiceStatus.dwCurrentState       = SERVICE_START_PENDING; 
    ServiceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode      = 0; 
    ServiceStatus.dwServiceSpecificExitCode = 0; 
    ServiceStatus.dwCheckPoint         = 0; 
    ServiceStatus.dwWaitHint           = 0; 
 
	if(!debug){
    	hStatus = RegisterServiceCtrlHandler(
			"hsflowd", 
			(LPHANDLER_FUNCTION)ControlHandler); 
    	if (hStatus == (SERVICE_STATUS_HANDLE)0) 
    	{ 
        	// Registering Control Handler failed
        	return; 
    	}  
	}
    // report the running status to SCM. 
    ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
    SetServiceStatus (hStatus, &ServiceStatus);

    // look up host-id fields at startup only (hostname
	// may change dynamically so will have to revisit this $$$)
	sp.host_hid.hostname.str = (char *)my_calloc(SFL_MAX_HOSTNAME_CHARS+1);
	sp.host_hid.os_release.str = (char *)my_calloc(SFL_MAX_OSRELEASE_CHARS+1);
	readHidCounters(&sp, &sp.host_hid);
	
	sp.nio_polling_secs = HSP_NIO_POLLING_SECS_32BIT;

	readInterfaces(&sp);
	HSPReadConfig(&sp);
	initAgent(&sp);
 
    // main loop
    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
	{
		sp.clk = time(NULL);
		tick(&sp);
		Sleep(SLEEP_TIME);
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