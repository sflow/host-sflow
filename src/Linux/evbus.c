/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "util.h"
#include "evbus.h"

  // only one running bus in each thread - keep track with thread-local var
  // so we can always know what the current "home" bus is and detect
  // inter-bus (inter-thread) messages automatically in EVEventTx
  static __thread EVBus *threadBus;

  /*_________________--------------------------------------------------__________________
    _________________  minimal module-loader with event bus mechanism  __________________
    -----------------__________________________________________________------------------
  */

  static EVMod *addModule(EVRoot *root, char *name);

  EVMod *EVInit(void *data) {
    EVRoot *root = (EVRoot *)my_calloc(sizeof(EVRoot));
    root->buses = UTHASH_NEW(EVBus, name, UTHASH_SKEY);
    root->sockets = UTHASH_NEW(EVSocket, fd, UTHASH_DFLT);
    root->modules = UTHASH_NEW(EVMod, name, UTHASH_SKEY);
    root->moduleList = UTArrayNew(UTARRAY_DFLT);
    root->rootModule = addModule(root, EVMOD_ROOT);
    root->rootModule->data = data;
    root->sync = (pthread_mutex_t *)my_calloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(root->sync, NULL);
    return root->rootModule;
  }
    
  EVBus *EVGetBus(EVMod *mod, char *name, bool create) {
    EVBus *bus;
    SEMLOCK_DO(mod->root->sync) {
      EVBus rlm = { .name = name };
      bus = UTHashGet(mod->root->buses, &rlm);
      if(!bus && create) {
	bus = (EVBus *)my_calloc(sizeof(EVBus));
	bus->root = mod->root;
	bus->name = my_strdup(name);
	UTHashAdd(mod->root->buses, bus);
	bus->events = UTHASH_NEW(EVEvent, name, UTHASH_SKEY);
	bus->eventList = UTArrayNew(UTARRAY_DFLT);
	bus->sockets = UTArrayNew(UTARRAY_DFLT);
	bus->sockets_run = UTArrayNew(UTARRAY_DFLT);
	if(pipe(bus->pipe) == -1) {
	  myLog(LOG_ERR, "pipe() failed : %s", strerror(errno));
	  abort();
	}
	// possibly set pipe to non-blocking with fcntl
	// but be aware that this may change the read/write behavior.
	// We probably want it to block because a full pipe may
	// indicate some sort of rare meltdown and losing events
	// to EWOULDBLOCK could make things worse.
	
	bus->select_mS = EVBUS_SELECT_MS;
	bus->stop = NO;
      }
    }
    return bus;
  }

  EVEvent *EVGetEvent(EVBus *bus, char *name) {
    EVEvent *evt;
    SEMLOCK_DO(bus->root->sync) {
      EVEvent search = { .name = name };
      evt = UTHashGet(bus->events, &search);
      if(!evt) {
	evt = (EVEvent *)my_calloc(sizeof(EVEvent));
	evt->name = my_strdup(name);
	UTHashAdd(bus->events, evt);
	evt->bus = bus;
	evt->actions = UTArrayNew(UTARRAY_DFLT);
	evt->actions_run = UTArrayNew(UTARRAY_DFLT);
	// evt->id is index into eventsList
	evt->id = UTArrayAdd(bus->eventList, evt);
      }
    }
    return evt;
  }

  bool EVBusAddSocket(EVMod *mod, EVBus *bus, int fd, EVReadCB readCB, void *data) {
    EVSocket *sock = NULL;
    SEMLOCK_DO(mod->root->sync) {
      EVSocket search = { .fd = fd };
      if(UTHashGet(mod->root->sockets, &search)) {
	myDebug(1, "socket for fd=%u already exists", fd);
      }
      else {
	sock = (EVSocket *)my_calloc(sizeof(EVSocket));
	sock->fd = fd;
	sock->readCB = readCB;
	sock->module = mod;
	sock->data = data;
	UTHashAdd(mod->root->sockets, sock);
	UTArrayAdd(bus->sockets, sock);
      }
    }
    return (sock != NULL);
  }
      

  void EVEventRx(EVMod *mod, EVEvent *evt, EVActionCB cb) {
    EVAction *act = (EVAction *)my_calloc(sizeof(EVAction));
    act->module = mod;
    act->actionCB = cb;
    SEMLOCK_DO(mod->root->sync) {
      UTArrayAdd(evt->actions, act);
    }
  }

  static EVMod *addModule(EVRoot *root, char *name) {
    EVMod *mod = (EVMod *)my_calloc(sizeof(EVMod));
    mod->root = root;
    mod->name = my_strdup(name);
    UTHashAdd(root->modules, mod);
    // mod->id is index into moduleList
    mod->id = UTArrayAdd(root->moduleList, mod);
    return mod;
  }

  static void loadModule(EVMod *mod, char *mod_dir) {
    if(mod_dir) {
      // try external load - if mod_dir has no "/" in it then
      // the env var LD_LIBRARY_PATH will be consulted.
#define MAX_MOD_PATH_LEN 255
      char path[MAX_MOD_PATH_LEN+1];
      snprintf(path, MAX_MOD_PATH_LEN, "%s/%s.so", mod_dir, mod->name);
      if((mod->libHandle = dlopen(path, RTLD_NOW)) == NULL) {
	myDebug(1, "dlopen(%s) failed : %s", path, dlerror());
      }
    }
    else {
      if((mod->libHandle = dlopen(NULL, RTLD_NOW)) == NULL) {
	myDebug(1, "dlopen(NULL) failed : %s", dlerror());
      }
    }
    if(mod->libHandle) {
      // the init function is the module name
      if((mod->initFn = (void (*)(EVMod *)) dlsym(mod->libHandle, mod->name)) == NULL) {
	myLog(LOG_ERR, "dlsym(%s) failed : %s", mod->name, dlerror());
      }
      else {
	(*mod->initFn)(mod);
      }
    }
  }

  EVMod *EVLoadModule(EVMod *lmod, char *name, char *mod_dir) {
    EVMod *mod;
    bool newMod = NO;
    SEMLOCK_DO(lmod->root->sync) {
      EVRoot *root = lmod->root;
      EVMod search = { .name = name };
      mod = UTHashGet(root->modules, &search);
      if(!mod) {
	mod = addModule(root, name);
	newMod = YES;
      }
    }
    if(newMod)
      loadModule(mod, mod_dir);
    return mod;
  }

  static bool pipeRead(EVBus *bus, int fd, void *buf, size_t bytes) {
    size_t expected = bytes;
    while(expected) {
      int n = read(fd, buf, expected);
      if(n == 0) {
	// indicates EOF
	return NO;
      }
      else if(n < 0) {
	if(errno != EAGAIN
	   && errno == EINTR) {
	  myLog(LOG_ERR, "bus %s readv(pipe) error: %s", bus->name, strerror(errno));
	  return NO;
	}
      }
      else {
	expected -= n;
      }
    }
    return YES;
  }

  static int busRxPipe(EVBus *bus, int fd) {
    EVEventHdr hdr = { 0 };
    char data[PIPE_BUF];
    if(pipeRead(bus, fd, &hdr, sizeof(hdr)) == NO)
      return 0;
    if(hdr.dataLen
       && pipeRead(bus, fd, data, hdr.dataLen) == NO)
      return 0;
    data[hdr.dataLen] = '\0'; // NULL-terminate (convenient if string msg)
    EVMod *mod;
    EVEvent *evt;
    SEMLOCK_DO(bus->root->sync) {
      mod = UTArrayAt(bus->root->moduleList, hdr.modId);
      evt = UTArrayAt(bus->eventList, hdr.eventId);
    }
    return EVEventTx(mod, evt, (hdr.dataLen ? data : NULL), hdr.dataLen);
  }

  static bool eventTxPipe(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    EVEventHdr hdr = { .modId = mod->id,
		       .eventId = evt->id,
		       .dataLen = dataLen };
    if((sizeof(hdr) + dataLen) > PIPE_BUF) {
      myLog(LOG_ERR, "write() from mod %s to event pipe %s : msg too long(%u) => not atomic",
	    mod->name,
	    evt->name,
	    dataLen);
      return NO;
    }
    
    struct iovec vec[2] = { { &hdr, sizeof(hdr) }, { data, dataLen } };
  try_again:
    if(writev(evt->bus->pipe[1], vec, 2) > 0) {
      // no partial writes for len <= PIPE_BUF
      return YES;
    }
    if(errno == EINTR) goto try_again;
    myLog(LOG_ERR, "write() from mod %s to event pipe %s failed : %s", mod->name, evt->name, strerror(errno));
    return NO;
  }

  static void syncArrays(EVRoot *root, UTArray *ar1, UTArray *ar2) {
    // Rebuild array that has to operate outside the semaphore protection
    // (because we don't want to hold mod->root>sync while we invoke action
    // or socket callback-functions in case those functions want to add
    // actions, sockets, buses etc. themselves).  Could get the same
    // effect using an atomic compare-and-exchange to add actions or sockets
    // to a singly linked list, but this is just as good really, and more
    // portable.

    // Currently only handles new entries being added.  If we allow deletions
    // then we can do it with a "changed" flag and a complete copy here.
    if(UTArrayN(ar2) != UTArrayN(ar1)) {
      SEMLOCK_DO(root->sync) {
	for(int aa = UTArrayN(ar2); aa < UTArrayN(ar1); aa++)
	  UTArrayAdd(ar2, UTArrayAt(ar1, aa));
      }
    }
  }

  int EVEventTx(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    int sent = 0;
    if(evt->bus == threadBus) {
      // local event
      EVAction *act;
      syncArrays(mod->root, evt->actions, evt->actions_run);
      UTARRAY_WALK(evt->actions_run, act) {
	(*act->actionCB)(act->module, evt, data, dataLen);
	sent++;
      }
    }
    else {
      // inter-bus event goes on pipe for simple select() sync.
      if(eventTxPipe(mod, evt, data, dataLen))
  	sent++;
    }
    return sent;
  }

  int EVEventTxAll(EVMod *mod, char *evt_name, void *data, size_t dataLen) {
    EVBus *bus;
    int sent = 0;
    UTHASH_WALK(mod->root->buses, bus) {
      sent += EVEventTx(mod, EVGetEvent(bus, evt_name), data, dataLen);
    }
    return sent;
  }

  static void busRead(EVBus *bus) {
    EVSocket *sock;
    fd_set readfds;
    FD_ZERO(&readfds);
    int max_fd = 0;
    // the input pipe
    FD_SET(bus->pipe[0], &readfds);
    max_fd = bus->pipe[0];
    // and other registered sockets
    syncArrays(bus->root, bus->sockets, bus->sockets_run);
    UTARRAY_WALK(bus->sockets_run, sock) {
      FD_SET(sock->fd, &readfds);
      if(sock->fd > max_fd)
	max_fd = sock->fd;
    }
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = (bus->select_mS * 1000);
    int nfds = select(max_fd + 1,
		      &readfds,
		      (fd_set *)NULL,
		      (fd_set *)NULL,
		      &timeout);
    if(nfds > 0) {
      if(FD_ISSET(bus->pipe[0], &readfds))
	busRxPipe(bus, bus->pipe[0]);
      UTARRAY_WALK(bus->sockets_run, sock) {
	if(FD_ISSET(sock->fd, &readfds))
	  (*sock->readCB)(sock->module, bus, sock->fd, sock->data);
      }
    }
    else if(nfds < 0) {
      // may return prematurely if a signal was caught, in which case nfds will be
      // -1 and errno will be set to EINTR.  If we get any other error, abort.
      if(errno != EINTR) {
	myLog(LOG_ERR, "bus %s select() returned %d : %s", bus->name, nfds, strerror(errno));
	abort();
      }
    }
  }
  
  static void *busRun(void *magic) {
    EVBus *bus = (EVBus *)magic;
    assert(bus->running == NO);
    threadBus = bus; // assign to thread-local var
    bus->running = YES;
    EVEvent *start = EVGetEvent(bus, EVEVENT_START);
    EVEvent *tick = EVGetEvent(bus, EVEVENT_TICK);
    EVEvent *tock = EVGetEvent(bus, EVEVENT_TOCK);
    EVEvent *final = EVGetEvent(bus, EVEVENT_FINAL);
    EVEvent *end = EVGetEvent(bus, EVEVENT_END);

    EVEventTx(bus->root->rootModule, start, NULL, 0);
    for(;;) {
      if(bus->stop) {
	EVEventTx(bus->root->rootModule, final, NULL, 0);
	EVEventTx(bus->root->rootModule, end, NULL, 0);
	break;
      }

      busRead(bus);

      // check for second boundaries and generate ticks for the sFlow library
      time_t test_clk = UTClockSeconds();
      if((test_clk < bus->clk)
	 || (test_clk - bus->clk) > EV_MAX_TICKS) {
	// avoid a busy-loop of ticks
	myLog(LOG_INFO, "time jump detected on bus %s", bus->name);
	bus->clk = test_clk - 1;
      }
      while(bus->clk < test_clk) {
	// TODO: this would be a good place to test the memory footprint and
	// bail out if it looks like we are leaking memory(?)
#ifdef UTHEAP
	UTHeapGC();
#endif
	bus->clk++;
	EVEventTx(bus->root->rootModule, tick, NULL, 0);
	EVEventTx(bus->root->rootModule, tock, NULL, 0);
      }
    }
    return NULL;
  }

  void EVBusRunThread(EVBus *bus, size_t stacksize) {
    // Set a more conservative stacksize here - partly because
    // we don't need more,  but mostly because Debian was refusing
    // to create the thread - I guess because it was enough to
    // blow through our mlockall() allocation.
    // http://www.mail-archive.com/xenomai-help@gna.org/msg06439.html 
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, stacksize);
    bus->thread = my_calloc(sizeof(pthread_t));
    int err = pthread_create(bus->thread, &attr, busRun, bus);
    if(err != 0) {
      myLog(LOG_ERR, "pthread_create() failed: %s\n", strerror(err));
      abort();
    }
  }

  // TODO: test this
  void EVBusRunProcess(EVBus *bus) {
    bus->pid = fork();
    if(bus->pid < 0) {
      myLog(LOG_ERR,"Cannot fork child");
      abort();
    }
    
    if(bus->pid > 0) {
      // in parent
    }
    else {
      // in child
      // close read-end of pipe?
      // TODO: does that mean the child can send to the master
      // but the master cannot send to the child?  I guess we
      // would need to have a second pipe to support 2-way.
      close(bus->pipe[0]);
      bus->pipe[0] = 0;
      busRun(bus);
    }
  }

  void EVBusStop(EVBus *bus) {
    if(bus->running) {
      bus->stop = YES;
      if(bus->thread) {
	pthread_join(*bus->thread, NULL);
	bus->thread = NULL;
      }
      else if(bus->pid) {
	// TODO: kill(bus->pid) and waitpid()
	bus->pid = 0;
      }
    }
  }

  EVBus *EVCurrentBus() {
    return threadBus;
  }

  void EVBusRun(EVBus *bus) {
    busRun(bus);
  }

  void EVRun(EVBus *mainBus) {
    EVBus *bus;
    UTHASH_WALK(mainBus->root->buses, bus) {
      if(bus != mainBus
	 && bus->running == NO)
	EVBusRunThread(bus, EV_BUS_STACKSIZE);
    }
    if(mainBus->running == NO)
      busRun(mainBus);
  }

  void EVStop(EVMod *mod) {
    EVBus *bus;
    // Don't take any lock here to iterate, since buses will
    // sent final/end events as they stop.
    UTHASH_WALK(mod->root->buses, bus) {
      EVBusStop(bus);
    }
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif

