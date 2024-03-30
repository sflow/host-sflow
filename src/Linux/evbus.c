/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "util.h"
#include "evbus.h"

#ifdef GPROF
#include "gperftools/profiler.h"
#endif

  // only one running bus in each thread - keep track with thread-local var
  // so we can always know what the current "home" bus is and detect
  // inter-bus (inter-thread) messages automatically in EVEventTx
  static __thread EVBus *threadBus;

  EVBus *EVCurrentBus() {
    return threadBus;
  }

  void EVCurrentBusSet(EVBus *bus) {
    threadBus = bus;  // assign to thread-local var
  }

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

  uint32_t EVBusCount(EVMod *mod) {
    return UTHashN(mod->root->buses);
  }

  static void evt_handshake(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    if(data) {
      // expect name of event to reply with.  Use EVEventTxAll so that sender
      // can just listen on his own bus only and avoid concurrency.
      EVEventTxAll(mod, (char *)data, evt->bus->name, my_strlen(evt->bus->name));
    }
  }

  EVBus *EVGetBus(EVMod *mod, char *name, bool create) {
    EVBus *bus;
    bool new_bus = NO;
    SEMLOCK_DO(mod->root->sync) {
      EVBus rlm = { .name = name };
      bus = UTHashGet(mod->root->buses, &rlm);
      if(!bus && create) {
	new_bus = YES;
	bus = (EVBus *)my_calloc(sizeof(EVBus));
	bus->root = mod->root;
	bus->name = my_strdup(name);
	UTHashAdd(mod->root->buses, bus);
	bus->msgs = UTHASH_NEW(EVLogMsg, msg, UTHASH_SKEY);
	bus->events = UTHASH_NEW(EVEvent, name, UTHASH_SKEY);
	bus->eventList = UTArrayNew(UTARRAY_DFLT);
	bus->sockets = UTArrayNew(UTARRAY_PACK);
	bus->sockets_run = UTArrayNew(UTARRAY_DFLT);
	bus->sockets_del = UTArrayNew(UTARRAY_DFLT);
	if(pipe(bus->pipe) == -1) {
	  myLog(LOG_ERR, "pipe() failed : %s", strerror(errno));
	  abort();
	}
	// possibly set pipe to non-blocking with fcntl
	// but be aware that this may change the read/write behavior.
	// We probably want it to block because a full pipe may
	// indicate some sort of rare meltdown and losing events
	// to EWOULDBLOCK could make things worse.

	bus->select_mS = EVBUS_SELECT_MS_TICK;
	bus->stop = NO;
      }
    }

    if(new_bus) {
      EVEvent *handshake = EVGetEvent(bus, EVEVENT_HANDSHAKE);
      EVEventRx(mod, handshake, evt_handshake);
    }

    return bus;
  }

  static EVEvent *getEvent(EVBus *bus, char *name, bool create) {
    EVEvent *evt;
    SEMLOCK_DO(bus->root->sync) {
      EVEvent search = { .name = name };
      evt = UTHashGet(bus->events, &search);
      if(!evt && create) {
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

  EVEvent *EVGetEvent(EVBus *bus, char *name) {
      return getEvent(bus, name, YES);
  }

  EVSocket *EVBusAddSocket(EVMod *mod, EVBus *bus, int fd, EVReadCB readCB, void *magic) {
    EVSocket *sock = NULL;
    SEMLOCK_DO(mod->root->sync) {
      EVSocket search = { .fd = fd };
      if(UTHashGet(mod->root->sockets, &search)) {
	myDebug(1, "socket for fd=%u already exists", fd);
      }
      else {
	sock = (EVSocket *)my_calloc(sizeof(EVSocket));
	sock->bus = bus;
	sock->fd = fd;
	sock->readCB = readCB;
	sock->module = mod;
	sock->magic = magic;
	UTHashAdd(mod->root->sockets, sock);
	UTArrayAdd(bus->sockets, sock);
	bus->socketsChanged = YES;
      }
    }
    return sock;
  }

  bool EVSocketClose(EVMod *mod, EVSocket *sock, bool closeFD) {
    EVSocket *deleted;
    SEMLOCK_DO(mod->root->sync) {
      EVSocket search = { .fd = sock->fd };
      deleted = UTHashDelKey(mod->root->sockets, &search);
      assert(deleted == sock);
      if(sock->fd > 0) {
	if(closeFD)
	  while(close(sock->fd) == -1 && errno == EINTR);
	sock->fd = 0;
      }
      if(sock->child_pid) {
	sock->bus->childCount--;
	waitpid(sock->child_pid, &sock->child_status, 0);
      }
      // move it to the condenmed list
      // (will be freed later when it's safer)
      EVBus *bus = sock->bus;
      UTArrayDel(bus->sockets, sock);
      UTArrayAdd(bus->sockets_del, sock);
      bus->socketsChanged = YES;
    }
    return (deleted != NULL);
  }

  void EVEventRx(EVMod *mod, EVEvent *evt, EVActionCB cb) {
    EVAction *act = (EVAction *)my_calloc(sizeof(EVAction));
    act->module = mod;
    act->actionCB = cb;
    SEMLOCK_DO(mod->root->sync) {
      // Note that ordering is preserved here. The last one to
      // ask for an event will be the one that gets it last.
      UTArrayAdd(evt->actions, act);
      evt->actionsChanged = YES;
    }
    if(my_strequal(evt->name, EVEVENT_DECI)) {
      // shorten select timeout so we can deliver deciTicks
      evt->bus->select_mS = EVBUS_SELECT_MS_DECI;
    }
  }

  void EVEventRxAll(EVMod *mod, char *evt_name, EVActionCB cb) {
    EVBus *bus;
    UTHASH_WALK(mod->root->buses, bus) {
      EVEvent *evt = getEvent(bus, evt_name, YES);
      EVEventRx(mod, evt, cb);
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
    if(mod->libHandle == NULL) {
      // try internal load, in case .o was included in executable
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

  EVMod *EVGetModule(EVMod *lmod, char *name) {
    EVMod *mod;
    SEMLOCK_DO(lmod->root->sync) {
      EVRoot *root = lmod->root;
      EVMod search = { .name = name };
      mod = UTHashGet(root->modules, &search);
    }
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

  static void EVSocketFree(EVSocket *sock) {
    assert(sock->fd <= 0);
    if(sock->iobuf)
      UTStrBuf_free(sock->iobuf);
    if(sock->ioline)
      UTStrBuf_free(sock->ioline);
    my_free(sock);
  }

  int EVEventTx(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    int sent = 0;
    if(evt->bus == EVCurrentBus()) {
      // local event
      EVAction *act;
      if(evt->actionsChanged) {
	SEMLOCK_DO(mod->root->sync) {
	  UTArrayReset(evt->actions_run);
	  UTArrayAddAll(evt->actions_run, evt->actions);
	  evt->actionsChanged = NO;
	}
      }
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
      // only tx if the event exists on the bus
      EVEvent *evt = getEvent(bus, evt_name, NO);
      if(evt)
	sent += EVEventTx(mod, evt, data, dataLen);
    }
    return sent;
  }

  void EVClockMono(struct timespec *ts) {
    clockid_t monoClock = CLOCK_MONOTONIC;
#ifdef CLOCK_MONOTONIC_COARSE
    // more efficient if supported,  since we only need mS accuracy
    monoClock = CLOCK_MONOTONIC_COARSE;
#endif
    if(clock_gettime(monoClock, ts) == -1) {
      myLog(LOG_ERR, "clock_gettime() failed: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  static void busRead(EVBus *bus) {
    EVSocket *sock;
    fd_set readfds;
    FD_ZERO(&readfds);
    sigset_t emptyset;
    sigemptyset(&emptyset);
    int max_fd = 0;
    // the input pipe
    FD_SET(bus->pipe[0], &readfds);
    max_fd = bus->pipe[0];
    // and other registered sockets
    if(bus->socketsChanged) {
      SEMLOCK_DO(bus->root->sync) {
	UTArrayReset(bus->sockets_run);
	UTArrayAddAll(bus->sockets_run, bus->sockets);
	UTARRAY_WALK(bus->sockets_del, sock) EVSocketFree(sock);
	UTArrayReset(bus->sockets_del);
	bus->socketsChanged = NO;
      }
    }
    UTARRAY_WALK(bus->sockets_run, sock) {
      FD_SET(sock->fd, &readfds);
      if(sock->fd > max_fd)
	max_fd = sock->fd;
    }
    struct timespec timeout;
    timeout.tv_sec = 0;
    timeout.tv_nsec = bus->select_mS * 1000000;
    int nfds = pselect(max_fd + 1,
		       &readfds,
		       (fd_set *)NULL,
		       (fd_set *)NULL,
		       &timeout,
		       &emptyset);

    // update clock - monotonic so that it is
    // safe to set timeouts in the future...
    EVClockMono(&bus->now);

    // see if we got anything
    if(nfds > 0) {
      if(FD_ISSET(bus->pipe[0], &readfds))
	busRxPipe(bus, bus->pipe[0]);
      UTARRAY_WALK(bus->sockets_run, sock) {
	if(FD_ISSET(sock->fd, &readfds))
	  (*sock->readCB)(sock->module, sock, sock->magic);
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

  int EVTimeDiff_nS(struct timespec *t1, struct timespec *t2) {
    int secs = t2->tv_sec - t1->tv_sec;
    int nanos = t2->tv_nsec - t1->tv_nsec;
    // if(nanos < 0) {
    //  secs--;
    //  nanos += 1000000000;
    // }
    return (secs * 1000000000) + nanos;
  }

  int EVTimeDiff_mS(struct timespec *t1, struct timespec *t2) {
    int secs = t2->tv_sec - t1->tv_sec;
    int nanos = t2->tv_nsec - t1->tv_nsec;
    return (secs * 1000) + (nanos / 1000000);
  }

  void EVTimeAdd_nS(struct timespec *t, int nS) {
    assert(nS <= 1000000000);
    t->tv_nsec += nS;
    if(t->tv_nsec > 1000000000) {
      t->tv_sec++;
      t->tv_nsec -= 1000000000;
    }
    else if(t->tv_nsec < 0) {
      t->tv_sec--;
      t->tv_nsec += 1000000000;
    }
  }

  static void *busRun(void *magic) {
#ifdef GPROF
    myDebug(1, "GPROF ProfilerRegisterThread()");
    ProfilerRegisterThread();
#endif
    EVBus *bus = (EVBus *)magic;
    EVMod *mod = bus->root->rootModule;
    assert(bus->running == NO);
    EVCurrentBusSet(bus);
    bus->running = YES;
    EVEvent *start = EVGetEvent(bus, EVEVENT_START);
    EVEvent *tick = EVGetEvent(bus, EVEVENT_TICK);
    EVEvent *tock = EVGetEvent(bus, EVEVENT_TOCK);
    EVEvent *deci = EVGetEvent(bus, EVEVENT_DECI);
    EVEvent *final = EVGetEvent(bus, EVEVENT_FINAL);
    EVEvent *end = EVGetEvent(bus, EVEVENT_END);

    EVClockMono(&bus->tstart);
    EVEventTx(mod, start, NULL, 0);

    for(;;) {

      if(bus->stop) {
	EVEventTx(mod, final, NULL, 0);
	EVEventTx(mod, end, NULL, 0);
	break;
      }

      busRead(bus);

      // Detect tick/deci boundaries.
      // These tick/tock/deci events used to skip if something
      // blocked for too long in this thread, but not any longer.
      while(EVTimeDiff_nS(&bus->now_deci, &bus->now) > 100000000) {
	EVTimeAdd_nS(&bus->now_deci, 100000000);
	EVEventTx(mod, deci, NULL, 0);
	if(EVTimeDiff_nS(&bus->now_tick, &bus->now_deci) > 1000000000) {
	  EVTimeAdd_nS(&bus->now_tick, 1000000000);
	  EVEventTx(mod, tick, NULL, 0);
	  EVEventTx(mod, tock, NULL, 0);
	}
      }
    }
    return NULL;
  }

  int EVBusRunningTime_mS(EVBus *bus) {
    return EVTimeDiff_mS(&bus->tstart, &bus->now);
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

  /*_________________---------------------------__________________
    _________________     EVBusExec             __________________
    -----------------___________________________------------------
    like popen(), but more secure coz the shell doesn't get
    to "reimagine" the args.  This should eventually take over
    from myExec() in util.c.  Newline sequences LF, CR and CRLF
    are all replaced with "\n".
  */

  static bool socketLine(EVSocket *sock, size_t start) {

    char *iobuf = UTSTRBUF_STR(sock->iobuf);
    size_t iolen = UTSTRBUF_LEN(sock->iobuf);

    for(int ii = start; ii < iolen; ii++) {
      char ch = iobuf[ii];
      if(ch == 10 || ch == 13 || ch == 0) {
	if(ch == 10 || ch == 13) ii++; // CR or LF
	if(ch == 13 && iobuf[ii] == 10) ii++; // CRLF
	UTStrBuf_append_n(sock->ioline, iobuf, ii);
	UTStrBuf_snip_prefix(sock->iobuf, ii);
	return YES;
      }
    }
    return NO; // line-end not found
  }

  void EVSocketReadLines(EVMod *mod, EVSocket *sock, EVSocketReadLineCB lineCB, bool tail, void *magic) {
    // When reading lines, use a per-line callback so we can easily handle the case where
    // a single read() call resulted in 0, 1 or >1 lines found,  or hit EOF with a trailing
    // line in the buffer.
    // insist this is only called from the same thread that opened the socket
    assert(sock->bus == EVCurrentBus());
    if(sock->fd <= 0)
      (*lineCB)(mod, sock, EVSOCKETREAD_BADF, magic);

    // allocate buffer so socket can accumulate data while looking for line-ends
    if(sock->iobuf == NULL)
      sock->iobuf = UTStrBuf_new();
    // and another to report lines (or accumulate them if required)
    if(sock->ioline == NULL)
      sock->ioline = UTStrBuf_new();

    // try to read more
    UTStrBuf_need(sock->iobuf, UTSTRBUF_LEN(sock->iobuf) + EVSOCKETREADLINE_INCBYTES);
    char *readStart = UTSTRBUF_STR(sock->iobuf) + UTSTRBUF_LEN(sock->iobuf);
    int cc;
  try_again:
    cc = read(sock->fd, readStart, EVSOCKETREADLINE_INCBYTES);
    if(cc < 0) {
      if(errno == EAGAIN || errno == EINTR) goto try_again;
      myLog(LOG_ERR, "EVSocketReadLines(): %s", strerror(errno));
      EVSocketClose(mod, sock, YES);
      (*lineCB)(mod, sock, EVSOCKETREAD_ERR, magic);
    }
    else if(cc == 0) {
      // EOF
      if(!tail)
	EVSocketClose(mod, sock, YES);
      // may have trailing line
      if(UTSTRBUF_LEN(sock->iobuf)) {
	UTStrBuf_append_n(sock->ioline, UTSTRBUF_STR(sock->iobuf), UTSTRBUF_LEN(sock->iobuf));
	(*lineCB)(mod, sock, EVSOCKETREAD_STR, magic);
      }
      (*lineCB)(mod, sock, EVSOCKETREAD_EOF, magic);
    }
    else {
      // got more, see if it completed a line - or more than one
      size_t start = UTSTRBUF_LEN(sock->iobuf);
      UTSTRBUF_LEN(sock->iobuf) += cc;
      for(;;) {
	if(socketLine(sock, start)) {
	  (*lineCB)(mod, sock, EVSOCKETREAD_STR, magic);
	  start = 0;
	}
	else break;
      }
      // please call again (when socket has data)
      (*lineCB)(mod, sock, EVSOCKETREAD_AGAIN, magic);
    }
  }

  pid_t EVBusExec(EVMod *mod, EVBus *bus, void *magic, char **cmd, EVReadCB readCB)
  {
    int outPipe[2];
    int errPipe[2];
    if(pipe(outPipe) == -1
       || pipe(errPipe) == -1) {
      myLog(LOG_ERR, "pipe() failed : %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    pid_t cpid;
    if((cpid = fork()) == -1) {
      myLog(LOG_ERR, "fork() failed : %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    if(cpid == 0) {
      // in child
      // close read-ends
      while(close(outPipe[0]) == -1 && errno == EINTR);
      while(close(errPipe[0]) == -1 && errno == EINTR);
      // stdout > write-end 1 and stderr > write-end 2
      while(dup2(outPipe[1], 1) == -1 && errno == EINTR);
      while(dup2(errPipe[1], 2) == -1 && errno == EINTR);
      // clean up
      while(close(outPipe[1]) == -1 && errno == EINTR);
      while(close(errPipe[1]) == -1 && errno == EINTR);
      // and exec
      if(execv(cmd[0], cmd) == -1) {
	myLog(LOG_ERR, "execv() failed : errno=%d (%s)", errno, strerror(errno));
	exit(EXIT_FAILURE);
      }
    }
    else {
      // in parent
      bus->childCount++; // TODO: limit childCount. How?
      // close write-ends
      while(close(outPipe[1]) == -1 && errno == EINTR);
      while(close(errPipe[1]) == -1 && errno == EINTR);
      // read from read-ends
      EVSocket *errSock = EVBusAddSocket(mod, bus, errPipe[0], readCB, magic);
      errSock->errOut = YES; // mark this so we know it's stderr
      EVSocket *outSock = EVBusAddSocket(mod, bus, outPipe[0], readCB, magic);
      outSock->child_pid = cpid; // only give this one the cpid
    }
    return cpid;
  }

  /*_________________---------------------------__________________
    _________________    bus run, stop          __________________
    -----------------___________________________------------------
  */

  void EVBusStop(EVBus *bus) {
    if(bus->running) {
      bus->stop = YES;
      if(bus->thread) {
	pthread_join(*bus->thread, NULL);
	bus->thread = NULL;
      }
    }
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

  void EVLog(uint32_t rl_secs, int syslogType, char *fmt, ...) {
    EVBus *bus = EVCurrentBus();
    EVLogMsg search = { .msg = fmt };
    EVLogMsg *msg = UTHashGet(bus->msgs, &search);
    if(msg == NULL) {
      msg = (EVLogMsg *)my_calloc(sizeof(EVLogMsg));
      msg->msg = my_strdup(fmt);
      UTHashAdd(bus->msgs, msg);
    }
    if((bus->now.tv_sec - msg->logTime) >= rl_secs) {
      va_list args;
      va_start(args, fmt);
      myLogv(syslogType, fmt, args);
      msg->logTime = bus->now.tv_sec;
      if(msg->count > 1)
	myLog(syslogType, "(msg repeated %u times in %u secs)", msg->count, rl_secs);
      msg->count = 1;
    }
    else {
      msg->count++;
    }
  }

  bool EVDebug(EVMod *mod, int level, char *fmt, ...) {
    if((mod
	&& mod->debugLevel >= level)
       || debug(level)) {
      if(fmt) {
	myLog2(level, NO, LOG_DEBUG, "%s:", mod->name);
	va_list args;
	va_start(args, fmt);
	myLogv2(level, YES, LOG_DEBUG, fmt, args);
      }
      return YES;
    }
    return NO;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif
