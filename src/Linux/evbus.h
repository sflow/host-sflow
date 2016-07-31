/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#ifndef EVBUS_H
#define EVBUS_H 1

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <pthread.h>
#include <dlfcn.h>
#include <limits.h> // for PIPE_BUF

#include "util.h"

  struct _EVMod; // fwd decl
  
  typedef struct _EVRoot {
    UTHash *buses;
    UTHash *modules;
    UTArray *moduleList;
    UTHash *sockets;
    struct _EVMod *rootModule;
    pthread_mutex_t *sync;
  } EVRoot;

#define EVMOD_ROOT "_root"

  typedef struct _EVMod {
    EVRoot *root;
    char *name;
    int id;
    void *libHandle;
    void (*initFn)(struct _EVMod *);
    void *data;
  } EVMod;

#define EVROOTDATA(m) (m)->root->rootModule->data
    
  struct _EVSocket; // fwd decl

  typedef struct _EVBus {
    EVRoot *root;
    char *name;
    UTHash *events;
    UTArray *eventList;
    int pipe[2];
    UTArray *sockets;
    UTArray *sockets_run;
    int select_mS;
#define EVBUS_SELECT_MS 900
#define EV_MAX_TICKS 60
    time_t clk;
    pthread_t *thread;
    pid_t pid;
    bool running;
    bool stop;
  } EVBus;

  typedef int (*EVReadCB)(EVMod *mod, EVBus *bus, int fd, void *data);

  typedef struct _EVSocket {
    struct _EVSocket *nxt;
    int fd;
    EVMod *module;
    EVReadCB readCB;
    void *data;
  } EVSocket;

  struct _EVAction; // fwd decl

  typedef struct _EVEvent {
    EVBus *bus;
    char *name;
    int id;
    UTArray *actions;
    UTArray *actions_run;
  } EVEvent;

  typedef void (*EVActionCB)(EVMod *mod, EVEvent *evt, void *data, size_t dataLen);

  typedef struct _EVAction {
    struct _EVAction *nxt;
    EVMod *module;
    EVActionCB actionCB;
  } EVAction;

#define EVEVENT_START "_start"
#define EVEVENT_TICK "_tick"
#define EVEVENT_TOCK "_tock"
#define EVEVENT_FINAL "_final"
#define EVEVENT_END "_end"

  typedef struct _EVEventHdr {
    uint32_t modId;
    uint32_t eventId;
    uint32_t dataLen;
  } EVEventHdr;

#define EV_MAX_EVT_DATALEN (PIPE_BUF - sizeof(EVEventHdr))

  EVMod *EVInit(void *data);
  EVMod *EVLoadModule(EVMod *mod, char *name, char *mod_dir);
  EVMod *EVGetModule(EVMod *lmod, char *name);
  EVBus *EVGetBus(EVMod *mod, char *name, bool create);
  EVEvent *EVGetEvent(EVBus *bus, char *name);
  void EVEventRx(EVMod *mod, EVEvent *evt, EVActionCB cb);
  int EVEventTx(EVMod *mod, EVEvent *evt, void *data, size_t dataLen);
  int EVEventTxAll(EVMod *mod, char *evt_name, void *data, size_t dataLen);
  bool EVBusAddSocket(EVMod *mod, EVBus *bus, int fd, EVReadCB readCB, void *data);
  
  // Use a more conservative stacksize here - partly because
  // we don't need more,  but mostly because Debian was refusing
  // to create the thread - I guess because it was enough to
  // blow through our mlockall() allocation.
  // http://www.mail-archive.com/xenomai-help@gna.org/msg06439.html 
#define EV_BUS_STACKSIZE 2000000

  void EVBusRunThread(EVBus *bus, size_t stacksize);
  void EVBusRunProcess(EVBus *bus);
  void EVBusRun(EVBus *bus);
  void EVBusStop(EVBus *bus);
  EVBus *EVCurrentBus(void);
  void EVRun(EVBus *mainBus);
  void EVStop(EVMod *mod);


#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* HSFLOWD_H */

