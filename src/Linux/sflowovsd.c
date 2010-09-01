/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#define SFLOWOVSD_MAIN

#include "sflowovsd.h"

  // globals - easier for signal handler
  SFVS SFVSDaemon;
  int exitStatus = EXIT_SUCCESS;
  int debug = 0;


  /*_________________---------------------------__________________
    _________________        logging            __________________
    -----------------___________________________------------------
  */

  void myLog(int syslogType, char *fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    if(debug) {
      vfprintf(stderr, fmt, args);
      fprintf(stderr, "\n");
    }
    else vsyslog(syslogType, fmt, args);
  }

  /*_________________---------------------------__________________
    _________________       my_calloc           __________________
    -----------------___________________________------------------
  */
  
  void *my_calloc(size_t bytes)
  {
    void *mem = calloc(1, bytes);
    if(mem == NULL) {
      myLog(LOG_ERR, "calloc() failed : %s", strerror(errno));
      if(debug) malloc_stats();
      exit(EXIT_FAILURE);
    }
    return mem;
  }
    
  /*_________________---------------------------__________________
    _________________     string fields         __________________
    -----------------___________________________------------------
  */
  
  static void setStr(char **fieldp, char *str) {
    if(*fieldp) free(*fieldp);
    (*fieldp) = str ? strdup(str) : NULL;
  }
    
  /*_________________---------------------------__________________
    _________________     string array          __________________
    -----------------___________________________------------------
  */

  static SFVSStringArray *strArrayNew() {
    return (SFVSStringArray *)my_calloc(sizeof(SFVSStringArray));
  }

  static void strArrayAdd(SFVSStringArray *ar, char *str) {
    if(ar->capacity <= ar->n) {
      uint32_t oldBytes = ar->capacity * sizeof(char *);
      ar->capacity = ar->n + 16;
      uint32_t newBytes = ar->capacity * sizeof(char *);
      char **newArray = (char **)my_calloc(newBytes);
      if(ar->strs) {
	memcpy(newArray, ar->strs, oldBytes);
	free(ar->strs);
      }
      ar->strs = newArray;
    }
    if(ar->strs[ar->n]) free(ar->strs[ar->n]);
    ar->strs[ar->n++] = str ? strdup(str) : NULL;
  }

  static void strArrayReset(SFVSStringArray *ar) {
    for(uint32_t i = 0; i < ar->n; i++) {
      if(ar->strs[i]) {
	free(ar->strs[i]);
	ar->strs[i] = NULL;
      }
    }
    ar->n = 0;
  }

  static void strArrayFree(SFVSStringArray *ar) {
    strArrayReset(ar);
    if(ar->strs) free(ar->strs);
    free(ar);
  }

  static char **strArray(SFVSStringArray *ar) {
    return ar->strs;
  }

  static uint32_t strArrayN(SFVSStringArray *ar) {
    return ar->n;
  }

  static char *strArrayAt(SFVSStringArray *ar, int i) {
    return ar->strs[i];
  }

  static int mysortcmp(const void *p1, const void* p2) {
    char *s1 = *(char **)p1;
    char *s2 = *(char **)p2;
    if(s1 == s2) return 0;
    if(s1 == NULL) return -1;
    if(s2 == NULL) return 1;
    return strcmp(s1, s2);
  }

  static void strArraySort(SFVSStringArray *ar) {
    qsort(ar->strs, ar->n, sizeof(char *), mysortcmp);
  }

  static char *strArrayStr(SFVSStringArray *ar, char *start, char *quote, char *delim, char *end) {
    size_t strbufLen = 256;
    char *strbuf = NULL;
    FILE *f_strbuf;
    if((f_strbuf = open_memstream(&strbuf, &strbufLen)) == NULL) {
      myLog(LOG_ERR, "error in open_memstream: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    if(start) fputs(start, f_strbuf);
    for(uint32_t i = 0; i < ar->n; i++) {
      if(i && delim) fputs(delim, f_strbuf);
      char *str = ar->strs[i];
      if(str) {
	if(quote) fputs(quote, f_strbuf);
	fputs(str, f_strbuf);
	if(quote) fputs(quote, f_strbuf);
      }
    }
    if(end) fputs(end, f_strbuf);
    fclose(f_strbuf);
    return strbuf;
  }

  static int strArrayEqual(SFVSStringArray *ar1, SFVSStringArray *ar2) {
    if(ar1->n != ar2->n) return NO;
    for(int i = 0; i < ar1->n; i++) {
      char *s1 = ar1->strs[i];
      char *s2 = ar2->strs[i];
      if((s1 != s2)
	 && (s1 == NULL || s2 == NULL || strcmp(s1, s2))) return NO;
    }
    return YES;
  }

  /*_________________---------------------------__________________
    _________________     setState              __________________
    -----------------___________________________------------------
  */

  static void setState(SFVS *sp, EnumSFVSState state) {
    if(debug) myLog(LOG_INFO, "state -> %s", SFVSStateNames[state]);
    sp->state = state;
  }

  /*_________________---------------------------__________________
    _________________       tick                __________________
    -----------------___________________________------------------
  */
  
  static void tick(SFVS *sv, time_t clk) {

    sv->tick++;

    if((sv->tick % 5) == 0) {
      struct stat statBuf;
      if(stat(sv->configFile, &statBuf) != 0) {
	if(debug) myLog(LOG_INFO, "cannot stat %s : %s", sv->configFile, strerror(errno));
	sv->configFile_modTime = 0;
	// clear the ovs config if the file is missing, or cannot be read
	setState(sv, SFVSSTATE_READCONFIG);
      }
      else if(statBuf.st_mtime != sv->configFile_modTime) {
	if(debug) myLog(LOG_INFO, "file changed on disk: %s", sv->configFile);
	sv->configFile_modTime = statBuf.st_mtime;
	setState(sv, SFVSSTATE_READCONFIG);
      }
      else if(sv->tick >= 60 && sv->state != SFVSSTATE_READCONFIG_FAILED) {
	// a minute has passed, and we are not still waiting for a valid config file
	sv->tick = 0;
	if(debug) myLog(LOG_INFO, "minute passed - check sync");
	setState(sv, SFVSSTATE_SYNC);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________     setDefaults           __________________
    -----------------___________________________------------------
  */

  static void setDefaults(SFVS *sv)
  {
    sv->configFile = SFVS_DEFAULT_CONFIGFILE;
    sv->pidFile = SFVS_DEFAULT_PIDFILE;
    sv->cmd = strArrayNew();
    sv->extras = strArrayNew();
    sv->config.targets = strArrayNew();
  }

  /*_________________---------------------------__________________
    _________________      instructions         __________________
    -----------------___________________________------------------
  */

  static void instructions(char *command)
  {
    fprintf(stderr,"Usage: %s [-d] [-v] [-p PIDFile] [-f CONFIGFile]\n", command);
    fprintf(stderr,"\n\
             -d:  debug mode - do not fork as a daemon, and log to stderr (repeat for more details)\n\
             -v:  print version number and exit\n\
     -p PIDFile:  specify PID file (default is " SFVS_DEFAULT_PIDFILE ")\n\
        -u UUID:  specify UUID as unique ID for this host\n\
  -f CONFIGFile:  specify config file (default is "SFVS_DEFAULT_CONFIGFILE")\n\n");
  fprintf(stderr, "=============== More Information ============================================\n");
  fprintf(stderr, "| sFlow standard        - http://www.sflow.org                              |\n");
  fprintf(stderr, "| sFlowTrend (FREE)     - http://www.inmon.com/products/sFlowTrend.php      |\n");
  fprintf(stderr, "=============================================================================\n");

    exit(EXIT_FAILURE);
  }

  /*_________________---------------------------__________________
    _________________   processCommandLine      __________________
    -----------------___________________________------------------
  */

  static void processCommandLine(SFVS *sp, int argc, char *argv[])
  {
    int in;
    while ((in = getopt(argc, argv, "dvp:f:u:?h")) != -1) {
      switch(in) {
      case 'd': debug++; break;
      case 'v': printf("%s version %s\n", argv[0], SFVS_VERSION); exit(EXIT_SUCCESS); break;
      case 'p': sp->pidFile = optarg; break;
      case 'f': sp->configFile = optarg; break;
      case '?':
      case 'h':
      default: instructions(*argv);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________     signal_handler        __________________
    -----------------___________________________------------------
  */

  static void signal_handler(int sig) {
    SFVS *sp = &SFVSDaemon;
    switch(sig) {
    case SIGTERM:
      myLog(LOG_INFO,"Received SIGTERM");
      setState(sp, SFVSSTATE_END);
      break;
    case SIGINT:
      myLog(LOG_INFO,"Received SIGINT");
      setState(sp, SFVSSTATE_END);
      break;
      //case SIGCHLD:
      //myLog(LOG_INFO,"Received SIGCHLD");
      //break;
    default:
      myLog(LOG_INFO,"Received signal %d", sig);
      break;
    }
  }

  /*_________________---------------------------__________________
    _________________     my_usleep             __________________
    -----------------___________________________------------------
  */
  
  void my_usleep(uint32_t microseconds) {
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = microseconds;
    int max_fd = 0;
    int nfds = select(max_fd + 1,
		      (fd_set *)NULL,
		      (fd_set *)NULL,
		      (fd_set *)NULL,
		      &timeout);
    // may return prematurely if a signal was caught, in which case nfds will be
    // -1 and errno will be set to EINTR.  If we get any other error, abort.
    if(nfds < 0 && errno != EINTR) {
      myLog(LOG_ERR, "select() returned %d : %s", nfds, strerror(errno));
      exit(EXIT_FAILURE);
    }
  }
      
  /*_________________---------------------------__________________
    _________________      formatTargets        __________________
    -----------------___________________________------------------
    turn the collectors list into the targets string array and
    formatted targetStr.
  */
  
  static void formatTargets(SFVS *sv) {
    strArrayReset(sv->config.targets);
    for(int i = 0; i < sv->config.num_collectors; i++) {
      char target[SFVS_MAX_LINELEN];
      sprintf(target, "%s:%u",
	      sv->config.collectors[i].ip,
	      sv->config.collectors[i].port); 
      strArrayAdd(sv->config.targets, target);
    }
    strArraySort(sv->config.targets);
    if(sv->config.targetStr) free(sv->config.targetStr);
    sv->config.targetStr = strArrayStr(sv->config.targets, "[", "\"", ", ", "]");
  }

      
  /*_________________---------------------------__________________
    _________________      resetConfig          __________________
    -----------------___________________________------------------
  */

  static void resetConfig(SFVSConfig *cfg) {
    cfg->error = NO;
    cfg->sampling_n = 0;
    cfg->polling_secs = 0;
    cfg->header_bytes = SFL_DEFAULT_HEADER_SIZE;
    setStr(&cfg->agentIP, NULL);
    cfg->num_collectors = 0;
    strArrayReset(cfg->targets);
    setStr(&cfg->targetStr, NULL);
  }
      
  /*_________________---------------------------__________________
    _________________      readConfig           __________________
    -----------------___________________________------------------
  */
  
  static int syntaxOK(SFVS *sv, uint32_t line, uint32_t tokc, uint32_t tokcMin, uint32_t tokcMax, char *syntax) {
    if(tokc < tokcMin || tokc > tokcMax) {
      sv->config.error = YES;
      myLog(LOG_ERR, "syntax error on line %u of %s: expected %s",
	    line,
	    sv->configFile,
	    syntax);
      return NO;
    }
    return YES;
  }

  static void syntaxError(SFVS *sv, uint32_t line, char *msg) {
    sv->config.error = YES;
    myLog(LOG_ERR, "syntax error on line %u of %s: %s",
	  line,
	  sv->configFile,
	  msg);
  }    

  static int readConfig(SFVS *sv)
  {
    resetConfig(&sv->config);
    
    FILE *cfg = NULL;
    if((cfg = fopen(sv->configFile, "r")) == NULL) {
      myLog(LOG_ERR,"cannot open config file %s : %s", sv->configFile, strerror(errno));
      return NO;
    }
    // loop until we get the same revision number at the beginning and the end
    uint32_t rev_start = 0;
    uint32_t rev_end = 0;
    do {
      char line[SFVS_MAX_LINELEN];
      uint32_t lineNo = 0;
      rev_start = 0;
      rev_end = 0;
      while(fgets(line, SFVS_MAX_LINELEN, cfg)) {
	lineNo++;
	char *p = line;
	// comments start with '#'
	p[strcspn(p, "#")] = '\0';
	// single-threaded, so we can just use strtok(3)
	char *var = strtok(line, SFVS_SEPARATORS);
	if(var) {
	  // There can be up to 3 arg tokens, so detect up to 4
	  char *tok1 = strtok(NULL, SFVS_SEPARATORS);
	  char *tok2 = strtok(NULL, SFVS_SEPARATORS);
	  char *tok3 = strtok(NULL, SFVS_SEPARATORS);
	  char *tok4 = strtok(NULL, SFVS_SEPARATORS);
	  uint32_t tokc = 0;
	  if(tok1) tokc++;
	  if(tok2) tokc++;
	  if(tok3) tokc++;
	  if(tok4) tokc++;
	  if(rev_start == 0) {
	    if(strcasecmp(var, "rev_start") == 0
	       && syntaxOK(sv, lineNo, tokc, 1, 1, "rev_start=<int>")) {
	      rev_start = strtol(tok1, NULL, 0);
	    }
	    else {
	      syntaxError(sv, lineNo, "must start with rev_start=<int>");
	    }
	  }
	  else if (rev_end != 0) {
	    syntaxError(sv, lineNo, "last line should be rev_end=<int>");
	  }
	  else if(strcasecmp(var, "rev_end") == 0
		  && syntaxOK(sv, lineNo, tokc, 1, 1, "rev_end=<int>")) {
	    rev_end = strtol(tok1, NULL, 0);
	  }
	  else if(strcasecmp(var, "sampling") == 0
		  && syntaxOK(sv, lineNo, tokc, 1, 1, "sampling=<int>")) {
	    sv->config.sampling_n = strtol(tok1, NULL, 0);
	  }
	  else if(strcasecmp(var, "polling") == 0 
		  && syntaxOK(sv, lineNo, tokc, 1, 1, "polling=<int>")) {
	    sv->config.polling_secs = strtol(tok1, NULL, 0);
	  }
	  else if(strcasecmp(var, "header") == 0
		  && syntaxOK(sv, lineNo, tokc, 1, 1, "header=<int>")) {
	    sv->config.header_bytes = strtol(tok1, NULL, 0);
	  }
	  else if(strcasecmp(var, "agentIP") == 0
		  && syntaxOK(sv, lineNo, tokc, 1, 1, "agentIP=<IP address>|<IPv6 address>")) {
	    // format with quotes
	    char ipbuf[SFVS_MAX_LINELEN];
	    sprintf(ipbuf, "\"%s\"", tok1);
	    setStr(&sv->config.agentIP, ipbuf);
	  }
	  else if(strcasecmp(var, "collector") == 0
		  && syntaxOK(sv, lineNo, tokc, 1, 3, "collector=<IP address>[ <port>[ <priority>]]")) {
	    if(sv->config.num_collectors < SFVS_MAX_COLLECTORS) {
	      uint32_t i = sv->config.num_collectors++;
	      setStr(&sv->config.collectors[i].ip, tok1);
	      sv->config.collectors[i].port = tokc >= 2 ? strtol(tok2, NULL, 0) : 6343;
	      sv->config.collectors[i].priority = tokc >= 3 ? strtol(tok3, NULL, 0) : 0;
	    }
	    else {
	      syntaxError(sv, lineNo, "exceeded max collectors");
	    }
	  }
	  else {
	    syntaxError(sv, lineNo, "unknown var=value setting");
	  }
	}
      }
    } while(rev_start != rev_end);
    fclose(cfg);
    
    // turn the collectors list into the targets string
    formatTargets(sv);

    // sanity checks...

    if(rev_start == 0 || rev_end == 0) {
      syntaxError(sv, 0, "missing non-zero revision numbers rev_start, rev_end");
    }

    if(!sv->config.agentIP) {
      syntaxError(sv, 0, "missing agentIP=<IP address>|<IPv6 address>");
    }

    return (!sv->config.error);
  }

      
  /*_________________---------------------------__________________
    _________________     myExec                __________________
    -----------------___________________________------------------

    like popen(), but more secure coz the shell doesn't get
    to "reimagine" the args.
  */

  static int myExec(SFVS *sv, char **cmd, SFVSExecCB lineCB)
  {
    int ans = YES;
    int pfd[2];
    pid_t cpid;
    if(pipe(pfd) == -1) {
      myLog(LOG_ERR, "pipe() failed : %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    if((cpid = fork()) == -1) {
      myLog(LOG_ERR, "fork() failed : %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    if(cpid == 0) {
      // in child
      close(pfd[0]);   // close read-end
      dup2(pfd[1], 1); // stdout -> write-end
      dup2(pfd[1], 2); // stderr -> write-end
      close(pfd[1]);
      // exec program
      char *env[] = { NULL };
      if(execve(cmd[0], cmd, env) == -1) {
	myLog(LOG_ERR, "execve() failed : errno=%d (%s)", errno, strerror(errno));
	exit(EXIT_FAILURE);
      }
    }
    else {
      // in parent
      close(pfd[1]); // close write-end
      // read from read-end
      FILE *ovs;
      if((ovs = fdopen(pfd[0], "r")) == NULL) {
	myLog(LOG_ERR, "fdopen() failed : %s", strerror(errno));
	exit(EXIT_FAILURE);
      }
      char line[SFVS_MAX_LINELEN];
      while(fgets(line, SFVS_MAX_LINELEN, ovs)) {
	if(debug > 1) myLog(LOG_INFO, "myExec input> <%s>", line);
	if((*lineCB)(sv, line) == NO) {
	  ans = NO;
	  break;
	}
      }
      fclose(ovs);
      wait(NULL); // block here until child is done
    }
    return ans;
  }

      
  /*_________________---------------------------__________________
    _________________     stripQuotes           __________________
    -----------------___________________________------------------
    strip runs of these chars from the beginning and end -
    but don't worry about matching them up one-for-one.  Be
    careful to only do this with stack-allocated strings.
  */

  static char *stripQuotes(char *str, char *quoteChars) {
    if(str) {
      str += strspn(str, quoteChars);
      size_t len = strlen(str);
      while(len > 0 && strchr(quoteChars, str[len-1])) {
	str[--len] = '\0';
      }
    }
    return str;
  }
    
  /*_________________---------------------------__________________
    _________________     syncOVS - utils       __________________
    -----------------___________________________------------------
  */

  static void addOvsArg(SFVS *sv, char *arg) {
    strArrayAdd(sv->cmd, arg);
  }

  static void addOvsVarEqVal(SFVS *sv, char *ovsvar, char *valstr) {
    uint32_t bytes = strlen(ovsvar) + 1 + strlen(valstr) + 1;
    char *setting = my_calloc(bytes);
    snprintf(setting, bytes, "%s=%s", ovsvar, valstr);
    addOvsArg(sv, setting);
    free(setting);
  }

  static void addOvsVarEqVal_int(SFVS *sv, char *ovsvar, uint32_t intval) {
    char valstr[16];
    snprintf(valstr, 16, "%u", intval);
    addOvsVarEqVal(sv, ovsvar, valstr);
  }

  static void addSFlowSetting(SFVS *sv, char *ovsvar, char *valstr) {
    addOvsArg(sv, "--");
    addOvsArg(sv, "set");
    addOvsArg(sv, "sflow");
    addOvsArg(sv, sv->sflowUUID);
    addOvsVarEqVal(sv, ovsvar, valstr);
  }

  static void addSFlowSetting_int(SFVS *sv, char *ovsvar, uint32_t intval) {
    addOvsArg(sv, "--");
    addOvsArg(sv, "set");
    addOvsArg(sv, "sflow");
    addOvsArg(sv, sv->sflowUUID);
    addOvsVarEqVal_int(sv, ovsvar, intval);
  }

  static void addBridgeSetting(SFVS *sv, char *ovsvar, char *valstr) {
    addOvsArg(sv, "--");
    addOvsArg(sv, "set");
    addOvsArg(sv, "bridge");
    addOvsArg(sv, sv->bridge);
    addOvsVarEqVal(sv, ovsvar, valstr);
  }

  static void addDestroySFlow(SFVS *sv, char *uuidStr) {
    addOvsArg(sv, "--");
    addOvsArg(sv, "destroy");
    addOvsArg(sv, "sflow");
    addOvsArg(sv, uuidStr);
  }

  static void addCreateSFlow(SFVS *sv) {
    addOvsArg(sv, "--");
#ifdef USEATVAR
    addOvsArg(sv, "--id=" SFVS_NEW_SFLOW_ID);
#endif
    addOvsArg(sv, "create");
    addOvsArg(sv, "sflow");
    addOvsVarEqVal(sv, "agent", sv->config.agentIP);
    addOvsVarEqVal_int(sv, "header", sv->config.header_bytes);
    addOvsVarEqVal_int(sv, "polling", sv->config.polling_secs);
    addOvsVarEqVal_int(sv, "sampling", sv->config.sampling_n);
    addOvsVarEqVal(sv, "targets", sv->config.targetStr);
  }

  static void logCmd(SFVS *sv) {
    char *cmdstr = strArrayStr(sv->cmd, "<", NULL, " ", ">");
    myLog(LOG_INFO, "cmd: %s\n", cmdstr);
    free(cmdstr);
  }

  static void resetCmd(SFVS *sv) {
    strArrayReset(sv->cmd);
    strArrayAdd(sv->cmd, SFVS_OVS_CMD);

  }

  static void resetExtras(SFVS *sv) {
    strArrayReset(sv->extras);
  }

  /*_________________---------------------------__________________
    _________________     syncOVS - callbacks   __________________
    -----------------___________________________------------------
  */

  int sFlowList(SFVS *sv, char *line)
  {
    // expect lines of form <var> : <val>
    int varlen = strcspn(line, ":");
    if(varlen >= strlen(line)) {
      myLog(LOG_ERR, "expected <var> : <val>, but got <%s>", line);
      return NO;
    }
    line[varlen] = '\0';
    char *var = stripQuotes(line, SFVS_QUOTES);
    char *val = stripQuotes(line + varlen + 1, SFVS_QUOTES);
    if(debug) myLog(LOG_INFO, "sFlowList> %s=%s", var, val);
    if(strcmp(var, "_uuid") == 0) {
      switch(sv->state) {
      case SFVSSTATE_SYNC_SEARCH:
	if(debug) myLog(LOG_ERR, "found sflow uuid %s", val);
	setStr(&sv->sflowUUID, val);
	setState(sv, SFVSSTATE_SYNC_FOUND);
	break;
      case SFVSSTATE_SYNC_FOUND:
      case SFVSSTATE_SYNC_DESTROY:
	setState(sv, SFVSSTATE_SYNC_DESTROY);
	if(debug) myLog(LOG_ERR, "found extra sflow uuid %s", val);
	strArrayAdd(sv->extras, val);
	break;
      default:
	myLog(LOG_ERR, "sFlowList: unexpected state %s", SFVSStateNames[sv->state]);
	setState(sv, SFVSSTATE_END);
	return NO;
      }
    }
    else if (sv->state == SFVSSTATE_SYNC_FOUND) {
      // we have adopted an existing sFlow object.  This is the one
      // we will keep. All others will be destroyed. Here we check in
      // case any of the individual parameters need to be changed too.
      if(strcmp(var, "agent") == 0) {
	char quoted[SFVS_MAX_LINELEN];
	snprintf(quoted, SFVS_MAX_LINELEN, "\"%s\"", val);
	if(strcmp(quoted, sv->config.agentIP) != 0) {
	  addSFlowSetting(sv, "agent", sv->config.agentIP);
	}
      }
      else if(strcmp(var, "header") == 0) {
	uint32_t n = strtol(val, NULL, 0);
	if(n != sv->config.header_bytes) {
	  addSFlowSetting_int(sv, "header", sv->config.header_bytes);
	}
      }
      else if(strcmp(var, "polling") == 0) {
	uint32_t n = strtol(val, NULL, 0);
	if(n != sv->config.polling_secs) {
	  addSFlowSetting_int(sv, "polling", sv->config.polling_secs);
	}
      }
      else if(strcmp(var, "sampling") == 0) {
	uint32_t n = strtol(val, NULL, 0);
	if(n != sv->config.sampling_n) {
	  addSFlowSetting_int(sv, "sampling", sv->config.sampling_n);
	}
      }
      else if(strcmp(var, "targets") == 0) {
	// the spaces between elements in the array are a nuisance, because they
	// could go away someday and break any scheme that relies on a simple
	// string-compare. So parse it into comma-separated tokens.
	// single-threaded, so we can just use strtok(3)
	SFVSStringArray *array = strArrayNew();
	val = stripQuotes(val, "[]");
	char *delim = ", ";
	for(char *tok = strtok(val, delim); tok != NULL; tok=strtok(NULL, delim)) {
	  strArrayAdd(array, stripQuotes(tok, SFVS_QUOTES));
	}
	strArraySort(array);
	if(!strArrayEqual(array, sv->config.targets)) {
	  addSFlowSetting(sv, "targets", sv->config.targetStr);
	}
	strArrayFree(array);
      }
    }
    return YES;
  }

  int bridgeGetSFlow(SFVS *sv, char *line)
  {
    char *uuid = stripQuotes(line, SFVS_QUOTES);
    if(uuid && strcmp(uuid, sv->sflowUUID) != 0) {
      // doesn't match
      if(debug) myLog(LOG_INFO, "setting sflow for bridge %s", sv->bridge);
      addBridgeSetting(sv, "sflow", sv->sflowUUID);
    }
    return YES;
  }

  int bridgeList(SFVS *sv, char *line)
  {
    // copy the bridge name
    char *br = stripQuotes(line, SFVS_QUOTES);
    if(debug) myLog(LOG_INFO, "bridgeList> %s", br);
    if(br && (br[0] != '\0')) {
      setStr(&sv->bridge, br);
      // now run a command to check (and possible change) the bridge sFlow setting
      char *bridge_get_sflow_cmd[] = { SFVS_OVS_CMD, "get", "bridge", br, "sflow", NULL };
      if(myExec(sv, bridge_get_sflow_cmd, bridgeGetSFlow) == NO) return NO;
    }
    return YES;
  }

#ifdef USEATVAR
  // no need for this - do it all in submit changes
#else
  int submitCreate(SFVS *sv, char *line)
  {
    char *uuid = stripQuotes(line, SFVS_QUOTES);
    if(uuid && strlen(uuid)) {
      // check format to see if it is really a uuid $$$
      setStr(&sv->sflowUUID, uuid);
    }
    return YES;
  }
#endif

  int submitChanges(SFVS *sv, char *line)
  {
    myLog(LOG_ERR, "sumbitChanges: %s", line);
    // if we get anything at all here, then it must mean something didn't work - but
    // return YES anway so we can log the whole error message if it spans multiple
    // lines.
    sv->cmdFailed = YES;
    return YES;
  }
    
  /*_________________---------------------------__________________
    _________________        syncOVS            __________________
    -----------------___________________________------------------
  */

  static int syncOVS(SFVS *sv)
  {
    resetCmd(sv);
    resetExtras(sv);

    if(sv->config.error
       || sv->config.num_collectors == 0
       || (sv->config.sampling_n == 0 && sv->config.polling_secs == 0)) {
      // no config or no targets or no sampling/polling - clear everything
      if(debug) myLog(LOG_INFO, "no config found: clearing all OVS sFlow config");
      setStr(&sv->sflowUUID, "[]");
      setState(sv, SFVSSTATE_SYNC_DESTROY);
    }
    else {
      // got config - assume here that we're going to create a new
      // sflow object, but if we find one we'll adopt it
      setStr(&sv->sflowUUID, SFVS_NEW_SFLOW_ID);
      setState(sv, SFVSSTATE_SYNC_SEARCH);
    }
    if(debug) myLog(LOG_INFO, "==== list sflow ====");
    char *list_sflow_cmd[] = { SFVS_OVS_CMD, "list", "sflow", NULL };
    if(myExec(sv, list_sflow_cmd, sFlowList) == NO) return NO;

#ifdef USEATVAR
    // we can add the create at the end
#else
    // create new sFlow object if there were none found (i.e. if
    // the sflowUUID has not changed from the initial setting we
    // gave it.
    if(strcmp(SFVS_NEW_SFLOW_ID, sv->sflowUUID) == 0) {
      addCreateSFlow(sv);
      logCmd(sv);
      strArrayAdd(sv->cmd, NULL); // for execve(2)
      if(myExec(sv, strArray(sv->cmd), submitCreate) == NO) return NO;
      resetCmd(sv);
    }
#endif

    // make sure every bridge is using this sFlow entry
    if(debug) myLog(LOG_INFO, "==== list bridge ====");
    char *list_bridge_cmd[] = { SFVS_OVS_CMD, "list-br", NULL};
    if(myExec(sv, list_bridge_cmd, bridgeList) == NO) return NO;

    // now it's safe to delete any extras that we found
    for(int ex = strArrayN(sv->extras); --ex >= 0; ) {
      addDestroySFlow(sv, strArrayAt(sv->extras, ex));
    }

#ifdef USEATVAR
    // create new sFlow object if there were none found (i.e. if
    // the sflowUUID has not changed from the initial setting we
    // gave it.
    if(strcmp(SFVS_NEW_SFLOW_ID, sv->sflowUUID) == 0) {
      addCreateSFlow(sv);
    }
#endif

    // if we decided to make any changes, submit them now
    if(strArrayN(sv->cmd) > 1) {
      logCmd(sv);
      strArrayAdd(sv->cmd, NULL); // for execve(2)
      if(myExec(sv, strArray(sv->cmd), submitChanges) == NO) return NO;
    }
    return sv->cmdFailed ? NO : YES;
  }


      
  /*_________________---------------------------__________________
    _________________         main              __________________
    -----------------___________________________------------------
  */

  int main(int argc, char *argv[])
  {
    SFVS *sv = &SFVSDaemon;

    // open syslog
    openlog(SFVS_DAEMON_NAME, LOG_CONS, LOG_USER);
    setlogmask(LOG_UPTO(LOG_DEBUG));

    // register signal handler
    signal(SIGTERM,signal_handler);
    signal(SIGINT,signal_handler); 
    // signal(SIGCHLD,signal_handler); 

    // init
    setDefaults(sv);

    // read the command line
    processCommandLine(sv, argc, argv);
      
    // don't run if we think another one is already running
    struct stat statBuf;
    if(stat(sv->pidFile, &statBuf) == 0) {
      myLog(LOG_ERR,"Another %s is already running. If this is an error, remove %s", argv[0], sv->pidFile);
      exit(EXIT_FAILURE);
    }
    
    if(stat(SFVS_OVS_CMD, &statBuf) != 0) {
      myLog(LOG_ERR,"Open VSwitch control command not found: %s", SFVS_OVS_CMD);
      exit(EXIT_FAILURE);
    }

    if(debug == 0) {
      // fork to daemonize
      pid_t pid = fork();
      if(pid < 0) {
	myLog(LOG_ERR,"Cannot fork child");
	exit(EXIT_FAILURE);
      }
      
      if(pid > 0) {
	// in parent - write pid file and exit
	FILE *f;
	if(!(f = fopen(sv->pidFile,"w"))) {
	  myLog(LOG_ERR,"Could not open the pid file %s for writing : %s", sv->pidFile, strerror(errno));
	  exit(EXIT_FAILURE);
	}
	fprintf(f,"%"PRIu64"\n",(uint64_t)pid);
	if(fclose(f) == -1) {
	  myLog(LOG_ERR,"Could not close pid file %s : %s", sv->pidFile, strerror(errno));
	  exit(EXIT_FAILURE);
	}
	
	exit(EXIT_SUCCESS);
      }
      else {
	// in child
	umask(0);

	// new session - with me as process group leader
	pid_t sid = setsid();
	if(sid < 0) {
	  myLog(LOG_ERR,"setsid failed");
	  exit(EXIT_FAILURE);
	}
	
	// close all file descriptors 
	int i;
	for(i=getdtablesize(); i >= 0; --i) close(i);
	// create stdin/out/err
	i = open("/dev/null",O_RDWR); // stdin
	dup(i);                       // stdout
	dup(i);                       // stderr
      }
    }

    myLog(LOG_INFO, "started");
    
    // initialize the clock so we can detect second boundaries
    time_t clk = time(NULL);
    
    setState(sv, SFVSSTATE_INIT);

    while(sv->state != SFVSSTATE_END) {
      
      switch(sv->state) {
	
      case SFVSSTATE_READCONFIG:
	if(readConfig(sv)) setState(sv, SFVSSTATE_SYNC);
	else setState(sv, SFVSSTATE_READCONFIG_FAILED);
	break;
	
      case SFVSSTATE_SYNC:
	{
	  if(syncOVS(sv)) setState(sv, SFVSSTATE_SYNC_OK);
	  else setState(sv, SFVSSTATE_SYNC_FAILED);
	}
	break;

      case SFVSSTATE_INIT:
      case SFVSSTATE_READCONFIG_FAILED:
      case SFVSSTATE_SYNC_SEARCH:
      case SFVSSTATE_SYNC_FOUND:
      case SFVSSTATE_SYNC_DESTROY:
      case SFVSSTATE_SYNC_FAILED:
      case SFVSSTATE_SYNC_OK:
      case SFVSSTATE_END:
	break;
      }

      // check for second boundaries and generate ticks
      time_t test_clk = time(NULL);
      if((test_clk < clk) || (test_clk - clk) > SFVS_MAX_TICKS) {
	// avoid a busy-loop of ticks
	myLog(LOG_INFO, "time jump detected");
	clk = test_clk - 1;
      }
      while(clk < test_clk) {
	// this would be a good place to test the memory footprint and
	// bail out if it looks like we are leaking memory(?)
	tick(sv, clk);
	clk++;
      }
      
      // set the timeout so that if all is quiet we will
      // still loop around and check for ticks/signals
      // at least once per second
      my_usleep(900000);
    }

    // get here if a signal kicks the state to SFVSSTATE_END
    // and we break out of the loop above.
    closelog();
    myLog(LOG_INFO,"stopped");

    if(debug == 0) {
      remove(sv->pidFile);
    }

    exit(exitStatus);
  } /* main() */


#if defined(__cplusplus)
} /* extern "C" */
#endif

