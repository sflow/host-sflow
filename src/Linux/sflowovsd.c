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
  extern int debug;

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
    sv->ovs10 = NO;
    sv->useAtVar = YES;
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
    if(sv->config.targetStr) my_free(sv->config.targetStr);
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
    setStr(&cfg->agent_ip, NULL);
    setStr(&cfg->agent_dev, NULL);
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
    
    // loop until we get the same revision number at the beginning and the end
    int readAgain = NO;
    uint32_t rev_start = 0;
    uint32_t rev_end = 0;
    do {
      readAgain = NO;
      resetConfig(&sv->config);
      FILE *cfg = NULL;
      if((cfg = fopen(sv->configFile, "r")) == NULL) {
	myLog(LOG_ERR,"cannot open config file %s : %s", sv->configFile, strerror(errno));
	return NO;
      }
      char line[SFVS_MAX_LINELEN];
      uint32_t lineNo = 0;
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
	    setStr(&sv->config.agent_ip, ipbuf);
	  }
	  else if(strcasecmp(var, "agent") == 0
		  && syntaxOK(sv, lineNo, tokc, 1, 1, "agent=<deviceName>")) {
	    // format with quotes?
	    char ipbuf[SFVS_MAX_LINELEN];
	    sprintf(ipbuf, "\"%s\"", tok1);
	    setStr(&sv->config.agent_dev, ipbuf);
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
	  else if(strncasecmp(var, "sampling.", 9) == 0) { /* ignore other sampling.<app> settings */ }
	  else if(strncasecmp(var, "polling.", 8) == 0) { /* ignore other polling.<app> settings */ }
	  else {
	    // don't abort just because we added a new setting for something
	    // syntaxError(sv, lineNo, "unknown var=value setting");
	  }
	}
      }
      fclose(cfg);

      if(rev_start && rev_end && rev_start != rev_end) {
	if(debug) fprintf(stderr, "re-read config (rev_start != rev_end)\n");
	readAgain = YES;
	rev_start = 0;
	rev_end = 0;
	// take a nap so we can't busy-loop here
	my_usleep(50000);
      }

    } while(readAgain);
    
    // turn the collectors list into the targets string
    formatTargets(sv);

    // sanity checks...

    if(rev_start == 0 || rev_end == 0) {
      syntaxError(sv, 0, "missing non-zero revision numbers rev_start, rev_end");
    }

    // for open vswitch we have to have the device name
    if(!sv->config.agent_dev /* && !sv->config.agent_ip*/) {
      //syntaxError(sv, 0, "missing agent=<deviceName> OR agentIP=<IP address>|<IPv6 address>");
      syntaxError(sv, 0, "missing agent=<deviceName>");
    }

    return (!sv->config.error);
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
    my_free(setting);
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
    if(sv->useAtVar) {
      addOvsArg(sv, "--id=" SFVS_NEW_SFLOW_ID);
    }
    sv->usingAtVar = sv->useAtVar;
    addOvsArg(sv, "create");
    addOvsArg(sv, "sflow");
    addOvsVarEqVal(sv, "agent", sv->config.agent_dev);
    addOvsVarEqVal_int(sv, "header", sv->config.header_bytes);
    addOvsVarEqVal_int(sv, "polling", sv->config.polling_secs);
    addOvsVarEqVal_int(sv, "sampling", sv->config.sampling_n);
    addOvsVarEqVal(sv, "targets", sv->config.targetStr);
  }

  static void logCmd(SFVS *sv) {
    char *cmdstr = strArrayStr(sv->cmd, "<", NULL, " ", ">");
    myLog(LOG_INFO, "cmd: %s\n", cmdstr);
    my_free(cmdstr);
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

  int sFlowList(void *magic, char *line)
  {
    SFVS *sv = (SFVS *)magic;
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
	if(strcmp(quoted, sv->config.agent_dev) != 0) {
	  addSFlowSetting(sv, "agent", sv->config.agent_dev);
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
	UTStringArray *array = strArrayNew();
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

  int bridgeGetSFlow(void *magic, char *line)
  {
    SFVS *sv = (SFVS *)magic;
    char *uuid = stripQuotes(line, SFVS_QUOTES);
    if(uuid && strcmp(uuid, sv->sflowUUID) != 0) {
      // doesn't match
      if(debug) myLog(LOG_INFO, "setting sflow for bridge %s", sv->bridge);
      addBridgeSetting(sv, "sflow", sv->sflowUUID);
    }
    return YES;
  }

  int bridgeList(void *magic, char *line)
  {
    SFVS *sv = (SFVS *)magic;
    // we're looking for the lines that have "name : <bridge-name>"
    // or specifically the sequence:
    // name
    // <whitespace>
    // :
    // <whitespace>
    // <bridge-name>
    // sscanf with format string "name%*[\t ]:%*[\t ]%s" works, but
    // assumes that the whitespace is not empty.  I don't think we
    // can necessarily assume that (?)
    char bridgeName[SFVS_MAX_LINELEN];
    if(sscanf(line, "name%*[\t ]:%*[\t ]%s", bridgeName) == 1) {
      // copy the bridge name
      char *br = stripQuotes(bridgeName, SFVS_QUOTES);
      if(debug) myLog(LOG_INFO, "bridgeList> %s", br);
      if(br && (br[0] != '\0')) {
	setStr(&sv->bridge, br);
	// now run a command to check (and possible change) the bridge sFlow setting
	char *bridge_get_sflow_cmd[] = { SFVS_OVS_CMD, "get", "bridge", br, "sflow", NULL };
	char line[SFVS_MAX_LINELEN];
	if(myExec(sv, bridge_get_sflow_cmd, bridgeGetSFlow, line, SFVS_MAX_LINELEN) == NO) return NO;
      }
    }
    return YES;
  }

  int submitCreate(void *magic, char *line)
  {
    SFVS *sv = (SFVS *)magic;
    char *uuid = stripQuotes(line, SFVS_QUOTES);
    if(uuid && strlen(uuid)) {
      // check format to see if it is really a uuid $$$
      setStr(&sv->sflowUUID, uuid);
    }
    return YES;
  }

  int submitChanges(void *magic, char *line)
  {
    SFVS *sv = (SFVS *)magic;
    myLog(LOG_INFO, "sumbitChanges: %s", line);
    // if we get anything at all here, then it probably means something didn't work - but
    // return YES anway so we can log the whole error message if it spans multiple
    // lines.  Note that with the --id=@tok settings we do now see the UUID of the newly
    // created sFlow object here.  Hence the change from LOG_ERR to LOG_INFO. It would
    // be a little awkward to change myExec to separate stdout and stderr, so this is the
    // best we can do without making bigger changes.
    sv->cmdFailed = YES;
    if(sv->usingAtVar && sv->ovs10 && sv->usedAtVarOK == NO) {
      if(debug) myLog(LOG_INFO, "command with --id=@tok failed and version is 1.0.*, so turn off --id=@tok");
      sv->useAtVar = NO;
    }
    return YES;
  }

  int readVersion(void *magic, char *line)
  {
    SFVS *sv = (SFVS *)magic;
    // the compulsory use of --id==@tok appeared between 1.0 and 1.1.0pre1
    // but before that it was not supported at all.  The format of this
    // version string may change at any time,  so the safest way to test
    // this is to assume that we can use --id==@tok unless we see a very
    // specific version string:
    if(memcmp(line, "ovs-vsctl (Open vSwitch) 1.0", 28) == 0) {
      if(debug) myLog(LOG_INFO, "detected ovs-vsctl version 1.0 - may turn off use of --id=@tok");
      sv->ovs10 = YES;
    }
    return NO; // only want the first line
  }
  
  /*_________________---------------------------__________________
    _________________        syncOVS            __________________
    -----------------___________________________------------------
  */

  static int syncOVS(SFVS *sv)
  {
    resetCmd(sv);
    resetExtras(sv);
    char line[SFVS_MAX_LINELEN];

    if(debug) myLog(LOG_INFO, "==== ovs-vsctl version ====");
    char *version_cmd[] = { SFVS_OVS_CMD, "--version", NULL};
    // don't abort if this fails: readVersion returns NO as an easy way
    // to only see the first line. (Line number should really be supplied to
    // callback from myExec)
    sv->ovs10 = NO; // assume newer version
    sv->usingAtVar = NO;
    myExec((void *)sv, version_cmd, readVersion, line, SFVS_MAX_LINELEN);
    // adapt if OVS is upgraded under our feet
    if(sv->ovs10 == NO) sv->useAtVar = YES; 
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
    if(myExec((void *)sv, list_sflow_cmd, sFlowList, line, SFVS_MAX_LINELEN) == NO) return NO;

    if(sv->useAtVar) {
      // we can add the create at the end
    }
    else {
      // create new sFlow object if there were none found (i.e. if
      // the sflowUUID has not changed from the initial setting we
      // gave it.
      if(strcmp(SFVS_NEW_SFLOW_ID, sv->sflowUUID) == 0) {
	addCreateSFlow(sv);
	logCmd(sv);
	strArrayAdd(sv->cmd, NULL); // for execve(2)
	if(myExec((void *)sv, strArray(sv->cmd), submitCreate, line, SFVS_MAX_LINELEN) == NO) return NO;
	resetCmd(sv);
      }
    }

    // make sure every bridge is using this sFlow entry
    if(debug) myLog(LOG_INFO, "==== list bridge ====");
    char *list_bridge_cmd[] = { SFVS_OVS_CMD, "list", "bridge", NULL};
    if(myExec((void *)sv, list_bridge_cmd, bridgeList, line, SFVS_MAX_LINELEN) == NO) return NO;

    // now it's safe to delete any extras that we found
    for(int ex = strArrayN(sv->extras); --ex >= 0; ) {
      addDestroySFlow(sv, strArrayAt(sv->extras, ex));
    }

    if(sv->useAtVar) {
      // create new sFlow object if there were none found (i.e. if
      // the sflowUUID has not changed from the initial setting we
      // gave it.
      if(strcmp(SFVS_NEW_SFLOW_ID, sv->sflowUUID) == 0) {
	addCreateSFlow(sv);
      }
    }

    // if we decided to make any changes, submit them now
    sv->cmdFailed = NO;
    if(strArrayN(sv->cmd) > 1) {
      logCmd(sv);
      strArrayAdd(sv->cmd, NULL); // for execve(2)
      if(myExec((void *)sv, strArray(sv->cmd), submitChanges, line, SFVS_MAX_LINELEN) == NO) return NO;
      if(sv->usingAtVar && sv->cmdFailed == NO) {
        // remember that it worked at least once
        sv->usedAtVarOK = YES;
      }
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

