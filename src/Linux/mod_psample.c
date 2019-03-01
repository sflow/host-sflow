/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <linux/types.h>
#include <linux/netlink.h>
#include <net/if.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#include <linux/genetlink.h>
#include <libmnl/libmnl.h>
#include <psample.h>

struct mnlg_socket {
	struct mnl_socket *nl;
	char *buf;
	uint16_t id;
	uint8_t version;
	unsigned int seq;
	unsigned int portid;
};

struct psample_msg {
	struct nlattr **tb;
};

struct psample_handle {
	struct mnlg_socket *sample_nlh;
	struct mnlg_socket *control_nlh;
	struct sock_fprog sample_filter_fprog;
};

typedef struct _HSP_mod_PSAMPLE {
  EVBus *packetBus;
  bool psample_configured;
  struct psample_handle *psampleHandle;
  uint32_t subSamplingRate;
  uint32_t actualSamplingRate;
} HSP_mod_PSAMPLE;

static int attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type;

	type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, PSAMPLE_ATTR_MAX) < 0)
		return MNL_CB_ERROR;

	if (type == PSAMPLE_ATTR_IIFINDEX &&
	    mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
		return MNL_CB_ERROR;
	if (type == PSAMPLE_ATTR_OIFINDEX &&
	    mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
		return MNL_CB_ERROR;
	if (type == PSAMPLE_ATTR_SAMPLE_RATE &&
	    mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
		return MNL_CB_ERROR;
	if (type == PSAMPLE_ATTR_ORIGSIZE &&
	    mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
		return MNL_CB_ERROR;
	if (type == PSAMPLE_ATTR_SAMPLE_GROUP &&
	    mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
		return MNL_CB_ERROR;
	if (type == PSAMPLE_ATTR_GROUP_SEQ &&
	    mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
		return MNL_CB_ERROR;
	if (type == PSAMPLE_ATTR_GROUP_REFCOUNT &&
	    mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
		return MNL_CB_ERROR;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int psample_event_handler(const struct nlmsghdr *nlhdr, void *data)
{
  struct nlattr *tb[PSAMPLE_ATTR_MAX + 1] = {};
  EVMod *mod = data;
  HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
  HSP *sp = (HSP *)EVROOTDATA(mod);
  int ret;

  mnl_attr_parse(nlhdr, sizeof(struct genlmsghdr), attr_cb, tb);
  struct psample_msg msg;
  msg.tb = tb;

  uint32_t ifin = 0;
  uint32_t ifout = 0;
  u_char *mac_hdr = NULL;
  uint32_t mac_len = 0;
  u_char *payload = NULL;
  uint32_t payload_len = 0;

  if (psample_msg_iif_exist(&msg))
    ifin = psample_msg_iif(&msg);

  if (psample_msg_oif_exist(&msg))
    ifout = psample_msg_oif(&msg);

  if (psample_msg_data_exist(&msg)) {
    mac_hdr = psample_msg_data(&msg);
    mac_len = ETH_HLEN;
    payload = mac_hdr + mac_len;
    payload_len = psample_msg_data_len(&msg) - mac_len;
  }

  takeSample(sp,
    adaptorByIndex(sp, ifin),
    adaptorByIndex(sp, ifout),
    NULL,
    sp->psample.ds_options,
    0,
    mac_hdr,
    mac_len,
    payload,
    payload_len,
    payload_len,
    0, //TODO: droppedSamples
    mdata->actualSamplingRate);

  if (ret != 0)
    return MNL_CB_STOP;

  return MNL_CB_OK;
}

  /*_________________---------------------------__________________
    _________________      readPackets          __________________
    -----------------___________________________------------------
  */

  static void readPackets_psample(EVMod *mod, EVSocket *sock, void *magic)
  {
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    struct mnlg_socket *nlg;
    int err;

    if(sp->sFlowSettings == NULL) {
      // config was turned off
      return;
    }

    nlg = mdata->psampleHandle->sample_nlh;

    do {
      err = mnl_socket_recvfrom(nlg->nl,
                                nlg->buf,
                                MNL_SOCKET_BUFFER_SIZE);
      if (err <= 0)
        break;

      err = mnl_cb_run(nlg->buf, err, nlg->seq, nlg->portid,
          psample_event_handler, mod);
    } while (err > 0);
  }

  /*_________________---------------------------__________________
    _________________     setSamplingRate       __________________
    -----------------___________________________------------------
  */

  static void setSamplingRate(EVMod *mod) {
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    uint32_t samplingRate = sp->sFlowSettings->samplingRate;

    // set defaults assuming we will get 1:1 on PSAMPLE and do our own sampling.
    mdata->subSamplingRate = samplingRate;
    mdata->actualSamplingRate = samplingRate;

    if(sp->hardwareSampling) {
      // all sampling is done in the hardware
      mdata->subSamplingRate = 1;
      return;
    }

    // calculate the psample sub-sampling rate to use. We may get the local sampling-rate from
    // the probability setting in the config file and the desired sampling rate from DNS-SD, so
    // that's why we have to reconcile the two here.
    uint32_t psamplesr = sp->psample.samplingRate;
    if(psamplesr > 1) {
      // use an integer divide to get the sub-sampling rate, but make sure we round up
      mdata->subSamplingRate = (samplingRate + psamplesr - 1) / psamplesr;
      // and pre-calculate the actual sampling rate that we will end up applying
      mdata->actualSamplingRate = mdata->subSamplingRate * psamplesr;
    }

  }

  /*_________________---------------------------__________________
    _________________    evt_config_changed     __________________
    -----------------___________________________------------------
  */

  static void evt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE*)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    int err;

    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    setSamplingRate(mod);

    if(mdata->psample_configured) {
      // already configured from the first time (when we still had root privileges)
      return;
    }

    mdata->psampleHandle = psample_open();
    if (!mdata->psampleHandle) {
      myLog(LOG_ERR, "PSAMPLE psample_open() failed %s\n", strerror(errno));
      return;
    }

    err = psample_bind_group(mdata->psampleHandle, sp->psample.group);
    if (err) {
      myLog(LOG_ERR, "PSAMPLE psample_bind_group() failed: %s\n", strerror(errno));
      return;
    }

    int fd = psample_get_sample_fd(mdata->psampleHandle);
    EVBusAddSocket(mod, mdata->packetBus, fd, readPackets_psample, NULL);

    mdata->psample_configured= YES;
  }

  /*_________________---------------------------__________________
    _________________    evt_intfs_changed      __________________
    -----------------___________________________------------------
  */

  static void evt_intfs_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    setSamplingRate(mod);
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_psample(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_PSAMPLE));
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE*)mod->data;
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_INTFS_CHANGED), evt_intfs_changed);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
