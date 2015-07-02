/* Copyright (C) 2007-2014 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Giuseppe Longo <giuseppe@glongo.it>
 */

#ifdef HAVE_PFRING
#include <pfring.h>
#endif /* HAVE_PFRING */

#include "suricata-common.h"
#include "suricata.h"
#include "conf.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "source-pfring.h"
#include "util-debug.h"
#include "util-checksum.h"
#include "util-privs.h"
#include "util-device.h"
#include "util-host-info.h"
#include "util-ioctl.h"
#include "runmodes.h"

TmEcode ReceivePfringThreadInit(ThreadVars *, void *, void **);

#ifndef HAVE_PFRING

/*Handle cases where we don't have PF_RING support built-in*/
TmEcode NoPfringSupportExit(ThreadVars *, void *, void **);

void TmModuleReceivePfringRegister (void)
{
    tmm_modules[TMM_RECEIVEPFRING].name = "ReceivePfring";
    tmm_modules[TMM_RECEIVEPFRING].ThreadInit = NoPfringSupportExit;
    tmm_modules[TMM_RECEIVEPFRING].Func = NULL;
    tmm_modules[TMM_RECEIVEPFRING].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEPFRING].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEPFRING].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEPFRING].cap_flags = SC_CAP_NET_ADMIN | SC_CAP_NET_RAW |
        SC_CAP_NET_BIND_SERVICE | SC_CAP_NET_BROADCAST;
    tmm_modules[TMM_RECEIVEPFRING].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleDecodePfringRegister (void)
{
    tmm_modules[TMM_DECODEPFRING].name = "DecodePfring";
    tmm_modules[TMM_DECODEPFRING].ThreadInit = NoPfringSupportExit;
    tmm_modules[TMM_DECODEPFRING].Func = NULL;
    tmm_modules[TMM_DECODEPFRING].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPFRING].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEPFRING].RegisterTests = NULL;
    tmm_modules[TMM_DECODEPFRING].cap_flags = 0;
    tmm_modules[TMM_DECODEPFRING].flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief this funciton prints an error message and exits.
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with PfringThreadVars
 */
TmEcode NoPfringSupportExit(ThreadVars *tv, void *initdata, void **data)
{
    SCLogError(SC_ERR_NO_PF_RING,"Error creating thread %s: you do not have support for pfring "
               "enabled please recompile with --enable-pfring", tv->name);
    exit(EXIT_FAILURE);
}

#else /* implied we do have PF_RING support */

/** protect pfring_set_bpf_filter, as it is not thread safe */
static SCMutex pfring_bpf_set_filter_lock = SCMUTEX_INITIALIZER;

/* XXX replace with user configurable options */
#define LIBPFRING_PROMISC     1
#define LIBPFRING_REENTRANT   0
#define LIBPFRING_WAIT_FOR_INCOMING 1

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct PfringThreadVars_
{
    /* thread specific handle */
    pfring *pd;

    /* counters */
    uint64_t bytes;
    uint64_t pkts;

    int flags;
    uint16_t capture_kernel_packets;
    uint16_t capture_kernel_drops;

    ThreadVars *tv;
    TmSlot *slot;

    int vlan_disabled;

    /* threads count */
    int threads;

    /* IPS stuff */
    char out_iface[PFRING_IFACE_NAME_LENGTH];
    int copy_mode;
    int flush_packet;
    PfringPeer *mpeer;

    cluster_type ctype;

    uint8_t cluster_id;
    char *interface;
    LiveDevice *livedev;

    char *bpf_filter;

     ChecksumValidationMode checksum_mode;
} PfringThreadVars;

typedef struct PfringPeersList {
    TAILQ_HEAD(, PfringPeer_) peers;
    int cnt;
    int peered;
    int turn;
    SC_ATOMIC_DECLARE(int, reached);
} PfringPeersList;
/**
 * \brief Registration Function for RecievePfring.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceivePfringRegister (void)
{
    tmm_modules[TMM_RECEIVEPFRING].name = "ReceivePfring";
    tmm_modules[TMM_RECEIVEPFRING].ThreadInit = ReceivePfringThreadInit;
    tmm_modules[TMM_RECEIVEPFRING].Func = NULL;
    tmm_modules[TMM_RECEIVEPFRING].PktAcqLoop = ReceivePfringLoop;
    tmm_modules[TMM_RECEIVEPFRING].ThreadExitPrintStats = ReceivePfringThreadExitStats;
    tmm_modules[TMM_RECEIVEPFRING].ThreadDeinit = ReceivePfringThreadDeinit;
    tmm_modules[TMM_RECEIVEPFRING].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEPFRING].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration Function for DecodePfring.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodePfringRegister (void)
{
    tmm_modules[TMM_DECODEPFRING].name = "DecodePfring";
    tmm_modules[TMM_DECODEPFRING].ThreadInit = DecodePfringThreadInit;
    tmm_modules[TMM_DECODEPFRING].Func = DecodePfring;
    tmm_modules[TMM_DECODEPFRING].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPFRING].ThreadDeinit = DecodePfringThreadDeinit;
    tmm_modules[TMM_DECODEPFRING].RegisterTests = NULL;
    tmm_modules[TMM_DECODEPFRING].flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief Init function for RecievePfring.
 *
 * This is a setup function for recieving packets
 * via libpfring.
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with PfringThreadVars
 * \todo add a config option for setting cluster id
 * \todo Create a general pfring setup function.
 * \retval TM_ECODE_OK on success
 * \retval TM_ECODE_FAILED on error
 */
TmEcode ReceivePfringThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    int rc;
    u_int32_t version = 0;
    PfringIfaceConfig *pfconf = (PfringIfaceConfig *) initdata;
    unsigned int opflag;


    if (pfconf == NULL)
        return TM_ECODE_FAILED;

    PfringThreadVars *ptv = SCMalloc(sizeof(PfringThreadVars));
    if (unlikely(ptv == NULL)) {
        pfconf->DerefFunc(pfconf);
        return TM_ECODE_FAILED;
    }
    memset(ptv, 0, sizeof(PfringThreadVars));

    ptv->tv = tv;
    ptv->threads = 1;

    ptv->interface = SCStrdup(pfconf->iface);
    if (unlikely(ptv->interface == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate device string");
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->livedev = LiveGetDevice(pfconf->iface);
    if (ptv->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to find Live device");
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->checksum_mode = pfconf->checksum_mode;

    opflag = PF_RING_REENTRANT | PF_RING_PROMISC;

    /* if suri uses VLAN and if we have a recent kernel, we need
     * to use parsed_pkt to get VLAN info */
    if ((! ptv->vlan_disabled) && SCKernelVersionIsAtLeast(3, 0)) {
        opflag |= PF_RING_LONG_HEADER;
    }

    if (ptv->checksum_mode == CHECKSUM_VALIDATION_RXONLY) {
        if (strncmp(ptv->interface, "dna", 3) == 0) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                         "Can't use rxonly checksum-checks on DNA interface,"
                         " resetting to auto");
            ptv->checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else {
            opflag |= PF_RING_LONG_HEADER;
        }
    }

    ptv->pd = pfring_open(ptv->interface, (uint32_t)default_packet_size, opflag);
    if (ptv->pd == NULL) {
        SCLogError(SC_ERR_PF_RING_OPEN,"Failed to open %s: pfring_open error."
                " Check if %s exists and pf_ring module is loaded.",
                ptv->interface,
                ptv->interface);
        pfconf->DerefFunc(pfconf);
        SCFree(ptv);
        return TM_ECODE_FAILED;
    } else {
        pfring_set_application_name(ptv->pd, PROG_NAME);
        pfring_version(ptv->pd, &version);
    }

    /* We only set cluster info if the number of pfring threads is greater than 1 */
    ptv->threads = pfconf->threads;

    ptv->cluster_id = pfconf->cluster_id;

    if ((ptv->threads == 1) && (strncmp(ptv->interface, "dna", 3) == 0)) {
        SCLogInfo("DNA interface detected, not adding thread to cluster");
    } else if (strncmp(ptv->interface, "zc", 2) == 0) {
        SCLogInfo("ZC interface detected, not adding thread to cluster");
    } else {
        ptv->ctype = pfconf->ctype;
        rc = pfring_set_cluster(ptv->pd, ptv->cluster_id, ptv->ctype);

        if (rc != 0) {
            SCLogError(SC_ERR_PF_RING_SET_CLUSTER_FAILED, "pfring_set_cluster "
                    "returned %d for cluster-id: %d", rc, ptv->cluster_id);
            pfconf->DerefFunc(pfconf);
            return TM_ECODE_FAILED;
        }
    }

    if (ptv->threads > 1) {
        SCLogInfo("(%s) Using PF_RING v.%d.%d.%d, interface %s, cluster-id %d",
                tv->name, (version & 0xFFFF0000) >> 16, (version & 0x0000FF00) >> 8,
                version & 0x000000FF, ptv->interface, ptv->cluster_id);
    } else {
        SCLogInfo("(%s) Using PF_RING v.%d.%d.%d, interface %s, cluster-id %d, single-pfring-thread",
                tv->name, (version & 0xFFFF0000) >> 16, (version & 0x0000FF00) >> 8,
                version & 0x000000FF, ptv->interface, ptv->cluster_id);
    }

    if (pfconf->bpf_filter) {
        ptv->bpf_filter = SCStrdup(pfconf->bpf_filter);
        if (unlikely(ptv->bpf_filter == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Set PF_RING bpf filter failed.");
        } else {
            SCMutexLock(&pfring_bpf_set_filter_lock);
            rc = pfring_set_bpf_filter(ptv->pd, ptv->bpf_filter);
            SCMutexUnlock(&pfring_bpf_set_filter_lock);

            if (rc < 0) {
                SCLogInfo("Set PF_RING bpf filter \"%s\" failed.",
                          ptv->bpf_filter);
            }
        }
    }

    ptv->copy_mode = pfconf->copy_mode;
    if (ptv->copy_mode != PFRING_COPY_MODE_NONE) {
        strlcpy(ptv->out_iface, pfconf->out_interface, PFRING_IFACE_NAME_LENGTH);
        ptv->out_iface[PFRING_IFACE_NAME_LENGTH - 1] = '\0';
        ptv->flush_packet = pfconf->flush_packet;
        if (ptv->bpf_filter) {
            SCLogWarning(SC_WARN_UNCOMMON, "Enabling a BPF filter in IPS mode result"
                      " in dropping all non matching packets.");
        }
    }

    if (PfringPeersListAdd(ptv) == TM_ECODE_FAILED) {
        SCFree(ptv);
        pfconf->DerefFunc(pfconf);
        return TM_ECODE_FAILED;
    }

    ptv->capture_kernel_packets = SCPerfTVRegisterCounter("capture.kernel_packets",
            ptv->tv,
            SC_PERF_TYPE_UINT64,
            "NULL");
    ptv->capture_kernel_drops = SCPerfTVRegisterCounter("capture.kernel_drops",
            ptv->tv,
            SC_PERF_TYPE_UINT64,
            "NULL");

    char *active_runmode = RunmodeGetActive();

    if (active_runmode && strcmp("workers", active_runmode) != 0)
        ptv->flags |= PFRING_RING_PROTECT;

    /* A bit strange to have this here but we only have vlan information
     * during reading so we need to know if we want to keep vlan during
     * the capture phase */
    int vlanbool = 0;
    if ((ConfGetBool("vlan.use-for-tracking", &vlanbool)) == 1 && vlanbool == 0) {
        ptv->vlan_disabled = 1;
    }

    /* If kernel is older than 3.8, VLAN is not stripped so we don't
     * get the info from packt extended header but we will use a standard
     * parsing */
    if (! SCKernelVersionIsAtLeast(3, 0)) {
        ptv->vlan_disabled = 1;
    }

    /* Since VLAN is disabled we force the cluster type to CLUSTER_FLOW_5_TUPLE */
    if (ptv->vlan_disabled == 1 && ptv->ctype == CLUSTER_FLOW) {
        SCLogInfo("VLAN disabled, setting cluster type to CLUSTER_FLOW_5_TUPLE");
        rc = pfring_set_cluster(ptv->pd, ptv->cluster_id, CLUSTER_FLOW_5_TUPLE);

        if (rc != 0) {
            SCLogError(SC_ERR_PF_RING_SET_CLUSTER_FAILED, "pfring_set_cluster "
                    "returned %d for cluster-id: %d", rc, ptv->cluster_id);
            pfconf->DerefFunc(pfconf);
            return TM_ECODE_FAILED;
        }
    }

    *data = (void *)ptv;
    pfconf->DerefFunc(pfconf);

    return TM_ECODE_OK;
}

#endif /* HAVE_PFRING */
/* eof */
