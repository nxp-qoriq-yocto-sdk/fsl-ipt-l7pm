/************************< BEGIN COPYRIGHT >************************
 *
 * Copyright (C) 2007-2008 Freescale Semiconductor, Inc. All rights reserved.
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 ************************< END COPYRIGHT >***************************/
/*
 * Kernel module to match application layer (OSI layer 7) data in
 * connections. with pattern match engine
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <linux/proc_fs.h>
#include <linux/ctype.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/spinlock.h>

#include <linux/netfilter_ipv4/ipt_l7pm.h>
#include <linux/netfilter_ipv4/ip_tables.h>

/*
 * freescale pm includes
 */
/*
 * #include "common.h"
 */
#include "asm/8572pme.h"

MODULE_AUTHOR("alex xian");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION
  ("iptables application layer match module/pattern match engine");
MODULE_VERSION("0.1");

static uint8_t *result_buf;
static int result_len = 1024;

/*
 * freescale pm
 */
/*
 * pme result code
 */
enum pme_report_type {
  PMP_SimpleMatchType_e = 0x01,
  PMP_SimpleMatchInconclusiveRightType_e = 0x11,
  PMP_SimpleMatchInconclusiveLeftType_e = 0x21,
  PMP_SimpleMatchInconclusiveBothType_e = 0x31,
  PMP_VerboseMatchType_e = 0x02,
  PMP_VerboseMatchInconclusiveRightType_e = 0x12,
  PMP_VerboseMatchInconclusiveLeftType_e = 0x22,
  PMP_VerboseMatchInconclusiveBothType_e = 0x32,
  PMP_StatelessRule_e = 0x03,
  PMP_DualStateRuleNoContext_e = 0x04,
  PMP_DualStateRuleWithContext_e = 0x05,
  PMP_DualStateRuleWithContextVerbose_e = 0x06,
  PMP_MultiStateRule_e = 0x07,
  PMP_MultiStateRuleVerbose_e = 0x08,
  PMP_RuleReportType_e = 0x70,
  PMP_EndOfReportType_e = 0x80,
  PMP_InconclusiveRightRecordTypeClass = 0x10,
  PMP_InconclusiveLeftRecordTypeClass = 0x20,
};

#define PME_WORKUINT_OFFSET_SIZE 6

struct pme_result {
  uint8_t type;
  uint8_t match_length;
  uint8_t uint_offset[PME_WORKUINT_OFFSET_SIZE];
  uint32_t match_offset;
  uint32_t tag;
};

#define COPY_DATA
static u32 max_delay = 0, min_delay = 0xffffffff;
struct pme_ctx {
  struct nf_conn *master_conntrack;
  struct timeval timestamp;
  uint8_t *result;
  int result_len;
  u32 sIp, dIp;
  u16 sPort, dPort;
  u8 proto;
#ifdef COPY_DATA
  u8 data[0];
#else
  struct sk_buff *skb;
#endif
};

struct l7pm_stat {
  u32 sIp, dIp;
  u16 sPort, dPort;
  u8 proto;
  u8 nMatch;
  u8 tags[8];
};

static int n_pme_ctx;

/*
 * NB skbuff changes! As of 2.6.22 there is a change in skbufs, i.e. nh is
 * gone.  A new macro is available in the kernel to fix this, ip_hdr(),
 * and it is not backwards compatable.  So, create some macros to check
 * for kernel version for each former nh call.
 */
/*
 * #if LINUX_CODE_VERSION >= KERNEL_VERSION(2,6,22)
 */
#define SKB_NH_PROTOCOL(b) (ip_hdr(b)->protocol)
#define SKB_NH_IPH(b) (ip_hdr(b))
#define SKB_NH_IHL(b) (ip_hdr(b)->ihl)
#define SKB_NH_SADDR(b) (ip_hdr(b)->saddr)
#define SKB_NH_DADDR(b) (ip_hdr(b)->daddr)

/*
 * #endif
 */

#define N_L7PM_STAT 64
static struct l7pm_stat _l7pm_stat_buf[N_L7PM_STAT];
static int _l7pm_stat_idx;
static int _l7pm_stat_num;

#define MAX_PME_CHAN 4
#define PME_NO_MATCH_RESULT_TAG 0	/* before match result come back */
#define PME_UNKNOWN_TAG (-1)	/* unknown protocol tag */
#define SKB_L7PM_SEEN(skb) (skb->cb[1])	/* l7pm control variable location
					 * in skb->cb[40]: seen this pkt
					 * before */
/*
 * pme channel thing
 */
static struct pme_channel *pmchan[MAX_PME_CHAN];
static int num_pmchan;
static int cur_pmchan;		/* round robin pme_channel index */
static int use_pmchan;		/* -1: round robin all available channel,
				 * use 0-3 specific channel */
#define NON_BLOCKING_PME_CTX_CREATE
#ifndef NON_BLOCKING_PME_CTX_CREATE
#define PME_CTX_POOL_SIZE 128
static struct pme_context *pme_ctx_pool[PME_CTX_POOL_SIZE];
static int cur_pme_ctx_idx;
#endif
module_param(use_pmchan, int, 0444);
MODULE_PARM_DESC(use_pmchan,
		 "use a specific pm channel: 0-3, or use any: -1");

#define CONFIG_IP_NF_MATCH_L7PM_DEBUG
#ifdef CONFIG_IP_NF_MATCH_L7PM_DEBUG
static int dbg;
#define DPRINTK(format, args...) \
	do { \
		if (dbg) \
			printk(format, ##args); \
	} while (0)
#else
#define DPRINTK(format, args...)
#endif

/*
 * #define TOTAL_PACKETS
 * master_conntrack->counters[IP_CT_DIR_ORIGINAL].packets +\
 */
/*
 * master_conntrack->counters[IP_CT_DIR_REPLY].packets
 */
/*
 * Number of packets whose data we look at. This can be modified through
 * /proc/net/l7pm_numpackets
 */
static int num_packets = 10;

DEFINE_RWLOCK(ct_lock);

static unsigned long long int
TOTAL_PACKETS(struct nf_conn *ct)
{
  struct nf_conn_counter *acct;
  acct = nf_conn_acct_find(ct);
  if (!acct)
    return 0;
  return (unsigned long long) (acct[IP_CT_DIR_ORIGINAL].packets +
			       acct[IP_CT_DIR_REPLY].packets);



}

static int
can_handle(const struct sk_buff *skb)
{
  if (!SKB_NH_IPH(skb))		/* not IP */
    return 0;
  if (SKB_NH_PROTOCOL(skb) != IPPROTO_TCP &&
      SKB_NH_PROTOCOL(skb) != IPPROTO_UDP &&
      SKB_NH_PROTOCOL(skb) != IPPROTO_ICMP)
    return 0;
  return 1;
}

/*
 * Returns offset the into the skb->data that the application data starts
 */
static int
app_data_offset(const struct sk_buff *skb)
{
  /*
   * In case we are ported somewhere (ebtables?) where skb->nh.iph isn't
   * set, this can be gotten from 4*(skb->data[0] & 0x0f) as well.
   */
  int ip_hl = 4 * SKB_NH_IHL(skb);
  if (SKB_NH_PROTOCOL(skb) == IPPROTO_TCP) {
    /*
     * 12 == offset into TCP header for the header length field. Can't
     * get this with skb->h.th->doff because the tcphdr struct doesn't
     * get set when routing (this is confirmed to be true in Netfilter
     * as well as QoS.)
     */
    int tcp_hl = 4 * (skb->data[ip_hl + 12] >> 4);
    return ip_hl + tcp_hl;
  } else if (SKB_NH_PROTOCOL(skb) == IPPROTO_UDP) {
    return ip_hl + 8;		/* UDP header is always 8 bytes */
  } else if (SKB_NH_PROTOCOL(skb) == IPPROTO_ICMP) {
    return ip_hl + 8;		/* ICMP header is 8 bytes */
  } else {
    if (net_ratelimit())
      printk(KERN_ERR "l7pm: tried to handle unknown protocol!\n");
    return ip_hl + 8;		/* something reasonable */
  }
}

/*
 * handles whether there's a match when we aren't appending data anymore
 */
static int
match_result(struct nf_conn *conntrack,
	     struct nf_conn *master_conntrack, struct ipt_l7pm_info *info)
{
  DPRINTK("match_result(%p %p %p)\n", conntrack, master_conntrack, info);
#ifdef NON_BLOCKING_PME_CTX_CREATE
  if (master_conntrack->layer7.num_skb == 0 &&
		master_conntrack->layer7.userctx) {
    /*cleanup*/
    struct pme_context *pme_ctx =
      (struct pme_context *) master_conntrack->layer7.userctx;
    DPRINTK("pme_context_delete %p\n", pme_ctx);
    write_lock(&ct_lock);
    pme_context_delete(pme_ctx);
    n_pme_ctx--;
    module_put(THIS_MODULE);
    master_conntrack->layer7.userctx = 0;
    write_unlock(&ct_lock);
  }
#endif
  if (master_conntrack->layer7.tag != PME_NO_MATCH_RESULT_TAG) {
    /*
     * Here child connections set their .app_proto (for
     * /proc/net/ip_conntrack)
     */
    write_lock(&ct_lock);
    if (conntrack->layer7.tag == PME_NO_MATCH_RESULT_TAG)
      conntrack->layer7.tag = master_conntrack->layer7.tag;
    write_unlock(&ct_lock);
    if (master_conntrack->layer7.tag == info->tag)
      DPRINTK("l7pm: matched with %s\n", info->protocol);
    return (int) master_conntrack->layer7.tag == info->tag;
  } else {
    /*
     * If not classified, set to "unknown" to distinguish from
     * connections that are still being tested.
     */
    DPRINTK("l7-filter gave up after %lld pkts\n",
	    TOTAL_PACKETS(master_conntrack));
    write_lock(&ct_lock);
    master_conntrack->layer7.tag = PME_UNKNOWN_TAG;
    conntrack->layer7.tag = master_conntrack->layer7.tag;
    write_unlock(&ct_lock);
    return 0;
  }
}

static int
pme_scan_done(struct pme_context *obj, u32 flags, u8 exception_code,
	      u64 streamID, struct pme_context_callback *cb,
	      size_t output_used, struct pme_fbchain *fb_output)
{
  struct pme_ctx *ctx = (struct pme_ctx *) cb->ctx.words[0];
  struct nf_conn *master_conntrack;
  struct pme_fbchain *fbchain = fb_output;
#ifdef NON_BLOCKING_PME_CTX_CREATE
  struct pme_context *pme_ctx;
#endif
  size_t size;
  void *data = 0;
  u8 *ptr, *d;
  int i, s, need_free = 0;
  int idx = 0;
  struct timeval t;
  u32 delta;

  DPRINTK("pme_scan_done(%p %u %d %llu %p %d %p)\n", obj, flags,
	  exception_code, streamID, cb, output_used, fb_output);
  master_conntrack = ctx->master_conntrack;
  DPRINTK("pme_scan_done: mc=%p, ctx=%p num_skb=%d\n", master_conntrack,
	  ctx, master_conntrack->layer7.num_skb);
  if (exception_code)
    printk(KERN_ERR "pme_scan_done: exception_code=0x%x\n", exception_code);
  do_gettimeofday(&t);
  delta = t.tv_sec - ctx->timestamp.tv_sec;
  delta = delta * 1000000 + (t.tv_usec - ctx->timestamp.tv_usec);
  if (delta > max_delay)
    max_delay = delta;
  if (delta < min_delay)
    min_delay = delta;
  if (flags & PME_COMPLETION_ABORTED) {
    printk(KERN_ERR "pme_scan_done: abortion\n");
    master_conntrack->layer7.tag = PME_UNKNOWN_TAG;
    goto out;
  }
  if (output_used <= 5 || (fb_output == 0 && ctx->result == 0)) {	/* no
									 * match
									 * case
									 */
    DPRINTK("pme_scan_done: no match report output=%p result=%p\n",
	    fb_output, ctx->result);
    goto out;
  }
  /*
   * match report available
   */
  if (fb_output) {
    data = pme_fbchain_current(fbchain);
    size = pme_fbchain_current_bufflen(fbchain);
    DPRINTK("data=%p, size=%d\n", data, size);
    if (output_used > size) {
      ptr = kmalloc(output_used, GFP_ATOMIC);
      if (ptr) {
	need_free = 1;
	size = 0;
	data = d = ptr;
	ptr = pme_fbchain_current(fbchain);
	while (ptr) {
	  s = pme_fbchain_current_bufflen(fbchain);
	  size += s;
	  for (i = 0; i < size; i++)
	    *d++ = *ptr++;
	  ptr = pme_fbchain_next(fbchain);
	}
      } else {
	printk(KERN_ERR
	       "pme_scan_done: allocate buffer for result fb failed\n");
      }
    }
    d = data;
  } else if (ctx->result) {
    int ii;
    DPRINTK("result buffer %d\n", output_used);
    for (ii = 0; ii < output_used; ii++)
      DPRINTK(" %02x", ctx->result[ii]);
    DPRINTK("\n");
    d = ctx->result;
    size = output_used;
  } else {
    printk(KERN_ERR "pme_scan_done: something wrong\n");
    d = data = 0;
    goto out;
  }
  /*
   * find entry
   */
  write_lock(&ct_lock);
  if (_l7pm_stat_num < N_L7PM_STAT)
    s = 0;
  else
    s = (_l7pm_stat_idx + 1) % N_L7PM_STAT;
  for (i = 0; i < _l7pm_stat_num; i++) {
    idx = (i + s) % N_L7PM_STAT;
    if (_l7pm_stat_buf[idx].sIp == ctx->sIp &&
	_l7pm_stat_buf[idx].dIp == ctx->dIp &&
	_l7pm_stat_buf[idx].sPort == ctx->sPort &&
	_l7pm_stat_buf[idx].dPort == ctx->dPort &&
	_l7pm_stat_buf[idx].proto == ctx->proto) {
      break;
    }
  }
  /*
   * not found
   */
  if (i == _l7pm_stat_num)
    idx = -1;
  write_unlock(&ct_lock);
  while (size >= sizeof(struct pme_result)) {
    struct pme_result *rst = (struct pme_result *) d;
    DPRINTK("match rst:%d\n", rst->type);
    if (rst->type == PMP_SimpleMatchType_e) {
      write_lock(&ct_lock);
      if (master_conntrack->layer7.tag == PME_NO_MATCH_RESULT_TAG)
	master_conntrack->layer7.tag = rst->tag;
      DPRINTK("match rst: tag %x\n", rst->tag);
      /*
       * update stat
       */
      if (idx == -1) {		/* new entry */
	if (_l7pm_stat_buf[_l7pm_stat_idx].sIp ||
	    _l7pm_stat_buf[_l7pm_stat_idx].dIp ||
	    _l7pm_stat_buf[_l7pm_stat_idx].sPort ||
	    _l7pm_stat_buf[_l7pm_stat_idx].dPort) {
	  _l7pm_stat_idx++;
	  _l7pm_stat_idx %= N_L7PM_STAT;
	}
	idx = _l7pm_stat_idx;
	if (_l7pm_stat_num < N_L7PM_STAT)
	  _l7pm_stat_num++;
	_l7pm_stat_buf[idx].sIp = ctx->sIp;
	_l7pm_stat_buf[idx].dIp = ctx->dIp;
	_l7pm_stat_buf[idx].sPort = ctx->sPort;
	_l7pm_stat_buf[idx].dPort = ctx->dPort;
	_l7pm_stat_buf[idx].proto = ctx->proto;
	_l7pm_stat_buf[idx].nMatch = 0;
      }
      for (i = 0; i < _l7pm_stat_buf[idx].nMatch; i++) {
	if (_l7pm_stat_buf[idx].tags[i] == rst->tag)
	  break;
      }
      if (_l7pm_stat_buf[idx].nMatch < 8 && i == _l7pm_stat_buf[idx].nMatch)
	_l7pm_stat_buf[idx].tags[_l7pm_stat_buf[idx].nMatch++] = rst->tag;
      write_unlock(&ct_lock);
    }
    d += sizeof(struct pme_result);
    size -= sizeof(struct pme_result);
  }
  if (need_free)
    kfree(data);
out:
  write_lock(&ct_lock);
  master_conntrack->layer7.num_skb--;
  if (master_conntrack->layer7.num_skb == 0 && (ctx->proto != IPPROTO_TCP ||
		master_conntrack->layer7.tag != PME_NO_MATCH_RESULT_TAG)) {
#ifdef NON_BLOCKING_PME_CTX_CREATE
    pme_ctx = (struct pme_context *) master_conntrack->layer7.userctx;
    DPRINTK("pme_context_delete %p\n", pme_ctx);
    pme_context_delete(pme_ctx);
    n_pme_ctx--;
    module_put(THIS_MODULE);
    master_conntrack->layer7.userctx = 0;
#endif
  }
  write_unlock(&ct_lock);
  if (fb_output)
    pme_fbchain_recycle(fb_output);
#ifndef COPY_DATA
  /*
   * if(ctx->skb->list == 0)
   */
  /*
   * kfree_skb(ctx->skb);
   */
#endif
  kfree(ctx);
  return 0;
}

/*
 * Returns true on match and false otherwise.
 */
static int
match(struct sk_buff *skb,
      const struct net_device *in,
      const struct net_device *out,
      const struct xt_match *match,
      const void *matchinfo, int offset, unsigned int protooff, int *hotdrop)
{
#ifdef COPY_DATA
  int i;
#endif
  struct ipt_l7pm_info *info = (struct ipt_l7pm_info *) matchinfo;
  enum ip_conntrack_info master_ctinfo, ctinfo;
  struct nf_conn *master_conntrack, *conntrack;
  unsigned char *app_data, *ptr;
  unsigned int pattern_result, appdatalen;
  /*
   * my ctx
   */
  struct pme_ctx *ctx;
  /*
   * pme data structure
   */
  struct pme_context *pme_ctx;
#ifdef NON_BLOCKING_PME_CTX_CREATE
  struct pme_channel *pme_chan;
  struct pme_parameters pme_params;
#endif
  struct pme_data dd_input = {.type = data_in_normal, .flags = 0 };
  struct pme_context_callback cb = {.completion = pme_scan_done, .ctx =
      {.words = {(unsigned long) skb} }
  };
  struct pme_data dd_scan = {.type = data_out_normal, .flags = 0 };

  DPRINTK("match: info=%s, skb=%p, seen=%d, tag=%lx set=%x\n",
	  info->protocol, skb, SKB_L7PM_SEEN(skb), info->tag, info->set);
  if (!can_handle(skb)) {
    DPRINTK("l7pm: This is some protocol I can't handle.\n");
    return info->invert;
  }
  /*
   * Treat parent & all its children together as one connection, except
   * for the purpose of setting conntrack->layer7.app_proto in the
   * actual connection. This makes /proc/net/ip_conntrack more
   * satisfying.
   */
  conntrack = nf_ct_get((struct sk_buff *) skb, &ctinfo);
  master_conntrack = nf_ct_get((struct sk_buff *) skb, &master_ctinfo);
  if (!(conntrack) || !(master_conntrack)) {
    DPRINTK("l7pm: packet is not from a known connection, giving up.\n");
    return info->invert;
  }
  /*
   * Try to get a master conntrack (and its master etc) for FTP, etc.
   */
  while (master_ct(master_conntrack) != NULL)
    master_conntrack = master_ct(master_conntrack);
  DPRINTK("detect conntrack: %p %p, pme_ctx %p\n", master_conntrack,
	  conntrack, master_conntrack->layer7.userctx);
  pme_ctx = (struct pme_context *) master_conntrack->layer7.userctx;
  /*
   * init conntrack layer7 attr
   */
#if 0
  if (pme_ctx == 0 && master_conntrack->layer7.tag == PME_NO_MATCH_RESULT_TAG) {
    write_lock(&ct_lock);
    master_conntrack->layer7.tag = PME_NO_MATCH_RESULT_TAG;
    master_conntrack->layer7.num_skb = 0;
    write_unlock(&ct_lock);
  }
#endif
  /*
   * if we've classified it or seen too many packets
   */
  /*
   * num_packets = 99;
   */
  if (master_conntrack->layer7.tag != PME_NO_MATCH_RESULT_TAG ||
      (TOTAL_PACKETS(master_conntrack) > num_packets
       && master_conntrack->layer7.num_skb == 0)) {
    DPRINTK("total_pkt %lld (max %d), tag=%x\n",
	    TOTAL_PACKETS(master_conntrack), num_packets,
	    master_conntrack->layer7.tag);
    pattern_result = match_result(conntrack, master_conntrack, info);
    return pattern_result ^ info->invert;
  }
  /*
   * saw this pkt but no pme result come back yet
   */
  if (SKB_L7PM_SEEN(skb)
      || TOTAL_PACKETS(master_conntrack) > num_packets) {
    return info->invert;
  }
  /*
   * mark it as seen pkt
   */
  SKB_L7PM_SEEN(skb) = 1;
  /*
   * check if any l7 data in skb
   */
  if (skb_is_nonlinear(skb)) {
    if (skb_linearize(skb) != 0) {
      if (net_ratelimit())
	printk(KERN_ERR "l7pm: failed to linearize packet, bailing.\n");
      return info->invert;
    }
    DPRINTK("match: skb_linearize %p\n", skb);
  }
  /*
   * now that the skb is linearized, it's safe to set these.
   */
  app_data = skb->data + app_data_offset(skb);
  appdatalen = skb->tail - app_data;
  /*
   * any l7 data?
   */
  DPRINTK("match: appdatalen %d\n", appdatalen);
  if (appdatalen == 0)
    return info->invert;
  DPRINTK("match: skb %d\n", skb->tail - skb->data);
#if 1
  for (ptr = skb->data, i = 0; i < skb->tail - skb->data; i++)
    DPRINTK("%02x", ptr[i]);
  DPRINTK("\n");
#endif
  /*
   * On the first packet of a connection, create pme ctx etc.
   */
  if (pme_ctx == 0) {
#ifdef NON_BLOCKING_PME_CTX_CREATE
    /*
     * prepare for the use of PME on first arrive l7 data
     */
    int rc;
    /*
     * prepare pme ctx
     */
    pme_chan = pmchan[cur_pmchan++];
    cur_pmchan %= num_pmchan;	/* round robin channels */
    pme_params.flags =
      PME_PARAM_SET | PME_PARAM_MODE | PME_PARAM_SUBSET |
      PME_PARAM_DONT_SLEEP | PME_PARAM_SESSION_ID |
      PME_PARAM_REPORT_VERBOSITY | PME_PARAM_END_OF_SUI_ENABLE;
    pme_params.pattern_set = info->set;
    pme_params.pattern_subset = 0xffff;
    pme_params.session_id = 1;	/* (uint32_t) master_conntrack; 
				 * session id has something to do
				 * with sre ctx numbers */
    pme_params.mode =
      (SKB_NH_PROTOCOL(skb) ==
       IPPROTO_TCP) ? PME_MODE_PASSTHRU_SCAN_RESIDUE : PME_MODE_PASSTHRU_SCAN;
    pme_params.end_of_sui_enable = 0;
    pme_params.report_verbosity = 0;
    rc = pme_context_create(&pme_ctx, pme_chan, &pme_params, 0ll, 1ll,
			    GFP_ATOMIC, 0, 0);
    DPRINTK("pme_context_create %p\n", pme_ctx);
    if (rc) {
      printk(KERN_ERR "l7pm: failed to create pme ctx. rc=%d\n", rc);
      goto out;
    }
    n_pme_ctx++;
    try_module_get(THIS_MODULE);
    DPRINTK("first pkt: pme_ctx=%p, chan=%p(%d)\n", pme_ctx, pme_chan,
	    cur_pmchan);
#else
    if (cur_pme_ctx_idx >= PME_CTX_POOL_SIZE) {
      printk(KERN_ERR "l7pm: run out of pre allocated pme_ctx.\n");
      goto out;
    }
    pme_ctx = pme_ctx_pool[cur_pme_ctx_idx++];
    DPRINTK("first pkt: pme_ctx=%p\n", pme_ctx);
#endif
    master_conntrack->layer7.userctx = (void *) pme_ctx;
  }
  /*
   * send data to pme
   */
#ifdef COPY_DATA
  ctx = kmalloc(sizeof(struct pme_ctx) + appdatalen + 1,
			       GFP_ATOMIC);
  if (!ctx) {
    printk(KERN_ERR "l7pm: allocate ctx failed\n");
    return info->invert;
  }
  for (i = 0; i < appdatalen; i++)
    ctx->data[i] = app_data[i];
  ptr = ctx->data;
#else
  ctx = kmalloc(sizeof(struct pme_ctx), GFP_ATOMIC);
  if (!ctx) {
    printk(KERN_ERR "l7pm: allocate ctx failed\n");
    return info->invert;
  }
  ctx->skb = skb_get(skb);
  ptr = app_data;
  DPRINTK("match: skb=%p\n", ctx->skb);
#endif
  ctx->master_conntrack = master_conntrack;
  {
    struct udphdr _udph;
    struct udphdr *th =
      skb_header_pointer(skb, SKB_NH_IHL(skb) * 4, sizeof(_udph),
			 &_udph);
    ctx->proto = SKB_NH_PROTOCOL(skb);
    ctx->sIp = SKB_NH_SADDR(skb);
    ctx->dIp = SKB_NH_DADDR(skb);
    if (th) {
      ctx->sPort = th->source;
      ctx->dPort = th->dest;
    } else {
      ctx->sPort = 0;
      ctx->dPort = 0;
    }
    ctx->result = result_buf;
    ctx->result_len = result_len;
  }
  write_lock(&ct_lock);
  master_conntrack->layer7.num_skb++;
  write_unlock(&ct_lock);
  dd_input.addr = DMA_MAP_SINGLE(ptr, appdatalen, DMA_TO_DEVICE);
  dd_input.size = dd_input.length = appdatalen;
  dd_scan.addr = DMA_MAP_SINGLE(result_buf, result_len, DMA_FROM_DEVICE);
  dd_scan.size = dd_scan.length = result_len;
  cb.ctx.words[0] = (u32) ctx;
  DPRINTK("pme result buffers result=%p, mappedPtr=%d\n", result_buf,
	  dd_scan.addr);
  DPRINTK
    ("pme_ctx=%p, dd_input=%p, cb=%p, dd_scan=%p, skb=%p, ctx=%p, data=%p\n",
     pme_ctx, &dd_input, &cb, &dd_scan, skb, ctx, ptr);
  do_gettimeofday(&ctx->timestamp);
  DPRINTK("match: ship %d data to pme\n", appdatalen);
#if 1
  for (i = 0; i < appdatalen; i++)
    DPRINTK("%02x", ptr[i]);
  DPRINTK("\n");
#endif
  if (pme_context_io_cmd
      (pme_ctx, PME_FLAG_POLL, &cb, &dd_input, NULL, &dd_scan)) {
    printk(KERN_ERR "l7pm: failed to pme_context_io_cmd: num_skb=%d\n",
	   master_conntrack->layer7.num_skb);
    write_lock(&ct_lock);
    master_conntrack->layer7.num_skb--;
    /*
     * dbg = 1;
     */
    write_unlock(&ct_lock);
    kfree(ctx);
#ifndef COPY_DATA
    /*
     * if(skb->list == 0)
     */
    /*
     * kfree_skb(skb);
     */
#endif
  }
out:
  /*
   * since we won't get result from pme here yet, just return unmatch
   * for now
   */
  /*
   * the match result will be returned for the following pkt after the
   * pme result comes back
   */
  return info->invert;
}

static int
checkentry(const char *tablename,
	   const void *inf,
	   const struct xt_match *match,
	   void *matchinfo, unsigned int hook_mask)
{
  DPRINTK("ipt_l7pm: checkentry\n");
  if (nf_ct_l3proto_try_module_get(match->family) < 0) {
    printk(KERN_WARNING "can't load conntrack support for proto=%d\n",
	   match->family);
    return 0;
  }
  return 1;
}

static void
destroy(const struct xt_match *match, void *matchinfo)
{
  nf_ct_l3proto_module_put(match->family);
}


static struct xt_match l7pm_match[] = {
  {
   .name = "l7pm",
   .family = AF_INET,
   .checkentry = checkentry,
   .match = match,
   .destroy = destroy,
   .matchsize = sizeof(struct ipt_l7pm_info),
   .me = THIS_MODULE}
};

/*
 * taken from drivers/video/modedb.c
 */
static int
my_atoi(const char *s)
{
  int val = 0;

  for (;; s++) {
    switch (*s) {
    case '0'...'9':
      val = 10 * val + (*s - '0');
      break;
    default:
      return val;
    }
  }
}

/*
 * write out num_packets to userland.
 */
static int
l7pm_read_proc(char *page, char **start, off_t off, int count,
	       int *eof, void *data)
{
  DPRINTK("ipt_l7pm: read_proc\n");
  if (num_packets > 99 && net_ratelimit())
    printk(KERN_ERR "l7pm: NOT REACHED. num_packets too big\n");

  page[0] = num_packets / 10 + '0';
  page[1] = num_packets % 10 + '0';
  page[2] = '\n';
  page[3] = '\0';

  *eof = 1;

  return 3;
}

/*
 * Read in num_packets from userland
 */
static int
l7pm_write_proc(struct file *file, const char *buffer,
		unsigned long count, void *data)
{
  char *foo = kmalloc(count, GFP_ATOMIC);
  DPRINTK("ipt_l7pm: write_proc\n");

  if (!foo) {
    if (net_ratelimit())
      printk(KERN_ERR
	     "l7pm: out of memory, bailing. num_packets unchanged.\n");
    return count;
  }

  if (copy_from_user(foo, buffer, count))
    return -EFAULT;


  num_packets = my_atoi(foo);
  kfree(foo);

  /*
   * This has an arbitrary limit to make the math easier. I'm lazy. But
   * anyway, 99 is a LOT! If you want more, you're doing it wrong!
   */
  if (num_packets > 99) {
    printk(KERN_WARNING "l7pm: num_packets can't be > 99.\n");
    num_packets = 99;
  } else if (num_packets < 1) {
    printk(KERN_WARNING "l7pm: num_packets can't be < 1.\n");
    num_packets = 1;
  }

  return count;
}

static int
l7pm_stat_read_proc(char *page, char **start, off_t off, int count,
		    int *eof, void *data)
{
  int len = 0;
  int i, s, idx, j;
  if (_l7pm_stat_num < N_L7PM_STAT)
    s = 0;
  else
    s = (_l7pm_stat_idx + 1) % N_L7PM_STAT;
#ifdef CONFIG_IP_NF_MATCH_L7PM_DEBUG
  len =
    sprintf(page,
		"total result %d, pme_ctx_in_use %d, "
		"max_delay %uus, min_delay %uus\n",
		_l7pm_stat_num, n_pme_ctx, max_delay, min_delay);
#else
  len =
    sprintf(page, "total result %d, pme_ctx_in_use %d\n",
	    _l7pm_stat_num, n_pme_ctx);
#endif
  len += sprintf(page + len, "saddr\t\tdaddr\t\tproto\tsport\tdport\ttags\n");
  for (i = 0; i < _l7pm_stat_num; i++) {
    idx = (i + s) % N_L7PM_STAT;
    len +=
      sprintf(page + len, "%08x\t%08x\t%d\t%d\t%d\t",
	      _l7pm_stat_buf[idx].sIp, _l7pm_stat_buf[idx].dIp,
	      _l7pm_stat_buf[idx].proto, _l7pm_stat_buf[idx].sPort,
	      _l7pm_stat_buf[idx].dPort);
    for (j = 0; j < _l7pm_stat_buf[idx].nMatch; j++)
      len += sprintf(page + len, "%08x\t", _l7pm_stat_buf[idx].tags[j]);
    len += sprintf(page + len, "\n");
  }
  page[len] = 0;
  *eof = 1;
  return len;
}

static int
l7pm_stat_write_proc(struct file *file, const char *buffer,
		     unsigned long count, void *data)
{
  /*
   * reset
   */
  _l7pm_stat_num = 0;
  _l7pm_stat_idx = 0;
  max_delay = 0;
  min_delay = 0xffffffff;
  return count;
}

#ifdef CONFIG_IP_NF_MATCH_L7PM_DEBUG
static int
l7pm_dbg_read_proc(char *page, char **start, off_t off, int count,
		   int *eof, void *data)
{
  int len;
  if (dbg)
    len = sprintf(page, "dbg = on\n");
  else
    len = sprintf(page, "dbg = off\n");
  *eof = 1;
  return len;
}

static int
l7pm_dbg_write_proc(struct file *file, const char *buffer,
		    unsigned long count, void *data)
{
  /*
   * reset
   */
  dbg ^= 1;
  return count;
}
#endif
/*
 * register the proc file
 */
static void
l7pm_init_proc(void)
{
  struct proc_dir_entry *entry;
  DPRINTK("ipt_l7pm: init_proc\n");
  result_buf = kmalloc(1024, GFP_KERNEL);
  DPRINTK("result_ptr: %p", result_buf);
  entry = create_proc_entry("l7pm_numpackets", 0644, init_net.proc_net);
  entry->read_proc = l7pm_read_proc;
  entry->write_proc = l7pm_write_proc;
  entry = create_proc_entry("l7pm_stat", 0644, init_net.proc_net);
  entry->read_proc = l7pm_stat_read_proc;
  entry->write_proc = l7pm_stat_write_proc;
#ifdef CONFIG_IP_NF_MATCH_L7PM_DEBUG
  entry = create_proc_entry("l7pm_dbg", 0644, init_net.proc_net);
  entry->read_proc = l7pm_dbg_read_proc;
  entry->write_proc = l7pm_dbg_write_proc;
#endif
}

static void
l7pm_cleanup_proc(void)
{
  DPRINTK("ipt_l7pm: cleanup_proc\n");
  remove_proc_entry("l7pm_numpackets", init_net.proc_net);
  remove_proc_entry("l7pm_stat", init_net.proc_net);
#ifdef CONFIG_IP_NF_MATCH_L7PM_DEBUG
  remove_proc_entry("l7pm_dbg", init_net.proc_net);
#endif
}

static int __init
init(void)
{
  int i;
  struct pme_channel *chan;
#ifndef NON_BLOCKING_PME_CTX_CREATE
  int rc;
  struct pme_context *pme_ctx;
  struct pme_parameters pme_params;
#endif

  DPRINTK("ipt_l7pm: init\n");

  need_conntrack();

  /*
   * freescale pm channel
   */
  if (use_pmchan == -1) {
    for (i = 0; i < 4; i++) {
      if (pme_channel_get(&chan, i) == 0)
	pmchan[num_pmchan++] = chan;
    }
    if (num_pmchan == 0) {
      printk(KERN_WARNING "no pm channel found\n");
      return -ENODEV;
    }
  } else {
    /*
     * use specific channel
     */
    if (pme_channel_get(&chan, use_pmchan) == 0) {
      pmchan[num_pmchan++] = chan;
    } else {
      printk(KERN_WARNING "pm channel %d not found\n", use_pmchan);
      return -ENODEV;
    }
  }
  cur_pmchan = 0;
#ifndef NON_BLOCKING_PME_CTX_CREATE
  /*
   * prepare pme ctx
   */
  for (i = 0; i < PME_CTX_POOL_SIZE; i++) {
    chan = pmchan[i % num_pmchan];
    pme_params.flags =
      PME_PARAM_SET | PME_PARAM_MODE | PME_PARAM_SUBSET |
      PME_PARAM_SESSION_ID | PME_PARAM_REPORT_VERBOSITY |
      PME_PARAM_END_OF_SUI_ENABLE;
    pme_params.pattern_set = 0xb7;
    pme_params.pattern_subset = 0xffff;
    pme_params.session_id = 0;
    pme_params.mode = PME_MODE_PASSTHRU_SCAN_RESIDUE;
    pme_params.end_of_sui_enable = 0;
    pme_params.report_verbosity = 0;
    rc = pme_context_create(&pme_ctx, chan, &pme_params, 0ll, 1ll,
			    GFP_ATOMIC, 0, 0);
    if (rc) {
      printk(KERN_ERR "l7pm: failed to create pme ctx. rc=%d\n", rc);
      return -ENODEV;
    }
    pme_ctx_pool[i] = pme_ctx;
  }
#endif
  l7pm_init_proc();
  return xt_register_matches(l7pm_match, ARRAY_SIZE(l7pm_match));
}

static void __exit
fini(void)
{
  int i;

  DPRINTK("ipt_l7pm: fini\n");
#ifndef NON_BLOCKING_PME_CTX_CREATE
  for (i = 0; i < PME_CTX_POOL_SIZE; i++) {
    if (pme_ctx_pool[i])
      pme_context_delete(pme_ctx_pool[i]);
  }
#endif
  for (i = 0; i < num_pmchan; i++)
    pme_channel_put(pmchan[i]);
  l7pm_cleanup_proc();
  kfree(result_buf);
  xt_unregister_matches(l7pm_match, ARRAY_SIZE(l7pm_match));
}

module_init(init);
module_exit(fini);
