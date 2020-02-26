/* for io_module_func def'ns */
#include "io_module.h"
/* for mtcp related def'ns */
#include "mtcp.h"
/* for errno */
#include <errno.h>
/* for close/optind */
#include <unistd.h>
/* for logging */
#include "debug.h"
/* for num_devices_* */
#include "config.h"
/* for rte_max_eth_ports */
#include <rte_common.h>
/* for rte_eth_rxconf */
#include <rte_ethdev.h>
/* for delay funcs */
#include <rte_cycles.h>
/* for ip pesudo-chksum */
#include <rte_ip.h>
#define ENABLE_STATS_IOCTL		1
#ifdef ENABLE_STATS_IOCTL
/* for open */
#include <fcntl.h>
/* for ioctl */
#include <sys/ioctl.h>
#endif /* !ENABLE_STATS_IOCTL */

/* for onvm rings */
#include <onvm_nflib.h>
#include <onvm_pkt_helper.h>

#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
//#define DBG_PKT
#ifdef DBG_PKT
static int total_send = 0, total_recv = 0;
#endif

/*----------------------------------------------------------------------------*/
//#define RX_IDLE_ENABLE			1
#define RX_IDLE_TIMEOUT			1	/* in micro-seconds */
#define RX_IDLE_THRESH			64

#define MAX_PKT_BURST			32/*64*//*128*//*32*/
/*----------------------------------------------------------------------------*/
/* packet memory pools for storing packet bufs */
static struct rte_mempool *pktmbuf_pool = NULL;

struct mbuf_table {
	unsigned len; /* length of queued packets */
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct dpdk_private_context {
	struct mbuf_table rmbufs[RTE_MAX_ETHPORTS];
	struct mbuf_table wmbufs[RTE_MAX_ETHPORTS];
	struct rte_mempool *pktmbuf_pool;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
#ifdef RX_IDLE_ENABLE
	uint8_t rx_idle;
#endif
#ifdef ENABLE_STATS_IOCTL
	int fd;
#endif /* !ENABLE_STATS_IOCTL */
} __rte_cache_aligned;

/* onvm structs */
struct onvm_args {
	uint8_t action;
	uint16_t destination;
};
struct onvm_args onvm_nf_args;
struct onvm_nf_info *nf_info;
struct rte_ring *onvm_rx_ring;
struct rte_ring *onvm_tx_ring;
volatile struct client_tx_stats *onvm_tx_stats;

#ifdef ENABLE_STATS_IOCTL
/**
 * stats struct passed on from user space to the driver
 */
struct stats_struct {
	uint64_t tx_bytes;
	uint64_t tx_pkts;
	uint64_t rx_bytes;
	uint64_t rx_pkts;
	uint8_t qid;
	uint8_t dev;
};
#endif /* !ENABLE_STATS_IOCTL */
/*----------------------------------------------------------------------------*/
void
onvm_init_handle(struct mtcp_thread_context *ctxt)
{
	struct dpdk_private_context *dpc;
	int i, j;
	char mempool_name[20];

	/* create and initialize private I/O module context */
	ctxt->io_private_context = calloc(1, sizeof(struct dpdk_private_context));
	if (ctxt->io_private_context == NULL) {
		TRACE_ERROR("Failed to initialize ctxt->io_private_context: "
			    "Can't allocate memory\n");
		exit(EXIT_FAILURE);
	}
	
	sprintf(mempool_name, "mbuf_pool-%d", ctxt->cpu);
	dpc = (struct dpdk_private_context *)ctxt->io_private_context;
	dpc->pktmbuf_pool = pktmbuf_pool;
	
	/* Complete onvm handshake */
	onvm_nflib_nf_ready(nf_info);

	/* Initialize onvm rings*/
	onvm_rx_ring = onvm_nflib_get_rx_ring(nf_info);
	onvm_tx_ring = onvm_nflib_get_tx_ring(nf_info);
	onvm_tx_stats = onvm_nflib_get_tx_stats(nf_info);	

	/* set wmbufs correctly */
	for (j = 0; j < g_config.mos->netdev_table->num; j++) {
		/* Allocate wmbufs for each registered port */
		for (i = 0; i < MAX_PKT_BURST; i++) {
			dpc->wmbufs[j].m_table[i] = rte_pktmbuf_alloc(pktmbuf_pool);
			if (dpc->wmbufs[j].m_table[i] == NULL) {
				TRACE_ERROR("Failed to allocate %d:wmbuf[%d] on device %d!\n",
					    ctxt->cpu, i, j);
				exit(EXIT_FAILURE);
			}
		}

		/* set mbufs queue length to 0 to begin with */
		dpc->wmbufs[j].len = 0;
	}

#ifdef ENABLE_STATS_IOCTL
	dpc->fd = open("/dev/dpdk-iface", O_RDWR);
	if (dpc->fd == -1) {
		TRACE_ERROR("Can't open /dev/dpdk-iface for context->cpu: %d! "
			    "Are you using mlx4/mlx5 driver?\n",
			    ctxt->cpu);
	}
#endif /* !ENABLE_STATS_IOCTL */
}
/*----------------------------------------------------------------------------*/
int
onvm_send_pkts(struct mtcp_thread_context *ctxt, int nif)
{
	struct dpdk_private_context *dpc;
	int ret;
	struct onvm_pkt_meta* meta;
	int i;
	
	dpc = (struct dpdk_private_context *)ctxt->io_private_context;
	ret = 0;

	/* if there are packets in the queue... flush them out to the wire */
	if (dpc->wmbufs[nif].len >/*= MAX_PKT_BURST*/ 0) {
		struct rte_mbuf **pkts;
#ifdef NETSTAT
#ifdef ENABLE_STATS_IOCTL
		struct stats_struct ss;
#endif /* !ENABLE_STATS_IOCTL */
#endif
		int cnt = dpc->wmbufs[nif].len;
		pkts = dpc->wmbufs[nif].m_table;
#ifdef NETSTAT
		mtcp_manager_t mtcp;
		mtcp = ctxt->mtcp_manager;
		mtcp->nstat.tx_packets[nif] += cnt;
#ifdef ENABLE_STATS_IOCTL
		if (likely(dpc->fd) >= 0) {
			ss.tx_pkts = mtcp->nstat.tx_packets[nif];
			ss.tx_bytes = mtcp->nstat.tx_bytes[nif];
			ss.rx_pkts = mtcp->nstat.rx_packets[nif];
			ss.rx_bytes = mtcp->nstat.rx_bytes[nif];
			ss.qid = ctxt->cpu;
			ss.dev = nif;
			ioctl(dpc->fd, 0, &ss);
		}
#endif /* !ENABLE_STATS_IOCTL */
#endif
		for (i = 0; i < cnt; i++) {
			/* fix port information */
			if (pkts[i]->port == 255) {
				if (g_config.mos->nic_forward_table != NULL)
					pkts[i]->port = g_config.mos->nic_forward_table->nic_fwd_table[nif];
				if (pkts[i]->port == 255)
					printf("Could not fix port information!\n");
			}
			meta = onvm_get_pkt_meta(pkts[i]);
			meta->action = onvm_nf_args.action;
			if (meta->action == ONVM_NF_ACTION_TONF) {
				meta->destination = onvm_nf_args.destination;
			}
			else if (meta->action == ONVM_NF_ACTION_OUT) {
				meta->destination = nif;
			}
			else meta->destination = 0;
#ifdef DBG_PKT
			printf("total_send: %d core: %d\n", total_send++, rte_lcore_id());
			printf("send_pkts_0: buf: %d %p, buf_len: %u, port: %d %p nif: %d nif_index: %d nb_seg: %d ol_flags: %llu wtable_len: %d rtable_len: %d\n", i, pkts[i], pkts[i]->pkt_len, pkts[i]->port, &(pkts[i]->port), nif, g_config.mos->netdev_table->ent[nif]->ifindex, pkts[i]->nb_segs, (unsigned long long)pkts[i]->ol_flags, cnt, dpc->rmbufs[nif].len);//grace
#endif
		}
		ret = rte_ring_enqueue_bulk(onvm_tx_ring, (void * const*)pkts, cnt);
		if (cnt > 0 && ret == -ENOBUFS) {
			TRACE_ERROR("Dropped %d packets\n",ret);
		}
		onvm_tx_stats->tx[nf_info->instance_id] += cnt;

#ifndef SHARE_IO_BUFFER
		int i;
		/* time to allocate fresh mbufs for the queue */
		for (i = 0; i < dpc->wmbufs[nif].len; i++) {
			dpc->wmbufs[nif].m_table[i] = rte_pktmbuf_alloc(pktmbuf_pool);
			/* error checking */
			if (unlikely(dpc->wmbufs[nif].m_table[i] == NULL)) {
				TRACE_ERROR("Failed to allocate %d:wmbuf[%d] on device %d!\n",
					    ctxt->cpu, i, nif);
				exit(EXIT_FAILURE);
			}
		}
#endif
		/* reset the len of mbufs var after flushing of packets */
		dpc->wmbufs[nif].len = 0;
#ifdef DBG_PKT
		if (cnt) printf("send_pkts: wtable_len: %d rtable_len: %d ret: %d\n\n", dpc->wmbufs[nif].len, dpc->rmbufs[nif].len, ret);//grace
#endif
	}
	
	return ret;
}
/*----------------------------------------------------------------------------*/
uint8_t *
onvm_get_wptr(struct mtcp_thread_context *ctxt, int nif, uint16_t pktsize)
{
	struct dpdk_private_context *dpc;
	struct rte_mbuf *m;
	uint8_t *ptr;
	int len_of_mbuf;

	dpc = (struct dpdk_private_context *) ctxt->io_private_context;
	
	/* sanity check */
	if (unlikely(dpc->wmbufs[nif].len == MAX_PKT_BURST))
		return NULL;

	len_of_mbuf = dpc->wmbufs[nif].len;
	m = dpc->wmbufs[nif].m_table[len_of_mbuf];
#ifdef DBG_PKT
	printf("get_wptr_0: buf_len: %u, port: %d %p nb_seg: %d, nif: %d wtable_len: %d rtable_len: %d\n", m->pkt_len, m->port, &(m->port), m->nb_segs, nif, len_of_mbuf, dpc->rmbufs[nif].len); //grace
#endif
	/* retrieve the right write offset */
	ptr = (void *)rte_pktmbuf_mtod(m, struct ether_hdr *);
	m->pkt_len = m->data_len = pktsize;
	m->nb_segs = 1;
	m->next = NULL;

#ifdef NETSTAT
	mtcp_manager_t mtcp;
	mtcp = ctxt->mtcp_manager;
	mtcp->nstat.tx_bytes[nif] += pktsize + ETHER_OVR;
#endif
	
	/* increment the len_of_mbuf var */
	dpc->wmbufs[nif].len = len_of_mbuf + 1;
#ifdef DBG_PKT
	printf("get_wptr: buf_len: %u, port: %d %p nb_seg: %d wtable_len:%d rtable_len:%d\n", m->pkt_len, m->port, &(m->port), m->nb_segs, dpc->wmbufs[nif].len, dpc->rmbufs[nif].len);//grace
#endif
	return (uint8_t *)ptr;
}
/*----------------------------------------------------------------------------*/
void
onvm_set_wptr(struct mtcp_thread_context *ctxt, int out_nif, int in_nif, int index)
{
	struct dpdk_private_context *dpc;
	int len_of_mbuf;

	dpc = (struct dpdk_private_context *) ctxt->io_private_context;
	
	/* sanity check */
	if (unlikely(dpc->wmbufs[out_nif].len == MAX_PKT_BURST))
		return;
#ifdef DBG_PKT
	printf("set_wptr_0: out_nif:%d (wtable:%d rtable:%d) in_nif:%d (wtable:%d rtable:%d) index: %d\n", out_nif, dpc->wmbufs[out_nif].len, dpc->rmbufs[out_nif].len, in_nif, dpc->wmbufs[in_nif].len, dpc->rmbufs[in_nif].len, index);//grace
#endif
	len_of_mbuf = dpc->wmbufs[out_nif].len;
	dpc->wmbufs[out_nif].m_table[len_of_mbuf] = 
		dpc->rmbufs[in_nif].m_table[index];
#ifdef DBG_PKT
	printf("set_wptr_1: buf: %d %p\n", index, dpc->rmbufs[in_nif].m_table[index]);
#endif
	dpc->wmbufs[out_nif].m_table[len_of_mbuf]->udata64 = 0;
	
#ifdef NETSTAT
	mtcp_manager_t mtcp;
	mtcp = ctxt->mtcp_manager;
	mtcp->nstat.tx_bytes[out_nif] += dpc->rmbufs[in_nif].m_table[index]->pkt_len + ETHER_OVR;
#endif
	
	/* increment the len_of_mbuf var */
	dpc->wmbufs[out_nif].len = len_of_mbuf + 1;
	
	return;
}
/*----------------------------------------------------------------------------*/
static inline void
free_pkts(struct rte_mbuf **mtable, unsigned len)
{
	int i;
	
	/* free the freaking packets */
	for (i = 0; i < len; i++) {
		if (mtable[i]->udata64 == 1) {
			rte_pktmbuf_free_seg(mtable[i]);
			RTE_MBUF_PREFETCH_TO_FREE(mtable[i+1]);
		}
	}
}
/*----------------------------------------------------------------------------*/
int32_t
onvm_recv_pkts(struct mtcp_thread_context *ctxt, int if_num)
{
	struct dpdk_private_context *dpc;
	struct rte_mbuf *pkts[MAX_PKT_BURST];
	int ret;
	int i;

	dpc = (struct dpdk_private_context *) ctxt->io_private_context;
	for (i = 0; i < if_num; i++) {
		if (dpc->rmbufs[i].len != 0) {
#ifndef SHARE_IO_BUFFER
			free_pkts(dpc->rmbufs[i].m_table, dpc->rmbufs[i].len);
#endif
#ifdef DBG_PKT
			printf("recv_pkts_0: ifnum: %d ifidx: %d rtalbe_len: %d wtable_len: %d\n", if_num, i, dpc->rmbufs[i].len, dpc->wmbufs[i].len);
#endif
			dpc->rmbufs[i].len = 0;
		}
	}

	ret = rte_ring_dequeue_burst(onvm_rx_ring, (void **) pkts, MAX_PKT_BURST);
	for (i = 0; i < ret; i++) {
		dpc->pkts_burst[i] = pkts[i];
#ifdef DBG_PKT
		printf("total_recv: %d\n", total_recv++);
		printf("recv_pkt_1 total: %d buf: %d %p, buf_len: %u, port: %d %p nb_segs: %d ol_flags: %llu\n", ret, i, pkts[i], pkts[i]->pkt_len, pkts[i]->port, &(pkts[i]->port), pkts[i]->nb_segs, (unsigned long long)pkts[i]->ol_flags);//grace
#endif
	}

#ifdef RX_IDLE_ENABLE
	dpc->rx_idle = (likely(ret != 0)) ? 0 : dpc->rx_idle + 1;
#endif
	return ret;
}
/*----------------------------------------------------------------------------*/
uint8_t *
onvm_get_rptr(struct mtcp_thread_context *ctxt, long ifidx, int index, uint16_t *len)
{
	struct dpdk_private_context *dpc;
	struct rte_mbuf *m;
	uint8_t *pktbuf;
	int *ifidx_addr = (int *)(long)ifidx;
	int len_of_mbuf;

	dpc = (struct dpdk_private_context *) ctxt->io_private_context;	
	m = dpc->pkts_burst[index];
#ifdef DBG_PKT
	printf("get_rptr_0: ifidx: %d (rtalbe:%d wtable:%d) pkt_idx: %d\n", m->port, dpc->rmbufs[m->port].len, dpc->wmbufs[m->port].len, index);
#endif
	/* tag to check if the packet is a local or a forwarded pkt */
	m->udata64 = 1;
	/* don't enable pre-fetching... performance goes down */
	//rte_prefetch0(rte_pktmbuf_mtod(m, void *));
	*len = m->pkt_len;
	pktbuf = rte_pktmbuf_mtod(m, uint8_t *);

	/* fill in_port information */
	*ifidx_addr = m->port;

	/* get current rmbuf len */
	len_of_mbuf = dpc->rmbufs[*ifidx_addr].len;
 
	/* enqueue the pkt ptr in mbuf */
	dpc->rmbufs[*ifidx_addr].m_table[len_of_mbuf] = m;

	/* update the length of rmbuf */
	dpc->rmbufs[*ifidx_addr].len = len_of_mbuf + 1;
#ifdef DBG_PKT
	printf("get_rptr_1: buf_len: %u, port: %d %p, ifidx: %d (rtalbe_len:%d wtable_len:%d)\n", m->pkt_len, m->port, &(m->port), *ifidx_addr, dpc->rmbufs[*ifidx_addr].len, dpc->wmbufs[*ifidx_addr].len);//grace
#endif
	return pktbuf;
}
/*----------------------------------------------------------------------------*/
int
onvm_get_nif(struct ifreq *ifr)
{
	int i;
	static int num_dev = -1;
	static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
	/* get mac addr entries of 'detected' dpdk ports */
	if (num_dev < 0) {
		num_dev = rte_eth_dev_count();
		for (i = 0; i < num_dev; i++)
			rte_eth_macaddr_get(i, &ports_eth_addr[i]);
	}

	for (i = 0; i < num_dev; i++)
		if (!memcmp(&ifr->ifr_addr.sa_data[0], &ports_eth_addr[i], ETH_ALEN))
			return i;

	return -1;
}
/*----------------------------------------------------------------------------*/
int32_t
onvm_select(struct mtcp_thread_context *ctxt)
{
#ifdef RX_IDLE_ENABLE
	struct dpdk_private_context *dpc;
	
	dpc = (struct dpdk_private_context *) ctxt->io_private_context;
	if (dpc->rx_idle > RX_IDLE_THRESH) {
		dpc->rx_idle = 0;
		usleep(RX_IDLE_TIMEOUT);
	}
#endif
	return 0;
}
/*----------------------------------------------------------------------------*/
void
onvm_destroy_handle(struct mtcp_thread_context *ctxt)
{
	struct dpdk_private_context *dpc;
	int i;

	dpc = (struct dpdk_private_context *) ctxt->io_private_context;	

	/* free wmbufs */
	for (i = 0; i < g_config.mos->netdev_table->num; i++)
		free_pkts(dpc->wmbufs[i].m_table, MAX_PKT_BURST);

#ifdef ENABLE_STATS_IOCTL
	/* free fd */
	if (dpc->fd >= 0)
		close(dpc->fd);
#endif /* !ENABLE_STATS_IOCTL */

	/* free it all up */
	free(dpc);
}
/*----------------------------------------------------------------------------*/
int32_t
onvm_dev_ioctl(struct mtcp_thread_context *ctx, int nif, int cmd, void *argp)
{
	struct dpdk_private_context *dpc;
	struct rte_mbuf *m;
	int len_of_mbuf;
	struct iphdr *iph;
	struct tcphdr *tcph;
	RssInfo *rss_i;

	iph = (struct iphdr *)argp;
	dpc = (struct dpdk_private_context *)ctx->io_private_context;
	len_of_mbuf = dpc->wmbufs[nif].len;
	rss_i = NULL;

	switch (cmd) {
	case PKT_TX_IP_CSUM:
		m = dpc->wmbufs[nif].m_table[len_of_mbuf - 1];
		m->ol_flags = PKT_TX_IP_CKSUM | PKT_TX_IPV4;
		m->l2_len = sizeof(struct ether_hdr);
		m->l3_len = (iph->ihl<<2);
		break;
	case PKT_TX_TCP_CSUM:
		m = dpc->wmbufs[nif].m_table[len_of_mbuf - 1];
		tcph = (struct tcphdr *)((unsigned char *)iph + (iph->ihl<<2));
		m->ol_flags |= PKT_TX_TCP_CKSUM;
		tcph->check = rte_ipv4_phdr_cksum((struct ipv4_hdr *)iph, m->ol_flags);
		break;
	case PKT_RX_RSS:
		rss_i = (RssInfo *)argp;
		m = dpc->pkts_burst[rss_i->pktidx];
		rss_i->hash_value = m->hash.rss;
		break;
	default:
		goto dev_ioctl_err;
	}

	return 0;
 dev_ioctl_err:
	return -1;
}
/*----------------------------------------------------------------------------*/
static void
onvm_conf_print(struct onvm_args *args, struct onvm_nf_info *info)
{
	printf("===== ONVM configuration =====\n");
	printf("| service:       %d\n", info->service_id);
	printf("| instance:      %d\n", info->instance_id);
	printf("| action:   	 %d\n",	args->action);
	printf("| destionation:  %d\n",args->destination);
	printf("\n");
}

void
onvm_load_module_upper_half(void)
{
	int cpu = g_config.mos->num_cores, ret;
	uint32_t cpumask = 0;
	char cpumaskbuf[10];
	char mem_channels[5];

	/* set the log level */
	rte_set_log_type(RTE_LOGTYPE_PMD, 0);
	rte_set_log_type(RTE_LOGTYPE_MALLOC, 0);
	rte_set_log_type(RTE_LOGTYPE_MEMPOOL, 0);
	rte_set_log_type(RTE_LOGTYPE_RING, 0);
	rte_set_log_level(RTE_LOG_WARNING);
	
	/* get the cpu mask */
	for (ret = 0; ret < cpu; ret++)
		cpumask = (cpumask | (1 << ret));
	sprintf(cpumaskbuf, "%X", cpumask);

	/* get the mem channels per socket */
	if (g_config.mos->nb_mem_channels == 0) {
		TRACE_ERROR("DPDK module requires # of memory channels "
				"per socket parameter!\n");
		exit(EXIT_FAILURE);
	}
	sprintf(mem_channels, "%d", g_config.mos->nb_mem_channels);

	struct conf_block *first_item = (struct conf_block *)TAILQ_FIRST(&g_config.app_blkh);
	struct app_conf * const appconf = (struct app_conf *)first_item->conf;
	char *service = appconf->app_argv[3];
	char *instance = appconf->app_argv[4];
	onvm_nf_args.action = (uint8_t)atoi(appconf->app_argv[5]);
	onvm_nf_args.destination = (uint16_t)atoi(appconf->app_argv[6]);
		
	/* initialize the rte env first, what a waste of implementation effort!  */
	char *argv[] = {"", 
			"-c", 
			cpumaskbuf, 
			"-n", 
			mem_channels,
			"--proc-type=auto",
			"--",
			"-r",
			service,
			instance,
			""
	};
	const int argc = 10;

	/* 
	 * re-set getopt extern variable optind.
	 * this issue was a bitch to debug
	 * rte_eal_init() internally uses getopt() syscall
	 * mtcp applications that also use an `external' getopt
	 * will cause a violent crash if optind is not reset to zero
	 * prior to calling the func below...
	 * see man getopt(3) for more details
	 */
	optind = 0;

	ret = onvm_nflib_init(argc, argv, "tcp_nf");
	onvm_conf_print(&onvm_nf_args, nf_info);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL args!\n");

}
/*----------------------------------------------------------------------------*/
void
onvm_load_module_lower_half(void)
{
	pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
	if (pktmbuf_pool == NULL){
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");	
	}
}
/*----------------------------------------------------------------------------*/
io_module_func onvm_module_func = {
	.load_module_upper_half	   = onvm_load_module_upper_half,
	.load_module_lower_half    = onvm_load_module_lower_half,
	.init_handle		   = onvm_init_handle,
	.link_devices		   = NULL,
	.release_pkt		   = NULL,
	.send_pkts		   = onvm_send_pkts,
	.get_wptr   		   = onvm_get_wptr,
	.recv_pkts		   = onvm_recv_pkts,
	.get_rptr	   	   = onvm_get_rptr,
	.get_nif		   = onvm_get_nif,
	.select			   = onvm_select,
	.destroy_handle		   = onvm_destroy_handle,
	.dev_ioctl		   = onvm_dev_ioctl,
	.set_wptr		   = onvm_set_wptr,
};
/*----------------------------------------------------------------------------*/
