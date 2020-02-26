#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <asm/byteorder.h>
#include <assert.h>
#include <signal.h>
#include <sys/queue.h>
#include <errno.h>

#include <mos_api.h>
#include "cpu.h"

#define ONVM

/* test overheads of different callbacks */
#define CB_CNT
//#define CB_PKT
//#define CB_FLOW

/* Maximum CPU cores */
#define MAX_CORES 		16
/* Number of TCP flags to monitor */
#define NUM_FLAG 		6
/* Default path to mOS configuration file */
#define MOS_CONFIG_FILE		"config/mos.conf"

//#define TIME_STAT
#ifdef TIME_STAT
#include "app_stat.h"
struct stat_counter stat_cb_cnt, stat_cb_content, stat_cb_flow_content;
#endif
uint64_t alert_cnt = 0;

/*----------------------------------------------------------------------------*/
/* Global variables */
int g_max_cores;                              /* Number of CPU cores to be used */
mctx_t g_mctx[MAX_CORES];                     /* mOS context */
//uint64_t g_cli_cnt = 0, g_svr_cnt = 0;
uint64_t g_svr_cnt = 0, g_cli_cnt = 0;
#ifdef ONVM
int g_run_core;
#endif
/*----------------------------------------------------------------------------*/
/* Signal handler */
static void
sigint_handler(int signum)
{
#ifdef ONVM
		mtcp_destroy_context(g_mctx[g_run_core]);
#else
	int i;

	/* Terminate the program if any interrupt happens */
	for (i = 0; i < g_max_cores; i++)
		mtcp_destroy_context(g_mctx[i]);
#endif
}
/*----------------------------------------------------------------------------*/
/* Print ongoing connection information based on connection structure */
static void
cb_printstat(mctx_t mctx, int sock, int side,
				  uint64_t events, filter_arg_t *arg)
{
	struct timeval tv_1sec = { /* 1 second */
		.tv_sec = 1,
		.tv_usec = 0
	};

	#ifdef TIME_STAT
	printf ("Total Pkts: Client: %llu, Server: %llu\n", (unsigned long long)g_cli_cnt, (unsigned long long)g_svr_cnt );
	printf("Callback_Time: (avg (cycles), max (cycles)) "
			"cb_cnt: (%4lu, %4lu), "
			"cb_content: (%4lu, %4lu), "
			"cb_flow_content: (%4lu, %4lu)\n",
			GetAverageStat(&stat_cb_cnt), stat_cb_cnt.max,
			GetAverageStat(&stat_cb_content), stat_cb_content.max,
			GetAverageStat(&stat_cb_flow_content), stat_cb_flow_content.max);
	InitStatCounter(&stat_cb_cnt);
	InitStatCounter(&stat_cb_content);
	InitStatCounter(&stat_cb_flow_content);
	#endif

	//printf("APP_Info: alert_cnt: %4lu\n", alert_cnt);

	/* Set a timer for next printing */
	if (mtcp_settimer(mctx, sock, &tv_1sec, cb_printstat)) {
		fprintf(stderr, "Failed to register print timer\n");
		exit(-1); /* no point in proceeding if the timer is broken */
	}

	return;
}
/*----------------------------------------------------------------------------*/
/* Update connection's TCP pkt count */
#ifdef CB_CNT
static void
cb_pkt_cnt(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	#ifdef TIME_STAT
	unsigned long long start_tsc = rdtscll();
	#endif	

	if (side == MOS_SIDE_SVR) g_svr_cnt++;
	else if (side == MOS_SIDE_CLI) g_cli_cnt++;
	//g_svr_cnt++;

	#ifdef TIME_STAT
	UpdateStatCounter(&stat_cb_cnt,	rdtscll() - start_tsc);	
	#endif	
}
#endif
/*----------------------------------------------------------------------------*/
#ifdef CB_PKT
/* Check connection's TCP pkt payload */
static void
cb_pkt_content(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	#ifdef TIME_STAT
	unsigned long long start_tsc = rdtscll();
	#endif	
	struct pkt_info pi;
	const char pattern[10] = "123";
	char *ret = NULL;

	if (mtcp_getlastpkt(mctx, sock, side, &pi) < 0) {
		fprintf(stderr, "Failed to get packet context\n");
		exit(-1); /* no point in proceeding if the timer is broken */
	}

	//printf("len: %d, %s\n", pi.payloadlen, pi.payload);
	ret = strstr((char *)pi.payload, pattern); 
	if (ret != NULL) {
		//printf("Find pattern: %s, alert: %d\n", ret, alert_cnt);
		alert_cnt++;
	}

	#ifdef TIME_STAT
	UpdateStatCounter(&stat_cb_content, rdtscll() - start_tsc);	
	#endif	
}
#endif
/*----------------------------------------------------------------------------*/
/* Check connection's TCP assembled payload */
#ifdef CB_FLOW
static void
cb_flow_content(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	#ifdef TIME_STAT
	unsigned long long start_tsc = rdtscll();
	#endif	
	struct pkt_info pi;
	char read_buf[1500];
	const char pattern[10] = "123";
	char *ret = NULL;
	int rt;

	if (mtcp_getlastpkt(mctx, sock, side, &pi) < 0) {
		fprintf(stderr, "Failed to get packet context\n");
		exit(-1); /* no point in proceeding if the timer is broken */
	}

	rt = mtcp_peek(mctx, sock, side, read_buf, pi.payloadlen);
	//rt = mtcp_ppeek(mctx, sock, side, read_buf, pi.payloadlen, pi.offset);
	if (rt > 0) {
		//printf("rt %d, read_buf: %s len: %d offset: %llu\n", rt, read_buf, pi.payloadlen, (unsigned long long)pi.offset);
		ret = strstr((char *)read_buf, pattern);
		if (ret != NULL) {
			printf("Find pattern: %s, alert: %ld\n", ret, alert_cnt);
			alert_cnt++;
		}
	}

	#ifdef TIME_STAT
	UpdateStatCounter(&stat_cb_flow_content, rdtscll() - start_tsc);	
	#endif	
}
#endif
/*----------------------------------------------------------------------------*/
/* Register required callbacks */
static void
RegisterCallbacks(mctx_t mctx, int sock, event_t ev_new_syn)
{
	struct timeval tv_1sec = { /* 1 second */
		.tv_sec = 1,
		.tv_usec = 0
	};

	#ifdef TIME_STAT
	InitStatCounter(&stat_cb_cnt);
	InitStatCounter(&stat_cb_content);
	InitStatCounter(&stat_cb_flow_content);
	#endif

#ifdef CB_CNT
	/* Register callbacks */
	if (mtcp_register_callback(mctx, sock, MOS_ON_PKT_IN,
				   MOS_HK_RCV, cb_pkt_cnt)) {
		fprintf(stderr, "Failed to register cb_pkt_cnt()\n");
		exit(-1); 
	}
#endif
#ifdef CB_PKT
	if (mtcp_register_callback(mctx, sock, MOS_ON_PKT_IN,
				   MOS_HK_RCV, cb_pkt_content)) {
		fprintf(stderr, "Failed to register cb_pkt_cnt()\n");
		exit(-1); 

	}
#endif
#ifdef CB_FLOW
	if (mtcp_register_callback(mctx, sock, MOS_ON_PKT_IN,
				   MOS_HK_RCV, cb_flow_content)) {
		fprintf(stderr, "Failed to register cb_pkt_cnt()\n");
		exit(-1); 

	}
#endif
	/* CPU 0 is in charge of printing stats */
	if (mctx->cpu == 0 &&
		mtcp_settimer(mctx, sock, &tv_1sec, cb_printstat)) {
		fprintf(stderr, "Failed to register print timer\n");
		exit(-1); /* no point in proceeding if the titmer is broken*/
	}	
}
/*----------------------------------------------------------------------------*/
/* Open monitoring socket and ready it for monitoring */
static void
InitMonitor(mctx_t mctx, event_t ev_new_syn)
{
	int sock;

	/* create socket and set it as nonblocking */
	if ((sock = mtcp_socket(mctx, AF_INET,
						 MOS_SOCK_MONITOR_STREAM, 0)) < 0) {
		fprintf(stderr, "Failed to create monitor listening socket!\n");
		exit(-1); /* no point in proceeding if we don't have a listening socket */
	}

#if 0
	/* Disable socket buffer */
	int optval = 0;
	if (mtcp_setsockopt(mctx, sock, SOL_MONSOCKET, MOS_CLIBUF,
							   &optval, sizeof(optval)) == -1) {
		fprintf(stderr, "Could not disable CLIBUF!\n");
	}
	if (mtcp_setsockopt(mctx, sock, SOL_MONSOCKET, MOS_SVRBUF,
							   &optval, sizeof(optval)) == -1) {
		fprintf(stderr, "Could not disable SVRBUF!\n");
	}
#endif
	RegisterCallbacks(mctx, sock, ev_new_syn);
}
/*----------------------------------------------------------------------------*/
int 
main(int argc, char **argv)
{
	int opt;
	event_t ev_new_syn;             /* New SYN UDE */
	char *fname = MOS_CONFIG_FILE;  /* path to the default mos config file */
	struct mtcp_conf mcfg;          /* mOS configuration */
#ifndef ONVM	
	int i;
#endif

	/* get the total # of cpu cores */
	g_max_cores = GetNumCPUs();       

	/* Parse command line arguments */
	while ((opt = getopt(argc, argv, "c:f:")) != -1) {
		switch (opt) {
		case 'f':
			fname = optarg;
			break;
		case 'c':
			if (atoi(optarg) > g_max_cores) {
				printf("Available number of CPU cores is %d\n", g_max_cores);
				return -1;
			}
			#ifdef ONVM
			g_run_core = atoi(optarg);
			#else
			g_max_cores = atoi(optarg);
			#endif
			break;
		default:
			printf("Usage: %s [-f mos_config_file] [-c #_of_cpu]\n", argv[0]);
			return 0;
		}
	}

	/* parse mos configuration file */
	if (mtcp_init(fname)) {
		fprintf(stderr, "Failed to initialize mtcp.\n");
		exit(EXIT_FAILURE);
	}
	/* set the core limit */
	mtcp_getconf(&mcfg);
	#ifdef ONVM
	mcfg.num_cores = 1;
	#else
	mcfg.num_cores = g_max_cores;
	#endif
	mtcp_setconf(&mcfg);

	/* Register signal handler */
	mtcp_register_signal(SIGINT, sigint_handler);

#ifdef CB_CNT
	printf("Test callback count pkt\n");
#endif
#ifdef CB_PKT
	printf("Test callback search pkt payload\n");
#endif
#ifdef CB_FLOW
	printf("Test callback search flow payload\n");
#endif

#ifdef ONVM
	printf("ONVM is enabled!\n\n");
	if (!(g_mctx[g_run_core] = mtcp_create_context(g_run_core))) {
		fprintf(stderr, "Failed to craete mtcp context.\n");
		return -1;
	}
	/* init monitor */
	InitMonitor(g_mctx[g_run_core], ev_new_syn);

	/* wait until mOS finishes */
	mtcp_app_join(g_mctx[g_run_core]);
#else
	printf("ONVM is disabled!\n\n");
	for (i = 0; i < g_max_cores; i++) {
		/* Run mOS for each CPU core */
		if (!(g_mctx[i] = mtcp_create_context(i))) {
			fprintf(stderr, "Failed to craete mtcp context.\n");
			return -1;
		}
		/* init monitor */
		InitMonitor(g_mctx[i], ev_new_syn);
	}

	/* wait until mOS finishes */
	for (i = 0; i < g_max_cores; i++)
		mtcp_app_join(g_mctx[i]);
#endif

	mtcp_destroy();
	return 0;
}
/*----------------------------------------------------------------------------*/
