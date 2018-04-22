/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// modified from Bond, exception_path, rxtxcallbacks examples.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_arp.h>

#define PRINT_MAC(addr)		printf("%02"PRIx8":%02"PRIx8":%02"PRIx8 \
		":%02"PRIx8":%02"PRIx8":%02"PRIx8,	\
		addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2], \
		addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5])
#define PRINT_IP(ip)       printf("%d.%d.%d.%d",  \
        (ip & 0xFF), (ip >> 8 & 0xFF), (ip >> 16 & 0xFF), (ip >> 24 & 0xFF))

	// bond_ip = BOND_IP_1 | (BOND_IP_2 << 8) |
	// 			(BOND_IP_3 << 16) | (BOND_IP_4 << 24);

/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1
#define FATAL_ERROR(fmt, args...)       rte_exit(EXIT_FAILURE, fmt "\n", ##args)
#define PRINT_INFO(fmt, args...)        RTE_LOG(INFO, APP, fmt "\n", ##args)

/* Max size of a single packet */
#define MAX_PACKET_SZ (2048)

/* Size of the data buffer in each mbuf */
#define MBUF_DATA_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
#define NB_MBUF                 8192

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            32

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ        PKT_BURST_SZ
/* Mempool for mbufs */
static struct rte_mempool * pktmbuf_pool = NULL;


uint32_t BOND_IP_1=	10;
uint32_t BOND_IP_2=	0;
uint32_t BOND_IP_3=	0;
uint32_t BOND_IP_4=	254;

/*
 * Create a tap network interface, or use existing one with same name.
 * If name[0]='\0' then a name is automatically assigned and returned in name.
 */
static int tap_create(char *name)
{
	struct ifreq ifr;
	int fd, ret;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
		return fd;

	memset(&ifr, 0, sizeof(ifr));

	/* TAP device without packet information */
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (name && *name)
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);

	ret = ioctl(fd, TUNSETIFF, (void *) &ifr);
	if (ret < 0) {
		close(fd);
		return ret;
	}

	if (name)
		snprintf(name, IFNAMSIZ, "%s", ifr.ifr_name);

	return fd;
}

//*
static inline size_t
get_vlan_offset(struct ether_hdr *eth_hdr, uint16_t *proto)
{
	size_t vlan_offset = 0;

	if (rte_cpu_to_be_16(ETHER_TYPE_VLAN) == *proto) {
		struct vlan_hdr *vlan_hdr = (struct vlan_hdr *)(eth_hdr + 1);

		vlan_offset = sizeof(struct vlan_hdr);
		*proto = vlan_hdr->eth_proto;

		if (rte_cpu_to_be_16(ETHER_TYPE_VLAN) == *proto) {
			vlan_hdr = vlan_hdr + 1;

			*proto = vlan_hdr->eth_proto;
			vlan_offset += sizeof(struct vlan_hdr);
		}
	}
	return vlan_offset;
}

static int
lcore_main(__attribute__((unused)) void *arg)
{
	const unsigned lcore_id = rte_lcore_id();
	char tap0_name[IFNAMSIZ];
	int tap0_fd;
	char tap1_name[IFNAMSIZ];
	int tap1_fd;

	
	struct ether_hdr *eth_hdr;
	struct arp_hdr *arp_hdr;
	uint16_t ether_type, offset;
    struct  ether_addr tmp_mac_add;

    tmp_mac_add.addr_bytes[0]= 6;
    tmp_mac_add.addr_bytes[1]= 5;
    tmp_mac_add.addr_bytes[2]= 4;
    tmp_mac_add.addr_bytes[3]= 3;
    tmp_mac_add.addr_bytes[4]= 2;
    tmp_mac_add.addr_bytes[5]= 1; //lsb

    uint32_t tmp_ip =  BOND_IP_1 | (BOND_IP_2 << 8) | (BOND_IP_3 << 16) | (BOND_IP_4 << 24);

	printf("Starting lcore_main on core %d Our IP:%d.%d.%d.%d\n",lcore_id,
		BOND_IP_1,
		BOND_IP_2,
		BOND_IP_3,
		BOND_IP_4
	);
	
	PRINT_MAC(tmp_mac_add);
	printf("\n ");	

	/* Create new tap interface */
	snprintf(tap0_name, IFNAMSIZ, "tap_dpdk_%.2u", 0);
	tap0_fd = tap_create(tap0_name);
	if (tap0_fd < 0)
		FATAL_ERROR("Could not create tap interface \"%s\" (%d)",
				tap0_name, tap0_fd);

	fflush(stdout);
	/* Create new tap interface */
	snprintf(tap1_name, IFNAMSIZ, "tap_dpdk_%.2u", 1);
	tap1_fd = tap_create(tap1_name);
	if (tap1_fd < 0)
		FATAL_ERROR("Could not create tap interface \"%s\" (%d)",
				tap1_name, tap1_fd);

	PRINT_INFO("Lcore %u is reading from %s and writing to %s",
	           lcore_id, tap0_name, tap1_name);
	fflush(stdout);


	/* Loop forever reading from NIC and writing to tap */
	for (;;) {

		int ret;
		struct rte_mbuf *m = rte_pktmbuf_alloc(pktmbuf_pool);
		if (m == NULL)
			continue;

		ret = read(tap0_fd, rte_pktmbuf_mtod(m, void *),
			MAX_PACKET_SZ);

		if (unlikely(ret < 0)) {
			FATAL_ERROR("Reading from %s interface failed",
			            tap0_name);
		}
			//*
		    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);//*
		    ether_type = eth_hdr->ether_type;//*
		   // printf("ethtype: %u\n", ether_type);

			if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN))
				printf("VLAN taged frame, offset:");
			offset = get_vlan_offset(eth_hdr, &ether_type);				
			if (offset > 0)
				printf("%d\n", offset);

			if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP)) {

				arp_hdr = (struct arp_hdr *)((char *)(eth_hdr + 1) + offset);
				
				if (arp_hdr->arp_op == rte_cpu_to_be_16(ARP_OP_REQUEST)) {

					// printf("ARP req\n s_addr: ");
					// PRINT_MAC(eth_hdr->s_addr);
					// printf(" d_addr: ");PRINT_MAC(eth_hdr->d_addr);
					// printf("arp_sip: "); 
					// PRINT_IP(arp_hdr->arp_data.arp_sip);
					// printf(", arp_tip: ");
					// PRINT_IP(arp_hdr->arp_data.arp_tip);
					// printf("\n");


					arp_hdr->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
					/* Switch src and dst data and set bonding MAC */
					tmp_mac_add.addr_bytes[0]= 6;
					tmp_mac_add.addr_bytes[1]= 5;
					tmp_mac_add.addr_bytes[2]= 4;
					tmp_mac_add.addr_bytes[3]= 3;
					tmp_mac_add.addr_bytes[4]= 2;
					tmp_mac_add.addr_bytes[5]= 1; //lsb

                    //s_addr, d_addr
					ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
					ether_addr_copy(&tmp_mac_add, &eth_hdr->s_addr);


                    //  
					tmp_mac_add.addr_bytes[0]= 0 ;
					tmp_mac_add.addr_bytes[1]= 0 ;
					tmp_mac_add.addr_bytes[2]= 0 ;
					tmp_mac_add.addr_bytes[3]= 0 ;
					tmp_mac_add.addr_bytes[4]= 0 ;
					tmp_mac_add.addr_bytes[5]= (arp_hdr->arp_data.arp_tip >> 24 & 0xFF);

					ether_addr_copy(&arp_hdr->arp_data.arp_sha, &arp_hdr->arp_data.arp_tha);
					ether_addr_copy(&tmp_mac_add, &arp_hdr->arp_data.arp_sha);

                    tmp_ip = arp_hdr->arp_data.arp_tip;
					arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;					
					arp_hdr->arp_data.arp_sip = tmp_ip;					


					// printf("ARP Reply..");
					// printf("s_addr: ");
					// PRINT_MAC(eth_hdr->s_addr);
					// printf(" d_addr: ");PRINT_MAC(eth_hdr->d_addr);

					// printf("arp_sha: ");PRINT_MAC(arp_hdr->arp_data.arp_sha);
					// printf("arp_tha: ");PRINT_MAC(arp_hdr->arp_data.arp_tha);

					// printf("arp_sip: "); 
					// PRINT_IP(arp_hdr->arp_data.arp_sip);
					// printf(", arp_tip: ");
					// PRINT_IP(arp_hdr->arp_data.arp_tip);
					// printf("\n");


					//*
					/* Ignore return val from write() */
					m->nb_segs = 1;
					m->next = NULL;
					m->pkt_len = (uint16_t)ret;
					m->data_len = (uint16_t)ret;				
				    ret = write(tap1_fd,
					                rte_pktmbuf_mtod(m, void*),
					                rte_pktmbuf_data_len(m));
                    fflush(stdout);
					// rte_pktmbuf_free(m);
					if (unlikely(ret < 0))
						printf("dropped :(\n");						
				}
				else if(arp_hdr->arp_op == rte_cpu_to_be_16(ARP_OP_REPLY)) {
					uint64_t now = rte_rdtsc();					
					struct timeval  tv;
					gettimeofday(&tv, NULL);
					double time_in_micro = (tv.tv_sec) * 1000000 + tv.tv_usec ;

					printf("%" PRIu64 " %.3f Drop ARP Reply**..", now, time_in_micro );
					printf("s_addr: ");
					PRINT_MAC(eth_hdr->s_addr);
					printf(" d_addr: ");PRINT_MAC(eth_hdr->d_addr);

					printf("arp_sha: ");PRINT_MAC(arp_hdr->arp_data.arp_sha);
					printf("arp_tha: ");PRINT_MAC(arp_hdr->arp_data.arp_tha);

					printf("arp_sip: "); 
					PRINT_IP(arp_hdr->arp_data.arp_sip);
					printf(", arp_tip: ");
					PRINT_IP(arp_hdr->arp_data.arp_tip);
					printf("\n");			
				}											
			} 			
            // else if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
            // }
	    rte_pktmbuf_free(m);

		//*
		// /* Ignore return val from write() */
		// m->nb_segs = 1;
		// m->next = NULL;
		// m->pkt_len = (uint16_t)ret;
		// m->data_len = (uint16_t)ret;				
	 //    ret = write(tap0_fd,
		//                 rte_pktmbuf_mtod(m, void*),
		//                 rte_pktmbuf_data_len(m));

		// rte_pktmbuf_free(m);
		// if (unlikely(ret < 0))
		// 	printf("dropped :(\n");
		// else
		// 	printf("TX :) \n");
		//}
	}

	/*
	 * Tap file is closed automatically when program exits. Putting close()
	 * here will cause the compiler to give an error about unreachable code.
	 */
}

int
main(int argc, char **argv)
{
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");


	/* Create the mbuf pool */
	pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
			MEMPOOL_CACHE_SZ, 0, MBUF_DATA_SZ, rte_socket_id());
	if (pktmbuf_pool == NULL) {
		FATAL_ERROR("Could not initialise mbuf pool");
		return -1;
	}

	/* call lcore_hello() on every slave lcore */
	// RTE_LCORE_FOREACH_SLAVE(lcore_id) {
	// 	rte_eal_remote_launch(lcore_main, NULL, lcore_id);
	// }

	/* call it on master lcore too */
	lcore_main(NULL);

    // The following code is equivalent and simpler:
    // http://dpdk.org/doc/guides/sample_app_ug/hello_world.html
    // rte_eal_mp_remote_launch(lcore_hello, NULL, CALL_MASTER);

	rte_eal_mp_wait_lcore();
	return 0;
}
