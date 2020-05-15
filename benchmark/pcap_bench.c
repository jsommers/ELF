/*
 * pcap clone benchmark code for host 2 (cml1)
 */
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sched.h>
#include <errno.h>

int done = false;
pcap_t *pdev = NULL;

void sighandler(int s) {
    pcap_breakloop(pdev);
    done = true;
}

pcap_t *create_pcap_device(char *devname) {
    printf("Creating pcap dev for %s\n", devname);
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcapdev = pcap_create(devname, ebuf);
    if (pcapdev == NULL) {
        printf("Error creating pcap device: %s\n", ebuf);
        return NULL;
    }

    if (pcap_set_snaplen(pcapdev, 128) < 0) {
        printf("Error setting snaplen: %s\n", ebuf);
        return NULL;
    }
    if (pcap_set_buffer_size(pcapdev, 4096) < 0) {
        printf("Error setting buffer size: %s\n", ebuf);
        return NULL;
    }
    if (pcap_set_timeout(pcapdev, 0) < 0) {
        printf("Error setting timeout: %s\n", ebuf);
        return NULL;
    }
    if (pcap_set_immediate_mode(pcapdev, 1) < 0) {
        printf("Error setting immediate mode: %s\n", ebuf);
        return NULL;
    }
    if (pcap_activate(pcapdev) < 0) {
        printf("Error activating pcap device: %s\n", ebuf);
        return NULL;
    }
    return pcapdev;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("usage: %s <indev> <outdev>\n", argv[0]);
        return -1;
    }

    pid_t pid = getpid();

    cpu_set_t cpuset;
    cpu_set_t newset;
    CPU_ZERO(&cpuset);
    CPU_ZERO(&newset);
    int sv = sched_getaffinity(pid, sizeof(cpuset), &cpuset);
    if (sv < 0) {
        printf("getaffinity failed: %s\n", strerror(errno));
    }
    int i = 2;
    for (; i < CPU_COUNT(&cpuset); i++) {
        if (CPU_ISSET(i, &cpuset)) {
            printf("Using CPU %d\n", i);
            CPU_SET(i, &newset);
            break;
        }
    }
    sv = sched_setaffinity(pid, sizeof(newset), &newset);
    if (sv < 0) {
        printf("setaffinity failed: %s\n", strerror(errno));
    }

    signal(SIGINT, sighandler);

    pcap_t *inputpcap = create_pcap_device(argv[1]);
    pcap_t *outputpcap = create_pcap_device(argv[2]);
    if (!inputpcap || !outputpcap) {
        printf("error initializing pcap devices\n");
        return -1;
    }
    pdev = inputpcap; // set global pcap dev

    // hard-coded src/dst MAC addrs to overwrite
    unsigned char srcmac[] = {0xb8, 0x2a, 0x72, 0xe0, 0xf0, 0x78};
    unsigned char dstmac[] = {0xb8, 0x2a, 0x72, 0xe0, 0xf0, 0x88};

    struct pcap_pkthdr *phdr = NULL;
    const u_char *pdata = NULL;
    printf("Going into pcap loop\n");
    // sit in loop until ctrl^c
    while (!done) {
        int rv = pcap_next_ex(inputpcap, &phdr, &pdata);
        // printf("pkt %ld.%06ld caplen %d len %d\n", phdr->ts.tv_sec, phdr->ts.tv_usec, phdr->caplen, phdr->len);

        struct ether_header *eth = (struct ether_header *)pdata;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
            continue;
        }

        if (phdr->caplen >= ETH_HLEN + sizeof(struct iphdr)) {
            struct iphdr *iph = (struct iphdr*)(pdata + ETH_HLEN);
            // printf("orig ttl %d\n", iph->ttl);

            // traffic of interest is UDP port 9
            if (iph->protocol != IPPROTO_UDP) {
                continue;
            }

            unsigned int iphlen = iph->ihl << 2;
            if (phdr->caplen < ETH_HLEN + iphlen + sizeof(struct udphdr)) {
                continue;
            }

            struct udphdr *udph = (struct udphdr *)(pdata + ETH_HLEN + iphlen);
            if (ntohs(udph->uh_dport) != 9) {
                continue;
            }

            unsigned int *offset = (unsigned int *)((void*)pdata + ETH_HLEN + iphlen + 12);
            unsigned int seq = *offset;
            seq = ntohl(seq);
            if (seq % 100 != 0) {
                continue;
            }

            // modify ethernet mac addresses
            memcpy(eth->ether_shost, srcmac, ETH_ALEN);
            memcpy(eth->ether_dhost, dstmac, ETH_ALEN);

            uint32_t ttldiff = ((uint32_t)iph->ttl - 3) << 8;
            iph->ttl = 3;
            uint32_t tmp = (uint32_t)ntohs(iph->check) + ttldiff;
            // printf("tmp1 0x%0x\n", tmp);
            if (tmp > 65535) {
                tmp -= 65535;
            }
            uint16_t newcheck = htons(tmp);
            // printf("tmp2 0x%0x\n", newcheck);
            iph->check = newcheck;
            int outbytes = pcap_inject(outputpcap, pdata, phdr->caplen);
            if (outbytes < phdr->caplen) {
                printf("wrote fewer than expected %d bytes vs %d\n", outbytes, phdr->caplen);
            }
            // printf("wrote %d bytes newttl %d\n", outbytes, iph->ttl);
        }
    }
    struct pcap_stat ps;
    pcap_stats(inputpcap, &ps);
    printf("input recv %d drop %d ifdrop %d\n", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);

    pcap_stats(outputpcap, &ps);
    printf("output recv %d drop %d ifdrop %d\n", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);

    pcap_close(inputpcap);
    pcap_close(outputpcap);
}

