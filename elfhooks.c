/*
 * elfhooks.c: ELF hooks -- override to add custom code for processing before send, and on receive.
 */
#ifndef __ELFHOOKS_C__
#define __ELFHOOKS_C__

inline int elf_v4_icmp_beforesend(struct __sk_buff *ctx) {
    return 0;
}

inline int elf_v4_tcp_beforesend(struct __sk_buff *ctx) {
    return 0;
}

inline int elf_v4_udp_beforesend(struct __sk_buff *ctx) {
    return 0;
}

inline int elf_v6_icmp_beforesend(struct __sk_buff *ctx) {
    return 0;
}

inline int elf_v6_tcp_beforesend(struct __sk_buff *ctx) {
    return 0;
}

inline int elf_v6_udp_beforesend(struct __sk_buff *ctx) {
    return 0;
}

inline void elf_v4_afterrecv(struct xdp_md *ctx) {
    return;
}

inline void elf_v6_afterrecv(struct xdp_md *ctx) {
    return;
}

#endif
