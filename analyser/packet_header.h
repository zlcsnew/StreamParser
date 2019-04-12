#ifndef _PACKET_HEADER
#define _PACKET_HEADER
#include <arpa/inet.h>
int MAC_HEADER_LEN=14;
int TCP_HEADER_LEN=20;
struct ip_header {
    u_char  ver_len;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_flag_off;                 /* fragment offset field */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_pro;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    u_int ip_src;  /* source and dest address */
    u_int ip_dst;
};

struct tcp_header {
    u_short sport;               /* source port */
    u_short dport;               /* destination port */
    u_int seqNum;                 /* sequence number */
    u_int ackNum;                 /* acknowledgement number */
    u_char  headerLen_reserved;               /* data offset, rsvd */
    u_char  flags;
    u_short win;                 /* window */
    u_short checkSum;                 /* checksum */
    u_short urp;                 /* urgent pointer */
};

#endif
