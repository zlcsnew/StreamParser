#ifndef _GENERSTRUCT
#define _GENERSTRUCT
#include <pcap.h>
struct flowInfo{
	u_int srcIP,dstIP;
	u_short srcPort,dstPort;
};
struct flowInfo constructBaseInfo(u_int srcIP,u_int dstIP,u_short src_port,u_short dst_port);
#endif
