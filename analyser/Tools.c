#include"generStruct.h"
#include<pcap.h>
#include"generStruct.h"
struct flowInfo constructBaseInfo(u_int srcIP,u_int dstIP,u_short src_port,u_short dst_port){
	struct flowInfo baseInfo;
	baseInfo.srcIP=srcIP;baseInfo.dstIP=dstIP;
	baseInfo.srcPort=src_port;baseInfo.dstPort=dst_port;
	return baseInfo;
}
