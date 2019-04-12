#include"functions.h"
#include"packet_header.h"
#include"generStruct.h"
#include"TLSStruct.h"
#include"HTTPStruct.h"
#include<stdio.h>
#include<pcap.h>
#include<netinet/in.h>
static int number=0;
void packet_process(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet){
	u_char * packet_index=packet+MAC_HEADER_LEN-2;
	u_short l3_pro= ntohs(*(u_short *)packet_index);
        number++;
	if(l3_pro!=0x0800)
		return;
	u_char * l3_index=packet_index+2;
	struct ip_header * IP=(struct ip_header *)l3_index;
	u_int srcIP=IP->ip_src,dstIP=IP->ip_dst;
	u_short IP_header_len=((IP->ver_len)&0x0F)*4;
	u_short l4Len=ntohs(IP->ip_len)-IP_header_len;
	u_char * l4_index=l3_index+IP_header_len;
	struct tcp_header * tcp=(struct tcp_header *)l4_index;	
	u_short src_port=ntohs(tcp->sport),dst_port=ntohs(tcp->dport);
        u_char headerLen=((tcp->headerLen_reserved&0xF0)>>4)*4;
	if ((src_port==443||dst_port==443)&&l4Len>headerLen){
		struct flowInfo baseInfo=constructBaseInfo(srcIP,dstIP,src_port,dst_port);               
		TLS_process(baseInfo,l4_index+headerLen);		
	}else if((dst_port==80)&&l4Len>headerLen){
		struct flowInfo baseInfo=constructBaseInfo(srcIP,dstIP,src_port,dst_port);    
		HTTP_process(baseInfo,l4_index+headerLen,l4Len-headerLen);
	}
}

void TLS_process(struct flowInfo baseInfo,u_char * application_data){
	int posi=getTLSPosi(baseInfo);
	int status=getTLSStatus(posi);
	if(status==1)
		return;
	struct SSL_header * index=(struct SSL_header *)application_data;
	if(index->protro!=22)
	    return;
	struct TLS_HeaderShake *hs_index=application_data+sizeof(struct SSL_header);
        u_char flag=hs_index->Type;
        char * next_index=application_data+sizeof(struct SSL_header)+sizeof(struct TLS_HeaderShake);
	if (flag==1&&((status&1)==0))
	    if (TLSClientInfo(posi,(u_char *)next_index))
		    printf("增加ClientHello信息成功\n");
        /*if(index==11&&((status&2)==0))
	    if (TLSCertInfo(posi,index+4))
		    printf("增加Cert信息成功\n");*/
	return;
}

void HTTP_process(struct flowInfo baseInfo,u_char * application_data,int length){
	int posi=getHTTPPosi(baseInfo);
	HTTP_Process(posi,application_data,length);
}
