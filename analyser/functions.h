#ifndef _FUNCTIONS
#define _FUNCTIONS
#include<pcap.h>
#include"generStruct.h"
void packet_process(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);
//TLS 信息获取
int getTLSPosi(struct flowInfo baseInfo);
void setTLSStatus(int posi,int offset);
int getTLSStatus(int posi);
void showTLSInfo();

//HTTP 信息获取
int getHTTPPosi(struct flowInfo baseInfo);
int getHTTPStatus(int posi);
void setHTTPStatus(int posi,int offset);
void HTTP_Process(int posi,u_char *app_data,int length);
void showHTTPInfo();
#endif
