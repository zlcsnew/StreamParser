#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "functions.h"
char fileName[]="../inshot_media.pcap";

int main(){
	struct pcap_pkthdr header;
	struct pcap_pkthdr pack;
	pcap_t *handle;
	char error[100];
        struct bpf_program filter;
	if((handle=pcap_open_offline(fileName,error))==NULL)  //打开文件
    {
        printf("%s\n",error);
        return 0;
    }
        int res=pcap_compile(handle,&filter,"tcp",1,0);
        if (res==-1)
            return 0;
        pcap_setfilter(handle,&filter);
	pcap_loop(handle, 10000, packet_process, NULL);
        showTLSInfo();
}
