#include"TLSStruct.h"
#include"generStruct.h"
#include"functions.h"
#include<string.h>
#include<netinet/in.h>
struct TLS_flowInfo TLSArray[1024];
int TLS_flowNum=0;
int baseinfo_compare(struct flowInfo baseInfo,struct flowInfo baseInfo2){
      return (baseInfo.srcIP==baseInfo2.srcIP)&&(baseInfo.dstIP==baseInfo2.dstIP)&&(baseInfo.dstPort==baseInfo2.dstPort)&&(baseInfo.srcPort==baseInfo2.srcPort);
}
int getTLSPosi(struct flowInfo baseInfo){
	int posi=0;
	struct flowInfo baseInfo_reverse;
	baseInfo_reverse.srcIP=baseInfo.dstIP;baseInfo_reverse.dstIP=baseInfo.srcIP;
	baseInfo_reverse.srcPort=baseInfo.dstPort;baseInfo_reverse.dstPort=baseInfo.srcPort;
	for(;posi<TLS_flowNum;posi++){
                if (baseinfo_compare(baseInfo,TLSArray[posi].Baseinfo)||baseinfo_compare(baseInfo_reverse,TLSArray[posi].Baseinfo))
			break;
	}
	if (posi==TLS_flowNum&&posi<1024){
		TLSArray[posi].Baseinfo.srcIP=baseInfo.srcIP;TLSArray[posi].Baseinfo.dstIP=baseInfo.dstIP;
		TLSArray[posi].Baseinfo.srcPort=baseInfo.srcPort;TLSArray[posi].Baseinfo.dstPort=baseInfo.dstPort;
                TLSArray[posi].status=0;
		TLS_flowNum++;
		return posi;
	}
	
	if(posi>=1024){
		return -1;
	}
	
	return posi;
}

int getTLSStatus(int posi){
	return TLSArray[posi].status;
}

void setTLSStatus(int posi,int offset){
	TLSArray[posi].status+=1<<offset;
}

void showTLSInfo(){
     int i=0;
     for(;i<TLS_flowNum;i++){
        if(TLSArray[i].status!=1)
            continue;
        printf("\n\nflow %d\n",i);
        int j=0;
        printf("ciber suit:\n");
        for(;j<TLSArray[i].ciberNum;j++)
            printf("%x  ",TLSArray[i].ciberType[j]);
        printf("\nserver name:\n");
        printf("%s  \n",TLSArray[i].servername);
     }
}


int TLSClientInfo(int posi,u_char * data){
	 struct TLS_HS_HelloClient * index=(struct TLS_HS_HelloClient *)data;
	 TLSArray[posi].ciberNum=ntohs(*((u_short *)index->ciberNum))/2;
	 int ciberNum=TLSArray[posi].ciberNum,i=0;
	 u_short tmp_Type;
	 for(;i<ciberNum;i++){
		 tmp_Type=*((u_short *)(data+sizeof(struct TLS_HS_HelloClient)+i*2));
	     TLSArray[posi].ciberType[i]=ntohs(tmp_Type);
	 }
	 u_char *after_fixed=(u_char *)(data+sizeof(struct TLS_HS_HelloClient)+ciberNum*2);
	 int compression_len=*after_fixed;
         u_short *extern_length=(u_short *)(after_fixed+1+compression_len);
         *extern_length=ntohs(*extern_length);
	 struct ExternsionHeader * extern_index=(struct ExternsionHeader *)(after_fixed+1+compression_len+2);
         u_char * baseIndex=(u_char *)(after_fixed+1+compression_len+2);
         u_short remain_length=0;
         while(remain_length<=(*extern_length)){
             if (extern_index->Type!=0x0000){
                     remain_length+=(ntohs(extern_index->length)+sizeof(struct ExternsionHeader));
                     extern_index=(struct ExternsionHeader *)(baseIndex+remain_length);
                     continue;
             }
             struct ServerName * server=(struct ServerName *)(baseIndex+remain_length+sizeof(struct ExternsionHeader));
             int namelength=ntohs(server->listLength)-3;
             memcpy(TLSArray[posi].servername,
             (u_char *)(baseIndex+remain_length+sizeof(struct ExternsionHeader)+/*sizeof(struct ServerName)*/5),
             namelength);
             TLSArray[posi].servername[namelength]='\0';
             break;
         }
         setTLSStatus(posi,0);	 
         return 1;
}


