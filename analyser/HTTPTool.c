#include"HTTPStruct.h"
#include"generStruct.h"
#include"functions.h"
#include<string.h>
#include<netinet/in.h>
#include<pcap.h>
#include<string.h>
struct HTTP_flowInfo HTTPArray[1024];
int HTTP_flowNum=0;
int baseinfo_compare_HTTP(struct flowInfo baseInfo,struct flowInfo baseInfo2){
      return (baseInfo.srcIP==baseInfo2.srcIP)&&(baseInfo.dstIP==baseInfo2.dstIP)&&(baseInfo.dstPort==baseInfo2.dstPort)&&(baseInfo.srcPort==baseInfo2.srcPort);
}
int getHTTPPosi(struct flowInfo baseInfo){
	int posi=0;
	struct flowInfo baseInfo_reverse;
	baseInfo_reverse.srcIP=baseInfo.dstIP;baseInfo_reverse.dstIP=baseInfo.srcIP;
	baseInfo_reverse.srcPort=baseInfo.dstPort;baseInfo_reverse.dstPort=baseInfo.srcPort;
	for(;posi<HTTP_flowNum;posi++){
         if (baseinfo_compare_HTTP(baseInfo,HTTPArray[posi].Baseinfo)||baseinfo_compare_HTTP(baseInfo_reverse,HTTPArray[posi].Baseinfo))
			  break;
	}
	if (posi==HTTP_flowNum&&posi<1024){
		HTTPArray[posi].Baseinfo.srcIP=baseInfo.srcIP;HTTPArray[posi].Baseinfo.dstIP=baseInfo.dstIP;
		HTTPArray[posi].Baseinfo.srcPort=baseInfo.srcPort;HTTPArray[posi].Baseinfo.dstPort=baseInfo.dstPort;
                HTTPArray[posi].status=0;
                HTTPArray[posi].URL_list_length=0;
                HTTPArray[posi].method_number=0;
		HTTP_flowNum++;
		return posi;
	}
	
	if(posi>=1024){
		return -1;
	}
	
	return posi;
}

int getHTTPStatus(int posi){
	return HTTPArray[posi].status;
}

void setHTTPStatus(int posi,int offset){
	HTTPArray[posi].status+=1<<offset;
}

void showHTTPInfo(){
     int i=0;
     for(;i<HTTP_flowNum;i++){
        if(HTTPArray[i].status!=1)
            continue;
        printf("\n\nflow %d\n",i);
        
     }
}


void HTTP_Process(int posi,u_char *app_data,int data_length){
    app_data[data_length-1]='\0';
    //printf("%s \n",app_data);
    u_char * method=strchr(app_data,' ');
    if (method==NULL)
        return;
    //printf("get method \n");
    u_char * uri=strstr(method,"\r\n");
    if(uri==NULL){
        return;
    }
    int i=0,length=0;
    for(;i<HTTPArray[posi].URL_list_length;i++){
        if ((strncmp(HTTPArray[posi].URI_list[i],method,uri-method)==0)
        &&(strncmp(HTTPArray[posi].HTTP_method[i],app_data,method-app_data)==0)){
            break;
        }
    }
    if (i==HTTPArray[posi].URL_list_length){
        strncpy(HTTPArray[posi].URI_list[i],method,uri-method);
        HTTPArray[posi].URI_list[i][uri-method]='\0';
        strncpy(HTTPArray[posi].HTTP_method[i],app_data,method-app_data);
        HTTPArray[posi].HTTP_method[i][method-app_data]='\0';
        HTTPArray[posi].method_number++;
        HTTPArray[posi].URL_list_length++;
        //printf("%s  %s\n",HTTPArray[posi].URI_list[i],HTTPArray[posi].HTTP_method[i]);
    }

}


