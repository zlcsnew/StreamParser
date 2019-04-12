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
        HTTPArray[posi].has_host=0;
        HTTPArray[posi].has_ua=0;
        HTTPArray[posi].has_cookie=0;
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
        printf("\n\nflow %d\n",i);
        int j;
        for(j=0;j<HTTPArray[i].URL_list_length;j++){
            printf("%s  %s\n",HTTPArray[i].HTTP_method[j],HTTPArray[i].URI_list[j]);
        }
        if(HTTPArray[i].has_ua)
            printf("%s\n",HTTPArray[i].HTTP_UA);
        if(HTTPArray[i].has_host)
            printf("%s\n",HTTPArray[i].HTTP_host);
        if(HTTPArray[i].has_cookie)
            printf("%s\n",HTTPArray[i].HTTP_cookie);
     }
}


void HTTP_Process(int posi,u_char *app_data,int data_length){
    app_data[data_length-1]='\0';
    u_char * method=strchr(app_data,' ');
    if (method==NULL)
        return;
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
    // method+uri
    if (i==HTTPArray[posi].URL_list_length){
        strncpy(HTTPArray[posi].URI_list[i],method,uri-method);
        HTTPArray[posi].URI_list[i][uri-method]='\0';
        strncpy(HTTPArray[posi].HTTP_method[i],app_data,method-app_data);
        HTTPArray[posi].HTTP_method[i][method-app_data]='\0';
        HTTPArray[posi].method_number++;
        HTTPArray[posi].URL_list_length++;
        //printf("%s  %s\n",HTTPArray[posi].URI_list[i],HTTPArray[posi].HTTP_method[i]);
    }
    //HTTP HOST
    if (!HTTPArray[posi].has_host){
        u_char * HOST_start=strstr(app_data,"Host:");
        u_char * HOST_end=strstr(HOST_start+strlen(str),"\r\n");
        strncpy(HTTPArray[posi].HTTP_host,HOST_start,HOST_end-HOST_start);
        HTTPArray[posi].HTTP_host[HOST_end-HOST_start]='\0';
        HTTPArray[posi].has_host=1;
    }
    //HTTP UA
    if (!HTTPArray[posi].has_ua){
        u_char * UA_start=strstr(app_data,"User-Agent");
        u_char * UA_end=strstr(app_data,"\r\n");
        strncpy(HTTPArray[posi].HTTP_UA,UA_start,UA_end-UA_start);
        HTTPArray[posi].HTTP_UA[UA_end-UA_start]='\0';
        HTTPArray[posi].has_ua=1;
    }

    if(!HTTPArray[posi].has_cookie){
        u_char * cookie_start=strstr(app_data,"Cookie:");
        if (cookie_start==NULL){
            goto end_cookie;
        }
        u_char *cookie_end=strstr(cookie_start,"/r/n");
        strncpy(HTTPArray[posi].HTTP_cookie,cookie_start,cookie_end-cookie_start);
        HTTPArray[posi].HTTP_cookie[cookie_end-cookie_start]='\0';
        HTTPArray[posi].has_cookie=1;
    }
end_cookie:
    return;
}


