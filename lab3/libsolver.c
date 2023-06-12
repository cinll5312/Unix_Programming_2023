/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libunwind.h>
#include <sys/mman.h>
#include "libpoem.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include "shuffle.h"
//got base 17a18
//got end 18ff8
//size 15e8


//main
//0x107a9

//17a18 - 107a9 = 726f
//plt
//0x107f1
//0x10801

#define LIB_CACULATE_PATH "./libpoem.so"


extern int errno;
char* start_addr;

int get_main(){
    int fd, sz;
	char buf[16384], *s = buf, *line, *saveptr;
	if((fd = open("/proc/self/maps", O_RDONLY)) < 0) errquit("get_base/open");
    while((sz = read(fd, s, sizeof(buf)-1-(s-buf))) > 0) { s += sz; }
    *s = 0;
    s = buf;
    void* base_addr;
    long int ad;
	close(fd);
    int i = 0;
    while((line = strtok_r(s, "\n\r", &saveptr)) != NULL){//get base address of chals 
		s = NULL;
        
        printf("%s\n",line);
        i++;
       
        if(i==4){
            size_t pagesize = sysconf(_SC_PAGESIZE);
            char head[13];
            start_addr = strtok(line,"-");
            strcat(head,start_addr);
            ad = strtol(head,NULL,16);//base_address long int type
            base_addr = ad;//void* base_addr
            printf("%p %ld %p\n", base_addr, ad, start_addr);

            if((mprotect(base_addr,pagesize*2,PROT_READ | PROT_WRITE))){
                perror("mprotect()");
            }
            break;
        }
	}
 

    void *handle = dlopen("./libpoem.so",RTLD_LAZY);//open

    if(!handle) {
        printf("open failed: %s\n",dlerror());
        return 1;
    }

    long int dynamic_base = dlsym(handle, "code_0");
    void *dynamic_base2 = dlsym(handle, "code_1");
    void *dynamic_end = dlsym(handle, "code_1476");
    long int list[1477];
    for(int k = 0; k < 1477; k++){
        char ss[]="code_";
        char *s = ss;
        char t[5] ;
        sprintf(t,"%d",k);
        strcat(ss,t);
        void* d = dlsym(handle,s);//actual code addr
        list[k] = ((long int*)d);
        printf("%d %p ", k, list[k]);
    }
    long int diff = dynamic_base2-dynamic_base;// compute actual code gap
    printf("%p %p %p diff %p\n", dynamic_base, dynamic_base2, dynamic_end, diff);

    long int end_addr = ad +strtol("0xa18",NULL,16) + strtol("0x15e0",NULL,16);//get end addr of got
    printf("end addr %p\n", end_addr); 

    ad = ad + strtol("0xa10 ",NULL,16);//got baseaddr of got[3]
    base_addr = ad;
    
    long int addr_content;
    long int code_num;

    i = 0;
    while(ad < end_addr){
 
        ad = ad + strtol("0x8",NULL,16);
        base_addr = ad;
        addr_content = *((long int*)base_addr);
        int len = sizeof(ndat)/sizeof(ndat[0]);
        long int target;
        for(int j = 0; j < 1477; j++){
            if(addr_content == list[j]){
                code_num = j;
                break;
            }
            code_num = -1;
        }
        if(code_num != -1){
            for(int j = 0; j < len; j++){
                if(code_num == ndat[j]){
                    code_num = j;
                    char ss[]="code_";
                    char *s = ss;
                    char t[5] ;
                    sprintf(t,"%d",j);
                    strcat(ss,t);
                    void* d = dlsym(handle,s);//actual code addr
                    memcpy(base_addr, &d, 8);//void base_addr = base + offset
                    printf("%d %p %p %ld %s %p\n",i, base_addr, *((long int*)base_addr), code_num,s,d);
                    break;
                }
                
            }
            
            
        }else{
            printf("%d %p %p \n",i, base_addr, addr_content);
        }
        i++;
    }

}
int init(){
    get_main();
}


