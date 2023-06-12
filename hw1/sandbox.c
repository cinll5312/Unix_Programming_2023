#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <dirent.h> 
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <dlfcn.h>
#include <elf.h> 
#include <netdb.h>
#include <time.h>

#if defined(__LP64__)
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif


/* Functions that you should be able to write: */
// Elf64_Shdr *section_by_index(Elf64_Ehdr *ehdr, int idx);
// Elf64_Shdr *section_by_name(Elf64_Ehdr *ehdr, char *name);
/* Helper to get pointer to section content: */
#define AT_SEC(ehdr, shdr) ((void *)(ehdr) + (shdr)->sh_offset)

//readelf -a sandbox.so > output.txt  
//objdump -D sandbox.so > sandbox.txt


static int (*open_orig)(const char *path, int oflag, ... );
ssize_t (*read_orig)(int fd, void *buf, size_t len);
ssize_t (*write_orig)(int fd, void* buf, size_t cnt); 
int (*connect_orig)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int (*getaddrinfo_orig)(const char *restrict node, const char *restrict service, 
                const struct addrinfo *restrict hints,struct addrinfo **restrict res);
int (*system_orig)(const char *command);
long int got_v;//got plt
long int got_size;
long int got_vv;//got
long int gotv_size;
long int relaplt;
long int relaplt_size;


long int index_system;
long int index_open;
long int index_read;
long int index_write;
long int index_con;
long int index_getaddr;


int my_open(const char *path, int oflag, ...){
    //open_orig = dlsym(RTLD_NEXT, "open");
    int mode = 0;
    if (oflag & O_CREAT)
    {
        va_list arg;
        va_start (arg, oflag);
        mode = va_arg (arg, int);
        va_end (arg);
    }
    char logger[25];//logger
    int my_open_ret = -1;//open 
    char* path_exist, resolved_path;
    path_exist = realpath(path, resolved_path);
    // printf("path %s resolved_path %s %s\n",path, resolved_path,path_exist);
    int permission = filter(1,path_exist,NULL);
 
    if(permission == 1){
        sprintf(logger,"[logger] open(\"%s\", 0, 0) = %d",path,my_open_ret);
        printf("%s\n",logger);
        errno = EACCES;
        return -1;
    }else{
        struct stat sb;
        if (lstat(path, &sb) == -1) {
            perror("stat");
            exit(EXIT_FAILURE);
        }
        if((sb.st_mode& S_IFMT)==S_IFLNK){ // deal with soft link
            //printf("symbolic link\n");
            char symbolic_link[256] = {0};
            readlink(path, symbolic_link, 255);
            //printf("%s",symbolic_link);
            permission = filter(1,symbolic_link,NULL);
            if(permission==1){
                
                sprintf(logger,"[logger] open(\"%s\", 0, 0) = %d",symbolic_link,my_open_ret);
                printf("%s\n",logger);
                errno = EACCES;
                return -1;
            }else{
                my_open_ret = open_orig(path,oflag,mode);
                sprintf(logger,"[logger] open(\"%s\", 0, 0) = %d",path,my_open_ret);
                printf("%s\n",logger);
                my_open_ret = open_orig(path,oflag,mode);
            }
        }else{
            
            my_open_ret = open_orig(path,oflag,mode);
            sprintf(logger,"[logger] open(\"%s\", 0, 0) = %d",path,my_open_ret);
            printf("%s\n",logger);
            my_open_ret = open_orig(path,oflag,mode);
        }
        
    }
    
}

ssize_t my_read(int fd, void *buf, size_t len){
    
    pid_t pid = getpid();
    char temp[len] ;
    char* temp_ptr = temp;
    int i = 0;
    char logger[100];//logger
    char log_file[20];
    int my_read_ret = 0;
    int log_index = -1;

    int fd_temp = getenv("LOGGER_FD");
    sprintf(log_file,"{%d}-{%d}-read.log",pid,fd_temp);
    
    // int my_read_ret = 0;
    // printf("buf %s\n",buf);
    // printf("fd %d\n",fd);
    // printf("before %s\n",temp_ptr);
    long int pos = lseek(fd,0,SEEK_CUR);
   
    // printf("now pos %d len %d\n",pos,len);
    my_read_ret = pread(fd, temp_ptr,len,pos);
    if(my_read_ret==-1)my_read_ret=len;//socket type
    // printf("pread %s\n",temp_ptr);
    log_index = filter(2," ",temp_ptr);//get filter result
  
    
    int f = open_orig("a.txt",O_WRONLY | O_APPEND | O_CREAT,0644);
    
    if(log_index != -1){//false
        
        write_orig(f,buf,log_index);
        close(f);
        errno = EIO;
        sprintf(logger,"[logger] read(%d, %p, %d) = -1",fd, buf, len);
        printf("%s\n",logger);
        return -1;
    }else{
        sprintf(logger,"[logger] read(%d, %p, %d) = %d",fd, buf, len, my_read_ret);
        printf("%s\n",logger);
        int ch;
        write_orig(f,buf,len);
        close(f);
        read_orig(fd,buf,len);
    }
    
}

ssize_t my_write(int fd, void* buf, size_t cnt){
    pid_t pid = getpid();
    
    char* temp_ptr = buf;
    char logger[100];//logger
    char log_file[20];


    int fd_temp = getenv("LOGGER_FD");
    sprintf(log_file,"{%d}-{%d}-write.log",pid,fd_temp);

    FILE *fp = fopen(log_file,"w");//create log
   
    int i = 0;
    while(*((char*)buf + i) != NULL){
        putc(*((char*)buf + i),fp);
        i++;
    }
    sprintf(logger,"[logger] write(%d, %p, %d) = %d",fd,buf,cnt,cnt);
    printf("%s\n",logger);
    write_orig(fd,buf,cnt);
    
} 

int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    char logger[100];

    int ret = 0;
    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
    char *s = inet_ntoa(addr_in->sin_addr);

    int permission = filter(4,s,NULL);

    if(permission == 1){//false
        sprintf(logger,"[logger] connect(%d, \"%s\", %d) = -1",sockfd,s,addrlen);
        printf("%s\n",logger);
        errno = ECONNREFUSED;
        return -1;
    }else{
        sprintf(logger,"[logger] connect(%d, \"%s\", %d) = 0",sockfd,s,addrlen);
        printf("%s\n",logger);
        connect_orig(sockfd,addr,addrlen);
    }
   

    
}

int my_getaddrinfo(const char *restrict node, const char *restrict service, 
                   const struct addrinfo *restrict hints,struct addrinfo **restrict res)
{
    char time_log[50];
    char logger[150];

    int permission = filter(3,node,NULL);

    int ret = -2;
    
    if(permission == 1){//false
        // printf("getaddrinfo false\n");
        sprintf(logger,"[logger] getaddrinfo(\"%s\",\"%s\",%p,%p) = -2",node,service,&hints,&res);
        printf("%s\n",logger);
        return -2;
    }else{
        sprintf(logger,"[logger] getaddrinfo(\"%s\",\"(null)\",%p,%p) = 0",node,&hints,&res);
        printf("%s\n",logger);
        getaddrinfo_orig(node, service, hints, res);
    }
}

int my_system(const char *command){
    // printf("fake system");
    char logger[150];
    sprintf(logger,"[logger] system(\"%s\")",command);
    printf("%s\n",logger);
    system_orig(command);
}

int filter(int mode, char* path, char* buf){
    char* line = NULL;
    size_t len = 0;
    ssize_t r;
    char* filter_file = getenv("SANDBOX_CONFIG");//open config file
    FILE* fd = fopen(filter_file, "r");
    if (fd == -1) {
        perror("filer_file false\n");
        exit(EXIT_FAILURE);
    }

    int exam = 0;//check rule true
    if(mode == 1){//open
        while ((r = getline(&line, &len, fd)) != -1) {
            if(strcmp(line, "BEGIN open-blacklist")==10){
                 exam = 1;
                 continue;
            }
            if(strcmp(line, "END open-blacklist")==10){
                exam = 0;
            }
            if(exam == 1){
                if(strcmp(line,path)==10)return 1;
            }
        }               
    }else if(mode == 2){//read
        
        while ((r = getline(&line, &len, fd)) != -1) {
            if(strcmp(line, "BEGIN read-blacklist")==10){
                exam = 1;
                continue;
            }
            if(strcmp(line, "END read-blacklist")==10){
                exam = 0;
                continue;
            }
            if(exam == 1){
                int line_max = strlen(line);
                char (*line_ptr)[line_max+2] = line;         
                char (*s)[strlen(buf)+2] = buf;
                int i = 0;
                int i_line = 0;
             
                while(1){
                    // putc((*s)[i],fp);
                    if((*s)[i] == '\0')break;
                    if((*s)[i+1] == (*line_ptr)[i_line] && (*s)[i] != (*line_ptr)[i_line]){
                        i++;
                        continue;
                    }
                    if((*s)[i] == (*line_ptr)[i_line] && i_line < line_max){
                        i_line++;
                    }else{
                        i_line = 0;
                    }
                    if(i_line == line_max-1){//find key word
                        return (i-line_max);
                    }
                    i++;
                }
                
            }

        }
        return -1;//there is no match word
    }else if(mode == 3){//getaddrinfo
        char* webname = path;
        // printf("web %s\n",webname);
        while ((r = getline(&line, &len, fd)) != -1) {
            if(strcmp(line, "BEGIN getaddrinfo-blacklist\n")==0){
                 exam = 1;
                 continue;
            }
            if(strcmp(line, "END getaddrinfo-blacklist\n")==0){
                exam = 0;
            }
            if(exam == 1){                
                if(strcmp(line,webname)== 10)return 1;
            }
        }      
    }else if(mode == 4){//connect
        struct addrinfo *ai, *aip;
        struct addrinfo hint;
        struct sockaddr_in *sinp;
        const char *addr;
        int err;
        char buf[1024];
        while ((r = getline(&line, &len, fd)) != -1) {
            if(strcmp(line, "BEGIN connect-blacklist\n")==0){
                exam = 1;
                continue;
            }
            if(strcmp(line, "END connect-blacklist\n")==0){
                exam = 0;
            }
            if(exam == 1){
                char* domain_name = strtok(line,"\n");
                char* port;
                domain_name = strtok_r(line,":",&port);
                hint.ai_flags = AI_CANONNAME;
                hint.ai_family = AF_UNSPEC;
                hint.ai_socktype = 0;
                hint.ai_protocol = 0;
                hint.ai_addrlen = 0;
                hint.ai_canonname = NULL;
                hint.ai_addr = NULL;
                hint.ai_next = NULL;
                if((err = getaddrinfo_orig(domain_name, NULL, &hint, &ai)) != 0)
                    printf("ERROR: getaddrinfo error: %s\n", gai_strerror(err));
                for(aip = ai; aip != NULL; aip = aip->ai_next)
                {

                    if(aip->ai_family == AF_INET)
                    {
                        char addr_port[10];
                        sinp = (struct sockaddr_in *)aip->ai_addr;
                        sprintf(addr_port,"%d",ntohs(sinp->sin_port));
                        addr = inet_ntop(AF_INET, &sinp->sin_addr, buf, sizeof buf);
    
                        if(strcmp(addr,path)==0&&strcmp(addr_port,port)==0){
                            // printf("%s %s is the same\n",addr,path);
                            return 1;
                        }
                        printf("IP Address: %s ", addr);
                        printf("Port: %s\n", addr_port);
                        
                    }
                }
            }
        }       

    }
    
    return 0;
    fclose(fd);
}

void readelf_header(int mode){
    
    char exe[256] = {0};
    readlink("/proc/self/exe", exe, 255);
    FILE* ElfFile = fopen(exe, "rb");
    if(!ElfFile){
        printf("open false\n");
        return;  
    }
    char* SectNames = NULL;
    Elf64_Ehdr elfHdr;
    Elf64_Shdr sectHdr;
    uint idx;
    // read ELF header
    fread(&elfHdr, 1, sizeof elfHdr, ElfFile);

    // read section name string table
    // first, read its header
    fseek(ElfFile, elfHdr.e_shoff + elfHdr.e_shstrndx * sizeof (sectHdr), SEEK_SET);
    fread(&sectHdr, 1, sizeof sectHdr, ElfFile);

    // next, read the section, string data
    SectNames = malloc(sectHdr.sh_size);
    fseek(ElfFile, sectHdr.sh_offset, SEEK_SET);
    fread(SectNames, 1, sectHdr.sh_size, ElfFile);
   
    long int dsize;
    
    Elf64_Sym *syms;
    
    system_orig = dlsym(RTLD_NEXT, "system");
    open_orig = dlsym(RTLD_NEXT, "open");
    read_orig = dlsym(RTLD_NEXT, "read");
    write_orig = dlsym(RTLD_NEXT, "write");
    connect_orig = dlsym(RTLD_NEXT, "connect");
    getaddrinfo_orig = dlsym(RTLD_NEXT, "getaddrinfo");
    // read all section headers
    for (idx = 0; idx < elfHdr.e_shnum; idx++)
    {
        const char* name = "";
    
        fseek(ElfFile, elfHdr.e_shoff + idx * sizeof sectHdr, SEEK_SET);
        fread(&sectHdr, 1, sizeof sectHdr, ElfFile);

        // print section name
        if (sectHdr.sh_name);
        name = SectNames + sectHdr.sh_name;
/*
        if(strcmp(name,".dynsym")==0&&mode==1){
            dsize = sectHdr.sh_size;
      
            Elf64_Sym *r = (Elf64_Sym *) (sectHdr.sh_addr);
            int i, count = dsize / sectHdr.sh_entsize;
            char* str = (char*) (sectHdr.sh_size);
            // printf("%p\n", sizeof(Elf64_Sym));
            
            fseek(ElfFile, elfHdr.e_shoff + sectHdr.sh_link * sizeof sectHdr, SEEK_SET);
            fread(&sectHdr, 1, sizeof sectHdr, ElfFile);
            char* str_p =(char *) (sectHdr.sh_addr);


            fseek(ElfFile, elfHdr.e_shoff + idx * sizeof sectHdr, SEEK_SET);
            fread(&sectHdr, 1, sizeof sectHdr, ElfFile);

            for (i = 0; i < count; i++) {
               
                if(strcmp("system",(char*)((int)str_p+r[i].st_name))==0){
                    index_system = i;
                }
                if(strcmp("open",(char*)((int)str_p+r[i].st_name))==0){
                    index_open = i;
                }
                if(strcmp("read",(char*)((int)str_p+r[i].st_name))==0){
                    index_read = i;
                }
                if(strcmp("write",(char*)((int)str_p+r[i].st_name))==0){
                    index_write = i;
                }
                if(strcmp("connect",(char*)((int)str_p+r[i].st_name))==0){
                    index_con = i;
                }
                if(strcmp("getaddrinfo",(char*)((int)str_p+r[i].st_name))==0){
                    index_getaddr = i;
                }
            }
        }*/
        if(strcmp(name,".rela.plt")==0){
            relaplt = sectHdr.sh_addr;
            relaplt_size = sectHdr.sh_size;
            // printf("relaplt %p %p\n",relaplt,relaplt_size);
            
            Elf64_Rela *relas = (Elf64_Rela *) (sectHdr.sh_addr);
            // Elf64_Rela *relas = AT_SEC(&elfHdr, reloc_entry);
            int i, count = relaplt_size / sizeof(Elf64_Rela);
            // printf("%p\n", sizeof(Elf64_Rela));
            // if(mode == 1){
            //     for (i = 0; i < count; i++) {
                    
            //         if(ELF64_R_SYM((relas+i)->r_info)==index_system){
            //             index_system = (relas+i)->r_offset;
            //         }
            //         if(ELF64_R_SYM((relas+i)->r_info)==index_open){
            //             index_open = (relas+i)->r_offset;
            //         }
            //         if(ELF64_R_SYM((relas+i)->r_info)==index_read){
            //             index_read = (relas+i)->r_offset;
            //         }
            //         if(ELF64_R_SYM((relas+i)->r_info)==index_write){
            //             index_write = (relas+i)->r_offset;
            //         }
            //         if(ELF64_R_SYM((relas+i)->r_info)==index_con){
            //             index_con = (relas+i)->r_offset;
            //         }
            //         if(ELF64_R_SYM((relas+i)->r_info)==index_getaddr){
            //             index_getaddr= (relas+i)->r_offset;
            //         }
            //     }
            // }
        }
        if(strcmp(name,".got.plt") == 0){
            got_v = sectHdr.sh_addr;
            got_size = sectHdr.sh_size;
            int i, count = got_size / sectHdr.sh_entsize;
            // printf("gotplt\n");
            // if(mode == 1){
            //     for (i = 0; i < count; i++) {
            //         // printf("%d %p %p\n",i,got_v+(i*sectHdr.sh_entsize),*(long int*)(got_v+(i*sectHdr.sh_entsize)));
            //         if(got_v+(i*sectHdr.sh_entsize)==index_system){
            //             *(long int*)(got_v+(i*sectHdr.sh_entsize)) = &my_system;
                        
            //             // printf("change sys in gotplt %p\n",*(long int*)(got_v+(i*sectHdr.sh_entsize)));
            //         }
            //         if(got_v+(i*sectHdr.sh_entsize)==index_open){
            //             *(long int*)(got_v+(i*sectHdr.sh_entsize)) = &my_open;
            //             // printf("change open in gotplt %p\n",*(long int*)(got_v+(i*sectHdr.sh_entsize)));
            //         }
            //         if(got_v+(i*sectHdr.sh_entsize)==index_read){
            //             *(long int*)(got_v+(i*sectHdr.sh_entsize)) = &my_read;
            //             // printf("change read in gotplt %p\n",*(long int*)(got_v+(i*sectHdr.sh_entsize)));
            //         }
            //         if(got_v+(i*sectHdr.sh_entsize)==index_write){
            //             *(long int*)(got_v+(i*sectHdr.sh_entsize)) = &my_write;
            //             // printf("change write in gotplt %p\n",*(long int*)(got_v+(i*sectHdr.sh_entsize)));
            //         }
            //         if(got_v+(i*sectHdr.sh_entsize)==index_con){
            //             *(long int*)(got_v+(i*sectHdr.sh_entsize)) = &my_connect;
            //             // printf("change con in gotplt %p\n",*(long int*)(got_v+(i*sectHdr.sh_entsize)));
            //         }
            //         if(got_v+(i*sectHdr.sh_entsize)==index_getaddr){
            //             *(long int*)(got_v+(i*sectHdr.sh_entsize)) = &my_getaddrinfo;
            //             // printf("change getaddr in gotplt %p\n",*(long int*)(got_v+(i*sectHdr.sh_entsize)));
            //         }
            //     }
            // }
            
        }
        if(strcmp(name,".got")==0){
            got_vv = sectHdr.sh_addr;
            gotv_size = sectHdr.sh_size;
            int i, count = gotv_size / sectHdr.sh_entsize;
        }
    }

}
int __libc_start_main(
    int (*main)(int, char **, char **),
    int argc,
    char **argv,
    int (*init)(int, char **, char **),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void *stack_end)
{

    readelf_header(0);

    int fd, sz;
	char buf[16384], *s = buf, *line, *saveptr;
	if((fd = open("/proc/self/maps", O_RDONLY)) < 0) errquit("get_base/open");
    while((sz = read(fd, s, sizeof(buf)-1-(s-buf))) > 0) { s += sz;}
    *s = 0;
    s = buf;

	close(fd);

    int i = 0;
    char* base;//process base addr
    while((line = strtok_r(s, "\n\r", &saveptr)) != NULL){
        s=NULL;
        i++;
        if(i==1){
            base = strtok(line,"-");// got process base addr
        }
        if(i==4){
            char* end_ptr;
            size_t pagesize = sysconf(_SC_PAGESIZE);
            char head[13];
            char end_head[13];
            void* start_addr = strtok_r(line,"-",&end_ptr);
            strcat(head,start_addr);
            void* end_addr = strtok_r(NULL, " ", &end_ptr);
            strcat(end_head,end_addr);
            long int ad = strtol(head,NULL,16);//mprotect base_address long int type
            long int add = strtol(end_head,NULL,16);
            long int ad_diff = ((add -ad)/pagesize);
            void* base_addr = ad;//void* base_addr
            

            if((mprotect(base_addr,pagesize*ad_diff, PROT_READ | PROT_WRITE))){
                perror("mprotect()");
            }
            break;
        }
    }
    if(strtol(base,NULL,16)< strtol("0x500000000000",NULL,16)){
        readelf_header(1);//special case for addr <0x500000000000 , mode = 1
    }
    
   if(line == NULL)printf("NULL\n");
    
    open_orig = dlsym(RTLD_NEXT, "open");

    read_orig = dlsym(RTLD_NEXT, "read");

    write_orig = dlsym(RTLD_NEXT, "write");
    char     *error;
    connect_orig = dlsym(RTLD_NEXT, "connect");

    getaddrinfo_orig = dlsym(RTLD_NEXT, "getaddrinfo");

    system_orig = dlsym(RTLD_NEXT, "system");
    if ((error = dlerror()) != NULL)  {
       fprintf(stderr, "%s\n", error);
    }
    void* got;//for gotplt if exist or for got
    
    int exam_got = 1;
    if(got_v==NULL){
        // printf("no gotplt");
        exam_got = 0;//no gotplt
        got_v = got_vv;
        got_size = gotv_size;
    }
    if(strtol(base,NULL,16) < strtol("0x500000000000",NULL,16)){
        got = got_v;//for python case

    }else{
        got = strtol(base,NULL,16) + got_v;//true got table addr
    }
    
    int got_index = gotv_size/8;//got table index
    int index = got_size/8;//gotplt table index
    long int content = 0;

 
    for(int i = 0; i<index;i++){
        content = *((long int*)got+i);
       
        if(content == open_orig){
            // printf("find open\n");
            void* target = (long int*)got+i;
            *((long int*)got+i) = &my_open;
        } 
        if(content == read_orig){
            
            void* target = (long int*)got+i;
            *((long int*)got+i) = &my_read;
        }
        if(content == write_orig){
            void* target = (long int*)got+i;
            *((long int*)got+i) = &my_write;
        }
        if(content == connect_orig){
            
            void* target = (long int*)got+i;
            *((long int*)got+i) = &my_connect;

        }
        if(content == getaddrinfo_orig){
            void* target = (long int*)got+i;
            *((long int*)got+i) = &my_getaddrinfo;
        }
        if(content == system_orig){
            void* target = (long int*)got+i;
            *((long int*)got+i) = &my_system;
        }
    }
    /* Find the real __libc_start_main()... */
    typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT, "__libc_start_main");
    return orig( main, argc, argv, init, fini, rtld_fini, stack_end);
}







