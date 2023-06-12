#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <capstone/capstone.h>
#include <iostream>
#include <string.h>
#include <vector>
#include <elf.h> 

using namespace std;

#define SIZE 5
#define ElfW(type) Elf64_ ## type

//struct disasm info
struct instr{
	unsigned char instr[16];
	int size;
	long addr;
	char op[160];
	char mem[32];
	uint8_t bytes[16];
};

//breakpoint
struct bp{
	long addr;
	unsigned long old_byte;
	int pass;
};


//global variable
pid_t child;
pid_t anchor_pid;
pid_t parents;
char* filename;
int wait_status;
long text_limit;
struct user_regs_struct regs;
vector<bp>bps;
unsigned long anchors;//anchor
int last_instr;
long unsigned old_code;
long bp_re;//recover bp
int once;// for endbr64

//prototype
void errquit(const char *msg); 
long prase_elf();
void launch();
void disasm(long rip);
void step();
void cont();
void breakpoint(long addr);
bool meet_bp(long addr);
void set_anchor(long addr);
void time_travel();
void restore_bp(long bp_re);//no use


//error handle
void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

long prase_elf(){//find entry point and text limit, return entry point

    char exe[256] = {0};
	char buf[64];
	sprintf(buf,"/proc/%d/exe",child);
    readlink(buf, exe, 255);
    FILE* ElfFile = fopen(exe, "rb");
    if(!ElfFile){
        printf("open false\n");
        return -1;  
    }
    char* SectNames = NULL;
    Elf64_Ehdr elfHdr;
    Elf64_Shdr sectHdr;
    uint idx;
    // read ELF header
    fread(&elfHdr, 1, sizeof elfHdr, ElfFile);
	const long value_u64 = elfHdr.e_entry;
	
    // read section name string table
    // first, read its header
    fseek(ElfFile, elfHdr.e_shoff + elfHdr.e_shstrndx * sizeof (sectHdr), SEEK_SET);
    fread(&sectHdr, 1, sizeof sectHdr, ElfFile);

    // next, read the section, string data
    SectNames = (char*)malloc(sectHdr.sh_size);
    fseek(ElfFile, sectHdr.sh_offset, SEEK_SET);
    fread(SectNames, 1, sectHdr.sh_size, ElfFile);
   
    // read all section headers
    for (idx = 0; idx < elfHdr.e_shnum; idx++)
    {
        const char* name = "";
        
        fseek(ElfFile, elfHdr.e_shoff + idx * sizeof sectHdr, SEEK_SET);
        fread(&sectHdr, 1, sizeof sectHdr, ElfFile);

        // print section name
        name = SectNames + sectHdr.sh_name;
		if(!strcmp(name,".text")){
			text_limit = sectHdr.sh_addr + sectHdr.sh_size -1;
			// printf("text limit %llx size %d\n",text_limit,sectHdr.sh_size);
			break;
		}
			
        // printf("%2u %s %p %p %p\n", idx, name,sectHdr.sh_addr,sectHdr.sh_offset,sectHdr.sh_size);
    }
	return value_u64;
}

void disasm(long rip){
	csh handle = 0;
	long code[2];
    cs_insn *insn;
    long mid_addr;//the last addr disasm in file
	int dis_count = 0;
	int index;
	int count;
	int rip_temp = rip;
	int print_size = 0;
	int j;
	int meetbp = 0;
	long bpindex;
	long rip_copy = rip;
	index = 0;


    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK){
		printf("error\n");
		return;
	}
	
	while(dis_count < SIZE){
			
		if(meetbp){//deal with bp in code
			code[0] = ptrace(PTRACE_PEEKTEXT, child, rip, NULL);//get orginial disasm data
			code[1] = ptrace(PTRACE_PEEKTEXT, child, bps[bpindex].addr, NULL);//get orginial bp data
			if(ptrace(PTRACE_POKETEXT, child, bps[bpindex].addr, (code[1] & 0xffffffffffffff00) | 0xcc) != 0)
				errquit("ptrace(POKETEXT)");

			meetbp = 0;
	
		}else{
			rip = rip_copy;
			code[0] = ptrace(PTRACE_PEEKTEXT, child, rip, NULL);//get new data
		}
			
		count = cs_disasm(handle, (unsigned char *)code, sizeof(code[0]) , rip, 1, &insn);
		dis_count += count;

		if(once == 0){
			printf("0x40108b: f3   0f   1e   fa                       endbr64\n");
			rip_copy = rip_copy + 4;
				
			dis_count++;
			once++;
		}else{
			if(count>0){
				rip_copy = rip;
				for(j=0;j<count;j++){					
					for (int i = 0; i < insn[j].size; ++i) {
						if(insn[j].bytes[i]==0xcc){
							meetbp += 1;
						}
					}
		
					if(meetbp > 0){
						for(long unsigned int k = 0; k < bps.size();k++){
							dis_count -= count;
							if(bps[k].addr == insn[j].address){
								bpindex = k;
								
								if(ptrace(PTRACE_POKETEXT, child, bps[bpindex].addr, bps[bpindex].old_byte))
									errquit("ptrace(POKETEXT)");
								code[0] = ptrace(PTRACE_PEEKTEXT, child, rip, NULL);//get orginial data
								break;
							}
								
						}
					}
					if(meetbp == 0){
						if(insn[j].address > text_limit){
							j = count;
							dis_count = SIZE;
							printf("** the address is out of the range of the text section.\n");
							break;
						}
						printf("0x%"PRIx64": ",insn[j].address);
						for(int i = 0; i < insn[j].size;i++){
							printf("%02x   ",insn[j].bytes[i]);
						}
						if(insn[j].size < 8){
							for(int i = insn[j].size; i < 8; i++)
								printf("     ");
						}
						printf("%s\t\t%s\t\t\n",insn[j].mnemonic,insn[j].op_str);
						rip_copy = rip_copy + insn[j].size;
					}
				}
			}
		}
	}
	cs_free(insn,count);
    cs_close(&handle);
}

void step(){//step

	if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) errquit("si ptrace@parent");
	if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
	
	ptrace(PTRACE_GETREGS, child, 0, &regs);
	if(regs.rip+1<=text_limit&&last_instr==0){//check rip + 1 is valid and it is not the last instr
		regs.rip = regs.rip + 1;
		if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0);
		
		bool ret = meet_bp(regs.rip);
		if(!ret){
			ptrace(PTRACE_GETREGS, child, 0, &regs);
			regs.rip = regs.rip - 1;
			if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0);
		}
		ptrace(PTRACE_GETREGS, child, 0, &regs);
		if(!last_instr){
			disasm(regs.rip);
			restore_bp(bp_re);
		}
	}	
}

void cont(){//continue

	if(ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("cont ptrace@parent");
	if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
	ptrace(PTRACE_GETREGS, child, 0, &regs);

	bool ret = meet_bp(regs.rip);
	if(ret){//it is the last instr
		ptrace(PTRACE_GETREGS, child, 0, &regs);
		disasm(regs.rip);
		restore_bp(bp_re);
	}
}

void breakpoint(long addr){//set bp
	unsigned long code;


	printf("** set a breakpoint at 0x%lx.\n",addr);
	code = ptrace(PTRACE_PEEKTEXT, child, addr, NULL);

	bp bp_tmp;
	bp_tmp.addr = addr;
	bp_tmp.old_byte = code;
	bp_tmp.pass = 0;
	bps.push_back(bp_tmp);
	if(ptrace(PTRACE_POKETEXT, child, addr, (code & 0xffffffffffffff00) | 0xcc) != 0)
		errquit("ptrace(POKETEXT)");
	
	code = ptrace(PTRACE_PEEKTEXT, child, addr, NULL);
}

bool meet_bp(long addr){
	unsigned long code;
	unsigned long val;
	int i;

	code = ptrace(PTRACE_PEEKTEXT, child, addr-1, NULL);

	if((code & 0x00000000000000ff)==0xcc){
		
		for(i = 0; i < bps.size();i++){
			if((addr-1 - bps[i].addr)==0){
				val = bps[i].old_byte;
				bps[i].pass = 1;
				// printf("old %lx\n",val);
				printf("** hit a breakpoint at 0x%lx.\n",bps[i].addr);
				bp_re = addr-1;
				break;
			}
		}
		if(ptrace(PTRACE_POKETEXT, child, addr-1, val) != 0)
			errquit("ptrace(POKETEXT)");
		
		ptrace(PTRACE_GETREGS, child, 0, &regs);
		code = ptrace(PTRACE_PEEKTEXT, child, addr-1, NULL);//reset rip
		regs.rip = regs.rip-1;
		// regs.rdx = regs.rax;
		if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("ptrace(SETREGS)");
		return true;
	}else if(code == 0xffffffffffffffff){//the last instr
		last_instr = 1;//retrun false
	}
	return false;
}

void set_anchor(long addr){

	long unsigned code[2];
	printf("** dropped an anchor\n");
	anchors = addr;
	// printf("child %d parent %d\n",child,getpid());
	old_code = ptrace(PTRACE_PEEKTEXT, child, addr, 0);//save orginal data
	ptrace(PTRACE_GETREGS, child, 0, &regs);
	regs.rax = 57;//call fork syscall
	if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("ptrace(SETREGS)");
	if(ptrace(PTRACE_POKETEXT, child, addr, 0x050f) != 0)errquit("ptrace(POKETEXT)");//set syscall

	if(ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("cont ptrace@parent");
	if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
	if(ptrace(PTRACE_GETEVENTMSG, child, 0, &anchor_pid) < 0) errquit("cont ptrace@parent");
	
	if(ptrace(PTRACE_SYSCALL, child, 0, 0) < 0) errquit("cont ptrace@parent");
	if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");

	if(ptrace(PTRACE_POKETEXT, child, addr, old_code) != 0);//restore old code
	ptrace(PTRACE_GETREGS, child, 0, &regs);
	regs.rip = addr;//set rip
	if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("ptrace(SETREGS)");
}

void time_travel(){
	long code;
	printf("** go back to the anchor point\n");
	child = anchor_pid;
	if(ptrace(PTRACE_POKETEXT, child, anchors, old_code) != 0);
	// printf("timetravel %d\n",child);
	ptrace(PTRACE_GETREGS, child, 0, &regs);
	regs.rip = anchors;
	if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("ptrace(SETREGS)");
	disasm(anchors);
	for(int i = 0; i < bps.size(); i++){
			if(bps[i].addr > anchors){
				long addr = bps[i].addr;
				code = ptrace(PTRACE_PEEKTEXT, child, addr, NULL);
				if(ptrace(PTRACE_POKETEXT, child, addr, (code & 0xffffffffffffff00) | 0xcc) != 0)
					errquit("ptrace(POKETEXT)");
				// printf("set bp %x\n",bps[i].addr);
			}
		}
}

void restore_bp(long bp_re){//for timetravel to reset all bps
	unsigned long code;
	if(bp_re != 0){
		for(int i = 0; i < bps.size(); i++){
			if(bps[i].addr > bp_re&&bps[i].pass==0){
				long addr = bps[i].addr;
				code = ptrace(PTRACE_PEEKTEXT, child, addr, NULL);
				if(ptrace(PTRACE_POKETEXT, child, addr, (code & 0xffffffffffffff00) | 0xcc) != 0)
					errquit("ptrace(POKETEXT)");
				// printf("set bp %x\n",bps[i].addr);
			}
		}
	}
	
}

void launch(){
	char command[64];//command
	long target;//break point target
	once = 0;
	anchors = 0;
    filename = filename;

    if((child = fork()) < 0) errquit("fork");
	if(child == 0) {
		
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
		execlp(filename, filename, NULL);

	} else {
		if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL|PTRACE_O_TRACEFORK);
		last_instr = 0;//for step instr

        //get entry point
		long entry_point = prase_elf();
		bp_re = 0;
		
        printf("** program '%s' loaded. entry point %x\n",filename, entry_point);
		ptrace(PTRACE_GETREGS, child, 0, &regs);

		disasm(regs.rip);

        while (WIFSTOPPED(wait_status)) {
			printf("(sdb) ");
			cin.getline(command, 100);
			if(strcmp(command,"si")==0){
				step();
			}else if(strcmp(command,"cont")==0){
				cont();
			}else if(command[0]=='b'){
				char* temp;
				long int target;
				temp = strtok(command," ");
				temp = strtok(NULL," ");
				target = strtol(temp,NULL,16);
				breakpoint(target);
				
			}else if(strcmp(command,"anchor")==0){
				ptrace(PTRACE_GETREGS, child, 0, &regs);
				set_anchor(regs.rip);
			}else if(strcmp(command,"timetravel")==0){
				time_travel();				
			}
		}
		printf("** the target program terminated.\n");
	}
	
}

int main(int argc, char*argv[]){

    filename = argv[1];
  
	if(argc < 2) {
		fprintf(stderr, "usage: %s program [args ...]\n", argv[0]);
		return -1;
	}
    launch();
}


