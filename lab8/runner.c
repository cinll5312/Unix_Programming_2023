#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>


void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}


int main(int argc, char* argv[]){
    int wait_status;
    pid_t child;


    int p1[2];
        
    if(pipe(p1)<0){
        errquit("pipe");
    }
                
    if((child = fork()) < 0) errquit("fork");
	if(child == 0) {
        close(p1[0]);
        close(1);
        dup2(p1[1], STDOUT_FILENO); //child stdout to pipe
        
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
		execvp(argv[1], argv+1);
		// close(p1[1]);
	} else {
		struct user_regs_struct regs;
        long counter = 0;
        close(p1[1]);
        
		if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        unsigned long addr, reset_addr, code, target, temp;
        long a;
        int bingo = 0;
        int magic[11]={0};
        
        while (WIFSTOPPED(wait_status)) {
            char buf[1024];

            if(ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("ptrace@parent");
            if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
            counter++;
            ptrace(PTRACE_GETREGS, child, 0, &regs);
            // fprintf(stderr, "%d 0x%llx\n",counter,regs.rip);
            
            if(counter==1){
                
                for(int i = 0; i <8; i++){
                    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) errquit("ptrace@parent");
                    if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
                }
                
                ptrace(PTRACE_GETREGS, child, 0, &regs);
                
                addr = regs.rdi;//magic


                
            }else if(counter==3){//reset
                ptrace(PTRACE_GETREGS, child, 0, &regs);
                reset_addr = (regs.rip-0x2);
                
            }else if(counter>=5 && bingo==0){//cc
                
                

                dup2(p1[0], STDIN_FILENO);
                read(p1[0],buf, sizeof(buf));
                printf("%s",buf);
                if(buf[0]=='B'){
                    bingo = 1;
                    // printf("bin");
                }else{
                    
                    magic[0] = magic[0] + 1;
                    if(ptrace(PTRACE_POKEDATA, child, addr+8, 49) != 0)errquit("ptrace(POKEDATA)");//change magic 
                    for(int i = 0; i < 9; i++){
                        // printf("change\n");
                        if(magic[i]==0){
                            if(ptrace(PTRACE_POKEDATA, child, addr+i, 48) != 0)errquit("ptrace(POKEDATA)");//change magic 
                        }else if(magic[i]==1){
                            if(ptrace(PTRACE_POKEDATA, child, addr+i, 49) != 0)errquit("ptrace(POKEDATA)");//change magic 
                        }else if(magic[i]==2){
                            magic[i] = 0;
                            magic[i+1]+=1;
                            if(ptrace(PTRACE_POKEDATA, child, addr+i, 48) != 0)errquit("ptrace(POKEDATA)");//change magic 
                            if(magic[i+1]==1&&i+1<9){
                                if(ptrace(PTRACE_POKEDATA, child, addr+i+1, 49) != 0)errquit("ptrace(POKEDATA)");//change magic 
                            }
                        }
                    }
                    // for(int i = 0; i < 9; i++){
                    //     a = ptrace(PTRACE_PEEKDATA, child, addr+i, 0);
                    //     printf("%c",a);
                    // }
                    // printf("\n");
                    
                    
                    // change rip
                    ptrace(PTRACE_GETREGS, child, 0, &regs);
                    regs.rip = reset_addr;
                    ptrace(PTRACE_SETREGS, child, 0, &regs);
                    if(ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("ptrace@parent");
                    if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");

                }
              
            }else if(bingo==1 ){//print magic number
                // printf("bingo = 1");
                dup2(p1[0], STDIN_FILENO);
                int num = read(p1[0],buf, sizeof(buf));
                close(p1[0]);
                printf("%s\n",buf);
                break;
            }
            
            
        }
	// fprintf(stderr, "## %lld instruction(s) executed\n", counter);

	}
}