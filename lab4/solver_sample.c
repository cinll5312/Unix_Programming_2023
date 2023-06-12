#include <stdio.h>
#include <inttypes.h>
//gcc -o solver_sample solver_sample.c
typedef int (*printf_ptr_t)(const char *format, ...);
//a2ff call fptr(print)
//a3a5
void solver(printf_ptr_t fptr) {
	char msg[8] = {3};

	long int sp; 
	long int rbp;
	
	asm("mov %%rsp, %0\n\t" 
		 "mov %%rbp, %0\n\t"
		 : "=r" (sp), "=r"(rbp):: );
	
	void* tt = sp;
	rbp =  *(long int*)tt;
	
 
	void* canary = (rbp - 0x8);
	unsigned long long canary_content = *(unsigned long long*)canary;
	
	void* ret_add = (rbp + 0x8);
	void* buf = (rbp - 0x30);
	char* buf_c = (rbp - 0x30);

	fptr("%p\n",rbp);//rbp
	//fptr("buf %p\n", (long int*)buf);//buf addr
	fptr("%p\n", *(long int*)ret_add);//ret addr content
	fptr("%p \n",canary_content);//canary content




	
	

}

int main() {
	char fmt[16] = "** main = %p\n";
	printf(fmt, main);
	solver(printf);
	return 0;
}