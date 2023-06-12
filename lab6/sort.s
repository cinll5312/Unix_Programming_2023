


sort_funcptr_t:
    push rbp
    mov rbp, rsp
    cmp rsi, 1
    jle end
    mov r10, 0
    mov rdx, rsi
    sub rdx, 1
    push r10            
    push rdx            
    call merge_sort
    
    jmp end

merge_sort:
    
    push rbp
    mov rbp, rsp

    mov rdx, [rsp+16]   
    mov r10, [rsp+24]   
 
    cmp r10, rdx
    je merge
    mov r9, r10             
    add r9, rdx         
    shr r9, 1           
    
   
    push r10            
    push r9             
    call merge_sort
    pop r9              
    pop r10           
    

    add r9, 1           
    mov rdx, [rsp+16]   
    
    
    push r9             
    push rdx            
    call merge_sort
    pop r9              
    pop r10             
    


    jmp merge
    jmp end

end:
    leave
    ret

merge:
    
    mov r9, [rbp+16]       
    mov r10, [rbp+24]     
    cmp r9, r10            
    je trvial_case

    
    mov rdx, r10                
    add rdx, r9          
    shr rdx, 1           
    mov rcx, r10         
    inc rdx              
    mov r11, 0           


compare:   

    mov r8, [rbp+24]
    add r8, [rbp+16]
    shr r8, 1

 
    cmp r10, r8            
    jnle noPush
    mov rax, [rdi + r10*8]  
    push rax
                
noPush:    
    
    mov rax, r11
    inc rax                 
    shl rax, 3              
    mov r9, rbp
    sub r9, rax            
    mov rax, [r9]          


    
    cmp rcx, r8         
    jnle L3             
    cmp rdx, [rbp+16]     
    jnle L4              

    mov r8, [rdi + rdx*8]  
    cmp rax, r8             
    jle L1                  
    jg L2                   

L1: 
    mov [rdi + r10*8], rax  
    inc r10               
    inc r11                 
    inc rcx                 

cleanStack:
    mov rax, r11           
    shl rax, 3             
    add rax, rsp
    cmp rax, rbp            
    mov rax, r11
    je L5                   
    jmp compare
L5:
    
    pop r8
    dec rax                
    cmp rax, 0
    jg L5
    mov r11, 0
    jmp compare


L2: 
    mov rax, [rdi + rdx*8]
    mov [rdi + r10*8], rax  
    inc r10                 
    inc rdx                
    jmp compare

L3:
    
    jnle trvial_case      

L4:
   
    inc r11                
    mov rax, r11
    
    shl rax, 3             
    mov r9, rbp
    sub r9, rax          
    mov rax, [r9]          
    mov [rdi + r10*8], rax
    inc r10                 
    cmp r9, rsp             
    
    jg L4

    mov rax, [rbp+24]
    add rax, [rbp+16]
    shr rax, 1
    cmp rcx, rax      
    jnle trvial_case            
    

trvial_case:
    leave
    ret


  



