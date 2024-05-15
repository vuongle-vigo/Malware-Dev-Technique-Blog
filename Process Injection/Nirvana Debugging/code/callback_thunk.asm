.code
    EXTERN callback : PROC
	callback_thunk proc
        ;save all register
		push rax       
        push rbx       
        push rcx       
        push rdx       
        push rsi       
        push rdi       
        push rbp       
        push rsp

        sub rsp, 20h            ; align stack
        mov rdx, rax            ;arg2
        mov rcx, r10            ;arg1
        call callback
        add rsp, 20h            ; align stack

        pop rsp        
        pop rbp        
        pop rdi        
        pop rsi        
        pop rdx        
        pop rcx        
        pop rbx        
        pop rax

		ret

	callback_thunk endp
end