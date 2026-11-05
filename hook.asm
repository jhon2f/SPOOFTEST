; hook.asm - NO-OP trampoline (isolation test): just forwards to the original dispatch.
; No completion routine. Tests whether the tail-call trampoline itself is safe.
.CODE

PUBLIC disk_hook
PUBLIC disk_hook_end

disk_hook PROC
    mov     rax, 1122334455667788h    ; orig_dispatch placeholder
    jmp     rax
disk_hook ENDP

disk_hook_end:
END
