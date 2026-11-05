; installer.asm - one-shot kernel stub, inline-hooked as chinese.sys's dispatch.
; Resolves \Driver\Disk via ObReferenceObjectByName, patches MajorFunction[14] to the hook,
; and returns the original MajorFunction[14] in the IRP SystemBuffer so the injector can
; patch the hook's placeholder.
; x64 stack args: 5th at [rsp+20h].
; Placeholders: 01=ObReferenceObjectByName, 02=IoCompleteRequest, 03=hook address,
;               04=IoDriverObjectType (dereferenced POBJECT_TYPE VALUE).
.CODE

PUBLIC installer
PUBLIC installer_end

installer PROC
    sub     rsp, 68h
    mov     [rsp+48h], rdx            ; save irp
    mov     qword ptr [rsp+40h], 0    ; zero-init drobj
    lea     rax, disk_name
    mov     word ptr [rsp+50h], 24
    mov     word ptr [rsp+52h], 24
    mov     [rsp+58h], rax
    lea     rcx, [rsp+50h]            ; &UNICODE_STRING
    mov     edx, 40h                  ; OBJ_CASE_INSENSITIVE
    xor     r8d, r8d                  ; AccessState = NULL
    ; DesiredAccess MUST be non-zero on Win10 19045+: ObReferenceObjectByName
    ; fails with STATUS_ACCESS_DENIED for driver objects when access == 0,
    ; which made the old stub bail early -> injector read garbage as the
    ; "original dispatch" -> hook jumped to a non-executable VA -> BSOD.
    mov     r9d, 00120000h            ; SYNCHRONIZE | READ_CONTROL
    mov     rax, 0B0B0B0B0B0B0B04h    ; -> IoDriverObjectType (value)
    mov     [rsp+20h], rax            ; ObjectType
    mov     qword ptr [rsp+28h], 0    ; AccessMode = KernelMode
    mov     qword ptr [rsp+30h], 0    ; ParseContext = NULL
    lea     rax, [rsp+40h]
    mov     [rsp+38h], rax            ; Object = &drobj
    mov     rax, 0B0B0B0B0B0B0B01h    ; -> ObReferenceObjectByName
    call    rax
    test    eax, eax
    js      done                      ; error -> just complete
    mov     rcx, [rsp+40h]            ; DRIVER_OBJECT
    test    rcx, rcx
    jz      done
    cmp     qword ptr [rcx + 0E0h], 0 ; MF14 must be populated
    je      deref_and_done            ; (offsets differ on some builds) -> bail safe
    ; Sanity-check the ORIGINAL MajorFunction[14] before we touch anything:
    ; it must be a canonical kernel VA (bits 47-63 all set). If not, bail
    ; WITHOUT patching — better a no-op than a BSOD.
    mov     r8, [rcx + 0E0h]          ; original MajorFunction[14]
    mov     rax, r8
    shr     rax, 3Ah                  ; >> 58
    and     eax, 3FFFFh               ; bits 47..62
    cmp     eax, 3FFFFh
    jne     deref_and_done            ; garbage MF14 -> do NOT install hook
    mov     rax, 0B0B0B0B0B0B0B03h    ; -> hook address
    mov     [rcx + 0E0h], rax         ; MajorFunction[14] = hook
    mov     rcx, [rsp+48h]            ; irp
    mov     rdx, [rcx + 18h]          ; SystemBuffer
    test    rdx, rdx
    jz      deref_and_done
    mov     [rdx], r8                 ; [0] = original dispatch (for injector)
    mov     rax, [rsp+40h]            ; rax = drobj
    mov     [rdx + 8], rax            ; [8] = DRIVER_OBJECT (for injector)
    mov     eax, dword ptr [rax]      ; eax = drobj->Type + drobj->Size
    mov     [rdx + 16], rax           ; [16] = Type+Size
    mov     rax, [rsp + 40h]          ; rax = drobj
    mov     rax, [rax + 40h]          ; rax = DriverName.Buffer
    test    rax, rax
    jz      deref_and_done
    mov     rax, [rax]                ; rax = first 4 wide chars of DriverName
    mov     [rdx + 24], rax           ; [24] = DriverName chars
    mov     rcx, [rsp+48h]            ; irp
    mov     qword ptr [rcx + 38h], 32 ; IoStatus.Information = 32
deref_and_done:
    ; ALWAYS drop the object reference we took (the old stub leaked it)
    mov     rcx, [rsp+40h]
    test    rcx, rcx
    jz      done
    mov     rax, 0B0B0B0B0B0B0B05h    ; -> ObDereferenceObject
    call    rax
done:
    mov     rcx, [rsp+48h]            ; irp
    xor     edx, edx
    mov     rax, 0B0B0B0B0B0B0B02h    ; -> IoCompleteRequest
    call    rax
    xor     eax, eax
    add     rsp, 68h
    ret
installer ENDP

    align 16
disk_name dw 5Ch,'D','r','i','v','e','r',5Ch,'D','i','s','k'

installer_end:
END
