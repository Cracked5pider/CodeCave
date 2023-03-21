
typedef struct __attribute__((packed))
{
    ULONG ExtendedProcessInfo;
    ULONG ExtendedProcessInfoBuffer;
} EXTENDED_PROCESS_INFORMATION, *PEXTENDED_PROCESS_INFORMATION;

/*!
 * @brief
 *  check if CFG is enforced in this current process.
 *
 * @return
 */
BOOL CfgQueryEnforced(
    VOID
) {
    EXTENDED_PROCESS_INFORMATION ProcInfoEx = { 0 };
    NTSTATUS                     NtStatus   = STATUS_SUCCESS;

    ProcInfoEx.ExtendedProcessInfo       = ProcessControlFlowGuardPolicy;
    ProcInfoEx.ExtendedProcessInfoBuffer = 0;

    /* query if Cfg is enabled or not. */
    if ( ! NT_SUCCESS( NtStatus = NtQueryInformationProcess(
        NtCurrentProcess(),
        ProcessCookie | ProcessUserModeIOPL,
        &ProcInfoEx,
        sizeof( ProcInfoEx ),
        NULL )
    ) ) {
        printf( "NtQueryInformationProcess Failed => %p", NtStatus );
        return FALSE; 
    } 

    printf( "Control Flow Guard Policy Enabled = %s", ProcInfoEx.ExtendedProcessInfoBuffer ? "TRUE" : "FALSE" );
    return ProcInfoEx.ExtendedProcessInfoBuffer;
}

/*!
 * @brief
 *  add module + function to CFG exception list.
 *
 * @param ImageBase
 * @param Function
 */
VOID CfgAddressAdd(
    IN PVOID ImageBase,
    IN PVOID Function
) {
    CFG_CALL_TARGET_INFO Cfg      = { 0 };
    MEMORY_RANGE_ENTRY   MemRange = { 0 };
    VM_INFORMATION       VmInfo   = { 0 };
    PIMAGE_NT_HEADERS    NtHeader = { 0 };
    ULONG                Output   = 0;
    NTSTATUS             NtStatus = STATUS_SUCCESS;

    NtHeader                = C_PTR( ImageBase + ( ( PIMAGE_DOS_HEADER ) ImageBase )->e_lfanew );
    MemRange.NumberOfBytes  = U_PTR( NtHeader->OptionalHeader.SizeOfImage + 0x1000 - 1 ) &~( 0x1000 - 1 );
    MemRange.VirtualAddress = ImageBase;

    /* set cfg target call info */
    Cfg.Flags  = CFG_CALL_TARGET_VALID;
    Cfg.Offset = Function - ImageBase;

    VmInfo.dwNumberOfOffsets = 1;
    VmInfo.plOutput          = &Output;
    VmInfo.ptOffsets         = &Cfg;
    VmInfo.pMustBeZero       = FALSE;
    VmInfo.pMoarZero         = FALSE;

    if ( ! NT_SUCCESS( NtStatus = NtSetInformationVirtualMemory( NtCurrentProcess(), VmCfgCallTargetInformation, 1, &MemRange, &VmInfo, sizeof( VmInfo ) ) ) ) {
        printf( "NtSetInformationVirtualMemory Failed => %p", NtStatus );
    }
}
