#include <windows.h>
#include <stdio.h>
#include "Native.h"

#define C_PTR( x ) ( PVOID )    x
#define U_PTR( x ) ( UINT_PTR ) x
#define D_API( x ) __typeof__( x ) * x

NTSTATUS
WINAPI
SystemFunction040(
    _Inout_ PVOID Memory,
    _In_    ULONG MemoryLength,
    _In_    ULONG OptionFlags
);

NTSTATUS
WINAPI
SystemFunction041(
    _Inout_ PVOID Memory,
    _In_    ULONG MemoryLength,
    _In_    ULONG OptionFlags
);

typedef struct {
    PVOID NtContinue;
    PVOID NtSetEvent;
    PVOID SystemFunction040;
    PVOID SystemFunction041;
    PVOID WaitForSingleObjectEx;
    PVOID VirtualProtect;
} API;

VOID EkkoEx040(
    _In_ ULONG Sleep
) {
    NTSTATUS Status    = STATUS_SUCCESS;
    CONTEXT  Rop[ 10 ] = { 0 };
    CONTEXT  RopInit   = { 0 };
    HANDLE   EvntTimer = { 0 };
    HANDLE   EvntStart = { 0 };
    HANDLE   EvntEnd   = { 0 };
    HANDLE   Queue     = { 0 };
    HANDLE   Timer     = { 0 };
    DWORD    Delay     = { 0 };
    DWORD    Value     = { 0 };
    API      Api       = { 0 };

    /* image base and size */
    PVOID ImageBase = { 0 };
    ULONG ImageSize = { 0 };

    ImageBase = GetModuleHandleA( NULL );
    ImageSize = ( ( PIMAGE_NT_HEADERS ) ( ImageBase + ( ( PIMAGE_DOS_HEADER ) ImageBase )->e_lfanew ) )->OptionalHeader.SizeOfImage;

    Api.NtContinue            = GetProcAddress( GetModuleHandleA( "Ntdll" ),    "NtContinue"            );
    Api.NtSetEvent            = GetProcAddress( GetModuleHandleA( "Ntdll" ),    "NtSetEvent"            );
    Api.WaitForSingleObjectEx = GetProcAddress( GetModuleHandleA( "Kernel32" ), "WaitForSingleObjectEx" );
    Api.VirtualProtect        = GetProcAddress( GetModuleHandleA( "Kernel32" ), "VirtualProtect"        );
    Api.SystemFunction040     = GetProcAddress( LoadLibraryA( "CryptBase" ), "SystemFunction040" );
    Api.SystemFunction041     = GetProcAddress( LoadLibraryA( "CryptBase" ), "SystemFunction041" );

    printf( "[_] Api.NtContinue            @ %p\n", Api.NtContinue );
    printf( "[_] Api.NtSetEvent            @ %p\n", Api.NtSetEvent );
    printf( "[_] Api.SystemFunction040     @ %p\n", Api.SystemFunction040 );
    printf( "[_] Api.SystemFunction041     @ %p\n", Api.SystemFunction041 );
    printf( "[_] Api.WaitForSingleObjectEx @ %p\n", Api.WaitForSingleObjectEx );
    printf( "[_] Api.VirtualProtect        @ %p\n", Api.VirtualProtect );

    /* create a timer queue */
    if ( ! NT_SUCCESS( RtlCreateTimerQueue( &Queue ) ) ) {
        printf( "[!] RtlCreateTimerQueue Failed: %lx\n", Status );
        goto LEAVE;
    }

    /* create events for starting the rop chain and waiting for the rop chain to finish */
    if ( ! NT_SUCCESS( Status = NtCreateEvent( &EvntStart, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) ||
         ! NT_SUCCESS( Status = NtCreateEvent( &EvntEnd,   EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) )
    ) {
        printf( "[!] NtCreateEvent Failed: %lx\n", Status );
        goto LEAVE;
    }

    printf( "[_] EvntTimer :: %p\n", EvntTimer );
    printf( "[_] EvntStart :: %p\n", EvntStart );
    printf( "[_] EvntEnd   :: %p\n", EvntEnd   );

    /* let's start the rop part of this operation/sleep obf */
    if ( NT_SUCCESS( Status = RtlCreateTimer( Queue, &Timer, C_PTR( RtlCaptureContext ), &RopInit, 0, 0, WT_EXECUTEINTIMERTHREAD ) ) )
    {
        WaitForSingleObject( NtCurrentProcess(), 500 );

        /* at this point we can start preparing the ROPs and execute the timers */
        for ( int i = 0; i < 7; i++ ) {
            memcpy( &Rop[ i ], &RopInit, sizeof( CONTEXT ) );
            Rop[ i ].Rsp -= sizeof( PVOID );
        }

        /* Start of obfuscation chain */
        Rop[ 0 ].Rip = U_PTR( Api.WaitForSingleObjectEx );
        Rop[ 0 ].Rcx = U_PTR( EvntStart );
        Rop[ 0 ].Rdx = U_PTR( INFINITE );
        Rop[ 0 ].R8  = U_PTR( NULL );

        /* Protect */
        Rop[ 1 ].Rip = U_PTR( Api.VirtualProtect );
        Rop[ 1 ].Rcx = U_PTR( ImageBase );
        Rop[ 1 ].Rdx = U_PTR( ImageSize );
        Rop[ 1 ].R8  = U_PTR( PAGE_READWRITE );
        Rop[ 1 ].R9  = U_PTR( &Value );

        /* Encrypt */
        Rop[ 2 ].Rip = U_PTR( Api.SystemFunction040 );
        Rop[ 2 ].Rcx = U_PTR( ImageBase );
        Rop[ 2 ].Rdx = U_PTR( ImageSize );
        Rop[ 2 ].R8  = U_PTR( 0 );

        /* Sleep    */
        Rop[ 3 ].Rip = U_PTR( Api.WaitForSingleObjectEx );
        Rop[ 3 ].Rcx = U_PTR( NtCurrentProcess() );
        Rop[ 3 ].Rdx = U_PTR( Sleep );
        Rop[ 3 ].R8  = U_PTR( FALSE );

        /* Decrypt */
        Rop[ 4 ].Rip = U_PTR( Api.SystemFunction041 );
        Rop[ 4 ].Rcx = U_PTR( ImageBase );
        Rop[ 4 ].Rdx = U_PTR( ImageSize );
        Rop[ 4 ].R8  = U_PTR( 0 );

        /* Protect  */
        Rop[ 5 ].Rip = U_PTR( Api.VirtualProtect );
        Rop[ 5 ].Rcx = U_PTR( ImageBase );
        Rop[ 5 ].Rdx = U_PTR( ImageSize );
        Rop[ 5 ].R8  = U_PTR( PAGE_EXECUTE_READ );
        Rop[ 5 ].R9  = U_PTR( &Value );

        /* End of obfuscation chain */
        Rop[ 6 ].Rip = U_PTR( Api.NtSetEvent );
        Rop[ 6 ].Rcx = U_PTR( EvntEnd );
        Rop[ 6 ].Rdx = U_PTR( NULL );

        /* execute timers */
        for ( int i = 0; i < 7; i++ ) {
            if ( ! NT_SUCCESS( Status = RtlCreateTimer( Queue, &Timer, Api.NtContinue, &Rop[ i ], Delay += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) {
                printf( "[!] RtlCreateTimer Failed: %lx [3]\n", Status );
                goto LEAVE;
            }
        }

        /* trigger/start the rop chain and wait for it to end */
        if ( ! NT_SUCCESS( NtSignalAndWaitForSingleObject( EvntStart, EvntEnd, FALSE, NULL ) ) ) {
            printf( "[!] NtSignalAndWaitForSingleObject Failed: %lx\n", Status );
            goto LEAVE;
        }
    } else {
        printf( "[!] RtlCreateTimer Failed: %lx [1]\n", Status );
    }

LEAVE:
    if ( Queue ) {
        RtlDeleteTimerQueue( Queue );
        Queue = NULL;
    }

    if ( EvntStart ) {
        NtClose( EvntStart );
        EvntStart = NULL;
    }

    if ( EvntEnd ) {
        NtClose( EvntEnd );
        EvntEnd = NULL;
    }
}

int main() {

    puts( "[*] EkkoEx with SystemFunction040 @ C5pider" );

    do {
        puts( "[*] sleeping..." );
        EkkoEx040( 3000 );
        puts( "[*] waking up" );
    } while ( TRUE );
}