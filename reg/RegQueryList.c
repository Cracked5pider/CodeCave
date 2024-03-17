#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

typedef enum _KEY_INFORMATION_CLASS     KEY_INFORMATION_CLASS;
typedef enum _KEY_SET_INFORMATION_CLASS KEY_SET_INFORMATION_CLASS;

#define MmHeapAlloc( size ) HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, size )
#define MmHeapFree( pointer ) HeapFree( GetProcessHeap(), HEAP_ZERO_MEMORY, pointer )

typedef struct _KEY_BASIC_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    _Field_size_bytes_(NameLength) WCHAR Name[1];
} KEY_BASIC_INFORMATION, * PKEY_BASIC_INFORMATION;

NTSYSCALLAPI NTSTATUS NTAPI NtOpenKey(
    _Out_ PHANDLE            KeyHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes
);

NTSYSCALLAPI NTSTATUS NTAPI NtEnumerateKey(
    _In_                           HANDLE                KeyHandle,
    _In_                           ULONG                 Index,
    _In_                           KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID                 KeyInformation,
    _In_                           ULONG                 Length,
    _Out_                          PULONG                ResultLength
);

int main()
{
    NTSTATUS               Status   = { 0 };
    HANDLE                 Key      = { 0 };
    UNICODE_STRING         KeyPath  = { 0 };
    OBJECT_ATTRIBUTES      KeyAttr  = { 0 };
    PKEY_BASIC_INFORMATION KeyInfo  = { 0 };
    ULONG                  KeyIndex = { 0 };
    ULONG                  Length   = { 0 };

    RtlSecureZeroMemory( &KeyPath, sizeof( KeyPath ) );
    RtlSecureZeroMemory( &KeyAttr, sizeof( KeyAttr ) );

    //
    // create an unicode string key path 
    //
    RtlInitUnicodeString( &KeyPath, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ); 

    //
    // initialize object attributes 
    //
    InitializeObjectAttributes( &KeyAttr, &KeyPath, OBJ_CASE_INSENSITIVE, 0, 0 );

    //
    // open registry key 
    //
    if ( ! NT_SUCCESS( Status = NtOpenKey( &Key, KEY_ALL_ACCESS, &KeyAttr ) ) ) {
        printf( "[-] NtOpenKey Failed: %lx\n", Status );
        goto END;
    }
    printf( "[*] Opened key path [%ls] :: %x\n", KeyPath.Buffer, Key );

    //
    // starting to enumerate keys 
    //
    do {
        //
        // first get the size of the key info
        //
        Status = NtEnumerateKey( Key, KeyIndex, 0, NULL, 0, &Length );

        //
        // allocate memory for the key info
        //
        if ( ! ( KeyInfo = MmHeapAlloc( Length * sizeof( KEY_BASIC_INFORMATION ) ) ) ) {
            goto END_OF_ENUM;
        }

        //
        // enumerate keys inside of the opened path
        //
        if ( ! NT_SUCCESS( Status = NtEnumerateKey( Key, KeyIndex, 0, KeyInfo, Length, &Length ) ) ) {
            //
            // STATUS_NO_MORE_ENTRIES
            //
            if ( Status != 0x8000001A ) {
                printf("[-] NtEnumerateKey Failed: %lx\n", Status);
            }
            goto END_OF_ENUM; 
        }

        printf(" [%ld] -> %ls\n", KeyIndex, KeyInfo->Name );

        KeyIndex++;

    END_OF_ENUM:
        if ( KeyInfo ) {
            RtlSecureZeroMemory( KeyInfo, Length );
            MmHeapFree( KeyInfo );
            KeyInfo = NULL; 
        }
    } while ( NT_SUCCESS( Status ) );


END:
    if ( Key ) {
        CloseHandle( Key );
        Key = NULL;
    }
}
