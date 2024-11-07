#include <netfw.h>
#include <objbase.h>
#include <stdio.h>

int main()
{
	HRESULT		   HResult           = {};
	INetFwPolicy2* FwPolicy          = {};
	INetFwRules*   FwRules           = {};
	INetFwRule*	   FwRule            = {};
	LONG		   FwRulesCount      = {};
	IUnknown*	   FwEnumUnknown     = {};
	IEnumVARIANT*  FwEnumVariant     = {};
	VARIANT		   FwVariant	     = {};
	BSTR		   FwRuleName        = {};
	BSTR		   FwRuleApplication = {};
	BSTR		   FwRuleDescription = {};
	BSTR		   FwRuleRemoteAddr  = {};
	VARIANT_BOOL   FwRuleEnabled     = {};

	//
	// initialize the COM library for the
	// calling thread with an apartment model 
	//

	if ( FAILED( HResult = CoInitializeEx( nullptr, COINIT_APARTMENTTHREADED ) ) ) {
		printf("[-] CoInitialize Failed: %x\n", HResult );
		goto LEAVE;
	};

	//
	// create the firewall policy instance 
	//

	if ( FAILED( HResult = CoCreateInstance(
		CLSID_NetFwPolicy2, nullptr, CLSCTX_INPROC_SERVER,
		IID_INetFwPolicy2,  reinterpret_cast<PVOID*>( &FwPolicy )
	) ) ) {
		printf( "[-] CoCreateInstance Failed: %x\n", HResult );
		goto LEAVE;
	};

	if ( FAILED( HResult = FwPolicy->get_Rules( &FwRules ) ) ) {
		printf("[-] FwPolicy->get_Rules Failed: %x\n", HResult );
		goto LEAVE;
	};
	
	if ( FAILED( HResult = FwRules->get_Count( &FwRulesCount ) ) ) {
		printf("[-] FwRules->get_Count Failed: %x\n", HResult );
		goto LEAVE;
	};

	if ( FAILED( HResult = FwRules->get__NewEnum( &FwEnumUnknown ) ) ) {
		printf("[-] FwRules->get__NewEnum Failed: %x\n", HResult);
		goto LEAVE;
	};

	if ( FAILED( HResult = FwEnumUnknown->QueryInterface( 
	    __uuidof( IEnumVARIANT ), 
		reinterpret_cast<PVOID*>( &FwEnumVariant )
	) ) ) {
		printf("[-] FwEnumUnknown->QueryInterface Failed: %x\n", HResult);
		goto LEAVE;
	};

	//
	// iterate over the firewall rules 
	//

	VariantInit( &FwVariant );
	while ( FwEnumVariant->Next( 1, &FwVariant, nullptr ) == S_OK ) {
		//
		// check if this variant holds an IDispatch COM object 
		//
	    if ( V_VT( &FwVariant ) == VT_DISPATCH ) {
			//
			// query the INetFwRule object 
			//
			if ( SUCCEEDED( HResult = V_DISPATCH( &FwVariant )->QueryInterface( 
			    __uuidof( INetFwRule ), 
				reinterpret_cast<PVOID*>( &FwRule ) 
			) ) ) {
				//
				// get the firewall rule name, application and description 
				//

				if ( FAILED( HResult = FwRule->get_Name( &FwRuleName ) ) ) {
					printf("[-] FwRule->get_Name Failed: %x\n", HResult );
				};

				if ( FAILED( HResult = FwRule->get_ApplicationName( &FwRuleApplication ) ) ) {
					printf( "[-] FwRule->get_ApplicationName Failed: %x\n", HResult );
				};

				if ( FAILED( HResult = FwRule->get_Description( &FwRuleName ) ) ) {
					printf( "[-] FwRule->get_Description Failed: %x\n", HResult );
				};

				if ( FAILED( HResult = FwRule->get_RemoteAddresses( &FwRuleRemoteAddr ) ) ) {
					printf( "[-] FwRule->get_RemoteAddresses Failed: %x\n", HResult );
				};

				if ( FAILED( HResult = FwRule->get_Enabled( &FwRuleEnabled ) ) ) {
					printf( "[-] FwRule->get_Enabled Failed: %x\n", HResult );
				};

				//
				// display firewall rule properties 
				//

				printf(
				    "[=] %ls:\n"
					"    ApplicationName. . . : %ls\n"
					"    Description. . . . . : %ls\n"
					"    Remote Address . . . : %ls\n"
					"    Enabled. . . . . . . : %ls\n"
                    "\n",
					FwRuleName, 
					FwRuleApplication,
					FwRuleDescription,
					FwRuleRemoteAddr,
					FwRuleEnabled == 0 ? L"FALSE" : L"TRUE"
				);

				if ( FwRuleName ) {
				    SysFreeString( FwRuleName );
					FwRuleName = nullptr;
				};

				if ( FwRuleApplication ) {
				    SysFreeString( FwRuleApplication );
					FwRuleApplication = nullptr;
				};

				if ( FwRuleDescription ) {
				    SysFreeString( FwRuleDescription );
					FwRuleDescription = nullptr;
				};

				if ( FwRuleRemoteAddr ) {
				    SysFreeString( FwRuleRemoteAddr );
					FwRuleRemoteAddr = nullptr;
				};

				FwRule->Release();
			} else {
				printf("[-] V_DISPATCH( &FwVariant )->QueryInterface Failed: %x\n", HResult);
			}
	    }

		VariantClear( &FwVariant );
	}

	printf( "[*] Firewall rules: %ld\n", FwRulesCount );

LEAVE:
    if ( FwEnumVariant ) {
		FwEnumVariant->Release();
		FwEnumVariant = nullptr;
    }

    if ( FwEnumUnknown ) {
		FwEnumUnknown->Release();
		FwEnumUnknown = nullptr;
    }

    if ( FwRules ) {
		FwRules->Release();
		FwRules = nullptr; 
    };

	if ( FwPolicy ) {
	    FwPolicy->Release();
		FwPolicy = nullptr;
	};

	CoUninitialize();
}
