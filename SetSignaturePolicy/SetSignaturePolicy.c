#define WINDOWS_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>

DWORD main(DWORD argc, PCHAR argv[], PCHAR envp[])
{
    DWORD ret = 0;

    BOOL instrument = strcmp(argv[1], "on") == 0;

    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy;

    HANDLE parent = CreateEventA(NULL, FALSE, FALSE, "SignaturePolicyFuzzerEvent");
    HANDLE child = CreateEventA(NULL, FALSE, FALSE, "SetSignaturePolicyEvent");
    
    for (UINT32 i = 1; i < argc; ++i)
    {
        // Signal the parent we are about the set the new policy
        if (i == argc - 1)
        {
            SetEvent(child);
            WaitForSingleObject(parent, INFINITE);
        }

        ZeroMemory(&policy, sizeof(policy));
        policy.Flags = strtoul(argv[i], NULL, 10);
        
        if (SetProcessMitigationPolicy(ProcessSignaturePolicy, &policy, sizeof(policy)) == FALSE)
        {
            ret = GetLastError();
            break;
        }
    }

    // Signal the parent the policy has been applied
    SetEvent(child);
    WaitForSingleObject(parent, INFINITE);

    return ret;
}