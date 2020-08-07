#define WINDOWS_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

#define SIGNATURE_POLICY_MIN_VALUE 0
#define SIGNATURE_POLICY_MAX_VALUE 32
#define SET_SIGNATURE_POLICY_EXE "SetSignaturePolicy.exe"
#define SEPARATOR " "

typedef struct _TRANSITION {
    SLIST_ENTRY ItemEntry;
    DWORD from;
    DWORD to;
    DWORD mutator;
} TRANSITION, * PTRANSITION;

PTRANSITION first = NULL;
PSLIST_HEADER transitions;

VOID fuzz(LPCSTR arguments, DWORD min, DWORD max)
{
    DWORD ret = 0;

    // Init the new transition list
    PSLIST_HEADER transitions_new = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), MEMORY_ALLOCATION_ALIGNMENT);
    if (transitions_new == NULL)
    {
        printf("Memory allocation failed.\n");
        return -1;
    }
    InitializeSListHead(transitions_new);

    for (DWORD i = min; i < max; ++i)
    {
        // Setup the child process
        STARTUPINFO si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));

        si.cb = sizeof(si);

        CHAR buffer[10] = { 0 };
        _ultoa(i, buffer, 10);

        char command_line[2048] = { 0 };
        strcat(command_line, arguments);
        strcat(command_line, SEPARATOR);
        strcat(command_line, buffer);

        HANDLE parent = CreateEventA(NULL, FALSE, FALSE, "SignaturePolicyFuzzerEvent");
        HANDLE child = CreateEventA(NULL, FALSE, FALSE, "SetSignaturePolicyEvent");
        ResetEvent(parent);
        ResetEvent(child);

        if (CreateProcessA(NULL, command_line, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) == FALSE)
        {
            printf("CreateProcess failed (%d).\n", GetLastError());
            return ERROR;
        }

        // Dump the child code signing policy as our initial state
        WaitForSingleObject(child, INFINITE);

        // Read child's code signing policy
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY old;
        ZeroMemory(&old, sizeof(old));
        if (GetProcessMitigationPolicy(pi.hProcess, ProcessSignaturePolicy, &old, sizeof(old)) == FALSE)
        {
            printf("0x%x\n", GetLastError());
        }

        // Signal child to continue
        SetEvent(parent);

        Sleep(50);

        // Ensure the child is still alive
        GetExitCodeProcess(pi.hProcess, &ret);
        if (ret != STILL_ACTIVE)
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            continue;
        }

        // Wait on child to set it's code signing policy
        WaitForSingleObject(child, INFINITE);

        // read child's code signing policy
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY new;
        ZeroMemory(&new, sizeof(new));
        if (GetProcessMitigationPolicy(pi.hProcess, ProcessSignaturePolicy, &new, sizeof(new)) == FALSE)
        {
            printf("0x%x\n", GetLastError());
        }

        // Signal child to continue
        SetEvent(parent);

        // Wait on the child to exit
        WaitForSingleObject(pi.hProcess, INFINITE);

        GetExitCodeProcess(pi.hProcess, &ret);

        // Cleanup
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // If the child exited successfuly and the state changed
        if (ret == 0 && old.Flags != new.Flags)
        {
            // Ensure this transition is unknown
            BOOL found = FALSE;
            PTRANSITION iter = first;
            while (iter != NULL)
            {
                if (iter->from == old.Flags && iter->to == new.Flags)
                {
                    found = TRUE;
                    break;
                }

                iter = (PTRANSITION)iter->ItemEntry.Next;
            }

            if (!found)
            {
                // Record this transition
                PTRANSITION transition = (PTRANSITION)_aligned_malloc(sizeof(PTRANSITION), MEMORY_ALLOCATION_ALIGNMENT);
                PTRANSITION transition_new = (PTRANSITION)_aligned_malloc(sizeof(PTRANSITION), MEMORY_ALLOCATION_ALIGNMENT);
                if (transition == NULL || transition_new == NULL)
                {
                    printf("Memory allocation failed.\n");
                    return -1;
                }
                transition->from = old.Flags;
                transition->to = new.Flags;
                transition->mutator = i;
                transition_new->from = old.Flags;
                transition_new->to = new.Flags;
                transition_new->mutator = i;

                InterlockedPushEntrySList(transitions, &(transition->ItemEntry));
                InterlockedPushEntrySList(transitions_new, &(transition_new->ItemEntry));

                first = transition;

                // Dump to stdout
                printf("(%d) %d -> %d\n", i, old.Flags, new.Flags);
                if (old.AuditMicrosoftSignedOnly != new.AuditMicrosoftSignedOnly)
                    printf("  + Audit Microsoft Signed Only : %d\n", new.AuditMicrosoftSignedOnly);
                if (old.AuditStoreSignedOnly != new.AuditStoreSignedOnly)
                    printf("  + Audit Store Signed Only : %d\n", new.AuditStoreSignedOnly);
                if (old.MicrosoftSignedOnly != new.MicrosoftSignedOnly)
                    printf("  + Microsoft Signed Only : %d\n", new.MicrosoftSignedOnly);
                if (old.StoreSignedOnly != new.StoreSignedOnly)
                    printf("  + Store Signed Only : %d\n", new.StoreSignedOnly);
                if (old.MitigationOptIn != new.MitigationOptIn)
                    printf("  + Mitigation Opt In : %d\n", new.MitigationOptIn);
                if (old.ReservedFlags != new.ReservedFlags)
                    printf("  + Reserved Flags : %d\n", new.ReservedFlags);
            }
        }
    }

    // For each new transition, fuzz
    PTRANSITION iter = (PTRANSITION)InterlockedPopEntrySList(transitions_new);
    while (iter != NULL)
    {
        // Build the transition to this new state
        CHAR buffer[10] = { 0 };
        _ultoa(iter->mutator, buffer, 10);

        char command_line[2048] = { 0 };
        strcat(command_line, arguments);
        strcat(command_line, SEPARATOR);
        strcat(command_line, buffer);

        // Fuzz that state
        fuzz(command_line, min, max);

        iter = (PTRANSITION)InterlockedPopEntrySList(transitions_new);
    }
}

DWORD main(DWORD argc, PCHAR argv[], PCHAR envp[])
{
    transitions = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), MEMORY_ALLOCATION_ALIGNMENT);

    if (transitions == NULL)
    {
        printf("Memory allocation failed.\n");
        return -1;
    }

    InitializeSListHead(transitions);

    DWORD min = SIGNATURE_POLICY_MIN_VALUE;
    DWORD max = SIGNATURE_POLICY_MAX_VALUE;
    if (argc > 2)
    {
        min = strtoul(argv[1], NULL, 10);
        max = strtoul(argv[2], NULL, 10);
    }

    fuzz(SET_SIGNATURE_POLICY_EXE, min, max);
   
    return TRUE;
}