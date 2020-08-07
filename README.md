# SignaturePolicyFuzzer
A stupid SetProcessMitigationPolicy fuzzer

## Description
This small program fuzz the `ntdll!SetProcessMitigationPolicy` function. The goal was to identify all the possible policy transition without reversing the `NtSetInformationProcess` syscall.

For a 1909 kernel this yelds the following output
```
(1) 0 -> 5
  + Microsoft Signed Only : 1
  + Mitigation Opt In : 1
(4) 0 -> 4
  + Mitigation Opt In : 1
(8) 0 -> 12
  + Audit Microsoft Signed Only : 1
  + Mitigation Opt In : 1
(16) 0 -> 20
  + Audit Store Signed Only : 1
  + Mitigation Opt In : 1
(1) 20 -> 5
  + Audit Store Signed Only : 0
  + Microsoft Signed Only : 1
(8) 20 -> 12
  + Audit Microsoft Signed Only : 1
  + Audit Store Signed Only : 0
(1) 12 -> 5
  + Audit Microsoft Signed Only : 0
  + Microsoft Signed Only : 1
(16) 12 -> 20
  + Audit Microsoft Signed Only : 0
  + Audit Store Signed Only : 1
(1) 4 -> 5
  + Microsoft Signed Only : 1
(8) 4 -> 12
  + Audit Microsoft Signed Only : 1
(16) 4 -> 20
  + Audit Store Signed Only : 1
```

which demonstrates that once a code signing mitigation policy is applied, one cannot simply downgrade it via this function.
