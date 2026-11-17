# Control & threat mapping

| Control in this project | Risk it reduces | MITRE ATT&CK | Framework reference |
|---|---|---|---|
| CA001 MFA for all users | Password spraying, phished credentials | T1110 Brute Force, T1078 Valid Accounts | NIST 800-53 IA-2(1); CIS Control 6 |
| CA002 MFA for admin roles | Privileged account takeover | T1078.004 Cloud Accounts | NIST AC-6, IA-2; CIS 5.4 |
| CA003 Block legacy auth | MFA bypass via IMAP/POP/SMTP | T1110.003 Password Spraying | CIS 6.3 |
| Break-glass group exclusion | Tenant lockout (availability) | n/a | Microsoft emergency-access guidance |
| RBAC groups (01-Setup-Lab) | Excess permissions, privilege creep | T1098 Account Manipulation | NIST AC-2, AC-6 (least privilege) |
| Privileged role audit (03) | Standing admin access | T1078.004, T1098.003 Additional Cloud Roles | NIST AC-6(5); CIS 5.4 |
| Stale / guest / no-MFA audit (04) | Dormant accounts abused by attackers | T1078 Valid Accounts | NIST AC-2(3); CIS 5.3 |
| Offboarding automation (05) | Orphaned access after leavers | T1078; insider misuse | NIST AC-2(2), PS-4 |
