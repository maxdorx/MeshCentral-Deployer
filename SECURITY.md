# Security policy

Report security issues privately to the maintainer responsible for your deployment. Do not include domain credentials, MeshCentral agent binaries, `.msh` contents, or production database files in public reports.

Operational hardening:

- use a dedicated domain account and a long random password
- grant target local-administrator membership through a narrowly scoped GPO
- deny interactive and Remote Desktop logon to the deployment account where compatible with policy
- restrict the deployer host and its local Administrators group
- code-sign the installer, service, setup tool, remote runner, and MeshAgent before production use
- limit Remote Service Management and SMB firewall rules to the deployer host
- monitor Windows service-install events and the deployer's SQLite/event logs
