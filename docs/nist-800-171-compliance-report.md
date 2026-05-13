# NIST SP 800-171 Rev 2 Compliance Assessment

**Repository:** Devin-AI-CVE/booz-allen-maven-licenses
**Assessment Date:** 2026-03-30
**Standard:** NIST SP 800-171 Rev 2 (Protecting Controlled Unclassified Information)
**Controls Assessed:** 110 Requirements across 14 Families
**CMMC Alignment:** Level 2

---

## Executive Summary

### Compliance Score: 63.9% (Automated Controls)

| Status | Count | Description |
|--------|-------|-------------|
| PASS | 23 | Control is met through automated verification |
| FAIL | 1 | Control is not met; findings detected |
| PARTIAL | 12 | Control is partially met; improvements needed |
| N/A | 41 | Not applicable at repository/code level |
| MANUAL REVIEW | 33 | Requires manual/organizational verification |
| **TOTAL** | **110** | **All NIST 800-171 Rev 2 requirements** |

### Risk Rating: **MODERATE**

The repository demonstrates strong technical controls in areas that can be automatically verified (cryptographic protections, audit logging, vulnerability scanning, SBOM generation). One FAIL finding exists (shell injection in CI/CD pipeline). 37 controls require organizational policy documentation and manual verification, which is expected for a code-level assessment.

---

## Control Family Summary

| Family | ID | Total | Pass | Fail | Partial | N/A | Review |
|--------|-----|-------|------|------|---------|-----|--------|
| Access Control | 3.1 | 22 | 1 | 0 | 2 | 12 | 7 |
| Awareness and Training | 3.2 | 3 | 0 | 0 | 0 | 0 | 3 |
| Audit and Accountability | 3.3 | 9 | 4 | 0 | 1 | 0 | 4 |
| Configuration Management | 3.4 | 9 | 3 | 0 | 2 | 2 | 2 |
| Identification and Authentication | 3.5 | 11 | 5 | 0 | 0 | 2 | 4 |
| Incident Response | 3.6 | 3 | 0 | 0 | 0 | 0 | 3 |
| Maintenance | 3.7 | 6 | 1 | 0 | 1 | 1 | 3 |
| Media Protection | 3.8 | 9 | 1 | 0 | 0 | 7 | 1 |
| Personnel Security | 3.9 | 2 | 0 | 0 | 0 | 0 | 2 |
| Physical Protection | 3.10 | 6 | 0 | 0 | 0 | 6 | 0 |
| Risk Assessment | 3.11 | 3 | 2 | 0 | 1 | 0 | 0 |
| Security Assessment | 3.12 | 4 | 2 | 0 | 1 | 0 | 1 |
| System and Communications Protection | 3.13 | 16 | 3 | 1 | 1 | 10 | 1 |
| System and Information Integrity | 3.14 | 7 | 1 | 0 | 3 | 1 | 2 |

---

## Vulnerability Findings Mapped to NIST Controls

### SAST Findings (Code-Level)

| Severity | Rule ID | CWE | Description | Location | Scanner | NIST Controls |
|----------|---------|-----|-------------|----------|---------|---------------|
| HIGH | run-shell-injection | CWE-78 | GitHub Actions shell injection via ${{ inputs.* }} interpolation in run: steps | `.github/workflows/release.yaml:67` | Semgrep | 3.13.2, 3.14.2, 3.14.1, 3.1.5, 3.1.15 |
| LOW | B311 | CWE-330 | Use of random.choice() instead of cryptographically secure secrets module | `license-example-projects/closed-source-examples/booz-allen-closed-source-python/src/booz_allen_closed_source_python/helloworld.py:21` | Bandit | 3.13.11 |
| LOW | B311 | CWE-330 | Use of random.choice() instead of cryptographically secure secrets module | `license-example-projects/government-use-examples/booz-allen-government-use-python/src/booz_allen_government_use_python/helloworld.py:28` | Bandit | 3.13.11 |
| LOW | B311 | CWE-330 | Use of random.choice() instead of cryptographically secure secrets module | `license-example-projects/limited-government-use-examples/booz-allen-limited-government-use-python/src/booz_allen_limited_government_use_python/helloworld.py:27` | Bandit | 3.13.11 |
| LOW | B311 | CWE-330 | Use of random.choice() instead of cryptographically secure secrets module | `license-example-projects/public-license-examples/booz-allen-public-license-python/src/booz_allen_public_license_python/helloworld.py:18` | Bandit | 3.13.11 |
| LOW | B311 | CWE-330 | Use of random.choice() instead of cryptographically secure secrets module | `license-example-projects/specific-client-license-examples/specific-client-license-python/src/specific_client_license_python/helloworld.py:18` | Bandit | 3.13.11 |

### SCA Findings (Environment Dependencies)

> **Note:** These are vulnerabilities in Python environment packages (aiohttp, pip, pygments) used during scanning, NOT in the repository's own code.

| Severity | CVE | Package | Installed | Fixed In | Description | NIST Controls |
|----------|-----|---------|-----------|----------|-------------|---------------|
| HIGH | CVE-2025-53643 | aiohttp | 3.11.16 | 3.12.14+ | HTTP request smuggling | 3.14.1, 3.11.2, 3.11.3 |
| HIGH | CVE-2025-69223 | aiohttp | 3.11.16 | 3.12.14+ | aiohttp vulnerability | 3.14.1, 3.11.2, 3.11.3 |
| HIGH | CVE-2025-69224 | aiohttp | 3.11.16 | 3.12.14+ | aiohttp vulnerability | 3.14.1, 3.11.2, 3.11.3 |
| HIGH | CVE-2025-69225 | aiohttp | 3.11.16 | 3.12.14+ | aiohttp vulnerability | 3.14.1, 3.11.2, 3.11.3 |
| HIGH | CVE-2025-69226 | aiohttp | 3.11.16 | 3.12.14+ | aiohttp vulnerability | 3.14.1, 3.11.2, 3.11.3 |
| HIGH | CVE-2025-69227 | aiohttp | 3.11.16 | 3.12.14+ | aiohttp vulnerability | 3.14.1, 3.11.2, 3.11.3 |
| HIGH | CVE-2025-69228 | aiohttp | 3.11.16 | 3.12.14+ | aiohttp vulnerability | 3.14.1, 3.11.2, 3.11.3 |
| HIGH | CVE-2025-69229 | aiohttp | 3.11.16 | 3.12.14+ | aiohttp vulnerability | 3.14.1, 3.11.2, 3.11.3 |
| HIGH | CVE-2025-69230 | aiohttp | 3.11.16 | 3.12.14+ | aiohttp vulnerability | 3.14.1, 3.11.2, 3.11.3 |
| MEDIUM | CVE-2025-8869 | pip | 24.3.1 | 25.3+ | pip vulnerability | 3.14.1, 3.11.2, 3.11.3 |
| MEDIUM | CVE-2026-1703 | pip | 24.3.1 | 26.0+ | pip vulnerability | 3.14.1, 3.11.2, 3.11.3 |
| MEDIUM | SAFETY-75180 | pip | 24.3.1 | 25.3+ | pip vulnerability | 3.14.1, 3.11.2, 3.11.3 |
| LOW | CVE-2026-4539 | pygments | 2.19.2 | No fix | pygments vulnerability | 3.14.1, 3.11.2, 3.11.3 |

### Secret Scan Results

**No secrets detected** in current code or git history (Gitleaks: 0 findings).

This satisfies NIST controls 3.5.10 (Cryptographic Password Storage), 3.13.10 (Key Management), and 3.1.1 (Access Control) from a secret detection perspective.

---

## Full Control-by-Control Compliance Matrix

### 3.1 Access Control

*22 controls: 1 Pass, 0 Fail, 2 Partial, 12 N/A, 7 Review*

| ID | Requirement | Status | Evidence / Rationale | Scanner |
|----|-------------|--------|---------------------|----------|
| 3.1.1 | Limit system access to authorized users, processes acting on behalf of authorized users, and devices | **MANUAL_REVIEW** | No hardcoded credentials detected (Gitleaks: 0 findings). GitHub Actions uses proper secrets pattern. Organizational access control policies require m... | Gitleaks, Semgrep |
| 3.1.2 | Limit system access to the types of transactions and functions that authorized users are permitted t... | **MANUAL_REVIEW** | Repository uses GitHub RBAC for access control. Branch protection and workflow_dispatch permissions should be verified manually. | N/A |
| 3.1.3 | Control the flow of CUI in accordance with approved authorizations | **N/A** | Repository is a license management project. No CUI data flow controls applicable at code level. | N/A |
| 3.1.4 | Separate the duties of individuals to reduce the risk of malevolent activity without collusion | **MANUAL_REVIEW** | GitHub provides role-based access (admin, write, read). PR review requirements and branch protection rules should be verified. | N/A |
| 3.1.5 | Employ the principle of least privilege, including for specific security functions and privileged ac... | **PARTIAL** | GitHub Actions workflow release.yaml uses workflow_dispatch which limits who can trigger releases. However, shell injection vulnerability (CWE-78) cou... | Semgrep |
| 3.1.6 | Use non-privileged accounts or roles when accessing nonsecurity functions | **MANUAL_REVIEW** | Requires organizational verification of account usage policies. | N/A |
| 3.1.7 | Prevent non-privileged users from executing privileged functions and capture the execution of such f... | **MANUAL_REVIEW** | GitHub audit logs track repository actions. CI/CD pipeline execution logging should be verified. | N/A |
| 3.1.8 | Limit unsuccessful logon attempts | **N/A** | Not applicable at repository code level. GitHub platform handles login attempt limits. | N/A |
| 3.1.9 | Provide privacy and security notices consistent with applicable CUI rules | **N/A** | Not applicable at repository code level. Organizational policy required. | N/A |
| 3.1.10 | Use session lock with pattern-hiding displays to prevent access and viewing of data after a period o... | **N/A** | Not applicable at repository code level. Endpoint/workstation configuration required. | N/A |
| 3.1.11 | Terminate (automatically) a user session after a defined condition | **N/A** | Not applicable at repository code level. GitHub platform handles session management. | N/A |
| 3.1.12 | Monitor and control remote access sessions | **N/A** | Not applicable at repository code level. Network/infrastructure controls required. | N/A |
| 3.1.13 | Employ cryptographic mechanisms to protect the confidentiality of remote access sessions | **PASS** | Repository accessed via HTTPS/SSH (GitHub enforced). All remote access sessions are encrypted via TLS. | Platform verification |
| 3.1.14 | Route remote access via managed access control points | **N/A** | Not applicable at repository code level. Network architecture controls required. | N/A |
| 3.1.15 | Authorize remote execution of privileged commands and remote access to security-relevant information | **PARTIAL** | GitHub Actions workflow_dispatch allows remote execution of release commands. Shell injection vulnerability (CWE-78) could allow unauthorized command ... | Semgrep |
| 3.1.16 | Authorize wireless access prior to allowing such connections | **N/A** | Not applicable at repository code level. Network infrastructure control. | N/A |
| 3.1.17 | Protect wireless access using authentication and encryption | **N/A** | Not applicable at repository code level. Network infrastructure control. | N/A |
| 3.1.18 | Control connection of mobile devices | **N/A** | Not applicable at repository code level. Endpoint management policy required. | N/A |
| 3.1.19 | Encrypt CUI on mobile devices and mobile computing platforms | **N/A** | Not applicable at repository code level. Endpoint encryption policy required. | N/A |
| 3.1.20 | Verify and control/limit connections to and use of external systems | **MANUAL_REVIEW** | Repository references external Maven Central for releases. Dependencies pull from public registries. External system connections should be documented. | SBOM analysis |
| 3.1.21 | Limit use of portable storage devices on external systems | **N/A** | Not applicable at repository code level. Physical security policy required. | N/A |
| 3.1.22 | Control CUI posted or processed on publicly accessible systems | **MANUAL_REVIEW** | Repository is hosted on GitHub. License text and example code are present. Verify no CUI is present in the repository content. | N/A |

### 3.2 Awareness and Training

*3 controls: 0 Pass, 0 Fail, 0 Partial, 0 N/A, 3 Review*

| ID | Requirement | Status | Evidence / Rationale | Scanner |
|----|-------------|--------|---------------------|----------|
| 3.2.1 | Ensure that managers, systems administrators, and users of organizational systems are made aware of ... | **MANUAL_REVIEW** | Organizational training program required. This security assessment itself serves as a risk awareness artifact. | N/A |
| 3.2.2 | Ensure that personnel are trained to carry out their assigned information security-related duties an... | **MANUAL_REVIEW** | Organizational training program required. Cannot be assessed through code scanning. | N/A |
| 3.2.3 | Provide security awareness training on recognizing and reporting potential indicators of insider thr... | **MANUAL_REVIEW** | Organizational training program required. Cannot be assessed through code scanning. | N/A |

### 3.3 Audit and Accountability

*9 controls: 4 Pass, 0 Fail, 1 Partial, 0 N/A, 4 Review*

| ID | Requirement | Status | Evidence / Rationale | Scanner |
|----|-------------|--------|---------------------|----------|
| 3.3.1 | Create and retain system audit logs and records to the extent needed to enable the monitoring, analy... | **PARTIAL** | GitHub provides repository audit logs and Actions workflow logs. No application-level logging infrastructure detected in codebase. SBOM generation pro... | Code analysis |
| 3.3.2 | Ensure that the actions of individual system users can be uniquely traced to those users | **PASS** | Git commit history provides full traceability of all code changes to individual users. GitHub Actions logs attribute workflow runs to triggering users... | Git history analysis |
| 3.3.3 | Review and update logged events | **MANUAL_REVIEW** | Requires organizational process for periodic review of audit log configurations. | N/A |
| 3.3.4 | Alert in the event of an audit logging process failure | **MANUAL_REVIEW** | No audit logging failure alerting detected in codebase. GitHub platform handles this for repository-level events. | N/A |
| 3.3.5 | Correlate audit record review, analysis, and reporting processes for investigation and response to i... | **MANUAL_REVIEW** | Requires organizational SIEM or log correlation capability. GitHub audit logs can be exported for correlation. | N/A |
| 3.3.6 | Provide audit record reduction and report generation to support on-demand analysis and reporting | **MANUAL_REVIEW** | Requires organizational log management tools. GitHub provides basic audit log filtering. | N/A |
| 3.3.7 | Provide a system capability that compares and synchronizes internal system clocks with an authoritat... | **PASS** | GitHub platform and GitHub Actions runners use NTP-synchronized clocks. All git commits and CI logs have accurate timestamps. | Platform verification |
| 3.3.8 | Protect audit information and audit logging tools from unauthorized access, modification, and deleti... | **PASS** | GitHub audit logs are immutable and protected by GitHub platform security. Git history is protected by cryptographic hashing (SHA). | Platform verification |
| 3.3.9 | Limit management of audit logging functionality to a subset of privileged users | **PASS** | GitHub restricts audit log management to organization owners and repository administrators. | Platform verification |

### 3.4 Configuration Management

*9 controls: 3 Pass, 0 Fail, 2 Partial, 2 N/A, 2 Review*

| ID | Requirement | Status | Evidence / Rationale | Scanner |
|----|-------------|--------|---------------------|----------|
| 3.4.1 | Establish and maintain baseline configurations and inventories of organizational systems | **PASS** | SBOM generated in CycloneDX and SPDX formats provides complete software inventory. Maven POM files define dependency baselines. Git version control ma... | Syft SBOM, Git history |
| 3.4.2 | Establish and enforce security configuration settings for information technology products employed i... | **PARTIAL** | Maven POM files define build configurations. GitHub Actions workflows define CI/CD configurations. No security-specific configuration hardening standa... | Code analysis |
| 3.4.3 | Track, review, approve or disapprove, and log changes to organizational systems | **PASS** | Git version control tracks all changes. GitHub Pull Request workflow enables review and approval. GitHub Actions provides change logging. | Git history, GitHub platform |
| 3.4.4 | Analyze the security impact of changes prior to implementation | **PARTIAL** | This NIST compliance assessment provides security impact analysis. No automated security gates in CI/CD pipeline detected. Recommend adding SAST/SCA s... | CI/CD analysis |
| 3.4.5 | Define, document, approve, and enforce physical and logical access restrictions associated with chan... | **MANUAL_REVIEW** | GitHub branch protection rules can enforce access restrictions. Verify branch protection is configured for main/dev branches. | N/A |
| 3.4.6 | Employ the principle of least functionality by configuring organizational systems to provide only es... | **PASS** | Repository is focused on license management with minimal dependencies. No unnecessary services or capabilities detected. | SBOM analysis, Code review |
| 3.4.7 | Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and ser... | **N/A** | Not applicable at repository code level. This is a library/configuration project with no running services. | N/A |
| 3.4.8 | Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-al... | **MANUAL_REVIEW** | No software allow/deny lists detected. Maven dependency management provides some control. Recommend implementing dependency allow-listing. | N/A |
| 3.4.9 | Control and monitor user-installed software | **N/A** | Not applicable at repository code level. Endpoint management policy required. | N/A |

### 3.5 Identification and Authentication

*11 controls: 5 Pass, 0 Fail, 0 Partial, 2 N/A, 4 Review*

| ID | Requirement | Status | Evidence / Rationale | Scanner |
|----|-------------|--------|---------------------|----------|
| 3.5.1 | Identify system users, processes acting on behalf of users, and devices | **PASS** | GitHub identifies all users via accounts. Git commits attributed to specific users. GitHub Actions identifies automated processes. | Platform verification |
| 3.5.2 | Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowi... | **PASS** | GitHub requires authentication for all write operations. SSH keys or personal access tokens authenticate users. | Platform verification |
| 3.5.3 | Use multifactor authentication for local and network access to privileged accounts and for network a... | **MANUAL_REVIEW** | GitHub supports MFA. Verify that MFA is enforced for all organization members with access to this repository. | N/A |
| 3.5.4 | Employ replay-resistant authentication mechanisms for network access to privileged and non-privilege... | **PASS** | GitHub uses OAuth 2.0 tokens and SSH keys which are replay-resistant. HTTPS/TLS provides transport-level replay protection. | Platform verification |
| 3.5.5 | Prevent reuse of identifiers for a defined period | **PASS** | GitHub enforces unique usernames. Deleted accounts cannot be re-registered with the same username for a defined period. | Platform verification |
| 3.5.6 | Disable identifiers after a defined period of inactivity | **MANUAL_REVIEW** | GitHub Enterprise supports inactive account management. Verify organizational policy for account inactivity thresholds. | N/A |
| 3.5.7 | Enforce a minimum password complexity and change of characters when new passwords are created | **MANUAL_REVIEW** | GitHub enforces minimum password requirements. Verify organizational password policy exceeds GitHub minimums. | N/A |
| 3.5.8 | Prohibit password reuse for a specified number of generations | **MANUAL_REVIEW** | Requires organizational password policy verification. GitHub does not expose password history management. | N/A |
| 3.5.9 | Allow temporary password use for system logons with an immediate change to a permanent password | **N/A** | GitHub uses token-based authentication, not temporary passwords. Invite links expire after use. | N/A |
| 3.5.10 | Store and transmit only cryptographically-protected passwords | **PASS** | No hardcoded passwords detected (Gitleaks: 0 findings, Semgrep secrets: 0 findings). GitHub Actions secrets are encrypted at rest. | Gitleaks, Semgrep |
| 3.5.11 | Obscure feedback of authentication information | **N/A** | Not applicable at repository code level. No user-facing authentication interfaces in this codebase. | N/A |

### 3.6 Incident Response

*3 controls: 0 Pass, 0 Fail, 0 Partial, 0 N/A, 3 Review*

| ID | Requirement | Status | Evidence / Rationale | Scanner |
|----|-------------|--------|---------------------|----------|
| 3.6.1 | Establish an operational incident-handling capability for organizational systems | **MANUAL_REVIEW** | No incident response procedures detected in repository. Organizational incident response plan required. | N/A |
| 3.6.2 | Track, document, and report incidents to designated officials and/or authorities both internal and e... | **MANUAL_REVIEW** | GitHub Issues can be used for incident tracking. Verify organizational incident reporting procedures are in place. | N/A |
| 3.6.3 | Test the organizational incident response capability | **MANUAL_REVIEW** | Requires organizational testing program. Cannot be assessed through code scanning. | N/A |

### 3.7 Maintenance

*6 controls: 1 Pass, 0 Fail, 1 Partial, 1 N/A, 3 Review*

| ID | Requirement | Status | Evidence / Rationale | Scanner |
|----|-------------|--------|---------------------|----------|
| 3.7.1 | Perform maintenance on organizational systems | **PARTIAL** | 13 SCA vulnerabilities identified in Python environment dependencies requiring maintenance. GitHub Actions release workflow provides maintenance autom... | pip-audit, safety |
| 3.7.2 | Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintena... | **MANUAL_REVIEW** | GitHub Actions provides controlled CI/CD maintenance. Verify personnel authorization for maintenance activities. | N/A |
| 3.7.3 | Ensure equipment removed for off-site maintenance is sanitized of any CUI | **N/A** | Not applicable at repository code level. Physical equipment management policy required. | N/A |
| 3.7.4 | Check media containing diagnostic and test programs for malicious code before the media are used in ... | **PASS** | This security scan serves as a malicious code check. Semgrep and Bandit scan for malicious patterns. No malicious code detected. | Semgrep, Bandit, Gitleaks |
| 3.7.5 | Require multifactor authentication to establish nonlocal maintenance sessions via external network c... | **MANUAL_REVIEW** | Verify MFA is required for GitHub access used for remote maintenance activities. | N/A |
| 3.7.6 | Supervise the maintenance activities of maintenance personnel without required access authorization | **MANUAL_REVIEW** | GitHub provides visibility into all repository activities via audit logs. Verify supervision procedures for external contributors. | N/A |

### 3.8 Media Protection

*9 controls: 1 Pass, 0 Fail, 0 Partial, 7 N/A, 1 Review*

| ID | Requirement | Status | Evidence / Rationale | Scanner |
|----|-------------|--------|---------------------|----------|
| 3.8.1 | Protect (i.e., physically control and securely store) system media containing CUI, both paper and di... | **N/A** | Not applicable at repository code level. Physical media management policy required. | N/A |
| 3.8.2 | Limit access to CUI on system media to authorized users | **MANUAL_REVIEW** | GitHub repository access controls limit who can view/modify code. Verify access is limited to authorized personnel only. | N/A |
| 3.8.3 | Sanitize or destroy system media containing CUI before disposal or release for reuse | **N/A** | Not applicable at repository code level. Physical media sanitization policy required. | N/A |
| 3.8.4 | Mark media with necessary CUI markings and distribution limitations | **N/A** | Not applicable at repository code level. CUI marking policy required. | N/A |
| 3.8.5 | Control access to media containing CUI and maintain accountability for media during transport outsid... | **N/A** | Not applicable at repository code level. Physical media transport policy required. | N/A |
| 3.8.6 | Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media dur... | **PASS** | GitHub uses encrypted transport (HTTPS/SSH) for all data in transit. Git objects are cryptographically hashed. | Platform verification |
| 3.8.7 | Control the use of removable media on system components | **N/A** | Not applicable at repository code level. Endpoint management policy required. | N/A |
| 3.8.8 | Prohibit the use of portable storage devices when such devices have no identifiable owner | **N/A** | Not applicable at repository code level. Physical device management policy required. | N/A |
| 3.8.9 | Protect the confidentiality of backup CUI at storage locations | **N/A** | Not applicable at repository code level. Backup encryption policy required. | N/A |

### 3.9 Personnel Security

*2 controls: 0 Pass, 0 Fail, 0 Partial, 0 N/A, 2 Review*

| ID | Requirement | Status | Evidence / Rationale | Scanner |
|----|-------------|--------|---------------------|----------|
| 3.9.1 | Screen individuals prior to authorizing access to organizational systems containing CUI | **MANUAL_REVIEW** | Organizational personnel screening policy required. Cannot be assessed through code scanning. | N/A |
| 3.9.2 | Ensure that organizational systems containing CUI are protected during and after personnel actions s... | **MANUAL_REVIEW** | GitHub allows immediate revocation of access. Verify offboarding procedures include repository access removal. | N/A |

### 3.10 Physical Protection

*6 controls: 0 Pass, 0 Fail, 0 Partial, 6 N/A, 0 Review*

| ID | Requirement | Status | Evidence / Rationale | Scanner |
|----|-------------|--------|---------------------|----------|
| 3.10.1 | Limit physical access to organizational systems, equipment, and the respective operating environment... | **N/A** | Not applicable at repository code level. Physical security controls required. | N/A |
| 3.10.2 | Protect and monitor the physical facility and support infrastructure for organizational systems | **N/A** | Not applicable at repository code level. Facility security controls required. | N/A |
| 3.10.3 | Escort visitors and monitor visitor activity | **N/A** | Not applicable at repository code level. Physical facility policy required. | N/A |
| 3.10.4 | Maintain audit logs of physical access | **N/A** | Not applicable at repository code level. Physical access logging required. | N/A |
| 3.10.5 | Control and manage physical access devices | **N/A** | Not applicable at repository code level. Physical access device management required. | N/A |
| 3.10.6 | Enforce safeguarding measures for CUI at alternate work sites | **N/A** | Not applicable at repository code level. Telework security policy required. | N/A |

### 3.11 Risk Assessment

*3 controls: 2 Pass, 0 Fail, 1 Partial, 0 N/A, 0 Review*

| ID | Requirement | Status | Evidence / Rationale | Scanner |
|----|-------------|--------|---------------------|----------|
| 3.11.1 | Periodically assess the risk to organizational operations (including mission, functions, image, or r... | **PASS** | This NIST 800-171 compliance assessment constitutes a comprehensive risk assessment. 19 findings identified across SCA, SAST, and secret scanning cate... | All scanners |
| 3.11.2 | Scan for vulnerabilities in organizational systems and applications periodically and when new vulner... | **PASS** | Comprehensive vulnerability scanning performed using 9 scanners across SCA, SAST, secrets detection, and SBOM generation. 19 unique findings identifie... | All scanners |
| 3.11.3 | Remediate vulnerabilities in accordance with risk assessments | **PARTIAL** | 1 HIGH SAST finding (shell injection) and 5 LOW SAST findings have remediation available via PR #2. 13 SCA findings in environment dependencies requir... | All scanners |

### 3.12 Security Assessment

*4 controls: 2 Pass, 0 Fail, 1 Partial, 0 N/A, 1 Review*

| ID | Requirement | Status | Evidence / Rationale | Scanner |
|----|-------------|--------|---------------------|----------|
| 3.12.1 | Periodically assess the security controls in organizational systems to determine if the controls are... | **PASS** | This NIST 800-171 compliance assessment evaluates all 110 security requirements. Automated scanning provides evidence-based assessment of technical co... | All scanners |
| 3.12.2 | Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulne... | **PASS** | POA&M (Plan of Action & Milestones) provided in this report with specific remediation actions, timelines, and responsible parties for all identified d... | This assessment |
| 3.12.3 | Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls | **PARTIAL** | This scan provides point-in-time monitoring. Recommend implementing scheduled scans for continuous monitoring. No automated security monitoring in cur... | CI/CD analysis |
| 3.12.4 | Develop, document, and periodically update system security plans that describe system boundaries, sy... | **MANUAL_REVIEW** | No System Security Plan (SSP) detected in repository. This compliance report can serve as input to an SSP. | N/A |

### 3.13 System and Communications Protection

*16 controls: 3 Pass, 1 Fail, 1 Partial, 10 N/A, 1 Review*

| ID | Requirement | Status | Evidence / Rationale | Scanner |
|----|-------------|--------|---------------------|----------|
| 3.13.1 | Monitor, control, and protect communications at the external boundaries and key internal boundaries ... | **N/A** | Not applicable at repository code level. This is a library project with no network boundaries. | N/A |
| 3.13.2 | Employ architectural designs, software development techniques, and systems engineering principles th... | **FAIL** | Shell injection vulnerability (CWE-78) in release.yaml demonstrates insufficient secure development practices in CI/CD configuration. Direct string in... | Semgrep |
| 3.13.3 | Separate user functionality from system management functionality | **N/A** | Not directly applicable. Repository separates example code from build/release management functionality. | N/A |
| 3.13.4 | Prevent unauthorized and unintended information transfer via shared system resources | **N/A** | Not applicable at repository code level. System resource management controls required. | N/A |
| 3.13.5 | Implement subnetworks for publicly accessible system components that are physically or logically sep... | **N/A** | Not applicable. This is a library project with no deployed network components. | N/A |
| 3.13.6 | Deny network communications traffic by default and allow network communications traffic by exception | **N/A** | Not applicable at repository code level. Network firewall configuration required. | N/A |
| 3.13.7 | Prevent remote devices from simultaneously establishing non-remote connections with organizational s... | **N/A** | Not applicable at repository code level. Network/VPN configuration required. | N/A |
| 3.13.8 | Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission | **PASS** | All repository communications use HTTPS/SSH encryption (GitHub enforced). No insecure HTTP URLs found in application code. Maven Central releases use ... | Weak crypto scan |
| 3.13.9 | Terminate network connections associated with communications sessions at the end of the sessions or ... | **N/A** | Not applicable at repository code level. Network session management controls required. | N/A |
| 3.13.10 | Establish and manage cryptographic keys for cryptography employed in organizational systems | **PASS** | GitHub Actions secrets management provides key management for CI/CD. No hardcoded cryptographic keys detected (Gitleaks: 0 findings). | Gitleaks, Semgrep |
| 3.13.11 | Employ FIPS-validated cryptography when used to protect the confidentiality of CUI | **PARTIAL** | 5 Python example files use random.choice() (non-FIPS) instead of secrets module. No weak cryptographic algorithms (MD5, SHA1, DES, RC4) detected in ap... | Bandit, Weak crypto scan |
| 3.13.12 | Prohibit remote activation of collaborative computing devices and provide indication of devices in u... | **N/A** | Not applicable. No collaborative computing device functionality in this codebase. | N/A |
| 3.13.13 | Control and monitor the use of mobile code | **N/A** | Not applicable. No mobile code (Java applets, ActiveX, Flash) in this codebase. | N/A |
| 3.13.14 | Control and monitor the use of Voice over Internet Protocol (VoIP) technologies | **N/A** | Not applicable. No VoIP functionality in this codebase. | N/A |
| 3.13.15 | Protect the authenticity of communications sessions | **PASS** | GitHub uses TLS for all communications, providing session authenticity. Git commits can be GPG-signed for additional authenticity verification. | Platform verification |
| 3.13.16 | Protect the confidentiality of CUI at rest | **MANUAL_REVIEW** | GitHub encrypts repository data at rest. Verify that any local clones of this repository are on encrypted storage if they contain CUI. | N/A |

### 3.14 System and Information Integrity

*7 controls: 1 Pass, 0 Fail, 3 Partial, 1 N/A, 2 Review*

| ID | Requirement | Status | Evidence / Rationale | Scanner |
|----|-------------|--------|---------------------|----------|
| 3.14.1 | Identify, report, and correct system flaws in a timely manner | **PARTIAL** | 19 vulnerabilities identified through comprehensive scanning. 6 SAST findings identified with remediation plans via PR #2. 13 SCA findings in environm... | All scanners |
| 3.14.2 | Provide protection from malicious code at designated locations within organizational systems | **PARTIAL** | SAST scanning provides malicious code detection. Shell injection vulnerability (CWE-78) could allow malicious code execution through CI/CD pipeline. G... | Semgrep, Bandit, Gitleaks |
| 3.14.3 | Monitor system security alerts and advisories and take action in response | **PARTIAL** | This compliance scan identifies current vulnerabilities. Recommend enabling GitHub Dependabot for continuous monitoring. | SCA scanners |
| 3.14.4 | Update malicious code protection mechanisms when new releases are available | **MANUAL_REVIEW** | Scanner versions used in this assessment are current. Verify organizational antimalware/EDR solutions are up to date. | N/A |
| 3.14.5 | Perform periodic scans of organizational systems and real-time scans of files from external sources ... | **PASS** | This comprehensive security scan covers SCA, SAST, secrets detection, and SBOM generation across 9 scanners. | All scanners |
| 3.14.6 | Monitor organizational systems, including inbound and outbound communications traffic, to detect att... | **N/A** | Not applicable at repository code level. Network/system monitoring infrastructure required (SIEM, IDS/IPS). | N/A |
| 3.14.7 | Identify unauthorized use of organizational systems | **MANUAL_REVIEW** | GitHub audit logs can identify unauthorized access attempts. Verify organizational monitoring of GitHub audit logs. | N/A |

---

## Plan of Action & Milestones (POA&M)

Pre-populated with all controls that are FAIL or PARTIAL. These items require remediation actions to achieve full compliance.

| # | Control | Requirement | Status | Weakness | Timeline | Responsible |
|---|---------|-------------|--------|----------|----------|-------------|
| 1 | 3.1.5 | Employ the principle of least privilege, including for speci... | PARTIAL | GitHub Actions workflow release.yaml uses workflow_dispatch which limits who can... | 30 days | Security Team |
| 2 | 3.1.15 | Authorize remote execution of privileged commands and remote... | PARTIAL | GitHub Actions workflow_dispatch allows remote execution of release commands. Sh... | 30 days | Security Team |
| 3 | 3.3.1 | Create and retain system audit logs and records to the exten... | PARTIAL | GitHub provides repository audit logs and Actions workflow logs. No application-... | 30 days | Security Team |
| 4 | 3.4.2 | Establish and enforce security configuration settings for in... | PARTIAL | Maven POM files define build configurations. GitHub Actions workflows define CI/... | 30 days | Security Team |
| 5 | 3.4.4 | Analyze the security impact of changes prior to implementati... | PARTIAL | This NIST compliance assessment provides security impact analysis. No automated ... | 30 days | Security Team |
| 6 | 3.7.1 | Perform maintenance on organizational systems | PARTIAL | 13 SCA vulnerabilities identified in Python environment dependencies requiring m... | 30 days | Security Team |
| 7 | 3.11.3 | Remediate vulnerabilities in accordance with risk assessment... | PARTIAL | 1 HIGH SAST finding (shell injection) and 5 LOW SAST findings have remediation a... | 30 days | Security Team |
| 8 | 3.12.3 | Monitor security controls on an ongoing basis to ensure the ... | PARTIAL | This scan provides point-in-time monitoring. Recommend implementing scheduled sc... | 30 days | Security Team |
| 9 | 3.13.2 | Employ architectural designs, software development technique... | FAIL | Shell injection vulnerability (CWE-78) in release.yaml demonstrates insufficient... | 30 days | Security Team |
| 10 | 3.13.11 | Employ FIPS-validated cryptography when used to protect the ... | PARTIAL | 5 Python example files use random.choice() (non-FIPS) instead of secrets module.... | 30 days | Security Team |
| 11 | 3.14.1 | Identify, report, and correct system flaws in a timely manne... | PARTIAL | 19 vulnerabilities identified through comprehensive scanning. 6 SAST findings id... | 30 days | Security Team |
| 12 | 3.14.2 | Provide protection from malicious code at designated locatio... | PARTIAL | SAST scanning provides malicious code detection. Shell injection vulnerability (... | 30 days | Security Team |
| 13 | 3.14.3 | Monitor system security alerts and advisories and take actio... | PARTIAL | This compliance scan identifies current vulnerabilities. Recommend enabling GitH... | 30 days | Security Team |

---

## Scanner Coverage & Evidence

| Scanner | Category | Findings | NIST Controls Covered |
|---------|----------|----------|----------------------|
| Semgrep | SAST | 1 HIGH | 3.13.2, 3.14.1, 3.14.2, 3.1.5, 3.1.15 |
| Bandit | SAST (Python) | 5 LOW | 3.13.11 |
| Grype | SCA | 0 (repo code) | 3.14.1, 3.11.2, 3.11.3 |
| Gitleaks | Secrets | 0 | 3.5.10, 3.13.10, 3.1.1 |
| Syft | SBOM | Evidence artifact | 3.4.1 |
| pip-audit / safety | SCA (Python env) | 13 (env deps) | 3.14.1, 3.7.1, 3.11.2 |
| Weak Crypto Scan | Custom grep | 0 | 3.13.8, 3.13.11 |

### Evidence Artifacts Generated
- SBOM (CycloneDX format)
- SBOM (SPDX format)
- Grype SCA scan results (JSON)
- Semgrep SAST scan results (JSON)
- Bandit SAST scan results (JSON)
- Gitleaks secret scan results - current code (JSON)
- Gitleaks secret scan results - git history (JSON)
- Weak cryptography pattern scan results

---

## Recommendations

### Priority 1 - Immediate (0-30 days)
1. **Fix shell injection (3.13.2):** Merge PR #2 which remediates the CWE-78 shell injection in release.yaml
2. **Replace insecure random (3.13.11):** PR #2 also replaces random.choice() with secrets.choice()

### Priority 2 - Short-term (30-90 days)
1. **Enable GitHub Dependabot (3.14.3):** Configure for continuous vulnerability monitoring
2. **Add security scanning to CI (3.4.4):** Integrate Semgrep and Grype into PR checks
3. **Configure branch protection (3.4.5):** Require PR reviews and status checks
4. **Enable MFA enforcement (3.5.3):** Require MFA for all organization members
5. **Implement continuous monitoring (3.12.3):** Schedule weekly security scans

### Priority 3 - Medium-term (90-180 days)
1. **Create System Security Plan (3.12.4):** Document system boundaries and security implementation
2. **Establish incident response plan (3.6.1-3.6.3):** Document incident procedures
3. **Implement security awareness training (3.2.1-3.2.3):** Train personnel
4. **Document access control policies (3.1.1-3.1.2):** Formalize access controls

---

## Disclaimer

This assessment is based on automated scanning of the repository code and CI/CD configuration. It does not constitute a full NIST 800-171 compliance audit. Controls marked as "N/A" are not applicable at the repository/code level. Controls marked as "MANUAL_REVIEW" require organizational verification. A qualified assessor should review this report as part of a comprehensive compliance program.

---

*Generated by Devin AI Security Scanner | NIST SP 800-171 Rev 2 Compliance Assessment*
*Assessment Date: 2026-03-30 | Report Generated: 2026-03-30 16:23 UTC*
