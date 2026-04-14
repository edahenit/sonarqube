
# SonarQube Server Upgrade: 2025.4.4 → 2026.1 LTA – User Guide

## Overview

This page describes the main changes and impacts for developers, QA, and security teams when upgrading SonarQube Server from **2025.4.4** to **2026.1 LTA**.  
It focuses on **new features**, **user-visible changes**, and the **compatibility matrix** with common client tools (SonarScanner, Sonar plugins, JDK, etc.).

SonarQube 2026.1 LTA is positioned as the most significant release to date, with a strong focus on:
- AI-native development workflows
- Software supply-chain security (SCA, SBOM, malicious packages)
- Broader compliance coverage (MISRA, OWASP, CWE, LLM-specific reports)
- Improved language coverage (Rust, C/C++, Swift, C#, Java, Python, Kotlin, etc.)
- Faster analysis and better IDE integration [cite:5][cite:8][cite:6]

## Main new features

### AI-native development and IDE

- Tighter integration with AI-native IDEs and agents (Claude Code, Cursor, Windsurf, Gemini).  
- SonarQube MCP Server enables AI agents to query your SonarQube instance for code-quality and security insights before AI-generated code reaches production. [cite:5][cite:2]  
- AI CodeFix (Bring-Your-Own-Model with Azure OpenAI) is now available as a one-click fix directly in VS Code and IntelliJ, without leaving the company’s private AI environment. [cite:2][cite:5]  
- Over 80 new QuickFixes for core JavaScript/TypeScript rules in “SonarQube for IDE”, enabling faster in-IDE remediation. [cite:8]

### Security and software supply chain

- Enhanced Advanced Security with:
  - SCA now generally available for **C/C++** (via Conan and vcpkg). [cite:6][cite:8]  
  - Detection of **malicious packages** using OpenSSF data, with dedicated “blocker” findings. [cite:2][cite:6]  
  - SCA and license information shown directly in IDEs (Visual Studio, IntelliJ, VS Code). [cite:8]  
  - SBOM import (beta) for CycloneDX and SPDX formats, enabling vulnerability analysis for containers, third-party apps, and C/C++ components. [cite:8][cite:6]  
- Updated SAST engines for the top Java, C#, and Python libraries, leading to more accurate security findings. [cite:6][cite:8]  
- Support for more than 450 secret patterns (including 60+ cloud platforms), with improved precision and reduced false positives. [cite:2][cite:8]

### Compliance and standards

- Full coverage of **MISRA C++:2023** (179 rules) for safety-critical systems (automotive, aerospace, medical). [cite:5][cite:8]  
- New and updated reports for:
  - **OWASP MASVS** (Mobile Application Security Verification Standard). [cite:2][cite:8]  
  - **OWASP Top 10 for LLM** (e.g., prompt injection, unsafe outputs). [cite:8]  
  - **CWE Top 25 2024**, **OWASP Mobile Top 10 2024**, and **STIG V6R3** (for Enterprise/Data Center editions). [cite:3]  
- New accessibility and functional-compliance rules (e.g., WCAG-aligned rules for mobile apps). [cite:2][cite:8]

### Language and stack support

- Full analysis support for **Rust**, including integration with Clippy-style checks. [cite:5][cite:8]  
- Full support for:
  - **C# 14 / .NET 10**  
  - **Java 22 / 23 / 24**  
  - **Python 3.14**  
  - **Swift 5.9–6.2**  
  - **Dart 3.8** [cite:5]  
- Improved coverage for AI/ML and data stacks (PyTorch, PySpark, Jupyter notebooks). [cite:5][cite:8]  
- Expanded support for Apex (Salesforce), Ruby on Rails, and for YAML, Bash/Shell, JSON, and GitHub Actions in CI pipelines. [cite:8]

### Performance and UX

- Analyses for **JavaScript, TypeScript, Python, and Kotlin** can be up to **50 % faster** thanks to engine optimizations. [cite:5][cite:8]  
- Existing features such as issue browsing, Quality Gates, and project dashboards work as before, but you may see **more findings** due to new and improved rules. [cite:8]  
- New “sandbox” feature for upgrades: issues caused by new or changed rules on existing code are placed in a sandbox and do **not immediately impact Quality Gates**, reducing the risk of breaking builds after upgrade. [cite:8][cite:16]

## Impact for users

### What developers will see

- More issues and security findings on existing code after the first 2026.1 analysis, especially for:
  - Dependencies (SCA, malicious packages)
  - Misuse of security APIs or data flows (SAST, taint analysis)
  - Secrets and configuration-related issues in scripts (Bash, GitHub Actions, Terraform, etc.) [cite:8][cite:6]  
- More **QuickFix suggestions** directly in the IDE for JavaScript/TypeScript. [cite:8]  
- More contextual feedback inside AI-native IDEs and agents, reducing the need to switch back and forth with the SonarQube web UI. [cite:2][cite:5]  
- For AI-assisted development, better verification of AI-generated code before committing. [cite:5][cite:2]

### Impact on QA / Quality Gates

- Quality Gates may appear **stricter** immediately after the upgrade, because of new rules and improved detection, even if the code did not change. [cite:8]  
- The **sandbox for upgrades** helps mitigate this by isolating “new on old code” issues, so teams can prioritize them without breaking CI/CD. [cite:8][cite:16]  
- QA teams are encouraged to:
  - Re-analyze key projects early after upgrade to establish a new baseline under 2026.1.  
  - Monitor pipeline performance and confirm the expected speed-ups (especially for JS/TS, Python, Kotlin). [cite:5][cite:8]

### Impact on security teams

- Finer-grained visibility into:
  - Supply-chain risks (licenses, CVEs, malicious packages, SBOM-based analysis). [cite:6][cite:8]  
  - Mobile- and LLM-specific security risks (via OWASP MASVS and OWASP Top 10 for LLM reports). [cite:2][cite:8]  
- More security-oriented SAST findings, especially for Java, C#, and Python, thanks to library-aware SAST engines. [cite:6][cite:8]  
- More coverage of secrets and configuration-related issues across CI/CD, scripts, and IaC. [cite:8]

## Compatibility matrix (clients, JDK, plugins)

The following table summarizes the compatibility between SonarQube Server 2026.1 LTA and common client tools and runtime components.

### Tool compatibility

| Tool / Component | Minimum / Recommended version for 2026.1 LTA | Notes |
| --- | --- | --- |
| SonarQube Server | 2026.1 LTA | Direct upgrade path from 2025.1 LTA is supported; 9.9 LTA requires an intermediate step via 2025.1 LTA. [cite:16][cite:40] |
| SonarScanner CLI | ≥ v7.1.x (latest recommended) [cite:28][cite:33] | Older versions may still work if a recent JRE is provided, but latest version recommended. |
| SonarScanner for Maven | ≥ 5.5.0.6356 [cite:28] | This is the minimum SonarSource-documented version for 2026.1. |
| SonarScanner for Gradle | ≥ 5.5.0.6356 [cite:28] | Same compatibility baseline as for Maven. |
| SonarQube Plugin (Jenkins) | Latest “SonarQube Scanner” plugin [cite:28][cite:33] | Provides the recommended SonarScanner and config for 2026.1. |
| JDK (SonarQube Server) | **JDK 21 or JDK 25 required**; JRE 17 and JDK 17 are removed. [cite:14][cite:16] | A full JDK is required, not only a JRE. |
| JDK (build / scanner side) | ≥ JDK 17 recommended; JDK 21 preferred [cite:30][cite:31] | JDK 17 is still tolerated on the client, but newer versions are recommended. |
| Sonar Plugins (official) | Versions listed in the **Plugin Version Matrix** as compatible with 2026.1 LTA [cite:25] | Each plugin has its own compatibility matrix; verify before upgrade. |
| Sonar-C++ plugin (community) | Use the version listed in the **Sonar-C++ Compatibility Matrix** for 2026.1. [cite:26] | Follow the official community matrix for C/C++ support. |
| IDE plugins (IntelliJ, VS Code, VS, Eclipse) | Latest versions of Sonar plugins [cite:5][cite:8] | Required to fully benefit from AI CodeFix, QuickFixes, and SCA-in-IDE features. |

### Environmental / platform notes

- **PostgreSQL**: 2026.1 encourages PostgreSQL 14+; PostgreSQL 13 support is being phased out and should be upgraded where possible. [cite:16][cite:40]  
- **MSSQL**: MSSQL 2016 (13.0) is removed; only 2017, 2019, and 2022 are supported. [cite:16]  
- **Kubernetes/Helm**: The SonarQube Helm chart no longer bundles PostgreSQL; you must manage PostgreSQL separately. [cite:32]  
- **Elasticsearch 8.x** is embedded in 2026.1 and requires write access to `/tmp` on Linux hosts. [cite:14]

## Recommendations before upgrading

- Communicate to teams that **more issues may appear** after the upgrade, due to new and improved rules.  
- Use the **sandbox for upgrades** during the first analyses to avoid immediate Quality-Gate breakage. [cite:8][cite:16]  
- Verify and update:
  - JDK on the SonarQube server
  - Database version (PostgreSQL / MSSQL)
  - SonarScanner versions (CLI, Maven, Gradle, Jenkins plugin) [cite:14][cite:28][cite:16]  
- Identify critical projects (MISRA-compliant, mobile, AI/ML, regulated) and plan a focused review of the first 2026.1 analyses for those.

## How to proceed

- Perform a **test upgrade** on a non-production SonarQube instance first.  
- Re-run analyses on representative projects with the **latest SonarScanner** to observe the new kind of issues generated. [cite:28][cite:8]  
- Once the test is validated, apply the upgrade path to production and adjust Quality Gates or rules according to the new baseline. [cite:16][cite:40]  
