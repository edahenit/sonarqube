# 🤖 User Guide — Sonar AI CodeFix

> **Target audience:** Developers, Tech Leads, Quality Teams
> **Prerequisites:** SonarQube Data Center already installed and AI CodeFix enabled by your administrator
> **Version:** SonarQube 2025.x / 2026.x

---

## Table of Contents

1. [What is Sonar AI CodeFix?](#what-is-sonar-ai-codefix)
2. [How to access AI CodeFix?](#how-to-access-ai-codefix)
3. [Using AI CodeFix in SonarQube (Web UI)](#using-ai-codefix-in-sonarqube-web-ui)
4. [Using AI CodeFix in your IDE](#using-ai-codefix-in-your-ide)
5. [Understanding the proposed fix](#understanding-the-proposed-fix)
6. [Supported languages and rules](#supported-languages-and-rules)
7. [Best practices](#best-practices)
8. [FAQ](#faq)

---

## What is Sonar AI CodeFix?

**Sonar AI CodeFix** is a feature built into SonarQube that uses a Large Language Model (LLM) to **automatically suggest a code fix** for issues detected by Sonar analysis.

```
┌─────────────────────────────────────────────────────────────┐
│                    SONAR AI CODEFIX                         │
│                                                             │
│  Sonar Analysis  →  Issue detected  →  Generate AI Fix      │
│                                             ↓               │
│                                    LLM analyses context     │
│                                             ↓               │
│                                    Fix proposal (diff)      │
│                                             ↓               │
│                          Developer: ✅ Apply | ❌ Decline   │
└─────────────────────────────────────────────────────────────┘
```

### What AI CodeFix does

- ✅ Proposes a **code patch** that resolves the Sonar issue
- ✅ Takes into account the **file context** surrounding the issue
- ✅ **Never applies anything automatically** — you stay in control
- ✅ Available in the **web interface** and directly in your **IDE**

### What AI CodeFix does NOT do

- ❌ Does not change the functional behaviour of the code
- ❌ Does not cover all issues (partial coverage per language)
- ❌ Does not replace human review of the proposed fix

---

## How to access AI CodeFix?

AI CodeFix is available in **two ways** depending on your work environment:

```
┌────────────────────────┐       ┌────────────────────────────┐
│   SonarQube Web UI     │       │   Connected IDE            │
│                        │  or   │   VS Code / IntelliJ       │
│   "Generate AI Fix"    │       │   (Connected Mode required)│
│   button on issue      │       │   SonarQube for IDE plugin │
└────────────────────────┘       └────────────────────────────┘
```

> **Note:** The feature must have been enabled by your SonarQube administrator on your project. If you do not see the **Generate AI Fix** button, contact your admin.

---

## Using AI CodeFix in SonarQube (Web UI)

### Step 1 — Open an issue in your project

1. Log in to SonarQube
2. Navigate to your **project**
3. Click on the **Issues** tab

> Filter by severity, type, or language to find the most critical issues to address first.

### Step 2 — Identify an issue eligible for AI CodeFix

Eligible issues display an **AI badge** or a **Generate AI Fix** button when you open the issue detail.

```
┌─────────────────────────────────────────────────────────────┐
│  Issue: S1117 - Variable shadows an outer scope variable    │
│  Severity: Minor   Language: Java   Status: Open            │
│                                                             │
│  [View code]                                                │
│                                                             │
│  ┌──────────────────────────────────┐                       │
│  │  🤖  Generate AI Fix             │  ← AI CodeFix button  │
│  └──────────────────────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

### Step 3 — Generate the fix

1. Click **Generate AI Fix**
2. SonarQube sends the issue context to the configured LLM
3. A fix proposal appears within a few seconds

### Step 4 — Review and apply

A diff view is displayed with the original code (red) and the proposed fix (green):

```diff
- int count = 0;
- for (int count = 0; count < list.size(); count++) {  // ← S1117: shadowing
+ for (int i = 0; i < list.size(); i++) {
      process(list.get(i));
  }
```

- Click **Apply** to accept the fix → SonarQube lets you **open in IDE** or copy the patch
- Click **Decline** to reject the suggestion and fix the issue manually

> ⚠️ **Always review** the proposal before applying. AI CodeFix is an assistant, not a replacement for code review.

---

## Using AI CodeFix in your IDE

Using AI CodeFix in the IDE is the **recommended approach** because you can apply the fix directly in your code without leaving your editor.

### IDE Prerequisites

| IDE | Required plugin |
|-----|-----------------|
| VS Code | SonarQube for VS Code (official extension) |
| IntelliJ IDEA / WebStorm / ... | SonarQube for IntelliJ (official plugin) |

The plugin must be configured in **Connected Mode** to your SonarQube Data Center instance.

### Workflow in VS Code

```
1. Open the relevant file in VS Code
2. Sonar issues appear as squiggly underlines
3. Hover over the issue → SonarQube panel opens
4. Click "Generate AI Fix" in the panel
5. Review the proposed diff in the editor
6. Click "Apply Fix" to integrate the fix
```

```
┌─────────────────────────────────────────────────────────────┐
│  VS Code — SonarQube Panel                                  │
│  ─────────────────────────────────────────────────────────  │
│  Issue: S106 - Standard outputs should not be used          │
│  File: src/main/App.java, line 42                           │
│                                                             │
│  Description: Using System.out or System.err...             │
│                                                             │
│  [Why is this an issue?]  [🤖 Generate AI Fix]              │
└─────────────────────────────────────────────────────────────┘
```

### Workflow in IntelliJ

```
1. Open the file in IntelliJ
2. Sonar annotations are visible in the gutter
3. Alt+Enter on the affected line → Sonar contextual menu
4. Select "SonarQube: Generate AI Fix"
5. Review the diff in the "Sonar AI Fix Preview" window
6. Confirm with "Apply"
```

---

## Understanding the proposed fix

The LLM receives two inputs to generate its proposal:

```
┌──────────────────────────┐    ┌──────────────────────────────┐
│  Code snippet            │    │  Sonar rule description      │
│  (file context)          │ +  │  (e.g. S1117)                │
│                          │    │  + good/bad code examples    │
└──────────────────────────┘    └──────────────────────────────┘
                   ↓
         LLM generates a minimal patch
                   ↓
         Diff displayed to the developer
```

### Confidence levels to keep in mind

| Situation | Recommendation |
|-----------|----------------|
| Simple and obvious fix (rename, bracket, import) | Apply directly after a quick review |
| Logic fix (refactoring, condition) | Read carefully + test before merging |
| Security fix (injection, XSS, ...) | Verify with a security expert if in doubt |
| Complex issue affecting multiple files | Fix manually — AI CodeFix is limited to 1 file |

---

## Supported languages and rules

AI CodeFix is available on a **certified selection of rules** by Sonar for the following languages:

| Language | AI CodeFix Coverage |
|----------|---------------------|
| ☕ Java + Java Security | ✅ Yes (broad coverage) |
| 🟨 JavaScript + JS Security | ✅ Yes (broad coverage) |
| 🔷 TypeScript + TS Security | ✅ Yes (broad coverage) |
| 🐍 Python + Python Security | ✅ Yes |
| 🔷 C# + Roslyn Security | ✅ Yes |
| ⚙️ C++ | ✅ Yes |
| 🎨 CSS | ✅ Yes (selection) |
| 🌐 HTML | ✅ Yes (selection) |

> The full list of eligible rules per language is available in the [official Sonar documentation](https://docs.sonarsource.com/sonarqube-server/2025.2/user-guide/rules/rules-for-ai-codefix).

### Why doesn't the "Generate AI Fix" button appear on some issues?

Two possible reasons:
1. The **rule** for this issue is not yet covered by AI CodeFix
2. The **project** has not been authorized by your administrator — contact your admin

---

## Best practices

### ✅ Do

- **Use AI CodeFix for repetitive issues** (style, dead code, shadowing, unused imports) to reduce the Sonar backlog quickly
- **Always review the diff** before applying, even for small fixes
- **Test the corrected code** (compile + unit tests) before committing
- **Use IDE mode** to apply fixes directly in your working branch
- **Report incorrect fixes** via the Decline button to help Sonar improve the model

### ❌ Avoid

- Applying fixes in bulk without review (LLMs can make mistakes)
- Using AI CodeFix as the sole validation for critical security fixes
- Applying a fix on code you do not understand

---

## FAQ

**Q: Does AI CodeFix automatically modify my code?**
No. AI CodeFix **only proposes** a fix. You must click "Apply" to integrate the change. Nothing is modified without your explicit action.

---

**Q: Is my code sent to an external service?**
It depends on your administrator's configuration. In Data Center mode, the admin may have configured a self-hosted LLM (Ollama, LiteLLM, vLLM), in which case the code never leaves your network. Ask your admin which configuration is in place.

---

**Q: Does the issue remain open after applying the fix?**
Yes, the issue stays open in SonarQube until the corrected code is **analysed** (next Sonar scan, typically on the next push/PR). Once the scan runs, if the fix resolves the issue, it automatically moves to **Closed** status.

---

**Q: Can I use AI CodeFix on a Pull Request?**
Yes. If your project is configured with PR analysis (GitHub, GitLab, Azure DevOps, Bitbucket), issues detected on the PR are eligible for AI CodeFix from the SonarQube interface or from the IDE in connected mode.

---

**Q: What should I do if the proposal is incorrect or incomplete?**
Click **Decline** and fix the issue manually. You can also click **Generate AI Fix** again to get a new proposal (the LLM may return a different result).

---

**Q: Does AI CodeFix work on private projects?**
Yes, provided the administrator has authorized the project in the AI CodeFix configuration of the SonarQube Data Center instance.

---

## Additional resources

| Resource | Link |
|----------|------|
| Official AI CodeFix documentation | [docs.sonarsource.com](https://docs.sonarsource.com/sonarqube-server/ai-capabilities/ai-codefix) |
| Eligible rules per language | [Rules for AI CodeFix](https://docs.sonarsource.com/sonarqube-server/2025.2/user-guide/rules/rules-for-ai-codefix) |
| SonarQube for VS Code | [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=SonarSource.sonarlint-vscode) |
| SonarQube for IntelliJ | [JetBrains Marketplace](https://plugins.jetbrains.com/plugin/7973-sonarlint) |
| Sonar Community | [community.sonarsource.com](https://community.sonarsource.com) |

---

> 📝 *Document maintained by the quality team — Repository [`edahenit/sonarqube`](https://github.com/edahenit/sonarqube)*
