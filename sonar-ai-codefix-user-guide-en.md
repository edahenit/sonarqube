# 🤖 User Guide — Sonar AI CodeFix

> **Target audience:** Developers, Tech Leads, Quality Teams
> **Prerequisites:** SonarQube Data Center already installed and AI CodeFix enabled by your administrator
> **Version:** SonarQube Server **2026.2**
> **LLM Configuration:** Self-Hosted Gateway (OpenAI-compatible)

---

## Table of Contents

1. [What is Sonar AI CodeFix?](#what-is-sonar-ai-codefix)
2. [Self-hosted LLM architecture](#self-hosted-llm-architecture)
3. [How to access AI CodeFix?](#how-to-access-ai-codefix)
4. [Using AI CodeFix in SonarQube (Web UI)](#using-ai-codefix-in-sonarqube-web-ui)
5. [Using AI CodeFix in your IDE](#using-ai-codefix-in-your-ide)
6. [Understanding the proposed fix](#understanding-the-proposed-fix)
7. [Supported languages and rules](#supported-languages-and-rules)
8. [Best practices](#best-practices)
9. [FAQ](#faq)
10. [Additional resources](#additional-resources)

---

## What is Sonar AI CodeFix?

**Sonar AI CodeFix** is a feature built into SonarQube Server (**Enterprise and Data Center editions**) that uses a Large Language Model (LLM) to **automatically suggest a code fix** for issues detected by Sonar analysis.

In your configuration, the LLM used is a **self-hosted OpenAI-compatible model** (Self-Hosted Gateway). Your code never leaves your internal network.

```
┌─────────────────────────────────────────────────────────────┐
│                    SONAR AI CODEFIX                         │
│                                                             │
│  Sonar Analysis  →  Issue detected  →  Generate AI Fix      │
│                                             ↓               │
│                       Self-hosted LLM (OpenAI-compatible)   │
│                           [your internal infrastructure]    │
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
- ✅ Available in the **web interface** and directly in your **IDE** (VS Code, IntelliJ)
- ✅ **No outbound internet required** — your code stays within your internal network
- ✅ **No Sonar usage quotas** — monthly Sonar limits do not apply in self-hosted mode

### What AI CodeFix does NOT do

- ❌ Does not change the functional behaviour of the code
- ❌ Does not cover all issues (partial, certified rule coverage)
- ❌ Does not replace human review of the proposed fix
- ❌ Limited to **a single file** per fix

---

## Self-hosted LLM architecture

In your configuration, SonarQube Data Center 2026.2 communicates directly with your **OpenAI-compatible LLM gateway** hosted within your infrastructure.

```
┌────────────────────────┐   HTTP(S)   ┌──────────────────────────┐
│  SonarQube Server      │ ---------> │  Self-Hosted Gateway    │
│  Data Center 2026.2   │            │  (OpenAI-compatible)    │
│                        │            │                        │
│  [AI CodeFix request]  │            │  Ollama / LiteLLM /    │
│  snippet + Sonar rule  │            │  vLLM / other          │
└────────────────────────┘            └──────────────────────────┘
         |                                        |
         |           INTERNAL NETWORK ONLY        |
         └────────────────────────────────────────┘
                   No outbound internet traffic
```

### Network requirement

> The SonarQube Server instance must be able to **reach your LLM endpoint**. That is the only network requirement. No outbound internet access needs to be opened.

### Administrator configuration (reference)

The administrator configured AI CodeFix under **Administration > Configuration > General Settings > AI CodeFix** with the following parameters:

| Parameter | Description | Example |
|-----------|-------------|---------|
| **Provider** | Self-Hosted Gateway | `openai-compatible` |
| **API Endpoint URL** | URL of your internal gateway | `https://llm.internal.mycompany.com/v1` |
| **API Key** | Authentication key for your gateway | `sk-xxxx...` |
| **Model** | Model name served by your gateway | `gpt-4o`, `llama3`, `mistral`, etc. |
| **Timeout** | Max wait time (ms) | `60000` |
| **Authorized projects** | All or selected projects | per configuration |

---

## How to access AI CodeFix?

AI CodeFix is available in **two ways** depending on your work environment:

```
┌────────────────────────┐       ┌────────────────────────────┐
│   SonarQube Web UI     │       │   Connected IDE            │
│                        │  or   │   VS Code / IntelliJ       │
│  "✨ Generate AI Fix"  │       │   (Connected Mode required)│
│   button on issue      │       │   ✨ sparkle icon on issue  │
└────────────────────────┘       └────────────────────────────┘
```

> **Note:** If you do not see the **✨ Generate AI Fix** button, either your project has not been authorized by your administrator, or the rule of the issue is not covered by AI CodeFix.

---

## Using AI CodeFix in SonarQube (Web UI)

### Step 1 — Open an issue in your project

1. Log in to SonarQube
2. Navigate to your **project**
3. Click on the **Issues** tab

> Filter by severity, type, or language to find the most critical issues to address first.

### Step 2 — Identify an issue eligible for AI CodeFix

Eligible issues display a **✨ sparkle icon** or a **✨ Generate AI Fix** button.

```
┌─────────────────────────────────────────────────────────────┐
│  Issue: S1117 - Variable shadows an outer scope variable    │
│  Severity: Minor   Language: Java   Status: Open            │
│                                                             │
│  [View code]                                                │
│                                                             │
│  ┌──────────────────────────────────┐                       │
│  │  ✨  Generate AI Fix             │  ← AI CodeFix button  │
│  └──────────────────────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

### Step 3 — Generate the fix

1. Click **✨ Generate AI Fix**
2. SonarQube sends the code snippet + rule description to your internal LLM gateway
3. A fix proposal appears within a few seconds

> ⏱️ Response time depends on your self-hosted LLM infrastructure performance.

### Step 4 — Review and apply

A diff view is displayed with the original code (red) and the proposed fix (green):

```diff
- int count = 0;
- for (int count = 0; count < list.size(); count++) {  // ← S1117: shadowing
+ for (int i = 0; i < list.size(); i++) {
      process(list.get(i));
  }
```

- Click **Apply** to accept the fix → SonarQube lets you **Open in IDE** or copy the patch
- Click **Decline** to reject the suggestion and fix the issue manually

> ⚠️ **Always review** the proposal before applying. AI CodeFix is an assistant, not a replacement for code review.

---

## Using AI CodeFix in your IDE

Using AI CodeFix in the IDE is the **recommended approach** because you can apply the fix directly in your code without leaving your editor.

### IDE Prerequisites

| IDE | Required plugin |
|-----|-----------------|
| VS Code | [SonarQube for VS Code](https://docs.sonarsource.com/sonarqube-for-vs-code/) (official extension) |
| IntelliJ IDEA / WebStorm / ... | [SonarQube for IntelliJ](https://docs.sonarsource.com/sonarqube-for-intellij/) (official plugin) |

The plugin must be configured in **Connected Mode** to your SonarQube Data Center 2026.2 instance.

### Workflow in VS Code

```
1. Open the relevant file in VS Code
2. Issues eligible for AI CodeFix show a ✨ sparkle icon in the gutter
3. Hover over the issue → SonarQube panel opens
4. Open "Rule Description" tab → select "✨ AI CodeFix" tab
5. Click "✨ Generate Fix"
   └→ Request is sent to your internal LLM gateway
6. Review the proposed diff in the editor
7. Click "Apply" or "Decline"
```

```
┌─────────────────────────────────────────────────────────────┐
│  VS Code — SonarQube Panel                                  │
│  ─────────────────────────────────────────────────────────  │
│  Issue ✨ : S106 - Standard outputs should not be used       │
│  File: src/main/App.java, line 42                           │
│                                                             │
│  [Why is this an issue?]  [✨ AI CodeFix]                   │
│                                                             │
│  > ✨ Generate Fix  → [internal LLM gateway]               │
└─────────────────────────────────────────────────────────────┘
```

### Workflow in IntelliJ

```
1. Open the file in IntelliJ
2. Sonar ✨ annotations are visible in the gutter
3. Click the ✨ icon → Rule Description panel opens
4. Select the "✨ AI CodeFix" tab → click "✨ Generate Fix"
   └→ Request is sent to your internal LLM gateway
5. Review the diff in the "Sonar AI Fix Preview" window
6. Confirm with "Apply" or reject with "Decline"
```

---

## Understanding the proposed fix

The LLM receives two inputs to generate its proposal:

```
┌──────────────────────────┐    ┌──────────────────────────────┐
│  Code snippet            │    │  Certified Sonar rule desc. │
│  (file context)          │ +  │  (e.g. S1117)                │
│                          │    │  + good/bad code examples    │
└──────────────────────────┘    └──────────────────────────────┘
                   ↓
     Your self-hosted OpenAI-compatible LLM generates a patch
                   ↓
         Diff displayed to the developer
```

> **Privacy:** In your self-hosted configuration, the code sent to the LLM **never leaves your internal network**. Sonar rule descriptions and prompts are embedded in the SonarQube Server installation and require no internet call.

### Confidence levels to keep in mind

| Situation | Recommendation |
|-----------|----------------|
| Simple and obvious fix (rename, bracket, import) | Apply directly after a quick review |
| Logic fix (refactoring, condition) | Read carefully + test before merging |
| Security fix (injection, XSS, ...) | Verify with a security expert if in doubt |
| Complex issue affecting multiple files | Fix manually — AI CodeFix is limited to 1 file |

---

## Supported languages and rules

AI CodeFix (2026.2) is available on a **certified selection of rules** validated by Sonar for the following languages:

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

> The full list of eligible rules per language is available in the [official Sonar documentation — SonarQube Server 2026.1 LTA](https://docs.sonarsource.com/sonarqube-server/2026.1/quality-standards-administration/managing-rules/rules-for-ai-codefix).

### Why doesn't the "✨ Generate AI Fix" button appear on some issues?

| Reason | Action |
|--------|--------|
| The rule is not covered by AI CodeFix | Check the eligible rules list |
| The project is not authorized by the admin | Contact your SonarQube administrator |
| Connection error with the self-hosted LLM | Contact your SonarQube administrator |

---

## Best practices

### ✅ Do

- **Use AI CodeFix for repetitive issues** (style, dead code, shadowing, unused imports) to reduce the Sonar backlog quickly
- **Always review the diff** before applying, even for small fixes
- **Test the corrected code** (compile + unit tests) before committing
- **Use IDE mode** to apply fixes directly in your working branch
- **Report incorrect fixes** via the Decline button

### ❌ Avoid

- Applying fixes in bulk without review (LLMs can make mistakes)
- Using AI CodeFix as the sole validation for critical security fixes
- Applying a fix on code you do not understand

---

## FAQ

**Q: Does AI CodeFix automatically modify my code?**
No. AI CodeFix **only proposes** a fix. You must click "Apply" to integrate the change.

---

**Q: Is my code sent to an external service?**
**No.** In your self-hosted configuration, the code snippet is sent to your internal LLM gateway only. **No data leaves your network.** Sonar rule descriptions and prompts are embedded in the SonarQube installation.

---

**Q: Are there usage limits?**
**No.** Sonar's monthly quotas do not apply in self-hosted mode. Limits from your own LLM infrastructure (RAM, GPU, concurrency) may still apply.

---

**Q: Does the issue remain open after applying the fix?**
Yes, until the next Sonar scan (push / PR). Once analysed, if the fix resolves the issue, it automatically moves to **Closed** status.

---

**Q: Can I use AI CodeFix on a Pull Request?**
Yes. If your project is configured with PR analysis (GitHub, GitLab, Azure DevOps, Bitbucket), issues detected on the PR are eligible for AI CodeFix.

---

**Q: What if the generation fails or is slow?**
In self-hosted mode, errors or slow responses usually come from your LLM gateway (insufficient resources, timeout too low). Contact your SonarQube administrator to check the provider configuration.

---

**Q: What should I do if the proposal is incorrect or incomplete?**
Click **Decline** and fix the issue manually. You can also click **✨ Generate AI Fix** again to get a new proposal.

---

## Additional resources

| Resource | Link |
|----------|------|
| AI CodeFix documentation — SonarQube Server 2026.2 | [docs.sonarsource.com/sonarqube-server/ai-capabilities/ai-codefix](https://docs.sonarsource.com/sonarqube-server/ai-capabilities/ai-codefix) |
| Enable AI CodeFix (admin) | [Enable AI CodeFix — 2026.2](https://docs.sonarsource.com/sonarqube-server/instance-administration/ai-features/enable-ai-codefix) |
| Eligible rules per language | [Rules for AI CodeFix — 2026.1 LTA](https://docs.sonarsource.com/sonarqube-server/2026.1/quality-standards-administration/managing-rules/rules-for-ai-codefix) |
| AI CodeFix in VS Code | [docs.sonarsource.com/sonarqube-for-vs-code](https://docs.sonarsource.com/sonarqube-for-vs-code/ai-capabilities/ai-codefix) |
| AI CodeFix in IntelliJ | [docs.sonarsource.com/sonarqube-for-intellij](https://docs.sonarsource.com/sonarqube-for-intellij/ai-capabilities/ai-codefix) |
| Sonar Community | [community.sonarsource.com](https://community.sonarsource.com) |

---

> 📝 *Document maintained by the quality team — Repository [`edahenit/sonarqube`](https://github.com/edahenit/sonarqube)*
