# 🤖 Guide Utilisateur — Sonar AI CodeFix

> **Public cible :** Développeurs, Tech Leads, Équipes qualité  
> **Prérequis :** SonarQube Data Center déjà installé et AI CodeFix activé par l'administrateur  
> **Version :** SonarQube Server **2026.2**  
> **Configuration LLM :** Self-Hosted Gateway (compatible OpenAI)

---

## Table des matières

1. [Qu'est-ce que Sonar AI CodeFix ?](#quest-ce-que-sonar-ai-codefix-)
2. [Architecture LLM self-hosted](#architecture-llm-self-hosted)
3. [Comment accéder à AI CodeFix ?](#comment-accéder-à-ai-codefix-)
4. [Utiliser AI CodeFix dans SonarQube (Web UI)](#utiliser-ai-codefix-dans-sonarqube-web-ui)
5. [Utiliser AI CodeFix dans l'IDE](#utiliser-ai-codefix-dans-lide)
6. [Comprendre la proposition de correctif](#comprendre-la-proposition-de-correctif)
7. [Langages et règles supportés](#langages-et-règles-supportés)
8. [Bonnes pratiques](#bonnes-pratiques)
9. [FAQ](#faq)
10. [Ressources complémentaires](#ressources-complémentaires)

---

## Qu'est-ce que Sonar AI CodeFix ?

**Sonar AI CodeFix** est une fonctionnalité intégrée à SonarQube Server (**editions Enterprise et Data Center**) qui utilise un grand modèle de langage (LLM) pour **proposer automatiquement une correction de code** sur les issues détectées par l'analyse Sonar.

Dans votre configuration, le LLM utilisé est un **modèle auto-hébergé compatible OpenAI** (Self-Hosted Gateway). Le code ne quitte jamais votre réseau interne.

```
┌─────────────────────────────────────────────────────────────┐
│                    SONAR AI CODEFIX                         │
│                                                             │
│  Analyse Sonar  →  Issue détectée  →  Generate AI Fix       │
│                                             ↓               │
│                           LLM self-hosted (compatible OpenAI)│
│                           [votre infrastructure interne]    │
│                                             ↓               │
│                                    Proposition de correctif │
│                                             ↓               │
│                          Développeur : ✅ Apply | ❌ Decline │
└─────────────────────────────────────────────────────────────┘
```

### Ce que fait AI CodeFix

- ✅ Propose un **patch de code** qui corrige l'issue Sonar
- ✅ Tient compte du **contexte du fichier** autour de l'issue
- ✅ **N'applique rien automatiquement** — vous gardez le contrôle
- ✅ Disponible dans l'**interface web** et dans votre **IDE** (VS Code, IntelliJ)
- ✅ **Aucun accès internet sortant nécessaire** — votre code reste dans votre réseau interne
- ✅ **Pas de quotas Sonar** — les limites mensuelles Sonar ne s'appliquent pas en mode self-hosted

### Ce que ne fait pas AI CodeFix

- ❌ Ne modifie pas le comportement fonctionnel du code
- ❌ Ne résout pas toutes les issues (couverture partielle certifiée par règle)
- ❌ Ne remplace pas la revue humaine du correctif proposé
- ❌ Limité à **un seul fichier** par correction

---

## Architecture LLM self-hosted

Dans votre configuration, SonarQube Data Center 2026.2 communique directement avec votre **gateway LLM compatible OpenAI** hébergée dans votre infrastructure.

```
┌────────────────────────┐   HTTP(S)   ┌──────────────────────────┐
│  SonarQube Server      │ ---------> │  Self-Hosted Gateway    │
│  Data Center 2026.2   │            │  (OpenAI-compatible)    │
│                        │            │                        │
│  [AI CodeFix request]  │            │  Ollama / LiteLLM /    │
│  snippet + règle Sonar │            │  vLLM / autre          │
└────────────────────────┘            └──────────────────────────┘
         |                                        |
         |         RéSEAU INTERNE UNIQUEMENT       |
         └────────────────────────────────────────┘
                  Aucun flux sortant vers internet
```

### Exigence réseau

> L'instance SonarQube Server doit être capable de **joindre l'endpoint de votre LLM**. C'est la seule exigence réseau. Il n'est pas nécessaire d'ouvrir un accès internet sortant.

### Configuration par l'administrateur (rappel)

L'administrateur a configuré AI CodeFix dans **Administration > Configuration > General Settings > AI CodeFix** en renseignant :

| Paramètre | Description | Exemple |
|-----------|-------------|--------|
| **Provider** | Self-Hosted Gateway | `openai-compatible` |
| **API Endpoint URL** | URL de votre gateway interne | `https://llm.interne.monentreprise.com/v1` |
| **API Key** | Clé d'authentification de votre gateway | `sk-xxxx...` |
| **Model** | Nom du modèle servi par votre gateway | `gpt-4o`, `llama3`, `mistral`, etc. |
| **Timeout** | Délai max d'attente (ms) | `60000` |
| **Projets autorisés** | Tous ou sélection de projets | selon configuration |

---

## Comment accéder à AI CodeFix ?

AI CodeFix est disponible de **deux façons** selon votre environnement de travail :

```
┌────────────────────────┐       ┌────────────────────────────┐
│   Interface Web        │       │   IDE connecté             │
│   SonarQube            │  ou   │   VS Code / IntelliJ       │
│                        │       │   (mode connecté requis)   │
│  Bouton               │       │   SonarQube for IDE plugin │
│ "✨ Generate AI Fix"   │       │   + icône ✨ sur l'issue   │
└────────────────────────┘       └────────────────────────────┘
```

> **Note :** Si vous ne voyez pas le bouton **✨ Generate AI Fix**, votre projet n'a peut-être pas été autorisé par l'administrateur, ou la règle de l'issue n'est pas couverte par AI CodeFix.

---

## Utiliser AI CodeFix dans SonarQube (Web UI)

### Étape 1 — Ouvrir une issue dans votre projet

1. Connectez-vous à SonarQube
2. Naviguez vers votre **projet**
3. Cliquez sur l'onglet **Issues**

> Filtrez par sévérité, type ou langage pour trouver les issues les plus critiques à traiter en priorité.

### Étape 2 — Identifier une issue éligible à AI CodeFix

Les issues éligibles affichent une **icône ✨ (sparkle)** ou un bouton **✨ Generate AI Fix**.

```
┌─────────────────────────────────────────────────────────────┐
│  Issue : S1117 - Variable shadows an outer scope variable   │
│  Sévérité : Minor   Langage : Java   Statut : Open          │
│                                                             │
│  [Voir le code]                                             │
│                                                             │
│  ┌──────────────────────────────────┐                       │
│  │  ✨ Generate AI Fix              │  ← Bouton AI CodeFix  │
│  └──────────────────────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

### Étape 3 — Générer le correctif

1. Cliquez sur **✨ Generate AI Fix**
2. SonarQube envoie le snippet de code + la description de la règle à votre gateway LLM interne
3. Une proposition de correctif apparaît après quelques secondes

> ⏱️ Le temps de réponse dépend des performances de votre infrastructure LLM self-hosted.

### Étape 4 — Réviser et appliquer

Une vue diff s'affiche avec le code original (rouge) et le code corrigé proposé (vert) :

```diff
- int count = 0;
- for (int count = 0; count < list.size(); count++) {  // ← S1117 : shadowing
+ for (int i = 0; i < list.size(); i++) {
      process(list.get(i));
  }
```

- Cliquez **Apply** pour accepter la correction → SonarQube vous propose d'**ouvrir dans l'IDE** (Open in IDE) ou de copier le patch
- Cliquez **Decline** pour rejeter la suggestion et traiter l'issue manuellement

> ⚠️ **Relisez toujours** la proposition avant d'appliquer. AI CodeFix est un assistant, pas un remplaçant de la revue de code.

---

## Utiliser AI CodeFix dans l'IDE

L'usage dans l'IDE est la méthode **recommandée** car vous pouvez appliquer le correctif directement dans votre code sans quitter l'éditeur.

### Prérequis IDE

| IDE | Plugin requis |
|-----|---------------|
| VS Code | [SonarQube for VS Code](https://docs.sonarsource.com/sonarqube-for-vs-code/) (extension officielle) |
| IntelliJ IDEA / WebStorm / ... | [SonarQube for IntelliJ](https://docs.sonarsource.com/sonarqube-for-intellij/) (plugin officiel) |

Le plugin doit être configuré en **mode connecté** (Connected Mode) à votre instance SonarQube Data Center 2026.2.

### Parcours dans VS Code

```
1. Ouvrir le fichier concerné dans VS Code
2. Les issues Sonar éligibles affichent l'icône ✨ dans la gouttière
3. Survoler l'issue → panneau SonarQube s'ouvre
4. Onglet "Rule Description" → tab "✨ AI CodeFix"
5. Cliquer "✨ Generate Fix"
   └→ La requête est envoyée à votre gateway LLM interne
6. Réviser le diff proposé dans l'éditeur
7. Cliquer "Apply" ou "Decline"
```

```
┌─────────────────────────────────────────────────────────────┐
│  VS Code — SonarQube Panel                                  │
│  ─────────────────────────────────────────────────────────  │
│  Issue ✨ : S106 - Standard outputs should not be used       │
│  Fichier : src/main/App.java, ligne 42                      │
│                                                             │
│  [Why is this an issue?]  [✨ AI CodeFix]                   │
│                                                             │
│  > ✨ Generate Fix  → [LLM interne]                         │
└─────────────────────────────────────────────────────────────┘
```

### Parcours dans IntelliJ

```
1. Ouvrir le fichier dans IntelliJ
2. Les annotations Sonar ✨ sont visibles dans la gouttière
3. Cliquer sur l'icône ✨ → panneau Rule Description s'ouvre
4. Onglet "✨ AI CodeFix" → cliquer "✨ Generate Fix"
   └→ La requête est envoyée à votre gateway LLM interne
5. Réviser le diff dans la fenêtre "Sonar AI Fix Preview"
6. Valider avec "Apply" ou rejeter avec "Decline"
```

---

## Comprendre la proposition de correctif

Le LLM reçoit deux éléments pour générer sa proposition :

```
┌──────────────────────────┐    ┌──────────────────────────────┐
│  Snippet de code         │    │  Description de la règle     │
│  (contexte du fichier)   │ +  │  Sonar certifiée (ex: S1117) │
│                          │    │  + exemples good/bad code    │
└──────────────────────────┘    └──────────────────────────────┘
                   ↓
     Votre LLM self-hosted (compatible OpenAI) génère un patch
                   ↓
         Diff affiché au développeur
```

> **Confidentialité :** Dans votre configuration self-hosted, le code envoyé au LLM **ne quitte pas votre réseau interne**. Les descriptions de règles et prompts Sonar sont intégrés dans l'installation SonarQube Server et nécessitent aucun appel internet.

### Niveaux de confiance à garder en tête

| Situation | Recommandation |
|-----------|---------------|
| Correction simple et évidente (renommage, parenthèse, import) | Applicable directement après relecture rapide |
| Correction de logique (refactoring, condition) | Relire attentivement + tester avant merge |
| Correction de sécurité (injection, XSS, ...) | Vérifier avec un expert sécurité si doute |
| Issue complexe avec plusieurs fichiers impactés | Traiter manuellement — AI CodeFix est limité à 1 fichier |

---

## Langages et règles supportés

AI CodeFix (2026.2) est disponible sur une **sélection de règles certifiées** par Sonar pour les langages suivants :

| Langage | Couverture AI CodeFix |
|---------|----------------------|
| ☕ Java + Java Security | ✅ Oui (large couverture) |
| 🟨 JavaScript + JS Security | ✅ Oui (large couverture) |
| 🔷 TypeScript + TS Security | ✅ Oui (large couverture) |
| 🐍 Python + Python Security | ✅ Oui |
| 🔷 C# + Roslyn Security | ✅ Oui |
| ⚙️ C++ | ✅ Oui |
| 🎨 CSS | ✅ Oui (sélection) |
| 🌐 HTML | ✅ Oui (sélection) |

> La liste complète des règles éligibles par langage est disponible dans la [documentation officielle Sonar — SonarQube Server 2026.1 LTA](https://docs.sonarsource.com/sonarqube-server/2026.1/quality-standards-administration/managing-rules/rules-for-ai-codefix).

### Pourquoi le bouton "✨ Generate AI Fix" n'apparaît-il pas sur certaines issues ?

| Raison | Action |
|--------|--------|
| La règle de l'issue n'est pas couverte par AI CodeFix | Consulter la liste des règles éligibles |
| Le projet n'est pas autorisé par l'admin | Contacter votre administrateur SonarQube |
| Erreur de connexion avec le LLM self-hosted | Contacter votre administrateur SonarQube |

---

## Bonnes pratiques

### ✅ À faire

- **Utiliser AI CodeFix pour les issues répétitives** (style, code mort, shadowing, imports inutilisés) afin de réduire le backlog Sonar rapidement
- **Toujours relire le diff** avant d'appliquer, même pour les petites corrections
- **Tester le code corrigé** (compilation + tests unitaires) avant de committer
- **Utiliser le mode IDE** pour appliquer les corrections directement dans votre branche de travail
- **Signaler les correctifs incorrects** via le bouton Decline

### ❌ À éviter

- Ne pas appliquer en masse sans relecture (les LLM peuvent faire des erreurs)
- Ne pas utiliser AI CodeFix comme unique validation pour des correctifs de sécurité critiques
- Ne pas appliquer une correction sur un code que vous ne comprenez pas

---

## FAQ

**Q : AI CodeFix modifie-t-il automatiquement mon code ?**  
Non. AI CodeFix **propose** uniquement. Vous devez cliquer sur "Apply" pour intégrer la correction.

---

**Q : Mon code est-il envoyé à un service externe ?**  
**Non.** Dans votre configuration self-hosted, le snippet de code est envoyé à votre gateway LLM interne uniquement. **Aucun flux ne quitte votre réseau.** Les descriptions de règles et prompts sont embarqués dans l'installation SonarQube.

---

**Q : Y a-t-il des limites d'utilisation ?**  
**Non.** Les quotas mensuels Sonar ne s'appliquent pas en mode self-hosted. Des limites propres à votre infrastructure LLM peuvent toutefois exister (RAM, GPU, concurrence).

---

**Q : L'issue reste-t-elle ouverte après avoir appliqué le correctif ?**  
Oui, jusqu'au prochain scan Sonar (push / PR). Une fois analysé, si la correction résout l'issue, elle passe automatiquement à l'état **Closed**.

---

**Q : Puis-je utiliser AI CodeFix sur une Pull Request ?**  
Oui. Si votre projet est configuré avec l'analyse des PR (GitHub, GitLab, Azure DevOps, Bitbucket), les issues détectées sur la PR sont éligibles à AI CodeFix.

---

**Q : Que faire si la génération échoue ou est lente ?**  
En mode self-hosted, les erreurs ou lenteurs proviennent généralement de votre gateway LLM (ressources insuffisantes, timeout configuré trop bas). Contactez votre administrateur SonarQube pour vérifier la configuration du provider.

---

**Q : Que faire si la proposition est incorrecte ou incomplète ?**  
Cliquez **Decline** et traitez l'issue manuellement. Vous pouvez aussi cliquer **✨ Generate AI Fix** une nouvelle fois (le LLM peut retourner un résultat différent).

---

## Ressources complémentaires

| Ressource | Lien |
|-----------|------|
| Documentation AI CodeFix — SonarQube Server 2026.2 | [docs.sonarsource.com/sonarqube-server/ai-capabilities/ai-codefix](https://docs.sonarsource.com/sonarqube-server/ai-capabilities/ai-codefix) |
| Activation AI CodeFix (admin) | [Enable AI CodeFix — 2026.2](https://docs.sonarsource.com/sonarqube-server/instance-administration/ai-features/enable-ai-codefix) |
| Règles éligibles par langage | [Rules for AI CodeFix — 2026.1 LTA](https://docs.sonarsource.com/sonarqube-server/2026.1/quality-standards-administration/managing-rules/rules-for-ai-codefix) |
| AI CodeFix dans VS Code | [docs.sonarsource.com/sonarqube-for-vs-code](https://docs.sonarsource.com/sonarqube-for-vs-code/ai-capabilities/ai-codefix) |
| AI CodeFix dans IntelliJ | [docs.sonarsource.com/sonarqube-for-intellij](https://docs.sonarsource.com/sonarqube-for-intellij/ai-capabilities/ai-codefix) |
| Communauté Sonar | [community.sonarsource.com](https://community.sonarsource.com) |

---

> 📝 *Document maintenu par l'équipe qualité — Dépôt [`edahenit/sonarqube`](https://github.com/edahenit/sonarqube)*
