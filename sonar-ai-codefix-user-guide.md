# 🤖 Guide Utilisateur — Sonar AI CodeFix

> **Public cible :** Développeurs, Tech Leads, Équipes qualité  
> **Prérequis :** SonarQube Data Center déjà installé et AI CodeFix activé par l'administrateur  
> **Version :** SonarQube Server **2026.2**

---

## Table des matières

1. [Qu'est-ce que Sonar AI CodeFix ?](#quest-ce-que-sonar-ai-codefix-)
2. [Comment accéder à AI CodeFix ?](#comment-accéder-à-ai-codefix-)
3. [Utiliser AI CodeFix dans SonarQube (Web UI)](#utiliser-ai-codefix-dans-sonarqube-web-ui)
4. [Utiliser AI CodeFix dans l'IDE](#utiliser-ai-codefix-dans-lide)
5. [Comprendre la proposition de correctif](#comprendre-la-proposition-de-correctif)
6. [Langages et règles supportés](#langages-et-règles-supportés)
7. [Bonnes pratiques](#bonnes-pratiques)
8. [FAQ](#faq)
9. [Ressources complémentaires](#ressources-complémentaires)

---

## Qu'est-ce que Sonar AI CodeFix ?

**Sonar AI CodeFix** est une fonctionnalité intégrée à SonarQube Server (editions **Enterprise** et **Data Center**) qui utilise un grand modèle de langage (LLM) pour **proposer automatiquement une correction de code** sur les issues détectées par l'analyse Sonar.

Disponible depuis SonarQube Server 2026.2, le modèle recommandé est **OpenAI GPT-5.1**, hébergé par Sonar, avec également la possibilité d'utiliser un LLM privé (Azure OpenAI, AWS Bedrock, ou une passerelle self-hosted type Ollama / LiteLLM / vLLM).

```
┌─────────────────────────────────────────────────────────────┐
│                    SONAR AI CODEFIX                         │
│                                                             │
│  Analyse Sonar  →  Issue détectée  →  Generate AI Fix       │
│                                             ↓               │
│                                    LLM analyse le contexte  │
│                              (GPT-5.1 ou LLM personnalisé)  │
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
- ✅ Fonctionne **sans accès internet sortant** si vous utilisez un LLM self-hosté

### Ce que ne fait pas AI CodeFix

- ❌ Ne modifie pas le comportement fonctionnel du code
- ❌ Ne résout pas toutes les issues (couverture partielle, certifiée par règle)
- ❌ Ne remplace pas la revue humaine du correctif proposé
- ❌ Limité à **un seul fichier** par correction

---

## Comment accéder à AI CodeFix ?

AI CodeFix est disponible de **deux façons** selon votre environnement de travail :

```
┌────────────────────────┐       ┌────────────────────────────┐
│   Interface Web        │       │   IDE connecté             │
│   SonarQube            │  ou   │   VS Code / IntelliJ       │
│                        │       │   (mode connecté requis)   │
│  Bouton               │       │   SonarQube for IDE plugin │
│ "Generate AI Fix"      │       │   + icône ✨ sur l'issue   │
└────────────────────────┘       └────────────────────────────┘
```

> **Note :** La fonctionnalité doit avoir été activée par votre administrateur SonarQube sur le projet. Si vous ne voyez pas le bouton **Generate AI Fix**, contactez votre admin.

---

## Utiliser AI CodeFix dans SonarQube (Web UI)

### Étape 1 — Ouvrir une issue dans votre projet

1. Connectez-vous à SonarQube
2. Naviguez vers votre **projet**
3. Cliquez sur l'onglet **Issues**

> Filtrez par sévérité, type ou langage pour trouver les issues les plus critiques à traiter en priorité.

### Étape 2 — Identifier une issue éligible à AI CodeFix

Les issues éligibles affichent une **icône ✨ (sparkle)** ou un bouton **Generate AI Fix** lorsque vous ouvrez le détail de l'issue.

```
┌─────────────────────────────────────────────────────────────┐
│  Issue : S1117 - Variable shadows an outer scope variable   │
│  Sévérité : Minor   Langage : Java   Statut : Open          │
│                                                             │
│  [Voir le code]                                             │
│                                                             │
│  ┌──────────────────────────────────┐                       │
│  │  ✨  Generate AI Fix             │  ← Bouton AI CodeFix  │
│  └──────────────────────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

### Étape 3 — Générer le correctif

1. Cliquez sur **Generate AI Fix**
2. SonarQube envoie le snippet de code + la description de la règle au LLM configuré
3. Une proposition de correctif apparaît après quelques secondes

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
│  > ✨ Generate Fix                                          │
└─────────────────────────────────────────────────────────────┘
```

### Parcours dans IntelliJ

```
1. Ouvrir le fichier dans IntelliJ
2. Les annotations Sonar ✨ sont visibles dans la gouttière
3. Cliquer sur l'icône ✨ → panneau Rule Description s'ouvre
4. Onglet "✨ AI CodeFix" → cliquer "✨ Generate Fix"
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
         GPT-5.1 (ou LLM configuré) génère un patch minimal
                   ↓
         Diff affiché au développeur
```

> **Note confidentialité :** Si le LLM hébergé par Sonar est utilisé, votre snippet de code est envoyé au service AI CodeFix, mais les accords de service **interdisent l'utilisation de votre code pour entraîner les modèles**. Pour les configurations self-hosted, le code ne quitte pas votre réseau.

### Niveaux de confiance à garder en tête

| Situation | Recommandation |
|-----------|---------------|
| Correction simple et évidente (renommage, parenthèse, import) | Applicable directement après relecture rapide |
| Correction de logique (refactoring, condition) | Relire attentivement + tester avant merge |
| Correction de sécurité (injection, XSS, ...) | Vérifier avec un expert sécurité si doute |
| Issue complexe avec plusieurs fichiers impactés | Traiter manuellement — AI CodeFix est limité à 1 fichier |

---

## Langages et règles supportés

AI CodeFix (2026.2) est disponible sur une **sélection de règles certifiées** par Sonar. Chaque règle passe par un processus de validation sur les modèles IA avant d'être ajoutée au service.

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

### Pourquoi le bouton "Generate AI Fix" n'apparaît-il pas sur certaines issues ?

Deux raisons possibles :
1. La **règle** de cette issue n'est pas encore couverte par AI CodeFix (couverture partielle certifiée)
2. Le **projet** n'a pas été autorisé par l'administrateur — contactez votre admin

---

## Bonnes pratiques

### ✅ À faire

- **Utiliser AI CodeFix pour les issues répétitives** (style, code mort, shadowing, imports inutilisés) afin de réduire le backlog Sonar rapidement
- **Toujours relire le diff** avant d'appliquer, même pour les petites corrections
- **Tester le code corrigé** (compilation + tests unitaires) avant de committer
- **Utiliser le mode IDE** pour appliquer les corrections directement dans votre branche de travail
- **Signaler les correctifs incorrects** via le bouton Decline pour aider Sonar à améliorer le modèle

### ❌ À éviter

- Ne pas appliquer en masse sans relecture (les LLM peuvent faire des erreurs)
- Ne pas utiliser AI CodeFix comme unique validation pour des correctifs de sécurité critiques
- Ne pas appliquer une correction sur un code que vous ne comprenez pas

---

## FAQ

**Q : AI CodeFix modifie-t-il automatiquement mon code ?**  
Non. AI CodeFix **propose** uniquement. Vous devez cliquer sur "Apply" pour intégrer la correction. Rien n'est modifié à votre insu.

---

**Q : Mon code est-il envoyé à un service externe ?**  
Cela dépend de la configuration de votre administrateur. Si votre instance utilise un LLM self-hosté (Ollama, LiteLLM, vLLM), le code ne quitte pas votre réseau. Si le LLM hébergé par Sonar est utilisé, le snippet est envoyé au service AI CodeFix via `api.sonarqube.io`, mais les accords contractuels empêchent son utilisation pour l'entraînement des modèles.

---

**Q : L'issue reste-t-elle ouverte après avoir appliqué le correctif ?**  
Oui, l'issue reste ouverte dans SonarQube jusqu'à ce que le code corrigé soit **analysé** (scan Sonar suivant, typiquement lors d'un nouveau push/PR). Une fois le scan effectué, si la correction résout l'issue, elle passe automatiquement à l'état **Closed**.

---

**Q : Puis-je utiliser AI CodeFix sur une Pull Request ?**  
Oui. Si votre projet est configuré avec l'analyse des PR (GitHub, GitLab, Azure DevOps, Bitbucket), les issues détectées sur la PR sont éligibles à AI CodeFix depuis l'interface SonarQube ou depuis l'IDE en mode connecté.

---

**Q : Que faire si la proposition est incorrecte ou incomplète ?**  
Cliquez **Decline** et traitez l'issue manuellement. Vous pouvez aussi cliquer **Generate AI Fix** une nouvelle fois pour obtenir une nouvelle proposition (le LLM peut retourner un résultat différent).

---

**Q : AI CodeFix fonctionne-t-il sur des projets privés ?**  
Oui, à condition que l'administrateur ait autorisé le projet dans la configuration AI CodeFix de l'instance SonarQube Data Center.

---

**Q : Existe-t-il des limites d'utilisation ?**  
Oui. Des quotas mensuels s'appliquent lorsque vous utilisez le LLM hébergé par Sonar. Une notification apparaît quand la limite est atteinte, et les quotas sont remis à zéro le premier jour de chaque mois. Il n'y a pas de limites Sonar si vous utilisez un LLM self-hosté.

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
| Conditions d'utilisation AI CodeFix | [sonarsource.com/legal/ai-codefix-terms](https://www.sonarsource.com/legal/ai-codefix-terms/) |

---

> 📝 *Document maintenu par l'équipe qualité — Dépôt [`edahenit/sonarqube`](https://github.com/edahenit/sonarqube)*
