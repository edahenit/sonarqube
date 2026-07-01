# Guide pratique — SonarQube CLI (`sonar`)

> Guide d'utilisation de la **SonarQube CLI**, le compagnon en ligne de commande pour développeurs et agents IA, qui se connecte à SonarQube Cloud ou SonarQube Server depuis votre terminal.
>
> ⚠️ Produit en **Beta** : des changements cassants peuvent survenir d'une version à l'autre.

---

## 1. Qu'est-ce que la SonarQube CLI ?

La **SonarQube CLI** (binaire `sonar`) est un outil en ligne de commande qui permet, directement depuis le terminal :

- de **détecter des secrets** (clés API, tokens, mots de passe en clair) avant qu'ils ne fuitent ;
- d'**analyser vos changements locaux** pour un retour rapide qualité/sécurité ;
- d'**interroger** vos projets et issues SonarQube (JSON, CSV, table, TOON) ;
- d'**intégrer SonarQube à vos agents IA** (Claude Code, GitHub Copilot, OpenAI Codex) et à Git ;
- de **déclencher la remédiation IA** d'issues éligibles (SonarQube Cloud).

### Ne pas confondre avec le SonarScanner CLI

| Outil | Binaire | Rôle |
|-------|---------|------|
| **SonarQube CLI** (ce guide) | `sonar` | Compagnon développeur/agent IA : secrets, analyse locale, requêtes, intégrations IA. |
| **SonarScanner CLI** | `sonar-scanner` | Scanner d'analyse complète d'un projet, surtout pour la CI/CD. Outil différent. |

La SonarQube CLI **interagit avec un projet SonarQube existant** ; elle ne remplace pas l'analyse complète faite par le scanner.

---

## 2. Prérequis

- Un compte **SonarQube Cloud** (région EU `https://sonarcloud.io` ou US `https://sonarqube.us`) ou un **SonarQube Server** auto-hébergé.
- Un **user token** (token utilisateur). ⚠️ Les *project tokens*, *global tokens* ou *organization-scoped tokens* ne fonctionnent **pas** pour configurer la CLI.
- Pour la connexion interactive : accès au **trousseau système** (keychain). Sous WSL, ce n'est pas disponible → utilisez les variables d'environnement.

---

## 3. Installation

### macOS / Linux

```bash
curl -o- https://raw.githubusercontent.com/SonarSource/sonarqube-cli/refs/heads/master/user-scripts/install.sh | bash
```

Le binaire `sonar` est installé dans `~/.local/share/sonarqube-cli/bin/` et ce dossier est ajouté au `PATH` (`~/.bashrc` ou `~/.zshrc`).

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/SonarSource/sonarqube-cli/refs/heads/master/user-scripts/install.ps1 | iex
```

Le binaire `sonar.exe` est installé dans `%LOCALAPPDATA%\sonarqube-cli\bin\`.

> **Redémarrez votre terminal après l'installation** : la commande `sonar` n'est disponible qu'après rechargement du `PATH`.

### Vérifier l'installation

```bash
sonar --version
# Affiche par ex. 0.14.0
```

### Mettre à jour

```bash
sonar self-update            # met à jour vers la dernière version
sonar self-update --status   # vérifie sans installer
sonar self-update --force    # réinstalle même si à jour
```

---

## 4. Authentification

Deux modes possibles.

### Mode interactif (usage personnel — recommandé)

```bash
sonar auth login
```

La CLI demande Cloud ou Server, puis la région/URL, ouvre le navigateur pour créer un token et le stocke dans le trousseau système.

Pour éviter les prompts :

```bash
# SonarQube Server auto-hébergé
sonar auth login --server https://sonarqube.mon-entreprise.com

# SonarQube Cloud (EU puis US)
sonar auth login --server "https://sonarcloud.io"
sonar auth login --server "https://sonarqube.us"

# Préciser l'organisation (Cloud uniquement)
sonar auth login --org mon-org
```

> La clé d'organisation se trouve sur SonarQube Cloud : **Account → Organizations** (`https://sonarcloud.io/account/organizations`).

### Mode non-interactif (CI/CD, agents IA, WSL)

```bash
export SONARQUBE_CLI_TOKEN=<votre_user_token>
export SONARQUBE_CLI_ORG=<votre_org>        # Cloud uniquement
```

Aucun navigateur ni trousseau requis.

### Vérifier / se déconnecter

```bash
sonar auth status   # affiche serveur, org et utilisateur résolu
sonar auth logout   # retire le token actif (et le révoque si créé via le navigateur)
sonar auth purge    # supprime tous les tokens stockés
```

---

## 5. Vos premières commandes

### Lister vos projets

```bash
sonar list projects
sonar list projects -q mon-projet           # filtrer par nom/clé
sonar list projects --page 2 --page-size 50
```

Sortie toujours en JSON (à piper dans `jq` au besoin).

### Scanner un fichier à la recherche de secrets

```bash
echo 'const API_KEY = "sqp_1aa323ae0689cd4a1abd062a2ad0a224ae8a1d13";' > test-secret.js
sonar analyze secrets test-secret.js
# Détecte le token et sort avec le code 51 ; supprimez ensuite le fichier
```

### Analyser ses changements locaux (SonarQube Cloud)

```bash
sonar analyze agentic          # change-set local
sonar analyze --staged         # fichiers indexés (git diff --cached)
sonar verify                   # alias de "analyze agentic"
```

---

## 6. Référence des commandes

| Groupe | Commandes |
|--------|-----------|
| **Authentification** | `sonar auth login` · `logout` · `purge` · `status` |
| **Intégrations** | `sonar integrate claude` · `copilot` · `git` |
| **Analyse** | `sonar analyze secrets` · `analyze agentic` · `verify` · `remediate` |
| **Information** | `sonar list issues` · `list projects` · `api` |
| **Configuration** | `sonar config telemetry` |
| **Maintenance** | `sonar self-update` |

### `sonar analyze secrets` — détection de secrets

```bash
sonar analyze secrets src/config.ts          # un fichier
sonar analyze secrets src/                    # un dossier
cat .env | sonar analyze secrets --stdin      # entrée standard
```

Sort avec le **code 51** si des secrets sont trouvés, `0` sinon.

### `sonar analyze agentic` / `sonar verify` — analyse des changements (Cloud)

| Option | Description |
|--------|-------------|
| `--file <chemin>` | Analyser un seul fichier |
| `--staged` | Fichiers indexés uniquement |
| `--base <ref>` | Changements par rapport à une branche/ref (ex. `main`) |
| `--branch <nom>` | Branche pour le contexte d'analyse |
| `--project, -p <clé>` | Forcer la clé de projet |
| `--force` | Ignorer la confirmation si > 50 fichiers |
| `--format <text\|json>` | Format de sortie (défaut `text`) |

```bash
sonar verify --staged
sonar verify --base main
```

### `sonar list issues` — rechercher des issues

| Option | Description |
|--------|-------------|
| `--project, -p <clé>` | **Obligatoire** — clé du projet |
| `--statuses` | `OPEN`, `CONFIRMED`, `FALSE_POSITIVE`, `ACCEPTED`, `FIXED` |
| `--severities` | `INFO`, `MINOR`, `MAJOR`, `CRITICAL`, `BLOCKER` |
| `--format` | `json` (défaut), `toon`, `table`, `csv` |
| `--branch` / `--pull-request` | Contexte branche / PR |
| `--page` / `--page-size` | Pagination (taille 1–500) |

```bash
sonar list issues -p mon-projet --severities CRITICAL,BLOCKER --format table
```

### `sonar remediate` — remédiation IA (Cloud)

```bash
sonar remediate -p mon-projet                              # choix interactif
sonar remediate -p mon-projet --issues cle-1,cle-2         # ciblé (max 20)
```

### `sonar api` — appels directs à l'API Web SonarQube

```bash
sonar api get "/api/system/status" --verbose
sonar api get "/api/rules/search?organization=mon-org&languages=ts"
sonar api post "/api/user_tokens/generate" --data '{"name":"mon-token"}'
```

### `sonar config telemetry`

```bash
sonar config telemetry --enabled
sonar config telemetry --disabled
```

---

## 7. Intégrations

### Agents IA (Claude Code, Copilot)

Installe les hooks de détection de secrets et configure le serveur MCP SonarQube + l'analyse agentique :

```bash
sonar integrate claude -p mon-projet     # projet courant
sonar integrate claude -g                # global (~/.claude)

sonar integrate copilot -p mon-projet
sonar integrate copilot -g               # global (~/.copilot)
```

### Hooks Git

Bloque les secrets au niveau Git :

```bash
sonar integrate git                      # pre-commit (fichiers indexés)
sonar integrate git --hook pre-push      # commits non poussés
sonar integrate git --global             # tous les dépôts
```

---

## 8. Codes de sortie (utiles en CI/CD)

| Code | Signification |
|------|---------------|
| `0` | Succès, aucun problème détecté |
| `51` | Des secrets / issues ont été détectés (fait échouer un job CI) |

L'analyse retourne un code non nul en présence de secrets ou d'issues, ce qui permet de **bloquer une pipeline** automatiquement.

---

## 9. Dépannage

| Symptôme | Solution |
|----------|----------|
| `command not found` après install | Redémarrez le terminal ; vérifiez que le binaire est dans `~/.local/share/sonarqube-cli/bin/` ; ajoutez-le au `PATH` si besoin. |
| Le login navigateur ne revient pas au terminal | Vérifiez qu'aucun pare-feu ne bloque `127.0.0.1` ; sinon, `Ctrl+C` et passez par les variables d'environnement. |
| `Invalid token` / `Authentication failed` | Utilisez bien un **user token** (pas project/global/org) ; vérifiez la région (un token EU ne marche pas sur US) ; relancez `sonar auth status`. |
| WSL : login impossible | Le trousseau n'existe pas sous WSL → authentifiez-vous via `SONARQUBE_CLI_TOKEN`. |

---

## 10. Bonnes pratiques

- **Jamais de token committé** : variables d'environnement ou secrets CI/CD.
- En **CI/CD et agents IA**, privilégier `SONARQUBE_CLI_TOKEN` (non-interactif) plutôt que `sonar auth login`.
- Installer les **hooks Git/IA** (`sonar integrate git`, `sonar integrate claude`) pour stopper les secrets avant le commit.
- Utiliser `sonar verify --staged` comme **garde-fou avant commit/PR**.
- Exploiter `--format json` / `csv` pour alimenter dashboards et scripts.
- Garder la CLI à jour avec `sonar self-update` (Beta, évolutions fréquentes).

---

## Sources

- [SonarQube CLI — Documentation Sonar](https://docs.sonarsource.com/sonarqube-cli)
- [Quickstart guide — SonarQube CLI](https://docs.sonarsource.com/sonarqube-cli/quickstart-guide)
- [Commands reference — SonarQube CLI](https://docs.sonarsource.com/sonarqube-cli/using-sonarqube-cli/commands)
- [Dépôt GitHub SonarSource/sonarqube-cli](https://github.com/SonarSource/sonarqube-cli)
