# Pipelines CI — SonarQube 2026.1 + JFrog Evidence Collection (Kubernetes)

Exemples de pipelines **exécutés sur Kubernetes**, qui enchaînent build,
`sonar-scanner`, puis `jf evd create` pour pousser le résultat du Quality
Gate SonarQube comme **preuve signée** attachée à un build Artifactory.

Chaque étape utilise un conteneur Docker dédié (isolation du build, du
scanner Sonar et de la CLI JFrog).

> **Projet de test fourni** : [test-project/](test-project/) — micro-projet
> Python (`calculator` + 5 tests pytest, coverage 100%) utilisé comme cible
> des deux pipelines. Voir son [README](test-project/README.md).

## Fichiers

| Fichier | Outil CI | Modèle d'exécution |
|---|---|---|
| [jenkins/Jenkinsfile](jenkins/Jenkinsfile) | Jenkins (pipeline déclaratif) | **1 pod, 3 conteneurs** (`build`, `sonar`, `jfrog`) via Kubernetes plugin |
| [gitlab/.gitlab-ci.yml](gitlab/.gitlab-ci.yml) | GitLab CI | **1 pod par job** via Kubernetes executor (image différente par job) |

## Architecture

```
Jenkins (1 pod)                        GitLab CI (N pods)
┌──────────────────────────┐           build      → python:3.12-slim
│ pod:                     │           sonar-scan → sonarsource/sonar-scanner-cli
│  ├─ build    (python)    │           publish   → jfrog/jfrog-cli-v2-jf
│  ├─ sonar    (scanner)   │           evidence  → jfrog/jfrog-cli-v2-jf
│  └─ jfrog    (jf CLI)    │
│  workspace partagé       │           workspace propagé via artifacts GitLab
└──────────────────────────┘
```

**Point clé** : le fichier `.scannerwork/report-task.txt` écrit par le
conteneur `sonar` doit être accessible au conteneur `jfrog` pour que
`jf evd create` puisse remonter à l'analyse SonarQube.
- **Jenkins** : workspace partagé nativement entre conteneurs du même pod
- **GitLab CI** : transmis via `artifacts:` entre jobs

## Prérequis

| Composant | Version minimale |
|---|---|
| SonarQube Server | **2026.1 LTA** (édition Enterprise) |
| JFrog Artifactory | Enterprise/Enterprise+ avec module Evidence |
| JFrog CLI | `2.x` (image `releases-docker.jfrog.io/jfrog/jfrog-cli-v2-jf`) |
| Clé de signature | Paire ED25519 ou RSA ; la clé **publique** doit être enregistrée dans JFrog avec un alias |
| Cluster Kubernetes | Jenkins : Kubernetes plugin configuré ; GitLab : runner avec Kubernetes executor (tag `kubernetes`) |

## Flux commun (projet Python)

```
pip install + pytest --cov  ──► coverage.xml + reports/pytest.xml
python -m build             ──► dist/*.whl
sonar-scanner               ──► .scannerwork/report-task.txt ──► QG check
                                                                       │
jf rt upload dist/*.whl                                                │
jf rt build-publish                                                    │
                                                                       ▼
                                                    jf evd create --integration sonar
                                                                       │
                                                                       ▼
                                                      Preuve signée attachée au build
                                                      dans JFrog Evidence Collection
```

## Images Docker utilisées

| Rôle | Image |
|---|---|
| Build | `python:3.12-slim` *(à adapter : maven, gradle, node…)* |
| Scanner Sonar | `sonarsource/sonar-scanner-cli:latest` |
| JFrog CLI | `releases-docker.jfrog.io/jfrog/jfrog-cli-v2-jf:latest` |

## Variables d'environnement requises

| Variable | Rôle |
|---|---|
| `SONAR_HOST_URL` / `SONAR_URL` | URL du serveur SonarQube |
| `SONAR_TOKEN` (ou `SONARQUBE_TOKEN`) | Token d'analyse |
| `JF_URL` | URL JFrog Platform |
| `JF_ACCESS_TOKEN` | Access token avec scope `evidence:create` |
| `EVIDENCE_SIGNING_KEY` | Clé **privée** de signature (fichier) |
| `EVIDENCE_KEY_ALIAS` | Alias de la clé publique côté JFrog |

## Emplacement par défaut de `report-task.txt`

La JFrog CLI lit ce fichier pour récupérer l'`analysisId` et interroger
l'API SonarQube. Emplacements attendus :

| Build tool | Chemin |
|---|---|
| sonar-scanner CLI | `.scannerwork/report-task.txt` |
| Maven | `target/sonar/report-task.txt` |
| Gradle | `build/sonar/report-task.txt` |
| MSBuild | `.sonarqube/out/.sonar/report-task.txt` |

À redéfinir via `SONAR_REPORT_TASK_FILE` si besoin.

## Commande pivot

```bash
jf evd create \
  --build-name="$BUILD_NAME" \
  --build-number="$BUILD_NUMBER" \
  --integration=sonar \
  --key="$EVIDENCE_SIGNING_KEY" \
  --key-alias="$EVIDENCE_KEY_ALIAS"
```

Alternatives (au lieu de `--build-name/--build-number`) :
- `--package-name` + `--package-version` + `--package-repo-name` pour attacher
  à un package (npm, Maven, Docker, …)
- `--release-bundle` + `--release-bundle-version` pour attacher à un
  release-bundle (AppTrust)

## Références

- [Announcing SonarQube Server 2026.1 LTA](https://www.sonarsource.com/blog/announcing-sonarqube-server-2026-1-lta/)
- [JFrog Evidence Collection integration | Sonar Docs](https://docs.sonarsource.com/sonarqube-server/analyzing-source-code/jfrog-evidence-collection-integration/)
- [Sonar Evidence Integration | JFrog Docs](https://docs.jfrog.com/governance/docs/sonar-evidence-integration)
- [jfrog-integrations/sonarqube/artifactory | GitHub](https://github.com/jfrog/jfrog-integrations/tree/master/sonarqube/artifactory)
