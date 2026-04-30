# Guide AI CodeFix — SonarQube Server 2026.1 LTA

> **Cible de ce guide** : utiliser AI CodeFix avec un **LLM auto-hébergé**
> exposant une API OpenAI-compatible (Ollama, vLLM, LiteLLM…), sans dépendre
> du LLM SaaS Sonar ni d'Azure OpenAI. Mode déployable **air-gapped**.

## Vue d'ensemble

**AI CodeFix** propose, pour chaque issue détectée, une **suggestion de
correction générée par un LLM**. Le développeur consulte le diff, l'édite
si besoin, puis l'applique depuis l'UI SonarQube, l'IDE, ou la PR
decoration (GitHub/GitLab/Bitbucket/Azure DevOps).

Trois fournisseurs LLM sont configurables :

| Fournisseur | Code source envoyé à… | Internet sortant requis ? |
|---|---|---|
| **Sonar default** (OpenAI géré par Sonar) | Sonar AI Gateway | Oui (`api.sonarqube.io`) |
| **Azure OpenAI** | Votre tenant Azure | Oui (orchestration via Sonar Gateway) |
| **Custom** (self-hosted) | Votre serveur LLM interne | **Non** — peut tourner air-gapped |

**Ce guide se concentre sur le mode Custom.**

## Disponibilité

| Critère | Exigence |
|---|---|
| Édition SonarQube Server | **Enterprise** ou **Data Center** |
| Version minimale | **2026.1 LTA** |
| Communauté / Developer | Non supporté |

## Langages et règles éligibles (2026.1)

| Langage | Règles éligibles |
|---|---|
| Java | 700+ règles + 16 règles security |
| JavaScript | 500+ règles + 6 règles security |
| TypeScript | 600+ règles + 4 règles security |
| Python | 600+ règles + 10 règles security |
| C# | 500+ règles + 12 règles Roslyn Security |
| C++ | 130+ règles |
| HTML | 40+ règles |
| CSS | 30+ règles |

Liste exhaustive : [Rules for AI CodeFix](https://docs.sonarsource.com/sonarqube-server/2026.1/quality-standards-administration/managing-rules/rules-for-ai-codefix/).

---

## Architecture cible (self-hosted)

```
┌──────────────┐    HTTPS      ┌─────────────────────┐
│  Développeur │ ────────────► │  SonarQube Server   │
│  (UI / IDE)  │               │  (Enterprise/DC)    │
└──────────────┘               │  2026.1 LTA         │
                               └─────────┬───────────┘
                                         │ HTTP(S) interne
                                         │ /v1/chat/completions
                                         ▼
                               ┌─────────────────────┐
                               │  LLM Gateway        │
                               │  Ollama / vLLM /    │
                               │  LiteLLM            │
                               │  (OpenAI-compatible)│
                               └─────────┬───────────┘
                                         │
                                         ▼
                               ┌─────────────────────┐
                               │  Modèle (.gguf,     │
                               │  HF weights, …)     │
                               │  ex: Llama 3.2,     │
                               │  Qwen2.5-Coder      │
                               └─────────────────────┘

                  Aucun flux sortant vers Internet requis.
```

## Prérequis réseau (mode Custom self-hosted)

| Flux | Obligatoire ? |
|---|---|
| SonarQube → `api.sonarqube.io` | **Non** (différence majeure avec Sonar default / Azure OpenAI) |
| SonarQube → endpoint LLM interne | Oui — TCP/HTTP(S) interne |
| Allowlist IPs Sonar (`99.83.135.55/32`, `15.197.164.24/32`) | **Non** |

> Les prompts et descriptions de règles sont **embarqués dans l'installation**
> SonarQube — aucun appel externe pour les obtenir.

## Choix du LLM Gateway

| Outil | Quand le choisir |
|---|---|
| **Ollama** | Setup simple, GPU/CPU, idéal pour PoC/équipe seule |
| **vLLM** | Production, fort débit, batching dynamique, multi-tenant |
| **LiteLLM** | Proxy unifié devant plusieurs backends (utile si vous avez aussi un Bedrock, Vertex, etc.) |

**Contrainte unique** : exposer un endpoint **OpenAI-compatible** (`/v1`).
Pour Ollama, **utiliser `/v1/...` et non `/api/...`**.

## Modèles recommandés pour CodeFix

Sonar n'impose pas de modèle en mode Custom mais **avertit** que la qualité
des suggestions varie selon le modèle. Bonnes options pour de la correction
de code :

| Modèle | Taille | Notes |
|---|---|---|
| Qwen2.5-Coder-32B-Instruct | ~32B | Excellent ratio qualité/taille pour code |
| Llama 3.3 70B Instruct | 70B | Plus généraliste, demande GPU haut de gamme |
| DeepSeek-Coder-V2-Lite | ~16B | Léger, bon pour Java/Python/JS |
| Codestral 22B | 22B | Spécialisé code |

GPU minimum recommandé pour un 32B en INT8 : 24 Go VRAM (RTX 4090 / A6000 / L4).
Pour un déploiement CPU, viser un modèle ≤ 7B (ex: Qwen2.5-Coder-7B).

---

## Mise en route — exemple Ollama

### 1. Déployer Ollama

```bash
# Installation (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Charger un modèle code
ollama pull qwen2.5-coder:32b

# Démarrer le service (par défaut sur :11434)
ollama serve
```

Ou via Docker :

```bash
docker run -d --gpus=all \
  -v ollama:/root/.ollama \
  -p 11434:11434 \
  --name ollama \
  ollama/ollama

docker exec -it ollama ollama pull qwen2.5-coder:32b
```

### 2. Vérifier l'API OpenAI-compatible

```bash
curl http://localhost:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen2.5-coder:32b",
    "messages": [{"role":"user","content":"Say OK"}]
  }'
```

Doit renvoyer un `choices[0].message.content` non vide.

### 3. Configurer SonarQube

UI : **Administration → Configuration → General Settings → AI CodeFix**

| Champ | Valeur |
|---|---|
| Enable AI CodeFix | ✅ coché |
| Provider | **Custom** |
| Endpoint | `http://ollama-internal.example.lan:11434/v1` |
| Model ID | `qwen2.5-coder:32b` |
| Header name (optionnel) | `Authorization` |
| Value (optionnel) | `Bearer <token>` (si reverse proxy avec auth) |

Cliquer **Save**.

### 4. Choisir la portée

- **All projects** : actif partout
- **Only selected projects** (recommandé pour un pilote) : ajouter
  manuellement les projets éligibles

### 5. Tester depuis l'UI

1. Ouvrir un projet, page **Issues**
2. Cliquer une issue d'une règle éligible (cf. tableau plus haut)
3. Cliquer **AI CodeFix**
4. Vérifier qu'un diff est proposé en quelques secondes

Si rien ne se passe → consulter le journal SonarQube
(`$SONAR_HOME/logs/web.log`) ; les erreurs LLM sont loggées avec préfixe
`AI CodeFix`.

---

## Variantes de déploiement

### vLLM (production, haut débit)

```bash
docker run -d --gpus all \
  -p 8000:8000 \
  vllm/vllm-openai:latest \
  --model Qwen/Qwen2.5-Coder-32B-Instruct \
  --served-model-name qwen2.5-coder \
  --api-key sk-internal-token
```

Configuration SonarQube :
- Endpoint : `http://vllm-internal:8000/v1`
- Model ID : `qwen2.5-coder`
- Header : `Authorization: Bearer sk-internal-token`

### LiteLLM (proxy multi-backends)

Utile si vous voulez router vers plusieurs modèles selon le langage,
ou ajouter du logging centralisé / quotas.

```yaml
# litellm-config.yaml
model_list:
  - model_name: codefix-default
    litellm_params:
      model: ollama/qwen2.5-coder:32b
      api_base: http://ollama:11434
  - model_name: codefix-csharp
    litellm_params:
      model: openai/codestral-22b
      api_base: http://vllm-csharp:8000/v1
      api_key: sk-internal
```

```bash
litellm --config litellm-config.yaml --port 4000
```

Configuration SonarQube : `Endpoint = http://litellm-internal:4000`,
`Model ID = codefix-default`.

---

## Sécurité & confidentialité

- **Le code source ne quitte jamais votre réseau** (en mode Custom)
- Authentifier l'endpoint LLM avec un reverse proxy (nginx, Traefik) +
  Bearer token, transmis via le champ Header de la config SonarQube
- TLS recommandé pour l'endpoint LLM, même en interne
- Logs LLM Gateway : journaliser les prompts est utile pour l'audit, mais
  veillez à **ne pas exporter ces logs hors de la zone réseau du code
  source** — sinon le bénéfice du self-hosting est perdu

## Limitations spécifiques au mode Custom

- **Qualité des suggestions non garantie par Sonar** ("fix suggestion quality
  may vary") — à mesurer empiriquement sur vos règles/langages prioritaires
- **Pas d'optimisation des prompts par modèle** : Sonar envoie le même
  prompt qu'au LLM par défaut
- **Pas de fallback** : si le LLM Custom est down, AI CodeFix est down
  (pas de bascule automatique vers Sonar default)
- **Rate limits** : ceux de votre infrastructure (GPU saturation = file
  d'attente côté gateway)

---

## Cacher AI CodeFix sans le désactiver

Pour des raisons de conformité ou phasing :

```properties
# sonar.properties
sonar.ai.codefix.hidden=true
```

Le bouton disparaît de l'UI sans toucher à la configuration backend.

## Workflow développeur

| Surface | Comment déclencher une correction |
|---|---|
| UI SonarQube | Page issue → bouton **AI CodeFix** → diff → *Apply* |
| SonarQube for IntelliJ | Issue dans le panneau Sonar → action "Suggest fix" |
| SonarQube for VS Code | Idem dans l'onglet "Sonar issues" |
| PR decoration | Suggestion postée en commentaire ; *Commit suggestion* natif Git provider |

## Mesure d'adoption

Métriques à suivre (via API SonarQube `/api/measures` et logs) :

- Nombre de suggestions générées / semaine
- Taux d'acceptation (suggestions appliquées / proposées)
- Latence p95 de génération
- Taux d'erreur LLM (5xx, timeouts)

Si le taux d'acceptation reste < 30 % après 4-6 semaines, changer de modèle
ou ajuster le déploiement (plus gros modèle, meilleur GPU).

---

## Annexe — checklist d'activation (mode Custom)

- [ ] SonarQube Server Enterprise ou Data Center, **2026.1 LTA**
- [ ] LLM Gateway interne déployé (Ollama / vLLM / LiteLLM)
- [ ] Endpoint **OpenAI-compatible** (`/v1`) testé avec `curl`
- [ ] Modèle code-aware chargé (Qwen2.5-Coder, Codestral, etc.)
- [ ] SonarQube peut joindre l'endpoint LLM (DNS + firewall interne)
- [ ] Authentification de l'endpoint configurée (Bearer / mTLS)
- [ ] Provider **Custom** sélectionné dans l'UI Admin
- [ ] Endpoint + Model ID + Header(s) renseignés
- [ ] Portée définie (All / Only selected)
- [ ] Test bout-en-bout sur une vraie issue
- [ ] Logs `web.log` vérifiés (pas d'erreur AI CodeFix)
- [ ] Plan de mesure d'adoption en place

## Références

- [AI CodeFix | SonarQube Server Docs](https://docs.sonarsource.com/sonarqube-server/ai-capabilities/ai-codefix)
- [Enable AI CodeFix | SonarQube Server](https://docs.sonarsource.com/sonarqube-server/instance-administration/ai-features/enable-ai-codefix)
- [Rules for AI CodeFix | SonarQube Server 2026.1](https://docs.sonarsource.com/sonarqube-server/2026.1/quality-standards-administration/managing-rules/rules-for-ai-codefix)
- [Sonar Community — AI CodeFix limit on self-hosted LLM](https://community.sonarsource.com/t/sonarqube-ai-codefix-limit-on-self-hosted-llm/149754)
- [Ollama OpenAI compatibility](https://github.com/ollama/ollama/blob/main/docs/openai.md)
- [vLLM — OpenAI-compatible server](https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html)
- [LiteLLM — proxy](https://docs.litellm.ai/docs/proxy/quick_start)
