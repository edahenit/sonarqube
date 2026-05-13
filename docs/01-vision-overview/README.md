# 01 - Vision et Vue d'ensemble SonarQube 2026 Data Center

> Audience : Tous les utilisateurs

## 1.1 Objectifs et enjeux

SonarQube est la plateforme centrale de qualite et securite du code de l'entreprise.
Deploye en edition Data Center 2026, il garantit :

- Haute disponibilite : cluster multi-noeuds, zero downtime
- Scalabilite horizontale : centaines de projets et analyses simultanees
- Securite renforcee : taint analysis, OWASP Top 10, CWE Top 25, SAST
- Eco-responsabilite : plugin ecocode integre

## 1.2 Architecture Data Center 2026

- Noeuds applicatifs (Web + Compute Engine) x3 minimum
- Base de donnees PostgreSQL (cluster haute disponibilite)
- Index Elasticsearch (dedie, non embarque)
- Load Balancer (HAProxy, Nginx ou equivalent)

## 1.3 Personas

| Persona | Usage principal |
|---|---|
| Developpeur | Corriger les issues, suivre le Quality Gate PR |
| Tech Lead | Standards, Quality Profiles, dette technique |
| Product Owner | Indicateurs, decision de release |
| DevOps | Integration CI/CD, tokens, pipelines |
| Securite/Compliance | Vulnerabilites, audits, hotspots |

## 1.4 Technologies couvertes

| Stack | Scanner | Couverture |
|---|---|---|
| Java/JVM | Maven / Gradle | JaCoCo XML |
| .NET | SonarScanner for .NET | coverlet |
| Angular | SonarScanner CLI | Jest/Karma LCOV |
| React | SonarScanner CLI | Jest LCOV |
| TypeScript | SonarScanner CLI | Jest LCOV |

## 1.5 Principes directeurs

1. Clean as You Code : priorite au Nouveau Code
2. Quality Gate = condition de release (aucune release si KO)
3. Standard unique : un seul Quality Gate corporate toutes stacks
4. Ecocode integre dans les Quality Profiles officiels
5. Gouvernance centralisee : tout changement passe par le Comite Qualite
