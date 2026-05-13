# SonarQube 2026 Data Center – Référentiel Qualité & Guide Utilisateurs

> **Edition** : SonarQube Data Center 2026  
> **Owner** : Équipe Plateforme Qualité  
> **Dernière mise à jour** : Mai 2026  
> **Statut** : Actif

---

## Objectif de ce référentiel

Ce référentiel constitue la **source de vérité** pour l'utilisation de SonarQube au sein de l'entreprise.  
Il complète la documentation officielle Sonar en y ajoutant les **conventions internes**, les **standards de qualité corporate**, et les **playbooks** par technologie et par rôle.

Il s'adresse à tous les acteurs du cycle de vie logiciel : développeurs, tech leads, Product Owners, équipes DevOps, sécurité et management.

---

## Périmètre

| Dimension | Détail |
|---|---|
| **Edition SonarQube** | Data Center 2026 |
| **Langages couverts** | Java/JVM, .NET, JavaScript, TypeScript, Angular, React |
| **Plugins** | éco-code, plugins reporting |
| **CI/CD** | Jenkins, GitLab CI, Azure DevOps, GitHub Actions |
| **Standards** | Quality Gate Corporate, Quality Profiles par langage |

---

## Structure de la documentation

```
docs/
├── 01-vision-overview/         # Architecture, principes, personas
├── 02-guides-par-role/         # Guides par profil utilisateur
│   ├── developpeurs.md
│   ├── tech-leads.md
│   ├── product-owners.md
│   ├── devops-cicd.md
│   └── securite-compliance.md
├── 03-guides-par-projet/       # Playbooks par technologie
│   ├── java-jvm.md
│   ├── dotnet.md
│   ├── angular-react-web.md
│   └── autres-stacks.md
├── 04-qualite-couverture-standards/  # Standards corporates
│   ├── modele-qualite.md
│   ├── politique-couverture.md
│   ├── quality-gate-standard.md
│   └── profils-qualite-ecocode.md
├── 05-integration-cicd/        # Intégration pipelines
│   ├── principes.md
│   ├── templates-pipelines.md
│   └── troubleshooting-ci.md
├── 06-release-management/      # Release & reporting
│   ├── gating-releases.md
│   ├── release-notes-qualite.md
│   └── reporting-multi-projets.md
├── 07-exploitation-datacenter/ # Ops & SRE
│   ├── architecture-slo.md
│   ├── operations-courantes.md
│   └── upgrades.md
├── 08-gouvernance/             # Gouvernance & évolution
│   ├── comite-sonar.md
│   ├── gestion-documentation.md
│   └── formation-onboarding.md
└── 09-annexes/                 # Modèles, FAQ, glossaire
    ├── glossaire.md
    ├── faq.md
    ├── modele-readme-sonar.md
    ├── fiche-derogation.md
    └── modele-release-notes.md
```

---

## Liens essentiels

| Ressource | Lien |
|---|---|
| Instance SonarQube | `https://sonarqube.entreprise.com` |
| Documentation officielle | https://docs.sonarsource.com/sonarqube-server |
| Support interne | Ouvrir un ticket sur le portail ITSM |
| Comité Qualité | Réunion mensuelle – contacter l'équipe Plateforme |

---

## Contacts

| Rôle | Responsabilité |
|---|---|
| Équipe Plateforme Qualité | Administration SonarQube, Quality Gates, Plugins |
| Leads Techniques | Quality Profiles par domaine |
| RSSI / Sécurité | Règles sécurité, hotspots, audits |

---

*Ce document est maintenu par l'équipe Plateforme Qualité. Toute modification doit suivre le processus de gouvernance décrit dans [08-gouvernance/gestion-documentation.md](08-gouvernance/gestion-documentation.md).*
