# Glossaire SonarQube 2026

Ce glossaire recense les termes cles utilises dans la documentation SonarQube 2026 Data Center.

---

## Termes SonarQube

**Bug** : Erreur certaine pouvant causer un comportement incorrect en production. Priorite de correction : bloquant ou critique.

**Vulnerabilite** : Faille de securite exploitable, action prioritaire obligatoire. Necessite une analyse et une correction immediate.

**Code Smell** : Mauvaise pratique nuisant a la maintenabilite du code. N'affecte pas directement le fonctionnement mais augmente la dette technique.

**Hotspot de securite** : Zone sensible necessitant une revue manuelle par un expert securite. Peut ou non etre une vraie vulnerabilite.

**Dette technique** : Temps estime pour corriger tous les code smells. Exprime en minutes, heures ou jours.

**Nouveau Code** : Code modifie depuis la date de reference definie (debut de sprint, derniere release, date specifique).

**Quality Gate** : Ensemble de conditions a remplir pour valider la qualite d'une release. Bloque ou autorise le passage en production.

**Quality Profile** : Ensemble de regles actives pour un langage donne. Peut etre herite et personnalise.

**Rating** : Note de A a E attribuee par metrique (A = excellent, E = critique). Utilise pour Fiabilite, Securite, Maintenabilite.

**Coverage (couverture)** : Pourcentage de code couvert par les tests automatises. Mesure par JaCoCo (Java), coverlet (.NET), LCOV (JS/TS).

**Duplication** : Pourcentage de code en doublon. Indicateur de refactoring necessaire.

**SonarLint** : Extension IDE permettant de detecter les issues en local, avant le commit. S'integre avec VS Code, IntelliJ, Eclipse, Visual Studio.

**Compute Engine** : Composant SonarQube responsable du traitement asynchrone des analyses soumises par les scanners.

**Taint Analysis** : Analyse du flux de donnees non validees (injection SQL, XSS, etc.). Disponible sur les langages Java, C#, PHP, Python.

**Portfolio** : Vue agregee multi-projets disponible en edition Data Center. Permet le suivi de la qualite par domaine metier.

**Application** : Agregation de projets representant une solution metier complete. Disponible en Data Center.

**Branch Analysis** : Analyse d'une branche de code specifique. Necessite la licence appropriee (Developer Edition ou superieure).

**Pull Request Analysis** : Analyse differentielles d'une PR/MR. Affiche les resultats directement dans l'interface de la forge.

**Scanner** : Outil CLI ou plugin qui execute l'analyse et envoie les resultats au serveur SonarQube.

---

## Termes internes entreprise

**Corporate Quality Gate** : Quality Gate standard unique de l'entreprise, applique a tous les projets. Defini et maintenu par la Plateforme Qualite.

**Comite Qualite** : Instance de gouvernance mensuelle des evolutions Sonar. Composee des referents techniques et de la Plateforme Qualite.

**Derogation** : Autorisation exceptionnelle et temporaire accordee pour un projet ne respectant pas le Quality Gate. Soumise au Comite Qualite.

**Plateforme Qualite** : Equipe transverse en charge de l'administration et de la gouvernance SonarQube au niveau entreprise.

**Referent Qualite** : Representant technique d'une equipe projet, interlocuteur privilegie de la Plateforme Qualite.

**Nouveau Code (definition entreprise)** : Tout code soumis apres la date de mise en service du projet sur SonarQube, ou apres chaque release taggee.

---

## Acronymes

| Acronyme | Signification |
|---|---|
| DC | Data Center |
| QG | Quality Gate |
| QP | Quality Profile |
| CI/CD | Continuous Integration / Continuous Deployment |
| LCOV | Linux Test Project Coverage Format |
| SAST | Static Application Security Testing |
| MR | Merge Request (GitLab) |
| PR | Pull Request (GitHub / Azure DevOps) |
| SCM | Source Code Management |
| SCA | Software Composition Analysis |

---

## Niveaux de severite

| Niveau | Description | Impact |
|---|---|---|
| Bloquant (Blocker) | Doit etre corrige immediatement | Bloque le Quality Gate |
| Critique (Critical) | Correction prioritaire requise | Bloque le Quality Gate |
| Majeur (Major) | Correction recommandee | Impact sur la note |
| Mineur (Minor) | Correction optionnelle | Impact faible |
| Info | A titre informatif | Aucun impact sur le QG |
