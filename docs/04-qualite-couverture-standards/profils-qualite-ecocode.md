# Quality Profiles et Plugin Ecocode - SonarQube 2026

## Quality Profiles officiels

L entreprise maintient les profils suivants :
- Sonar Way Java Corporate : base Sonar Way + regles securite + ecocode Java
- Sonar Way DotNet Corporate : base Sonar Way + regles securite + ecocode .NET
- Sonar Way JS TS Corporate : base Sonar Way + regles securite + ecocode JS

Ces profils sont en lecture seule pour les equipes projet.
Toute modification passe par le Comite Qualite.

## Plugin Ecocode

Objectif : identifier les patterns de code qui consomment inutilement des ressources (CPU, memoire, reseau, energie).

Regles examples :
- Eviter les boucles inutiles sur de grandes collections
- Fermer les flux (streams) apres utilisation
- Preferer les operations en batch aux appels unitaires
- Eviter les chargements de donnees inutiles (over-fetching)
- Reduire les allocations memoire excessives

Visibilite dans SonarQube : les regles ecocode apparaissent dans les Quality Profiles avec le tag ecocode.
Elles sont classifiees par severite et par langage.

## Comportement des regles ecocode en 2026

Mode : WARNING (signalement sans blocage du Quality Gate)
Impact visible dans le tableau de bord projet (onglet Issues)
Plan de migration 2027 : passage des regles critiques en BLOCKER

## Proposer une modification de profil

1. Identifier la regle cible (cle, severite, tags)
2. Rediger la justification metier
3. Soumettre au Comite Qualite via le formulaire de demande
4. Periode de validation : 1 mois minimum
5. Communication aux equipes avant activation
