# Guide Tech Lead et Architecte - SonarQube 2026

Audience : Tech Leads, Architectes

## Responsabilites

- Definir et maintenir les Quality Profiles par langage
- Piloter la dette technique des portefeuilles applicatifs
- Arbitrer les derogations au Quality Gate
- Valider les exclusions de code et les suppressions d issues

## Quality Profiles

Un Quality Profile est un ensemble de regles actives pour un langage.
L entreprise dispose de profils officiels par langage :
- Sonar Way Java Corporate
- Sonar Way DotNet Corporate
- Sonar Way JavaScript TypeScript Corporate
Ces profils integrent les regles ecocode.

Pour proposer une modification : soumettre une demande au Comite Qualite.

## Pilotage de la dette technique

Indicateurs a suivre :
- Evolution de la dette (trending sur 3 mois)
- Ratio dette/taille du code base
- Repartition par severite (Blocker, Critical, Major)
- Couverture globale vs couverture nouveau code

## Strategie legacy vs nouveau code

Nouveau code : Quality Gate strict (zero bug critique, couverture >= seuil)
Legacy : plan de remboursement de dette defini par sprint
Objectif : ne pas accroitre la dette et reduire de X pourcent par trimestre

## Gerer les derogations

1. Developpeur soumet une demande de derogation (fiche annexe 09)
2. Tech Lead valide ou refuse avec justification
3. Trace dans Sonar (commentaire sur l issue) et dans le registre des derogations
4. Duree limitee : 1 sprint maximum sauf exception documentee

## Vue Applications et Portfolios

Utiliser la vue Applications pour agreger plusieurs projets d une meme solution.
Utiliser les Portfolios pour avoir une vision par produit ou domaine metier.
Ces vues sont disponibles en edition Data Center.
