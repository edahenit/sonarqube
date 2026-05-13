# Gating des Releases - SonarQube 2026

## Principe

Aucune release ne peut etre deployee en production si le Quality Gate est en echec.
Politique non negociable sauf derogation formelle.

## Workflow de release type

1. Dev sur branche feature
2. PR vers main/develop : Quality Gate verifie
3. Merge autorise si Quality Gate PASSED seulement
4. Build de release : analyse Sonar sur branche release
5. Quality Gate PASSED : artefact promu vers registre
6. Quality Gate FAILED : correction obligatoire ou derogation formelle
7. Production : artefact qualifie uniquement

## Modele Release Notes Qualite

Version : X.Y.Z - Date : DD/MM/YYYY
Statut Quality Gate : PASSED ou FAILED avec derogation

Indicateurs Sonar :
- Couverture nouveau code : X pourcent
- Bugs critiques corriges : X
- Vulnerabilites traitees : X
- Dette technique ajoutee : X minutes
- Hotspots securite revus : X sur Y

## Derogation

Cas autorises : faux positif confirme, contrainte externe documentee
Processus : fiche signee, tracee ITSM + commentaire dans Sonar
Duree max : 1 sprint

## Maintenance evolutive

Suivre les tendances par release :
- Evolution de la dette sur 3 releases
- Regression ou amelioration de la couverture
- Nombre de vulnerabilites nouvelles ou corrigees
Ces donnees alimentent les comites de pilotage trimestriels.
