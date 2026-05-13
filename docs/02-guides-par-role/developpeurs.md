# Guide Developpeur SonarQube 2026

Audience : Developpeurs Java .NET Angular React

## Routine quotidienne

1. Verifier le Quality Gate sur votre branche
2. Corriger les issues bloquantes sur le Nouveau Code
3. S assurer que la couverture respecte le seuil corporate

## Indicateurs cles

Bugs : erreurs certaines - tout bug critique doit etre corrige
Vulnerabilites : failles exploitables - aucune critique toleree
Code Smells : mauvaises pratiques - rating B minimum
Hotspots : zones a risque a valider manuellement
Couverture : seuil defini par le Quality Gate corporate
Duplications : moins de 3 pourcent sur nouveau code

## Nouveau Code (Clean as You Code)

Le Nouveau Code designe le code modifie depuis la reference de periode.
Priorite absolue : ne pas degrader le Nouveau Code.
Le legacy est traite separement via un plan de refactoring.

## Corriger les issues

Lire la regle Why is this an issue
Consulter How to fix it avec les exemples
Appliquer le correctif
Re-lancer l analyse via pipeline
Verifier la disparition de l issue

## Statuts d une issue

Open : a traiter
Confirmed : prise en compte
Accepted : won t fix avec justification obligatoire
Fixed : fermeture automatique apres correction

## Pull Requests et Quality Gate

SonarQube decore les PR avec le statut du Quality Gate.
Quality Gate Passed : merge autorise
Quality Gate Failed : merge bloque - politique corporate

## SonarLint

Extension IDE pour detecter les issues avant de committer.
Configurer en Connected Mode avec l instance SonarQube pour synchroniser les Quality Profiles officiels.

IDEs supportes : IntelliJ IDEA, VS Code, Visual Studio, Eclipse
