# Guide Product Owner - SonarQube 2026

Audience : Product Owners, Delivery Managers

## Lire le tableau de bord projet

Niveaux de rating :
A = Excellent, B = Bon, C = Acceptable, D = Mauvais, E = Critique

Indicateurs strategiques a suivre :
- Reliability Rating : fiabilite du code (bugs)
- Security Rating : securite du code (vulnerabilites)
- Maintainability Rating : maintenabilite (code smells)
- Security Review Rating : hotspots de securite
- Couverture de tests : pourcentage de code teste
- Dette technique : effort pour corriger les smells

## Quality Gate et decision de release

Le Quality Gate est le critere GO/NO-GO technique de la release.

Quality Gate Passed : tous les criteres sont remplis. Release autorisee.
Quality Gate Failed : un ou plusieurs criteres non remplis. Release bloquee sauf derogation formelle.

Processus de derogation :
1. Le Tech Lead soumet une fiche de derogation motivee
2. Le PO valide apres evaluation du risque metier
3. La derogation est tracee et limitee dans le temps

## Integrer Sonar dans la planification

- Inclure dans le Definition of Done : Quality Gate Passed obligatoire
- Prevoir des US de refactoring si la dette technique depasse le seuil
- Surveiller les tendances (amelioration ou degradation sur 3 sprints)
- Utiliser le rapport Application pour la vue produit complete

## Rapports pour les comites

Disponibles depuis SonarQube Data Center :
- Rapport PDF par projet ou application
- Portfolio global par produit ou BU
- Historique des evolutions (charts de tendance)

Frequence recommandee : rapport mensuel pour les comites de pilotage.
