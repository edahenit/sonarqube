# Guide DevOps et CI/CD - SonarQube 2026

Audience : Equipes DevOps, Ingenieur CI/CD

## Integration SonarQube dans les pipelines

Etapes standard dans un pipeline :
1. Build du projet
2. Execution des tests unitaires + generation du rapport de couverture
3. Lancement du scanner SonarQube
4. Attente et verification du Quality Gate (waitForQualityGate)
5. Blocage du pipeline si Quality Gate KO
6. Publication de l artefact si Quality Gate OK

## Configuration du scanner

Variables d environnement necessaires :
- SONAR_HOST_URL : URL de l instance SonarQube
- SONAR_TOKEN : token d authentification (utiliser les secrets CI)

Ne jamais stocker le token en clair dans les fichiers de configuration.
Utiliser les secrets managers de la plateforme CI/CD.

## Gestion des branches

Branche principale (main/master) : analyse complete
Branches feature : analyse avec decoration PR
Branches release : analyse complete, Quality Gate obligatoire

Configuration de la strategie de branches dans sonar-project.properties :
sonar.branch.name=${BRANCH_NAME}

## Templates de pipelines

Voir le fichier 05-integration-cicd/templates-pipelines.md pour les exemples complets par technologie.

## Troubleshooting courant

- Erreur 401 : verifier le token SONAR_TOKEN
- Erreur de memoire : augmenter -Xmx pour le scanner
- Timeout Quality Gate : augmenter le delai dans waitForQualityGate
- Rapport de couverture non trouve : verifier le chemin dans sonar.coverage.jacoco.xmlReportPaths
- Issues non detectees : verifier sonar.sources et sonar.exclusions

## Monitoring des analyses

- Surveiller les logs du Compute Engine dans l administration Sonar
- Alertes sur les analyses en echec (webhook vers Slack/Teams)
- Tableau de bord des temps d analyse par projet
