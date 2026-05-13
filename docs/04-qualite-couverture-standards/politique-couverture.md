# Politique de Couverture de Code - SonarQube 2026

## Principe

SonarQube n execute pas les tests. Il importe les rapports de couverture generes par les outils de test.
Le pipeline doit : executer les tests, generer le rapport, puis lancer l analyse Sonar.

## Objectifs de couverture

Nouveau code : minimum 80 pourcent de couverture
Code global (historique) : objectif non bloquant, tendance surveillee
Code de test lui-meme : exclu de la couverture

## Par langage

Java : JaCoCo XML (sonar.coverage.jacoco.xmlReportPaths)
.NET : OpenCover ou Cobertura (sonar.cs.opencover.reportsPaths)
JavaScript TypeScript Angular React : LCOV (sonar.javascript.lcov.reportPaths)
Python : coverage.xml (sonar.python.coverage.reportPaths)

## Exclusions de couverture

Exclure systematiquement :
- Code genere (JOOQ, Swagger, Protobuf)
- Classes de configuration
- Classes main/Startup
- DTOs et entites pures
- Scripts de migration

Parametre : sonar.coverage.exclusions=**/generated/**,**/*Config.*,**/dto/**

## Ce qui est mesure

Line coverage : pourcentage de lignes de code executees par les tests
Condition coverage : pourcentage de branches conditionnelles testees

SonarQube affiche les deux, la condition du Quality Gate porte sur la line coverage.

## Recommandations

- Ecrire les tests avant l analyse (TDD ou au moins les tests d abord)
- Ne pas ecrire des tests vides juste pour augmenter la couverture
- Cibler les chemins metier critiques en priorite
- Les tests d integration comptent si le rapport est configure correctement
