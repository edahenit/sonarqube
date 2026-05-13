# Guide Autres Stacks et Cas Particuliers - SonarQube 2026

Audience : Tech Leads, Equipes avec stacks non standards

## Principe pour les stacks non listees

SonarQube 2026 supporte nativement plus de 30 langages.
Pour tout langage non couvert par un guide dedie, appliquer le principe :
1. Verifier le support dans la documentation officielle Sonar
2. Utiliser SonarScanner CLI generique
3. Configurer sonar.sources, sonar.projectKey, sonar.token
4. La couverture peut ne pas etre disponible pour certains langages

## Scripts et automatisation (Shell, Python, etc.)

Sonar analyse Python, Shell, PHP, Ruby, Go, Kotlin, Swift, etc.
Configuration minimale :
sonar.projectKey=mon-projet-python
sonar.sources=src
sonar.language=py

Couverture Python : utiliser pytest-cov et le format XML
sonar.python.coverage.reportPaths=coverage.xml

## Projets legacy et dette historique

Si la couverture est impossible (code legacy sans tests) :
- Ne pas bloquer le Quality Gate sur la couverture globale
- Appliquer la politique Nouveau Code uniquement
- Ouvrir un chantier de refactoring planifie
- Documenter dans le registre de dette technique

## Code genere automatiquement

Exclure systematiquement :
- Code genere par des outils (JOOQ, Swagger, Protobuf, etc.)
- Code tiers embarque
- Scripts de migration de base de donnees

sonar.exclusions=**/generated/**,**/gen/**,**/*.pb.go,**/migrations/**

## Politique par defaut

Tout projet sans guide dedie doit au minimum :
- Etre analyse par SonarScanner CLI
- Respecter le Quality Gate corporate sur les issues de securite
- Etre reference dans le catalogue des projets Sonar
