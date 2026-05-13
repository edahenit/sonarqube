# Guide Projet .NET - SonarQube 2026

Audience : Developpeurs .NET, Tech Leads .NET

## Prerequis
.NET SDK 6/7/8, SonarScanner for .NET (dotnet tool), token SonarQube

Installation du scanner :
dotnet tool install --global dotnet-sonarscanner

## Pipeline type Azure DevOps / Jenkins

Etape 1 : Begin
dotnet sonarscanner begin /k:mon-projet /d:sonar.host.url=${SONAR_HOST_URL} /d:sonar.token=${SONAR_TOKEN} /d:sonar.cs.opencover.reportsPaths=coverage/coverage.opencover.xml

Etape 2 : Build
dotnet build --no-restore

Etape 3 : Tests + Couverture
dotnet test --no-build --collect:"XPlat Code Coverage" --results-directory:./coverage -- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Format=opencover

Etape 4 : End
dotnet sonarscanner end /d:sonar.token=${SONAR_TOKEN}

## Couverture de code

Outil recommande : coverlet (integre dans .NET SDK)
Format requis : OpenCover ou Cobertura
Parametre Sonar : sonar.cs.opencover.reportsPaths ou sonar.cs.cobertura.reportsPaths

## Exclusions recommandees
sonar.exclusions=**/*.Designer.cs,**/Migrations/**,**/*.g.cs
sonar.coverage.exclusions=**/Program.cs,**/Startup.cs,**/Migrations/**

## Cas particuliers
Solutions multi-projets : analyser depuis le repertoire de la solution (.sln)
Azure DevOps : utiliser la task officielle SonarQubePrepare, SonarQubeAnalyze, SonarQubePublish
