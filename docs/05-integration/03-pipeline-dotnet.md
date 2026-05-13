# Pipeline CI/CD - .NET (C#)

## Objectif

Ce guide decrit l'integration de SonarQube 2026 Data Center dans un pipeline CI/CD pour les projets .NET (C#, ASP.NET Core, Blazor). Il couvre l'analyse statique, la couverture de code avec coverlet, le Quality Gate et l'eco-conception.

---

## Prerequis

- SonarQube 2026 Data Center accessible (URL + token de service)
- .NET 8 ou .NET 9 SDK
- SonarScanner for .NET : `dotnet-sonarscanner` (outil global)
- coverlet pour la couverture de code
- Plugin eco-code active cote SonarQube

---

## Installation du SonarScanner .NET

```bash
# Installation globale (a faire une fois par agent CI)
dotnet tool install --global dotnet-sonarscanner

# Verification
dotnet sonarscanner --version
```

---

## Configuration du projet (.csproj)

```xml
<ItemGroup>
  <PackageReference Include="coverlet.collector" Version="6.0.2">
    <PrivateAssets>all</PrivateAssets>
    <IncludeAssets>runtime; build; native; contentfiles; analyzers</IncludeAssets>
  </PackageReference>
  <PackageReference Include="coverlet.msbuild" Version="6.0.2">
    <PrivateAssets>all</PrivateAssets>
  </PackageReference>
</ItemGroup>
```

---

## Pipeline GitLab CI

```yaml
sonarqube-analysis:
  stage: quality
  image: mcr.microsoft.com/dotnet/sdk:8.0
  variables:
    SONAR_TOKEN: $SONAR_TOKEN
    SONAR_HOST_URL: $SONAR_HOST_URL
  before_script:
    - dotnet tool install --global dotnet-sonarscanner
    - export PATH="$PATH:$HOME/.dotnet/tools"
  script:
    - dotnet sonarscanner begin
        /k:"${CI_PROJECT_PATH_SLUG}"
        /d:sonar.host.url="${SONAR_HOST_URL}"
        /d:sonar.token="${SONAR_TOKEN}"
        /d:sonar.branch.name="${CI_COMMIT_REF_NAME}"
        /d:sonar.cs.opencover.reportsPaths="**/coverage.opencover.xml"
        /d:sonar.qualitygate.wait=true
    - dotnet build --no-incremental
    - dotnet test
        --collect:"XPlat Code Coverage"
        -- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Format=opencover
    - dotnet sonarscanner end /d:sonar.token="${SONAR_TOKEN}"
  rules:
    - if: '$CI_COMMIT_BRANCH == "main" || $CI_PIPELINE_SOURCE == "merge_request_event"'
  artifacts:
    paths:
      - '**/TestResults/'
    expire_in: 7 days
```

---

## Pipeline Jenkins (Declarative)

```groovy
pipeline {
  agent { label 'dotnet-agent' }

  environment {
    SONAR_TOKEN = credentials('sonar-token')
    SONAR_HOST_URL = 'https://sonarqube.entreprise.fr'
  }

  stages {
    stage('Begin Analysis') {
      steps {
        sh '''
          dotnet sonarscanner begin \
            /k:"${JOB_NAME}" \
            /d:sonar.host.url="${SONAR_HOST_URL}" \
            /d:sonar.token="${SONAR_TOKEN}" \
            /d:sonar.branch.name="${BRANCH_NAME}" \
            /d:sonar.cs.opencover.reportsPaths="**/coverage.opencover.xml" \
            /d:sonar.qualitygate.wait=true
        '''
      }
    }

    stage('Build') {
      steps { sh 'dotnet build --no-incremental' }
    }

    stage('Test') {
      steps {
        sh '''
          dotnet test \
            --collect:"XPlat Code Coverage" \
            -- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Format=opencover
        '''
      }
    }

    stage('End Analysis') {
      steps {
        sh 'dotnet sonarscanner end /d:sonar.token="${SONAR_TOKEN}"'
      }
    }

    stage('Quality Gate') {
      steps {
        timeout(time: 5, unit: 'MINUTES') {
          waitForQualityGate abortPipeline: true
        }
      }
    }
  }
}
```

---

## Pipeline GitHub Actions

```yaml
name: SonarQube Analysis - .NET

on:
  push:
    branches: [main, develop]
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  sonar:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up .NET 8
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '8.0.x'

      - name: Install SonarScanner
        run: dotnet tool install --global dotnet-sonarscanner

      - name: Begin SonarQube Analysis
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        run: |
          dotnet sonarscanner begin \
            /k:"${{ github.repository_owner }}_${{ github.event.repository.name }}" \
            /d:sonar.host.url="${{ secrets.SONAR_HOST_URL }}" \
            /d:sonar.token="${{ secrets.SONAR_TOKEN }}" \
            /d:sonar.cs.opencover.reportsPaths="**/coverage.opencover.xml" \
            /d:sonar.qualitygate.wait=true

      - name: Build
        run: dotnet build --no-incremental

      - name: Test
        run: |
          dotnet test \
            --collect:"XPlat Code Coverage" \
            -- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Format=opencover

      - name: End SonarQube Analysis
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        run: dotnet sonarscanner end /d:sonar.token="${{ secrets.SONAR_TOKEN }}"
```

---

## Couverture de code - Options coverlet

| Option | Description | Valeur recommandee |
|---|---|---|
| Format opencover | Compatible SonarQube | `opencover` (obligatoire) |
| Exclude par attribut | Exclure le code genere | `[ExcludeFromCodeCoverage]` |
| Threshold | Seuil minimal de coverage | Configurer dans Quality Gate Sonar |

```bash
# Commande complete avec exclusions
dotnet test \
  --collect:"XPlat Code Coverage" \
  -- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Format=opencover \
     DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Exclude="[*]*.Migrations.*"
```

---

## Variables CI/CD requises

| Variable | Description | Portee |
|---|---|---|
| `SONAR_TOKEN` | Token de service dedie (role Execute Analysis) | Secret CI |
| `SONAR_HOST_URL` | URL de l'instance SonarQube Data Center | Variable CI |

---

## Resolution des problemes courants

| Symptome | Cause probable | Solution |
|---|---|---|
| Coverage a 0% | Format opencover absent | Ajouter `Format=opencover` dans la commande test |
| SonarScanner introuvable | Outil non installe | `dotnet tool install --global dotnet-sonarscanner` |
| Analyse bloquee | begin sans end | Toujours appeler `sonarscanner end` |
| Quality Gate timeout | Reseau ou token invalide | Verifier connectivite et token |
