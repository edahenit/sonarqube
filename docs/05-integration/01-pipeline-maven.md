# Pipeline CI/CD – Maven (Java)

## Objectif

Ce guide décrit l'intégration de SonarQube 2026 Data Center dans un pipeline CI/CD pour les projets Java construits avec Maven. Il couvre l'analyse statique, la couverture de code, le Quality Gate, et l'éco-conception.

---

## Prérequis

- SonarQube 2026 Data Center accessible (URL + token de service)
- Maven 3.8+ configuré
- JDK 17 ou 21
- Plugin Sonar Maven : `org.sonarsource.scanner.maven:sonar-maven-plugin:4.x`
- JaCoCo pour la couverture de code
- Plugin eco-code activé côté SonarQube

---

## Configuration Maven (`pom.xml`)

### Plugin JaCoCo

```xml
<plugin>
  <groupId>org.jacoco</groupId>
  <artifactId>jacoco-maven-plugin</artifactId>
  <version>0.8.11</version>
  <executions>
    <execution>
      <id>prepare-agent</id>
      <goals><goal>prepare-agent</goal></goals>
    </execution>
    <execution>
      <id>report</id>
      <phase>verify</phase>
      <goals><goal>report</goal></goals>
    </execution>
  </executions>
</plugin>
```

### Propriétés Sonar

```xml
<properties>
  <sonar.host.url>https://sonarqube.entreprise.fr</sonar.host.url>
  <sonar.projectKey>mon-projet-java</sonar.projectKey>
  <sonar.projectName>Mon Projet Java</sonar.projectName>
  <sonar.java.coveragePlugin>jacoco</sonar.java.coveragePlugin>
  <sonar.coverage.jacoco.xmlReportPaths>target/site/jacoco/jacoco.xml</sonar.coverage.jacoco.xmlReportPaths>
  <sonar.qualitygate.wait>true</sonar.qualitygate.wait>
</properties>
```

---

## Pipeline GitLab CI

```yaml
sonarqube-analysis:
  stage: quality
  image: maven:3.9-eclipse-temurin-21
  variables:
    SONAR_TOKEN: $SONAR_TOKEN
    SONAR_HOST_URL: $SONAR_HOST_URL
  script:
    - mvn verify sonar:sonar
      -Dsonar.projectKey=${CI_PROJECT_PATH_SLUG}
      -Dsonar.branch.name=${CI_COMMIT_REF_NAME}
      -Dsonar.qualitygate.wait=true
  rules:
    - if: '$CI_COMMIT_BRANCH == "main" || $CI_PIPELINE_SOURCE == "merge_request_event"'
  artifacts:
    reports:
      junit: target/surefire-reports/TEST-*.xml
    paths:
      - target/site/jacoco/
    expire_in: 7 days
```

---

## Pipeline Jenkins (Declarative)

```groovy
pipeline {
  agent { label 'maven-agent' }

  environment {
    SONAR_TOKEN = credentials('sonar-token')
    SONAR_HOST_URL = 'https://sonarqube.entreprise.fr'
  }

  stages {
    stage('Build & Test') {
      steps {
        sh 'mvn clean verify'
      }
    }

    stage('SonarQube Analysis') {
      steps {
        withSonarQubeEnv('SonarQube-DC') {
          sh '''
            mvn sonar:sonar \
              -Dsonar.projectKey=${JOB_NAME} \
              -Dsonar.branch.name=${BRANCH_NAME} \
              -Dsonar.qualitygate.wait=true
          '''
        }
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

  post {
    always {
      junit 'target/surefire-reports/**/*.xml'
      publishHTML([
        reportDir: 'target/site/jacoco',
        reportFiles: 'index.html',
        reportName: 'JaCoCo Coverage'
      ])
    }
  }
}
```

---

## Pipeline GitHub Actions

```yaml
name: SonarQube Analysis – Maven

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

      - name: Set up JDK 21
        uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'temurin'

      - name: Cache Maven packages
        uses: actions/cache@v3
        with:
          path: ~/.m2
          key: ${{ runner.os }}-m2-${{ hashFiles('**/pom.xml') }}

      - name: Build, Test & Analyze
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        run: |
          mvn verify sonar:sonar \
            -Dsonar.host.url=${{ secrets.SONAR_HOST_URL }} \
            -Dsonar.projectKey=${{ github.repository_owner }}_${{ github.event.repository.name }} \
            -Dsonar.qualitygate.wait=true
```

---

## Règles de déclenchement recommandées

| Événement | Comportement |
|---|---|
| Push sur `main` / `master` | Analyse complète + Quality Gate bloquant |
| Merge Request / Pull Request | Analyse différentielle (Nouveau Code uniquement) |
| Push sur branche feature | Analyse avec Quality Gate non-bloquant (warning) |
| Tag de release | Analyse + génération rapport complet |

---

## Eco-Code : paramètres spécifiques Maven

Le plugin eco-code est activé au niveau du Quality Profile SonarQube. Aucune configuration Maven spécifique n'est requise. Vérifier que le Quality Profile `Corporate-Java-EcoCode` est bien associé au projet.

Pour forcer l'activation en local (SonarLint) :

```xml
<!-- Dans .sonarlint/connectedMode.json -->
{
  "projectKey": "mon-projet-java",
  "serverId": "sonarqube-entreprise"
}
```

---

## Variables CI/CD requises

| Variable | Description | Portée |
|---|---|---|
| `SONAR_TOKEN` | Token de service dédié (rôle Execute Analysis) | Secret CI |
| `SONAR_HOST_URL` | URL de l'instance SonarQube Data Center | Variable CI |
| `SONAR_PROJECT_KEY` | Clé unique du projet | Variable CI ou pom.xml |

---

## Résolution des problèmes courants

| Symptôme | Cause probable | Solution |
|---|---|---|
| Quality Gate en timeout | `sonar.qualitygate.wait=true` sans réseau | Vérifier la connectivité au serveur Sonar |
| Coverage à 0% | JaCoCo non exécuté avant Sonar | Exécuter `mvn verify` (pas `package`) |
| Analyse hors branche | Branch plugin non configuré | Vérifier la licence et `sonar.branch.name` |
| Token invalide | Token expiré ou révoqué | Renouveler le token dans Administration > Security |
