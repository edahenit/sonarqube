# Pipeline CI/CD - Gradle (Java/Kotlin)

## Objectif

Ce guide decrit l'integration de SonarQube 2026 Data Center dans un pipeline CI/CD pour les projets Java ou Kotlin construits avec Gradle.

---

## Prerequis

- SonarQube 2026 Data Center accessible (URL + token de service)
- Gradle 8.x configure
- JDK 17 ou 21
- Plugin SonarQube Gradle : `id "org.sonarqube" version "5.x"`
- Plugin JaCoCo integre Gradle
- Plugin eco-code active cote SonarQube

---

## Configuration Gradle (build.gradle.kts)

```kotlin
plugins {
    java
    jacoco
    id("org.sonarqube") version "5.0.0.4638"
}

sonar {
    properties {
        property("sonar.host.url", System.getenv("SONAR_HOST_URL") ?: "https://sonarqube.entreprise.fr")
        property("sonar.projectKey", "mon-projet-gradle")
        property("sonar.projectName", "Mon Projet Gradle")
        property("sonar.coverage.jacoco.xmlReportPaths", "build/reports/jacoco/test/jacocoTestReport.xml")
        property("sonar.qualitygate.wait", "true")
    }
}

jacoco {
    toolVersion = "0.8.11"
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        html.required.set(true)
    }
}

tasks.sonarqube {
    dependsOn(tasks.jacocoTestReport)
}
```

---

## Pipeline GitLab CI

```yaml
sonarqube-analysis:
  stage: quality
  image: gradle:8-jdk21
  variables:
    SONAR_TOKEN: $SONAR_TOKEN
    SONAR_HOST_URL: $SONAR_HOST_URL
    GRADLE_OPTS: "-Dorg.gradle.daemon=false"
  script:
    - gradle test jacocoTestReport sonar
      -Dsonar.projectKey=${CI_PROJECT_PATH_SLUG}
      -Dsonar.branch.name=${CI_COMMIT_REF_NAME}
      -Dsonar.qualitygate.wait=true
  rules:
    - if: '$CI_COMMIT_BRANCH == "main" || $CI_PIPELINE_SOURCE == "merge_request_event"'
  artifacts:
    reports:
      junit: build/test-results/test/TEST-*.xml
    paths:
      - build/reports/jacoco/
    expire_in: 7 days
```

---

## Pipeline Jenkins (Declarative)

```groovy
pipeline {
  agent { label 'gradle-agent' }

  environment {
    SONAR_TOKEN = credentials('sonar-token')
    SONAR_HOST_URL = 'https://sonarqube.entreprise.fr'
  }

  stages {
    stage('Build & Test') {
      steps { sh './gradlew clean test jacocoTestReport' }
    }
    stage('SonarQube Analysis') {
      steps {
        withSonarQubeEnv('SonarQube-DC') {
          sh './gradlew sonar -Dsonar.projectKey=${JOB_NAME} -Dsonar.branch.name=${BRANCH_NAME} -Dsonar.qualitygate.wait=true'
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
}
```

---

## Pipeline GitHub Actions

```yaml
name: SonarQube Analysis - Gradle

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
      - name: Cache Gradle packages
        uses: actions/cache@v3
        with:
          path: |
            ~/.gradle/caches
            ~/.gradle/wrapper
          key: ${{ runner.os }}-gradle-${{ hashFiles('**/*.gradle*') }}
      - name: Build, Test & Analyze
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        run: |
          ./gradlew test jacocoTestReport sonar
            -Dsonar.host.url=${{ secrets.SONAR_HOST_URL }}
            -Dsonar.projectKey=${{ github.repository_owner }}_${{ github.event.repository.name }}
            -Dsonar.qualitygate.wait=true
```

---

## Variables CI/CD requises

| Variable | Description | Portee |
|---|---|---|
| `SONAR_TOKEN` | Token de service dedie (role Execute Analysis) | Secret CI |
| `SONAR_HOST_URL` | URL de l'instance SonarQube Data Center | Variable CI |
| `GRADLE_OPTS` | Options JVM pour desactiver le daemon Gradle en CI | Variable CI |

---

## Resolution des problemes courants

| Symptome | Cause probable | Solution |
|---|---|---|
| Task sonarqube introuvable | Plugin non applique | Verifier plugins block |
| Coverage a 0% | jacocoTestReport non execute avant sonar | Ajouter dependsOn |
| OOM en CI | Heap insuffisant | GRADLE_OPTS=-Xmx2g |
| Daemon Gradle actif | Conflit de processus | org.gradle.daemon=false |
