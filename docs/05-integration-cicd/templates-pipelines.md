# Templates de Pipelines CI/CD - SonarQube 2026

## Jenkins - Java Maven

stage SonarQube Analysis :
  withSonarQubeEnv SonarQube :
    sh mvn sonar:sonar
stage Quality Gate :
  timeout 5 minutes :
    waitForQualityGate abortPipeline true

## GitLab CI - Java Maven

sonarqube-check:
  image: maven:3.9-eclipse-temurin-17
  script:
    - mvn clean verify sonar:sonar -Dsonar.qualitygate.wait=true -Dsonar.host.url=$SONAR_HOST_URL -Dsonar.token=$SONAR_TOKEN

## GitHub Actions - Java Gradle

step SonarQube Scan:
  uses: SonarSource/sonarqube-scan-action@master
  env:
    SONAR_TOKEN: secrets.SONAR_TOKEN
    SONAR_HOST_URL: vars.SONAR_HOST_URL

## Azure DevOps - .NET

task: SonarQubePrepare@6
  scannerMode: MSBuild
  projectKey: mon-projet-dotnet
task: DotNetCoreCLI@2
  command: test
  arguments: --collect XPlat Code Coverage
task: SonarQubeAnalyze@6
task: SonarQubePublish@6
  pollingTimeoutSec: 300

## GitLab CI - Angular React Node

sonarqube-check:
  image: node:18-alpine
  script:
    - npm ci
    - npm test -- --coverage --watchAll=false
    - npx sonarqube-scanner -Dsonar.host.url=$SONAR_HOST_URL -Dsonar.token=$SONAR_TOKEN -Dsonar.qualitygate.wait=true

## Variables requises dans tous les pipelines

SOMAR_HOST_URL : URL de l instance SonarQube (stocker en variable CI)
SONAR_TOKEN : token d authentification (stocker en secret CI, ne jamais committer)
