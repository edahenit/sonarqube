# Guide Projet Java JVM - SonarQube 2026

Audience : Developpeurs Java, Tech Leads

## Prerequis
JDK 17+, Maven 3.8+ ou Gradle 8+, token SonarQube

## Configuration Maven sonar-project.properties
sonar.projectKey=mon-projet-java
sonar.projectName=Mon Projet Java
sonar.host.url=${SONAR_HOST_URL}
sonar.token=${SONAR_TOKEN}
sonar.java.source=17
sonar.sources=src/main/java
sonar.tests=src/test/java
sonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml

Lancer : mvn clean verify sonar:sonar

## Configuration Gradle
Ajouter plugin id org.sonarqube
Lancer : ./gradlew test jacocoTestReport sonarqube

## Couverture JaCoCo
Ajouter jacoco-maven-plugin dans pom.xml avec goal report en phase verify.
Format XML requis : target/site/jacoco/jacoco.xml
Parametre Sonar : sonar.coverage.jacoco.xmlReportPaths

## Multi-modules Maven
Lancer sonar:sonar depuis le module parent.
Utiliser jacoco-aggregate pour le rapport consolide.
sonar.coverage.jacoco.xmlReportPaths=report-aggregate/target/site/jacoco-aggregate/jacoco.xml

## Exclusions
sonar.exclusions=**/generated-sources/**,**/target/**
sonar.coverage.exclusions=**/*Config.java,**/*Application.java,**/dto/**

## Cas particuliers
Spring Boot : aucune config specifique
Microservices : un projet Sonar par service
Monorepo : sonar.projectBaseDir + modules Sonar
