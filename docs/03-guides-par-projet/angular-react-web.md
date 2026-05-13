# Guide Projet Angular React Web - SonarQube 2026

Audience : Developpeurs Front-end, Tech Leads

## Prerequis
Node.js 18+, SonarScanner CLI, token SonarQube

Installation du scanner :
npm install -g sonarqube-scanner

## Configuration sonar-project.properties
sonar.projectKey=mon-projet-angular
sonar.projectName=Mon Projet Angular
sonar.sources=src
sonar.exclusions=**/*.spec.ts,node_modules/**,dist/**
sonar.tests=src
sonar.test.inclusions=**/*.spec.ts
sonar.javascript.lcov.reportPaths=coverage/lcov.info
sonar.typescript.tsconfigPath=tsconfig.json

## Angular - Couverture avec Jest ou Karma

Jest (recommande) :
Dans jest.config.js, ajouter :
collectCoverage: true
coverageReporters: [lcov, text]
coverageDirectory: coverage

Lancer : npx jest --coverage
Rapport : coverage/lcov.info

Karma :
Dans karma.conf.js, ajouter le reporter lcovonly.
Lancer : ng test --no-watch --code-coverage
Rapport : coverage/lcov.info

## React - Couverture avec Jest

Dans package.json scripts :
test: react-scripts test --coverage --watchAll=false --coverageReporters=lcov

Ou avec Vite :
npx vitest run --coverage

Rapport : coverage/lcov.info
Parametre Sonar : sonar.javascript.lcov.reportPaths=coverage/lcov.info

## Monorepo (Nx, Turborepo)

Nx : utiliser nx affected:test ou nx run-many --target=test
Un projet Sonar par application ou bibliotheque strategique.
Utiliser sonar.projectBaseDir pour pointer vers chaque app.

## Exclusions recommandees
sonar.exclusions=node_modules/**,dist/**,build/**,**/*.d.ts,**/environments/**
sonar.coverage.exclusions=**/*.module.ts,**/*.routing.ts,**/*.stories.ts,**/index.ts
