# Pipeline CI/CD - Angular et React

## Objectif

Ce guide decrit l'integration de SonarQube 2026 Data Center dans un pipeline CI/CD pour les projets front-end Angular et React. Il couvre l'analyse statique TypeScript/JavaScript, la couverture de code (Jest/Karma), le Quality Gate et l'eco-conception.

---

## Prerequis

- SonarQube 2026 Data Center accessible (URL + token de service)
- Node.js 20 LTS ou superieur
- sonar-scanner-cli ou `sonarqube-scanner` npm
- Jest (React) ou Karma/Jest (Angular) configure pour generer des rapports LCOV
- Plugin eco-code active cote SonarQube

---

## Configuration Angular

### karma.conf.js - Rapport de couverture

```javascript
// karma.conf.js
module.exports = function (config) {
  config.set({
    // ... autres configurations
    coverageReporter: {
      type: 'lcovonly',
      dir: require('path').join(__dirname, './coverage'),
      subdir: '.',
      file: 'lcov.dat'
    },
    reporters: ['progress', 'kjhtml', 'coverage'],
    singleRun: true
  });
};
```

### angular.json - Activer la couverture

```json
"test": {
  "options": {
    "codeCoverage": true,
    "codeCoverageExclude": [
      "src/**/*.module.ts",
      "src/main.ts",
      "src/environments/**"
    ]
  }
}
```

### sonar-project.properties (Angular)

```properties
sonar.projectKey=mon-projet-angular
sonar.projectName=Mon Projet Angular
sonar.sources=src
sonar.exclusions=**/node_modules/**,**/*.spec.ts,src/environments/**
sonar.tests=src
sonar.test.inclusions=**/*.spec.ts
sonar.javascript.lcov.reportPaths=coverage/lcov.dat
sonar.qualitygate.wait=true
sonar.typescript.tsconfigPath=tsconfig.json
```

---

## Configuration React

### package.json - Configuration Jest

```json
"jest": {
  "collectCoverage": true,
  "coverageDirectory": "coverage",
  "coverageReporters": ["lcov", "text"],
  "collectCoverageFrom": [
    "src/**/*.{ts,tsx,js,jsx}",
    "!src/**/*.test.{ts,tsx}",
    "!src/index.{ts,tsx}",
    "!src/setupTests.{ts,tsx}"
  ]
}
```

### sonar-project.properties (React)

```properties
sonar.projectKey=mon-projet-react
sonar.projectName=Mon Projet React
sonar.sources=src
sonar.exclusions=**/node_modules/**,**/*.test.{ts,tsx,js,jsx}
sonar.tests=src
sonar.test.inclusions=**/*.test.{ts,tsx,js,jsx}
sonar.javascript.lcov.reportPaths=coverage/lcov.info
sonar.qualitygate.wait=true
sonar.typescript.tsconfigPath=tsconfig.json
```

---

## Pipeline GitLab CI (Angular)

```yaml
sonarqube-angular:
  stage: quality
  image: node:20-alpine
  before_script:
    - npm ci --cache .npm --prefer-offline
    - npm install -g @sonarqube/scanner
  script:
    - npx ng test --watch=false --browsers=ChromeHeadless --code-coverage
    - sonar-scanner
      -Dsonar.host.url=${SONAR_HOST_URL}
      -Dsonar.token=${SONAR_TOKEN}
      -Dsonar.projectKey=${CI_PROJECT_PATH_SLUG}
      -Dsonar.branch.name=${CI_COMMIT_REF_NAME}
  cache:
    key: node-modules
    paths: [node_modules/, .npm/]
  rules:
    - if: '$CI_COMMIT_BRANCH == "main" || $CI_PIPELINE_SOURCE == "merge_request_event"'
```

## Pipeline GitLab CI (React)

```yaml
sonarqube-react:
  stage: quality
  image: node:20-alpine
  before_script:
    - npm ci --cache .npm --prefer-offline
    - npm install -g @sonarqube/scanner
  script:
    - npm test -- --coverage --watchAll=false --ci
    - sonar-scanner
      -Dsonar.host.url=${SONAR_HOST_URL}
      -Dsonar.token=${SONAR_TOKEN}
      -Dsonar.projectKey=${CI_PROJECT_PATH_SLUG}
      -Dsonar.branch.name=${CI_COMMIT_REF_NAME}
  cache:
    key: node-modules
    paths: [node_modules/, .npm/]
  rules:
    - if: '$CI_COMMIT_BRANCH == "main" || $CI_PIPELINE_SOURCE == "merge_request_event"'
```

---

## Pipeline GitHub Actions (Angular et React)

```yaml
name: SonarQube Analysis - Frontend

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

      - name: Use Node.js 20
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      # Angular
      - name: Run Angular tests with coverage
        run: npx ng test --watch=false --browsers=ChromeHeadlessNoSandbox --code-coverage
        # Pour React, remplacer par : npm test -- --coverage --watchAll=false --ci

      - name: SonarQube Scan
        uses: SonarSource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        with:
          args: >
            -Dsonar.projectKey=${{ github.repository_owner }}_${{ github.event.repository.name }}
            -Dsonar.branch.name=${{ github.ref_name }}
            -Dsonar.qualitygate.wait=true
```

---

## Eco-Code : specificites front-end

Le plugin eco-code inclut des regles specifiques JavaScript/TypeScript pour :
- Detection des boucles inefficaces
- Utilisation de `document.querySelector` vs acces direct
- Eviter les re-renders inutiles (React hooks)
- Optimisation des imports (tree-shaking)

Ces regles sont actives automatiquement via le Quality Profile `Corporate-Frontend-EcoCode` associe au projet.

---

## Specificites TypeScript

Pour une analyse optimale du TypeScript :

```properties
# sonar-project.properties
sonar.typescript.tsconfigPath=tsconfig.json
# Pour les projets avec plusieurs tsconfig
sonar.typescript.tsconfigPath=tsconfig.app.json,tsconfig.spec.json
```

---

## Variables CI/CD requises

| Variable | Description | Portee |
|---|---|---|
| `SONAR_TOKEN` | Token de service dedie | Secret CI |
| `SONAR_HOST_URL` | URL de l'instance SonarQube Data Center | Variable CI |

---

## Resolution des problemes courants

| Symptome | Cause probable | Solution |
|---|---|---|
| Coverage a 0% | Rapport LCOV absent | Verifier le chemin dans `sonar.javascript.lcov.reportPaths` |
| Tests Chrome en CI | ChromeHeadless absent | Utiliser `ChromeHeadlessNoSandbox` ou image avec Chrome |
| Fichiers node_modules analyses | Exclusions manquantes | Ajouter `**/node_modules/**` dans `sonar.exclusions` |
| Lenteur analyse | Trop de fichiers inclus | Affiner `sonar.sources` et `sonar.exclusions` |
