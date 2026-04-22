# Projet Python de test — SonarQube 2026.1 + JFrog Evidence

Projet minimal utilisé pour valider les pipelines [../jenkins/Jenkinsfile](../jenkins/Jenkinsfile)
et [../gitlab/.gitlab-ci.yml](../gitlab/.gitlab-ci.yml).

## Structure

```
test-project/
├── pyproject.toml              # build (wheel) + config pytest/coverage
├── sonar-project.properties    # clé projet + chemins coverage/tests pour Sonar
├── src/calculator/
│   ├── __init__.py
│   └── calculator.py           # add, subtract, multiply, divide
└── tests/
    └── test_calculator.py      # 5 tests pytest
```

## Exécution locale

```bash
python -m pip install -e '.[dev]'
pytest                          # -> coverage.xml + reports/pytest.xml
python -m build                 # -> dist/*.whl et dist/*.tar.gz
```

## Artefacts consommés par les pipelines

| Artefact | Producteur | Consommateur |
|---|---|---|
| `coverage.xml` | `pytest --cov` | `sonar-scanner` (via `sonar.python.coverage.reportPaths`) |
| `reports/pytest.xml` | `pytest --junitxml` | `sonar-scanner` (via `sonar.python.xunit.reportPath`) |
| `.scannerwork/report-task.txt` | `sonar-scanner` | `jf evd create --integration=sonar` |
| `dist/*.whl` | `python -m build` | `jf rt upload` vers PyPI Artifactory |

## Paramètres Sonar clés

- `sonar.sources=src` — le scanner analyse `src/calculator/`
- `sonar.tests=tests` — les tests ne comptent pas dans les métriques de dette
- `sonar.python.coverage.reportPaths=coverage.xml` — couverture remontée au Quality Gate
