#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

import requests

# ─── Configuration via variables d'environnement ──────────────────────────────
SONAR_URL   = os.environ.get("SONAR_URL", "").rstrip("/")
SONAR_TOKEN = os.environ.get("SONAR_TOKEN", "")

# ─── Paramètres ───────────────────────────────────────────────────────────────
YEAR_HISTORY  = 2025
SNAPSHOT_DATE = "2015-12-31"
OUTPUT_DIR    = Path("sonar_exports")

DEFAULT_METRICS = [
    "bugs",
    "vulnerabilities",
    "code_smells",
    "coverage",
    "duplicated_lines_density",
    "sqale_rating",
    "reliability_rating",
    "security_rating",
    "ncloc",
    "lines",
]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def check_env():
    """Vérifie que les variables d'environnement sont définies."""
    if not SONAR_URL:
        sys.exit("❌ Variable SONAR_URL non définie. Ex: export SONAR_URL=http://mon-sonar:9000")
    if not SONAR_TOKEN:
        sys.exit("❌ Variable SONAR_TOKEN non définie. Ex: export SONAR_TOKEN=mon_token")


def build_session() -> requests.Session:
    """Session authentifiée SonarQube via token Basic Auth."""
    session = requests.Session()
    session.auth = (SONAR_TOKEN, "")
    return session


def parse_sonar_datetime(dt_str: str) -> datetime:
    """Parse datetime SonarQube (ex: 2024-01-13T14:47:51+0200)."""
    if len(dt_str) >= 5 and dt_str[-5] in ["+", "-"] and dt_str[-3] != ":":
        dt_str = dt_str[:-2] + ":" + dt_str[-2:]
    return datetime.fromisoformat(dt_str)


def to_sonar_utc(dt: datetime) -> str:
    """Convertit un datetime en format UTC attendu par SonarQube."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000")


# ─── Récupération des analyses via /api/ce/activity ───────────────────────────

def get_all_ce_analyses(year: int, session: requests.Session, page_size: int = 500) -> list:
    """
    Récupère TOUTES les analyses (REPORT, SUCCESS) de l'année donnée
    via /api/ce/activity uniquement (pas de /api/projects/search).
    Retourne la liste de toutes les analyses avec :
      - project_key, project_name
      - analysis_id, task_id
      - branch, pull_request
      - executed_at, submitted_at
    """
    url = urljoin(SONAR_URL, "/api/ce/activity")
    start = datetime(year, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    end   = datetime(year, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

    analyses = []
    page = 1

    while True:
        params = {
            "type"        : "REPORT",
            "status"      : "SUCCESS",
            "minExecutedAt": to_sonar_utc(start),
            "maxExecutedAt": to_sonar_utc(end),
            "ps"          : page_size,
            "p"           : page,
        }

        resp = session.get(url, params=params)

        if resp.status_code == 403:
            sys.exit("❌ Accès /api/ce/activity refusé (droits admin requis).")

        resp.raise_for_status()
        data  = resp.json()
        tasks = data.get("tasks", [])

        if not tasks:
            break

        for task in tasks:
            component = task.get("component", {})
            key = component.get("key", "")
            if not key or not task.get("analysisId"):
                continue
            analyses.append({
                "project_key"  : key,
                "project_name" : component.get("name", key),
                "analysis_id"  : task.get("analysisId", ""),
                "task_id"      : task.get("id", ""),
                "branch"       : task.get("branch", ""),
                "pull_request" : task.get("pullRequest", ""),
                "executed_at"  : task.get("executedAt", ""),
                "submitted_at" : task.get("submittedAt", ""),
            })

        paging = data.get("paging", {})
        total  = paging.get("total", 0)
        if page * page_size >= total:
            break
        page += 1

    return analyses


# ─── Métriques par analysisId ──────────────────────────────────────────────────

def get_metrics_for_analysis(
    session: requests.Session,
    project_key: str,
    analysis_id: str,
    metrics: list,
) -> dict:
    """
    Récupère les valeurs des métriques pour une analyse précise
    via /api/measures/component?analysisId=<id>.
    """
    url = urljoin(SONAR_URL, "/api/measures/component")
    params = {
        "component" : project_key,
        "analysisId": analysis_id,
        "metricKeys": ",".join(metrics),
    }

    resp = session.get(url, params=params)
    resp.raise_for_status()

    result = {}
    for m in resp.json().get("component", {}).get("measures", []):
        result[m.get("metric")] = m.get("value", "")
    return result


# ─── Quality Gate par analysisId ──────────────────────────────────────────────

def get_quality_gate_for_analysis(
    session: requests.Session,
    project_key: str,
    analysis_id: str,
) -> str:
    """
    Récupère le statut du Quality Gate pour une analyse précise
    via /api/qualitygates/project_status?analysisId=<id>.
    Valeurs : OK, ERROR, WARN, NONE.
    """
    url = urljoin(SONAR_URL, "/api/qualitygates/project_status")
    params = {"projectKey": project_key, "analysisId": analysis_id}

    resp = session.get(url, params=params)
    if resp.status_code in [403, 404]:
        return ""
    resp.raise_for_status()
    return resp.json().get("projectStatus", {}).get("status", "")


# ─── Snapshot à la date précise ───────────────────────────────────────────────

def export_snapshot(
    analyses: list,
    session: requests.Session,
    target_date: datetime,
    metrics: list,
    output_dir: Path,
):
    """
    Pour chaque projet, trouve la dernière analyse AVANT ou ÉGALE à target_date,
    récupère ses métriques + Quality Gate via analysisId,
    et exporte le tout dans un seul fichier CSV snapshot.
    """
    print(f"\n📸 Génération snapshot au {target_date.strftime('%Y-%m-%d')}...")

    # Groupement par projet
    projects = {}
    for a in analyses:
        key = a["project_key"]
        if key not in projects:
            projects[key] = []
        projects[key].append(a)

    rows = []
    for project_key, project_analyses in projects.items():
        # Analyses <= target_date
        candidates = [
            a for a in project_analyses
            if a["executed_at"] and parse_sonar_datetime(a["executed_at"]) <= target_date
        ]
        if not candidates:
            continue

        # Dernière analyse avant la date cible
        best = max(candidates, key=lambda x: parse_sonar_datetime(x["executed_at"]))

        metrics_data = get_metrics_for_analysis(session, project_key, best["analysis_id"], metrics)
        qg_status    = get_quality_gate_for_analysis(session, project_key, best["analysis_id"])

        row = {
            "project_key"        : project_key,
            "project_name"       : best["project_name"],
            "analysis_id"        : best["analysis_id"],
            "task_id"            : best["task_id"],
            "executed_at"        : best["executed_at"],
            "branch"             : best["branch"],
            "pull_request"       : best["pull_request"],
            "quality_gate_status": qg_status,
        }
        for m in metrics:
            row[m] = metrics_data.get(m, "")
        rows.append(row)

    if not rows:
        print("   ⚠️  Aucun projet avec analyse avant cette date.")
        return

    filename = output_dir / f"snapshot_{target_date.strftime('%Y%m%d')}.csv"
    fieldnames = [
        "project_key", "project_name", "analysis_id", "task_id",
        "executed_at", "branch", "pull_request", "quality_gate_status",
    ] + metrics

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"   ✅ {len(rows)} projets → {filename}")


# ─── Historique 2025 ──────────────────────────────────────────────────────────

def export_history(
    analyses: list,
    session: requests.Session,
    year: int,
    metrics: list,
    output_dir: Path,
):
    """
    Pour chaque projet, exporte TOUTES les analyses de l'année
    avec métriques + Quality Gate dans un CSV séparé.
    Tri chronologique dans chaque fichier.
    """
    print(f"\n📈 Génération historique {year} (1 CSV par projet)...")

    # Groupement par projet
    projects = {}
    for a in analyses:
        key = a["project_key"]
        if key not in projects:
            projects[key] = []
        projects[key].append(a)

    total = 0
    for project_key, project_analyses in projects.items():
        rows = []

        # Tri chronologique
        for analysis in sorted(project_analyses, key=lambda x: parse_sonar_datetime(x["executed_at"])):
            metrics_data = get_metrics_for_analysis(session, project_key, analysis["analysis_id"], metrics)
            qg_status    = get_quality_gate_for_analysis(session, project_key, analysis["analysis_id"])

            executed_dt = parse_sonar_datetime(analysis["executed_at"])
            row = {
                "project_key"        : project_key,
                "project_name"       : analysis["project_name"],
                "date"               : executed_dt.strftime("%Y-%m-%d"),
                "executed_at"        : analysis["executed_at"],
                "analysis_id"        : analysis["analysis_id"],
                "task_id"            : analysis["task_id"],
                "branch"             : analysis["branch"],
                "pull_request"       : analysis["pull_request"],
                "quality_gate_status": qg_status,
            }
            for m in metrics:
                row[m] = metrics_data.get(m, "")

            rows.append(row)

        filename = output_dir / f"{project_key}_history_{year}.csv"
        if rows:
            fieldnames = [
                "project_key", "project_name", "date", "executed_at",
                "analysis_id", "task_id", "branch", "pull_request",
                "quality_gate_status",
            ] + metrics
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            total += len(rows)
            print(f"   ✅ {project_key}: {len(rows)} analyses → {filename.name}")

    print(f"   📊 Total : {total} analyses exportées")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    check_env()

    OUTPUT_DIR.mkdir(exist_ok=True)
    session = build_session()

    print("🚀 EXPORT SONARQUBE OPTIMISÉ")
    print(f"🔗 Serveur  : {SONAR_URL}")
    print(f"📅 Snapshot : {SNAPSHOT_DATE}")
    print(f"📊 Métriques: {', '.join(DEFAULT_METRICS)}")
    print(f"📁 Sortie   : {OUTPUT_DIR.absolute()}")

    # 1. UNIQUEMENT /api/ce/activity (pas de /api/projects/search)
    print(f"\n🔍 Récupération analyses {YEAR_HISTORY} via /api/ce/activity...")
    analyses = get_all_ce_analyses(YEAR_HISTORY, session)

    if not analyses:
        sys.exit(f"❌ Aucune analyse trouvée pour {YEAR_HISTORY}.")

    nb_projects = len(set(a["project_key"] for a in analyses))
    print(f"   ✅ {len(analyses)} analyses → {nb_projects} projets actifs en {YEAR_HISTORY}")

    # 2. Snapshot à la date précise
    target_date = datetime.strptime(SNAPSHOT_DATE, "%Y-%m-%d")
    export_snapshot(analyses, session, target_date, DEFAULT_METRICS, OUTPUT_DIR)

    # 3. Historique complet 2025
    export_history(analyses, session, YEAR_HISTORY, DEFAULT_METRICS, OUTPUT_DIR)

    print(f"\n🎉 EXPORT TERMINÉ → {OUTPUT_DIR.absolute()}")


if __name__ == "__main__":
    main()
