#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

import requests

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

YEAR_HISTORY = 2025


def build_session(base_url: str, token: str) -> requests.Session:
    """Session SonarQube."""
    session = requests.Session()
    session.auth = (token, "")
    return session


def parse_sonar_datetime(dt_str: str) -> datetime:
    """Parse datetime SonarQube."""
    if len(dt_str) >= 5 and dt_str[-5] in ["+", "-"] and dt_str[-3] != ":":
        dt_str = dt_str[:-2] + ":" + dt_str[-2:]
    return datetime.fromisoformat(dt_str)


def to_sonar_utc(dt: datetime) -> str:
    """UTC SonarQube."""
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%S+0000")


def get_all_ce_analyses_2025(base_url: str, session: requests.Session, page_size: int = 500):
    """Récupère TOUTES les analyses REPORT SUCCESS de 2025 via /api/ce/activity."""
    url = urljoin(base_url, "/api/ce/activity")

    start = datetime(YEAR_HISTORY, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(YEAR_HISTORY, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

    analyses = []
    page = 1

    while True:
        params = {
            "type": "REPORT",
            "status": "SUCCESS",
            "minExecutedAt": to_sonar_utc(start),
            "maxExecutedAt": to_sonar_utc(end),
            "ps": page_size,
            "p": page,
        }

        resp = session.get(url, params=params)
        if resp.status_code == 403:
            print("⚠️  /api/ce/activity restreint (admin requis)")
            return []

        resp.raise_for_status()
        data = resp.json()

        tasks = data.get("tasks", [])
        if not tasks:
            break

        for task in tasks:
            analysis = {
                "task_id": task.get("id", ""),
                "analysis_id": task.get("analysisId", ""),
                "project_key": "",
                "project_name": "",
                "branch": task.get("branch", ""),
                "pull_request": task.get("pullRequest", ""),
                "executed_at": task.get("executedAt", ""),
                "submitted_at": task.get("submittedAt", ""),
            }

            component = task.get("component", {})
            analysis["project_key"] = component.get("key", "")
            analysis["project_name"] = component.get("name", analysis["project_key"])

            if analysis["project_key"] and analysis["analysis_id"]:
                analyses.append(analysis)

        paging = data.get("paging", {})
        total = paging.get("total", 0)
        if page * page_size >= total:
            break
        page += 1

    return analyses


def get_metrics_for_analysis(
    base_url: str,
    session: requests.Session,
    project_key: str,
    analysis_id: str,
    metrics: list[str],
):
    """Métriques précises d'une analyse (colonnes de métriques dans l'historique)."""
    url = urljoin(base_url, "/api/measures/component")
    params = {
        "component": project_key,
        "analysisId": analysis_id,
        "metricKeys": ",".join(metrics),
    }

    resp = session.get(url, params=params)
    resp.raise_for_status()
    data = resp.json()

    snapshot = {}
    measures = data.get("component", {}).get("measures", [])
    for m in measures:
        snapshot[m.get("metric")] = m.get("value", "")
    return snapshot


def get_quality_gate_for_analysis(
    base_url: str,
    session: requests.Session,
    project_key: str,
    analysis_id: str,
):
    """Quality Gate précis d'une analyse."""
    url = urljoin(base_url, "/api/qualitygates/project_status")
    params = {"projectKey": project_key, "analysisId": analysis_id}

    resp = session.get(url, params=params)
    if resp.status_code in [403, 404]:
        return ""

    resp.raise_for_status()
    data = resp.json()
    return data.get("projectStatus", {}).get("status", "")


def export_project_history(
    base_url: str,
    session: requests.Session,
    analyses: list,
    metrics: list[str],
    output_dir: Path,
):
    """Exporte l'historique 2025 par projet (1 CSV par projet) AVEC métriques."""
    # Groupement par projet
    projects_analyses = {}
    for analysis in analyses:
        key = analysis["project_key"]
        if key not in projects_analyses:
            projects_analyses[key] = []
        projects_analyses[key].append(analysis)

    total_analyses = 0
    for project_key, project_analyses in projects_analyses.items():
        rows = []

        # Tri chronologique par date d'exécution
        project_analyses_sorted = sorted(
            project_analyses,
            key=lambda x: parse_sonar_datetime(x["executed_at"]),
        )

        for analysis in project_analyses_sorted:
            if not analysis["analysis_id"]:
                continue

            # Métriques pour CETTE analyse
            metrics_data = get_metrics_for_analysis(
                base_url, session, project_key, analysis["analysis_id"], metrics
            )
            qg_status = get_quality_gate_for_analysis(
                base_url, session, project_key, analysis["analysis_id"]
            )

            executed_dt = parse_sonar_datetime(analysis["executed_at"]) if analysis["executed_at"] else None
            row = {
                "project_key": project_key,
                "project_name": analysis["project_name"],
                "date": executed_dt.strftime("%Y-%m-%d") if executed_dt else "",
                "executed_at": analysis["executed_at"],
                "analysis_id": analysis["analysis_id"],
                "task_id": analysis["task_id"],
                "branch": analysis["branch"],
                "pull_request": analysis["pull_request"],
                "quality_gate_status": qg_status,
            }

            # Ajout des colonnes de métriques
            for m in metrics:
                row[m] = metrics_data.get(m, "")

            rows.append(row)

        # CSV par projet
        filename = output_dir / f"{project_key}_history_{YEAR_HISTORY}.csv"
        if rows:
            fieldnames = [
                "project_key",
                "project_name",
                "date",
                "executed_at",
                "analysis_id",
                "task_id",
                "branch",
                "pull_request",
                "quality_gate_status",
            ] + metrics

            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

            total_analyses += len(rows)
            print(f"✅ {project_key}: {len(rows)} analyses → {filename}")

    return total_analyses


def main():
    parser = argparse.ArgumentParser(
        description="Historique COMPLET métriques 2025 par projet (avec métriques dans les fichiers)"
    )
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-t", "--token", required=True)
    parser.add_argument("-m", "--metrics", nargs="+", default=DEFAULT_METRICS)
    parser.add_argument("-o", "--output-dir", default="sonar_history_2025")

    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    base_url = args.url.rstrip("/")
    session = build_session(base_url, args.token)

    print("🚀 HISTORIQUE COMPLET 2025 (via /api/ce/activity)")
    print(f"📊 Métriques : {', '.join(args.metrics)}")

    # 1. Toutes les analyses 2025
    print("\n🔍 Récupération TOUTES les analyses CE 2025...")
    analyses_2025 = get_all_ce_analyses_2025(base_url, session)

    if not analyses_2025:
        print("❌ Aucune analyse 2025 trouvée")
        return

    projects_count = len(set(a["project_key"] for a in analyses_2025))
    print(f"✅ {len(analyses_2025)} analyses → {projects_count} projets")

    # 2. Export historique complet par projet (AVEC métriques)
    print("\n📈 Génération historiques (1 CSV par projet, avec métriques)...")
    total_analyses_exported = export_project_history(
        base_url, session, analyses_2025, args.metrics, output_dir
    )

    print(f"\n🎉 HISTORIQUE 2025 TERMINÉ")
    print(f"📁 {output_dir.absolute()}")
    print(f"📊 {total_analyses_exported} analyses exportées")
    print(f"📂 {len(set(a['project_key'] for a in analyses_2025))} fichiers CSV")


if __name__ == "__main__":
    main()
