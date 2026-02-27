#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

import requests

DEFAULT_METRICS = [
    "alert_status",
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
    """Cree une session HTTP authentifiee pour SonarQube."""
    session = requests.Session()
    session.auth = (token, "")
    return session


def to_sonar_utc(dt: datetime) -> str:
    """Formate une datetime en chaine UTC attendue par SonarQube."""
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%S+0000")


def get_active_projects_from_ce_activity(
    base_url: str,
    session: requests.Session,
    year: int,
    page_size: int = 500,
) -> dict:
    """
    Utilise /api/ce/activity pour recuperer tous les projets
    ayant lance au moins une analyse SUCCESS en {year}.
    Retourne un dict { project_key: project_name }.
    """
    url = urljoin(base_url, "/api/ce/activity")
    start = datetime(year, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(year, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

    active_projects = {}
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
            print("  ⚠️  /api/ce/activity restreint (droits admin requis)")
            return {}
        resp.raise_for_status()
        data = resp.json()

        tasks = data.get("tasks", [])
        if not tasks:
            break

        for task in tasks:
            component = task.get("component", {})
            key = component.get("key", "")
            name = component.get("name", key)
            if key and key not in active_projects:
                active_projects[key] = name

        paging = data.get("paging", {})
        total = paging.get("total", 0)
        if page * page_size >= total:
            break
        page += 1

    return active_projects


def get_metrics_history(
    base_url: str,
    session: requests.Session,
    project_key: str,
    metrics: list,
    from_date: str,
    to_date: str,
) -> dict:
    """
    Recupere l historique complet des metriques d un projet
    via /api/measures/search_history.
    Retourne un dict { date_str: { metric: value } }.
    """
    url = urljoin(base_url, "/api/measures/search_history")
    page_size = 1000

    history_by_date = {}

    params = {
        "component": project_key,
        "metrics": ",".join(metrics),
        "from": from_date,
        "to": to_date,
        "ps": page_size,
        "p": 1,
    }

    while True:
        resp = session.get(url, params=params)
        if resp.status_code in [403, 404]:
            print(f"  ⚠️  Acces refuse ou projet introuvable : {project_key}")
            return {}
        resp.raise_for_status()
        data = resp.json()

        measures = data.get("measures", [])
        for measure in measures:
            metric = measure.get("metric", "")
            for entry in measure.get("history", []):
                date_str = entry.get("date", "")
                value = entry.get("value", "")
                if date_str not in history_by_date:
                    history_by_date[date_str] = {}
                history_by_date[date_str][metric] = value

        paging = data.get("paging", {})
        total = paging.get("total", 0)
        current_page = params["p"]
        if current_page * page_size >= total:
            break
        params["p"] += 1

    return history_by_date


def get_last_snapshot(history_by_date: dict) -> dict:
    """
    Retourne uniquement le snapshot de la DERNIERE date (date max).
    """
    if not history_by_date:
        return {}
    last_date = max(history_by_date.keys())
    return {"date": last_date, "metrics": history_by_date[last_date]}


def export_last_analysis(
    base_url: str,
    session: requests.Session,
    active_projects: dict,
    metrics: list,
    output_path: Path,
    from_date: str,
    to_date: str,
):
    """
    Mode LAST : 1 seul CSV global avec la derniere analyse de chaque projet actif.
    """
    fieldnames = ["project_key", "project_name", "last_analysis_date"] + metrics
    rows = []

    for project_key, project_name in active_projects.items():
        print(f"  🔍 {project_key}")

        history = get_metrics_history(
            base_url, session, project_key, metrics, from_date, to_date
        )
        last = get_last_snapshot(history)

        row = {
            "project_key": project_key,
            "project_name": project_name,
            "last_analysis_date": last.get("date", ""),
        }
        for m in metrics:
            row[m] = last.get("metrics", {}).get(m, "") if last else ""

        rows.append(row)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"
  ✅ {len(rows)} projets exportes → {output_path.absolute()}")


def export_full_history(
    base_url: str,
    session: requests.Session,
    active_projects: dict,
    metrics: list,
    output_dir: Path,
    from_date: str,
    to_date: str,
    year: int,
):
    """
    Mode HISTORY : 1 CSV par projet avec tout l historique de l annee.
    """
    fieldnames = ["project_key", "project_name", "date"] + metrics
    total_analyses = 0

    for project_key, project_name in active_projects.items():
        print(f"  🔍 {project_key}")

        history = get_metrics_history(
            base_url, session, project_key, metrics, from_date, to_date
        )

        if not history:
            print(f"  ⚠️  Aucune metrique pour {project_key}")
            continue

        sorted_dates = sorted(history.keys())
        rows = []
        for date_str in sorted_dates:
            row = {
                "project_key": project_key,
                "project_name": project_name,
                "date": date_str,
            }
            for m in metrics:
                row[m] = history[date_str].get(m, "")
            rows.append(row)

        safe_key = project_key.replace("/", "_").replace(":", "_")
        filename = output_dir / f"{safe_key}_history_{year}.csv"
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        total_analyses += len(rows)
        print(f"  ✅ {project_key}: {len(rows)} analyses → {filename.name}")

    return total_analyses


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Export metriques SonarQube : "
            "filtre les projets actifs via /api/ce/activity "
            "puis recupere l historique via /api/measures/search_history."
        )
    )
    parser.add_argument("-u", "--url", required=True,
                        help="URL SonarQube (ex: https://sonar.monsite.fr)")
    parser.add_argument("-t", "--token", required=True,
                        help="Token API SonarQube")
    parser.add_argument("-m", "--metrics", nargs="+", default=DEFAULT_METRICS,
                        help="Metriques a extraire")
    parser.add_argument("-o", "--output-dir", default="sonar_export",
                        help="Dossier de sortie")
    parser.add_argument(
        "--mode",
        choices=["last", "history"],
        default="last",
        help=(
            "last     = 1 CSV global avec la derniere analyse par projet
"
            "history  = 1 CSV par projet avec l historique complet"
        ),
    )
    parser.add_argument("--year", type=int, default=YEAR_HISTORY,
                        help="Annee de reference (defaut: 2025)")

    args = parser.parse_args()

    year = args.year
    from_date = f"{year}-01-01"
    to_date = f"{year}-12-31"

    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    base_url = args.url.rstrip("/")
    session = build_session(base_url, args.token)

    print("=" * 65)
    print("🚀  EXPORT SONARQUBE")
    print(f"📡  URL     : {base_url}")
    print(f"📅  Periode : {from_date}  →  {to_date}")
    print(f"📊  Metriques : {', '.join(args.metrics)}")
    print(f"🔧  Mode    : {args.mode}")
    print(f"💾  Sortie  : {output_dir.absolute()}")
    print("=" * 65)

    # ------------------------------------------------------------------ #
    # ETAPE 1 : projets actifs en {year} via /api/ce/activity             #
    # ------------------------------------------------------------------ #
    print(f"
🔍 Etape 1 — Projets ayant une analyse SUCCESS en {year}...")
    active_projects = get_active_projects_from_ce_activity(base_url, session, year)

    if not active_projects:
        print("❌ Aucun projet actif trouve (verifiez les droits admin).")
        return

    print(f"✅ {len(active_projects)} projets actifs trouves en {year}")

    # ------------------------------------------------------------------ #
    # ETAPE 2 : historique metriques via /api/measures/search_history     #
    # ------------------------------------------------------------------ #
    print(f"
📈 Etape 2 — Extraction metriques via search_history...")

    if args.mode == "last":
        output_path = output_dir / f"sonar_last_analysis_{year}.csv"
        export_last_analysis(
            base_url, session, active_projects,
            args.metrics, output_path, from_date, to_date
        )

    else:  # history
        total = export_full_history(
            base_url, session, active_projects,
            args.metrics, output_dir, from_date, to_date, year
        )
        print(f"
🎉 {total} analyses exportees au total")

    print("
✅ Export termine !")


if __name__ == "__main__":
    main()
