#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import logging
import sys
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


def setup_logging(output_dir: Path, year: int) -> logging.Logger:
    """Configure le logger : console + fichier."""
    logger = logging.getLogger("sonar_export")
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Handler console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    # Handler fichier (niveau DEBUG pour tout logger)
    log_file = output_dir / f"sonar_export_{year}.log"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


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
    logger: logging.Logger,
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

        logger.debug("GET /api/ce/activity page=%d", page)
        resp = session.get(url, params=params)

        if resp.status_code == 403:
            logger.warning("/api/ce/activity restreint (droits admin requis)")
            return {}

        resp.raise_for_status()
        data = resp.json()

        tasks = data.get("tasks", [])
        if not tasks:
            logger.debug("Aucune tache sur la page %d, arret de la pagination", page)
            break

        for task in tasks:
            component = task.get("component", {})
            key = component.get("key", "")
            name = component.get("name", key)
            if key and key not in active_projects:
                active_projects[key] = name
                logger.debug("Projet actif detecte : %s (%s)", key, name)

        paging = data.get("paging", {})
        total = paging.get("total", 0)
        logger.debug("Page %d/%d — %d projets uniques trouves jusqu ici",
                     page, -(-total // page_size), len(active_projects))

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
    logger: logging.Logger,
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
        logger.debug("GET /api/measures/search_history component=%s page=%d",
                     project_key, params["p"])
        resp = session.get(url, params=params)

        if resp.status_code == 404:
            logger.warning("Projet introuvable dans search_history : %s", project_key)
            return {}
        if resp.status_code == 403:
            logger.warning("Acces refuse pour le projet : %s", project_key)
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

        logger.debug("search_history %s — page %d — %d points d historique",
                     project_key, current_page, len(history_by_date))

        if current_page * page_size >= total:
            break
        params["p"] += 1

    return history_by_date


def get_last_snapshot(history_by_date: dict) -> dict:
    """Retourne uniquement le snapshot de la DERNIERE date (date max)."""
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
    logger: logging.Logger,
):
    """Mode LAST : 1 CSV global avec la derniere analyse de chaque projet actif."""
    fieldnames = ["project_key", "project_name", "last_analysis_date"] + metrics
    rows = []
    errors = 0

    for idx, (project_key, project_name) in enumerate(active_projects.items(), start=1):
        logger.info("[%d/%d] Extraction last analysis : %s",
                    idx, len(active_projects), project_key)

        history = get_metrics_history(
            base_url, session, project_key, metrics, from_date, to_date, logger
        )
        last = get_last_snapshot(history)

        if not last:
            logger.warning("Aucune donnee pour %s — ligne vide dans le CSV", project_key)
            errors += 1

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

    logger.info("CSV global genere : %s (%d projets, %d erreurs)",
                output_path.absolute(), len(rows), errors)


def export_full_history(
    base_url: str,
    session: requests.Session,
    active_projects: dict,
    metrics: list,
    output_dir: Path,
    from_date: str,
    to_date: str,
    year: int,
    logger: logging.Logger,
) -> int:
    """Mode HISTORY : 1 CSV par projet avec tout l historique de l annee."""
    fieldnames = ["project_key", "project_name", "date"] + metrics
    total_analyses = 0
    errors = 0

    for idx, (project_key, project_name) in enumerate(active_projects.items(), start=1):
        logger.info("[%d/%d] Extraction historique : %s",
                    idx, len(active_projects), project_key)

        history = get_metrics_history(
            base_url, session, project_key, metrics, from_date, to_date, logger
        )

        if not history:
            logger.warning("Aucune metrique pour %s — fichier non genere", project_key)
            errors += 1
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
        logger.info("CSV genere : %s (%d analyses)", filename.name, len(rows))

    logger.info("Export history termine : %d analyses, %d erreurs", total_analyses, errors)
    return total_analyses


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Export metriques SonarQube : filtre les projets actifs via "
            "/api/ce/activity puis recupere l historique via "
            "/api/measures/search_history."
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
        help="last = 1 CSV global derniere analyse | history = 1 CSV par projet",
    )
    parser.add_argument("--year", type=int, default=YEAR_HISTORY,
                        help="Annee de reference (defaut: 2025)")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Niveau de log console (defaut: INFO)",
    )

    args = parser.parse_args()

    year = args.year
    from_date = f"{year}-01-01"
    to_date = f"{year}-12-31"

    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    # Initialisation du logger
    logger = setup_logging(output_dir, year)
    # Ajustement niveau console selon l argument
    logger.handlers[0].setLevel(getattr(logging, args.log_level))

    base_url = args.url.rstrip("/")
    session = build_session(base_url, args.token)

    logger.info("=" * 60)
    logger.info("EXPORT SONARQUBE")
    logger.info("URL      : %s", base_url)
    logger.info("Periode  : %s  ->  %s", from_date, to_date)
    logger.info("Metriques: %s", ", ".join(args.metrics))
    logger.info("Mode     : %s", args.mode)
    logger.info("Sortie   : %s", output_dir.absolute())
    logger.info("=" * 60)

    # ------------------------------------------------------------------ #
    # ETAPE 1 : projets actifs en {year} via /api/ce/activity             #
    # ------------------------------------------------------------------ #
    logger.info("Etape 1 — Projets ayant une analyse SUCCESS en %d...", year)
    active_projects = get_active_projects_from_ce_activity(
        base_url, session, year, logger
    )

    if not active_projects:
        logger.error("Aucun projet actif trouve (verifiez les droits admin).")
        sys.exit(1)

    logger.info("%d projets actifs trouves en %d", len(active_projects), year)

    # ------------------------------------------------------------------ #
    # ETAPE 2 : historique metriques via /api/measures/search_history     #
    # ------------------------------------------------------------------ #
    logger.info("Etape 2 — Extraction metriques via search_history...")

    if args.mode == "last":
        output_path = output_dir / f"sonar_last_analysis_{year}.csv"
        export_last_analysis(
            base_url, session, active_projects,
            args.metrics, output_path, from_date, to_date, logger
        )

    else:
        total = export_full_history(
            base_url, session, active_projects,
            args.metrics, output_dir, from_date, to_date, year, logger
        )
        logger.info("Total : %d analyses exportees", total)

    logger.info("Export termine avec succes !")


if __name__ == "__main__":
    main()
