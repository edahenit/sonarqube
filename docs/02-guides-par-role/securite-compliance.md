# Guide Securite et Compliance - SonarQube 2026

Audience : RSSI, Equipe Securite, Auditeurs

## Vulnerabilites et Hotspots de securite

Vulnerabilites : failles de securite certaines, a corriger obligatoirement
Hotspots : zones sensibles qui necessitent une revue manuelle

Difference cle :
- Une vulnerabilite est confirmee : elle doit etre corrigee
- Un hotspot peut etre false positive : il doit etre evalue puis marque Reviewed ou Acknowledge

## Classifications de securite

SonarQube 2026 aligne les regles sur :
- OWASP Top 10 (Web Application Security)
- CWE Top 25 (Common Weakness Enumeration)
- SANS Top 25
- PCI DSS
- OWASP Mobile Top 10

Filtrer par taxonomie depuis la vue Issues : onglet Security Standards.

## Taint Analysis

La taint analysis (disponible en Data Center) trace le chemin des donnees non validees depuis l entree jusqu a une sink potentiellement dangereuse.

Supporte pour Java et C# notamment.
Activee par defaut sur les Quality Profiles corporate.

## Processus de traitement des vulnerabilites

Critique ou Bloquante : correction obligatoire avant release
Majeure : a corriger dans le sprint suivant
Mineure : a planifier dans le backlog de securite

Aucune vulnerabilite critique ne peut passer en production.

## Rapports pour les audits

- Export PDF des vulnerabilites par projet ou application
- Vue Portfolio securite pour le RSSI
- Audit trail des modifications de profils et Quality Gates
- Historique des analyses disponible sur 365 jours

## Conformite et audit trail

SonarQube Data Center conserve :
- L historique complet des analyses
- Les modifications de configuration (qui, quand, quoi)
- Les decisions sur les issues (Accepted, Wont Fix + justification)

Ces donnees sont disponibles via l API SonarQube pour extraction.
