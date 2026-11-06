#!/usr/bin/env python3
"""SOC Alert Triage and Response Automation Prototype.

Inspired by FortiSOAR's Playbook Architecture.
Demonstrates automated ingestion, context enrichment, risk scoring,
conditional playbook execution, safe response simulation, incident management,
audit reporting, and real-time Playbook Execution Tracing.
"""

import os
import sys
import argparse
from typing import List, Dict, Any

# Re-export SOCTriagePipeline for backward compatibility with existing tests and scripts
from modules.pipeline import SOCTriagePipeline


def print_banner():
    print("=" * 80)
    print("     SECURITY OPERATIONS CENTER (SOC) - ALERT TRIAGE & RESPONSE PIPELINE")
    print("           Inspired by FortiSOAR Playbook Automation Architecture")
    print("                     [SIMULATION & SAFE DRY-RUN MODE]")
    print("=" * 80)


def print_incident_summary(incidents: List[Dict[str, Any]]):
    print("\n" + "-" * 80)
    print(f"{'INCIDENT ID':<18} | {'ALERT ID':<12} | {'PRIORITY':<8} | {'SCORE':<5} | {'PLAYBOOK':<18} | {'STATUS'}")
    print("-" * 80)
    for inc in incidents:
        pb_id = inc.get("triggered_playbook", {}).get("playbook_id", "N/A")
        status = inc.get("status", inc.get("incident_status", "NEW"))
        print(
            f"{inc.get('incident_id'):<18} | "
            f"{inc.get('original_alert_id'):<12} | "
            f"{inc.get('priority'):<8} | "
            f"{inc.get('risk_score'):<5} | "
            f"{pb_id:<18} | "
            f"{status}"
        )
    print("-" * 80)


def main():
    parser = argparse.ArgumentParser(description="SOC Alert Triage & Response Automation")
    parser.add_argument("--file", type=str, help="Path to a single alert JSON file")
    parser.add_argument("--dir", type=str, default="data/alerts", help="Directory containing alert JSON files")
    parser.add_argument("--base-dir", type=str, default=".", help="Base directory of the project")
    parser.add_argument("--no-trace", action="store_true", help="Disable execution trace terminal output")
    args = parser.parse_args()

    print_banner()

    pipeline = SOCTriagePipeline(base_dir=args.base_dir)
    show_trace = not args.no_trace

    if args.file:
        print(f"[*] Processing single alert file: {args.file}\n")
        incidents = pipeline.process_file(args.file, show_trace=show_trace)
    else:
        target_dir = args.dir
        if not os.path.isabs(target_dir):
            target_dir = os.path.join(args.base_dir, target_dir)
        print(f"[*] Batch processing alerts from directory: {target_dir}\n")
        incidents = pipeline.process_directory(target_dir, show_trace=show_trace)

    if incidents:
        print_incident_summary(incidents)
        print(f"\n[+] Total Incidents Created: {len(incidents)}")
        print(f"[+] Consolidated JSON Report: {os.path.join(pipeline.reports_dir, 'all_incidents.json')}")
        print(f"[+] Tabular CSV Summary:      {os.path.join(pipeline.reports_dir, 'incidents_summary.csv')}")
        print(f"[+] Audit History Log:         {pipeline.audit_logger.log_filepath}")
        print("\n[*] Execution completed successfully.")
    else:
        print("[!] No incidents were generated.")
        sys.exit(1)


if __name__ == "__main__":
    main()
