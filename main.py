"""Application Entry Point for SENTINEL – Security Change Impact Analyzer.

Coordinates configuration loading, security rule evaluation, change impact analysis,
and displays a professional, structured analysis report using Rich.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from compare import (
    CLASSIFICATION_EXISTING_WEAKNESS,
    CLASSIFICATION_NEW_WEAKNESS,
    CLASSIFICATION_NO_WEAKNESS,
    CLASSIFICATION_RESOLVED_WEAKNESS,
    ComparisonReport,
    compare_rule_results,
)
from config import ConfigError, load_config
from rules import RuleResult, evaluate_rules


def render_header(console: Console) -> None:
    """Render Section 1: SENTINEL application header."""
    header_text = Text()
    header_text.append("SENTINEL", style="bold cyan")
    header_text.append(" — Security Change Impact Analyzer\n", style="bold white")
    header_text.append(
        "A tool that analyses proposed changes in simulated system configurations,\n"
        "identifies security risks caused by individual changes or interactions\n"
        "between security settings, and recommends corrective actions.",
        style="dim white",
    )
    console.print(Panel(header_text, border_style="cyan", padding=(1, 2)))


def render_input_status(
    console: Console,
    orig_path: Path,
    prop_path: Path,
    orig_cfg: Dict[str, Any],
    prop_cfg: Dict[str, Any],
) -> None:
    """Render Section 2: Configuration input status."""
    table = Table(
        title="1. Configuration Input Status",
        title_style="bold magenta",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Setting Key", style="bold", no_wrap=True)
    table.add_column(f"Original Value\n({orig_path.name})", justify="center")
    table.add_column(f"Proposed Value\n({prop_path.name})", justify="center")
    table.add_column("Delta Status", justify="center")

    all_keys = ["firewall_enabled", "password_min_length", "api_exposure", "authentication_required"]

    for key in all_keys:
        orig_val = orig_cfg.get(key)
        prop_val = prop_cfg.get(key)
        if orig_val == prop_val:
            delta = Text("UNCHANGED", style="dim green")
        else:
            delta = Text("MODIFIED", style="bold yellow")

        table.add_row(
            key,
            str(orig_val),
            str(prop_val),
            delta,
        )

    console.print(table)
    console.print()


def render_rule_evaluation(
    console: Console,
    orig_results: Dict[str, RuleResult],
    prop_results: Dict[str, RuleResult],
) -> None:
    """Render Section 3: Security rule evaluation."""
    table = Table(
        title="2. Security Rule Evaluation",
        title_style="bold magenta",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Security Rule", style="bold")
    table.add_column("Original Evaluation", justify="center")
    table.add_column("Proposed Evaluation", justify="center")
    table.add_column("Rule Evaluation Summary", style="dim")

    for rule_id, orig_res in orig_results.items():
        prop_res = prop_results[rule_id]

        orig_badge = (
            Text("PASS", style="bold green") if orig_res.passed else Text("FAIL", style="bold red")
        )
        prop_badge = (
            Text("PASS", style="bold green") if prop_res.passed else Text("FAIL", style="bold red")
        )

        summary = f"Original: {orig_res.details}\nProposed: {prop_res.details}"
        table.add_row(orig_res.rule_name, orig_badge, prop_badge, summary)

    console.print(table)
    console.print()


def render_change_impact(console: Console, report: ComparisonReport) -> None:
    """Render Section 4: Change impact analysis."""
    table = Table(
        title="3. Change Impact Analysis",
        title_style="bold magenta",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Security Rule", style="bold")
    table.add_column("Original", justify="center")
    table.add_column("Proposed", justify="center")
    table.add_column("Impact Classification", justify="center")
    table.add_column("Technical Explanation")

    for finding in report.findings:
        orig_badge = (
            Text("PASS", style="bold green")
            if finding.original_passed
            else Text("FAIL", style="bold red")
        )
        prop_badge = (
            Text("PASS", style="bold green")
            if finding.proposed_passed
            else Text("FAIL", style="bold red")
        )

        if finding.classification == CLASSIFICATION_NEW_WEAKNESS:
            class_style = "bold red on #3b0a0a"
        elif finding.classification == CLASSIFICATION_RESOLVED_WEAKNESS:
            class_style = "bold green"
        elif finding.classification == CLASSIFICATION_EXISTING_WEAKNESS:
            class_style = "bold yellow"
        else:
            class_style = "bold cyan"

        class_text = Text(finding.classification, style=class_style)

        table.add_row(
            finding.rule_name,
            orig_badge,
            prop_badge,
            class_text,
            finding.explanation,
        )

    console.print(table)
    console.print()


def render_dependency_break(console: Console, report: ComparisonReport) -> None:
    """Render Section 5: Dependency break detection."""
    console.print("[bold magenta]4. Dependency Break Detection[/bold magenta]")
    if report.silent_dependency_breaks:
        for dep in report.silent_dependency_breaks:
            body = Text()
            body.append("WARNING: Silent Dependency Break Detected!\n\n", style="bold red")
            body.append("• Changed Setting: ", style="bold yellow")
            body.append(
                f"'{dep.changed_setting}' changed from '{dep.changed_from}' to '{dep.changed_to}'\n",
                style="white",
            )
            body.append("• Affected Unchanged Setting: ", style="bold yellow")
            body.append(
                f"'{dep.affected_unchanged_setting}' remained '{dep.affected_unchanged_value}'\n\n",
                style="white",
            )
            body.append("• Why Dependency Became Unsafe:\n  ", style="bold cyan")
            body.append(f"{dep.why_unsafe}\n\n", style="white")
            body.append("• Corrective Action:\n  ", style="bold green")
            body.append(f"{dep.corrective_action}", style="bold white")

            console.print(
                Panel(
                    body,
                    title="[bold red]CRITICAL ALERT: Interacting Setting Inadequacy[/bold red]",
                    border_style="red",
                    padding=(1, 2),
                )
            )
    else:
        info = Text(
            "No silent dependency breaks detected. Interacting settings remain harmonized with security policy.",
            style="green",
        )
        console.print(Panel(info, border_style="green", padding=(0, 2)))
    console.print()


def render_recommendations(console: Console, report: ComparisonReport) -> None:
    """Render Section 6: Corrective recommendations."""
    table = Table(
        title="5. Corrective Recommendations",
        title_style="bold magenta",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Rule", style="bold", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Remediation Action")

    has_actions = False
    for finding in report.findings:
        if finding.recommendation:
            has_actions = True
            badge = (
                Text("ACTION REQUIRED", style="bold red")
                if finding.classification == CLASSIFICATION_NEW_WEAKNESS
                else Text("REMEDIATE", style="bold yellow")
            )
            table.add_row(finding.rule_name, badge, finding.recommendation)

    if has_actions:
        console.print(table)
    else:
        panel = Panel(
            Text(
                "All security rules are satisfied. No corrective remediation required.",
                style="bold green",
            ),
            title="5. Corrective Recommendations",
            border_style="green",
        )
        console.print(panel)
    console.print()


def render_completion_status(console: Console, report: ComparisonReport) -> None:
    """Render Section 7: Analysis completion status."""
    summary_table = Table(
        title="6. Analysis Completion Status",
        title_style="bold magenta",
        header_style="bold cyan",
        show_lines=True,
    )
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Count", justify="center")
    summary_table.add_column("Security Implication")

    summary_table.add_row(
        "New Weaknesses",
        str(report.new_weaknesses_count),
        "[red]Introduced regressions requiring remediation before deployment[/red]"
        if report.new_weaknesses_count > 0
        else "[green]No regression introduced[/green]",
    )
    summary_table.add_row(
        "Resolved Weaknesses",
        str(report.resolved_weaknesses_count),
        "[green]Prior security weaknesses remediated by proposed changes[/green]"
        if report.resolved_weaknesses_count > 0
        else "No previously failing settings were fixed",
    )
    summary_table.add_row(
        "Existing Weaknesses",
        str(report.existing_weaknesses_count),
        "[yellow]Pre-existing non-compliant settings carried forward unchanged[/yellow]"
        if report.existing_weaknesses_count > 0
        else "[green]No pre-existing non-compliant settings[/green]",
    )
    summary_table.add_row(
        "No Weakness Detected",
        str(report.no_weakness_count),
        "Rules passing across both baseline and proposed configurations",
    )

    console.print(summary_table)

    # Final verdict banner
    if report.new_weaknesses_count > 0:
        verdict = Panel(
            Text(
                "ANALYSIS VERDICT: REJECT PROPOSED CHANGE\n"
                f"Detected {report.new_weaknesses_count} new security weakness(es). "
                "Apply corrective recommendations before approving configuration change.",
                style="bold red",
                justify="center",
            ),
            border_style="red",
            padding=(1, 2),
        )
    elif report.existing_weaknesses_count > 0:
        verdict = Panel(
            Text(
                "ANALYSIS VERDICT: ACCEPT WITH WARNING\n"
                f"No new weaknesses introduced, but {report.existing_weaknesses_count} existing weakness(es) persist.",
                style="bold yellow",
                justify="center",
            ),
            border_style="yellow",
            padding=(1, 2),
        )
    else:
        verdict = Panel(
            Text(
                "ANALYSIS VERDICT: APPROVED\n"
                "All proposed configurations meet or exceed security baselines.",
                style="bold green",
                justify="center",
            ),
            border_style="green",
            padding=(1, 2),
        )
    console.print(verdict)


def parse_arguments(args: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for SENTINEL."""
    parser = argparse.ArgumentParser(
        prog="python main.py",
        description="SENTINEL – Security Change Impact Analyzer: Evaluate security risks and silent dependency breaks in configuration changes.",
    )
    parser.add_argument(
        "--original",
        "-o",
        required=True,
        type=str,
        help="Path to the original (baseline) JSON configuration file.",
    )
    parser.add_argument(
        "--proposed",
        "-p",
        required=True,
        type=str,
        help="Path to the proposed JSON configuration file.",
    )
    return parser.parse_args(args)


def run_analysis(original_path_str: str, proposed_path_str: str, console: Console) -> int:
    """Execute complete analysis pipeline and render the terminal report.

    Returns:
        0 on successful analysis completion.
        1 on error (file missing, malformed JSON, validation failure).
    """
    orig_path = Path(original_path_str)
    prop_path = Path(proposed_path_str)

    try:
        # 1. Load and validate configurations
        original_config = load_config(orig_path)
        proposed_config = load_config(prop_path)
    except ConfigError as err:
        error_panel = Panel(
            Text(f"{err}", style="bold red"),
            title="[bold red]SENTINEL Configuration Error[/bold red]",
            border_style="red",
            padding=(1, 2),
        )
        console.print(error_panel)
        return 1
    except Exception as err:
        error_panel = Panel(
            Text(f"Unexpected operational error: {err}", style="bold red"),
            title="[bold red]SENTINEL Execution Error[/bold red]",
            border_style="red",
            padding=(1, 2),
        )
        console.print(error_panel)
        return 1

    # 2. Evaluate security rules independently
    original_results = evaluate_rules(original_config)
    proposed_results = evaluate_rules(proposed_config)

    # 3. Compare evaluation results and analyze dependency breaks
    comparison_report = compare_rule_results(
        original_config=original_config,
        proposed_config=proposed_config,
        original_results=original_results,
        proposed_results=proposed_results,
    )

    # 4. Display organized terminal report
    render_header(console)
    render_input_status(console, orig_path, prop_path, original_config, proposed_config)
    render_rule_evaluation(console, original_results, proposed_results)
    render_change_impact(console, comparison_report)
    render_dependency_break(console, comparison_report)
    render_recommendations(console, comparison_report)
    render_completion_status(console, comparison_report)

    return 0


def main() -> None:
    """Main CLI entry point."""
    console = Console()
    args = parse_arguments()
    exit_code = run_analysis(args.original, args.proposed, console)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
