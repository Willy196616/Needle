#!/usr/bin/env python3
"""
Needle - Automated Security Testing for Large Language Models
Point it at any LLM API and it systematically tests hundreds of attack vectors.

Usage:
    python main.py --target "http://localhost:11434/v1/chat/completions" --model llama3.1
    python main.py --target anthropic --api-key sk-ant-... --model claude-sonnet-4-20250514
    python main.py --target "https://api.openai.com/v1/chat/completions" --api-key sk-... --model gpt-4
"""

import argparse
import os
import sys
import time
from datetime import datetime

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich.table import Table
from rich import box

from core.client import TargetClient
from core.analyzer import ResponseAnalyzer, Verdict
from core.report import generate_markdown_report, generate_json_report, calculate_score, score_to_grade
from attacks.registry import ATTACK_MODULES, ALL_ATTACKS

console = Console()

BANNER = """[bold red]
    ███╗   ██╗███████╗███████╗██████╗ ██╗     ███████╗
    ████╗  ██║██╔════╝██╔════╝██╔══██╗██║     ██╔════╝
    ██╔██╗ ██║█████╗  █████╗  ██║  ██║██║     █████╗  
    ██║╚██╗██║██╔══╝  ██╔══╝  ██║  ██║██║     ██╔══╝  
    ██║ ╚████║███████╗███████╗██████╔╝███████╗███████╗
    ╚═╝  ╚═══╝╚══════╝╚══════╝╚═════╝ ╚══════╝╚══════╝
    [white]🪡 Find what breaks your LLM[/white]
    [dim]Automated LLM Security Assessment[/dim]
[/bold red]"""


def load_config(path: str = "config/settings.yaml") -> dict:
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return {
            "scan": {"concurrent_requests": 3, "request_timeout": 30, "delay_between_requests": 0.5},
            "detection": {},
            "report": {"format": "markdown", "max_response_length": 500}
        }


def run_scan(args):
    """Execute the full security scan."""
    config = load_config(args.config)

    # Initialize client
    console.print("\n[bold blue]⚡ Connecting to target...[/bold blue]")
    try:
        client = TargetClient(
            target=args.target,
            api_key=args.api_key or "",
            model=args.model or "",
            system_prompt=args.system_prompt or "",
            timeout=config.get("scan", {}).get("request_timeout", 30)
        )
        console.print(f"[green]  ✓ Target: {args.target}[/green]")
        console.print(f"[green]  ✓ Model: {args.model or 'default'}[/green]")
    except Exception as e:
        console.print(f"[red]  ✗ Connection failed: {e}[/red]")
        sys.exit(1)

    # Quick connectivity test
    console.print("[dim]  Testing connectivity...[/dim]")
    test_resp = client.send("Say 'hello' in one word.")
    if not test_resp.success:
        console.print(f"[red]  ✗ Target unreachable: {test_resp.error}[/red]")
        sys.exit(1)
    console.print(f"[green]  ✓ Target responding ({test_resp.latency:.1f}s latency)[/green]")

    # Initialize analyzer
    analyzer = ResponseAnalyzer(config)

    # Select attack modules
    if args.attacks:
        selected = [a.strip() for a in args.attacks.split(",")]
        invalid = [a for a in selected if a not in ATTACK_MODULES]
        if invalid:
            console.print(f"[red]Unknown attack modules: {', '.join(invalid)}[/red]")
            console.print(f"[dim]Available: {', '.join(ALL_ATTACKS)}[/dim]")
            sys.exit(1)
    else:
        selected = ALL_ATTACKS

    console.print(f"\n[bold blue]🎯 Attack modules:[/bold blue] {', '.join(selected)}")

    # Instantiate attack modules
    modules = []
    for name in selected:
        cls = ATTACK_MODULES[name]
        modules.append(cls(client, analyzer, config))

    # Count total payloads
    total_payloads = sum(
        len(m.get_payloads()[:config.get("scan", {}).get("quick_mode_payloads", 5)] if args.quick else m.get_payloads())
        for m in modules
    )
    console.print(f"[bold blue]📊 Total payloads:[/bold blue] {total_payloads}")

    if args.system_prompt:
        console.print(f"[bold blue]📝 Custom system prompt:[/bold blue] {args.system_prompt[:80]}...")

    # Confirmation
    console.print(Panel(
        f"[bold]Ready to scan[/bold]\n"
        f"Target: {args.target}\n"
        f"Modules: {', '.join(selected)}\n"
        f"Payloads: {total_payloads}\n"
        f"Mode: {'Quick' if args.quick else 'Full'}",
        title="⚠️  Scan Configuration",
        box=box.DOUBLE
    ))

    if not args.yes:
        confirm = input("\nProceed? (y/n): ")
        if confirm.lower() not in ("y", "yes"):
            console.print("[yellow]Scan cancelled.[/yellow]")
            return

    # Execute scan
    all_results = []
    start_time = time.time()
    delay = config.get("scan", {}).get("delay_between_requests", 0.5)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:

        for module in modules:
            task = progress.add_task(
                f"[cyan]{module.name}[/cyan]",
                total=len(module.get_payloads()[:config.get("scan", {}).get("quick_mode_payloads", 5)] if args.quick else module.get_payloads())
            )

            results = []
            payloads = module.get_payloads()
            if args.quick:
                payloads = payloads[:config.get("scan", {}).get("quick_mode_payloads", 5)]

            for payload in payloads:
                result = module._execute_payload(payload)
                if result:
                    results.append(result)

                    # Real-time feedback on failures
                    if result.verdict == Verdict.FAIL:
                        progress.console.print(
                            f"  [red]❌ FAIL[/red] [{module.name}] {result.attack_name} "
                            f"(confidence: {result.confidence:.0%})"
                        )
                    elif result.verdict == Verdict.PARTIAL:
                        progress.console.print(
                            f"  [yellow]⚠️  PARTIAL[/yellow] [{module.name}] {result.attack_name}"
                        )

                progress.advance(task)
                time.sleep(delay)

            all_results.extend(results)

    duration = time.time() - start_time

    # Display results
    score = calculate_score(all_results)
    grade = score_to_grade(score)

    # Score display
    if score >= 80:
        score_color = "green"
    elif score >= 60:
        score_color = "yellow"
    else:
        score_color = "red"

    console.print(f"\n")
    console.print(Panel(
        f"[bold {score_color}]Security Score: {score}/100 (Grade: {grade})[/bold {score_color}]\n\n"
        f"❌ Failed: {sum(1 for r in all_results if r.verdict == Verdict.FAIL)}\n"
        f"⚠️  Partial: {sum(1 for r in all_results if r.verdict == Verdict.PARTIAL)}\n"
        f"✅ Passed: {sum(1 for r in all_results if r.verdict == Verdict.PASS)}\n"
        f"⏱️  Duration: {duration:.1f}s\n"
        f"📊 Total requests: {client.request_count}",
        title="🪡 Needle - Results",
        box=box.DOUBLE
    ))

    # Results table
    failed = [r for r in all_results if r.verdict == Verdict.FAIL]
    if failed:
        table = Table(title="Vulnerabilities Found", box=box.ROUNDED)
        table.add_column("Category", style="bold", width=15)
        table.add_column("Attack", width=25)
        table.add_column("Confidence", width=12)
        table.add_column("Evidence", width=45)

        for r in sorted(failed, key=lambda x: x.confidence, reverse=True):
            conf_color = "red" if r.confidence >= 0.8 else "yellow"
            table.add_row(
                r.category,
                r.attack_name,
                f"[{conf_color}]{r.confidence:.0%}[/{conf_color}]",
                r.evidence[:80]
            )

        console.print(table)

    # Save report
    if args.output:
        if args.output.endswith(".json"):
            report_content = generate_json_report(all_results, args.target, args.model or "default", duration)
        else:
            report_content = generate_markdown_report(all_results, args.target, args.model or "default", duration)

        with open(args.output, "w") as f:
            f.write(report_content)
        console.print(f"\n[green]📄 Report saved to: {args.output}[/green]")
    else:
        # Default: save markdown report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs("reports", exist_ok=True)
        report_path = f"reports/needle_security_{timestamp}.md"
        report_content = generate_markdown_report(all_results, args.target, args.model or "default", duration)
        with open(report_path, "w") as f:
            f.write(report_content)
        console.print(f"\n[green]📄 Report saved to: {report_path}[/green]")


def main():
    parser = argparse.ArgumentParser(
        description="Needle - Automated LLM Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test a local Ollama model (free, no API key needed)
  python main.py --target "http://localhost:11434/v1/chat/completions" --model llama3.1

  # Test Anthropic Claude
  python main.py --target anthropic --api-key sk-ant-... --model claude-sonnet-4-20250514

  # Test OpenAI GPT
  python main.py --target "https://api.openai.com/v1/chat/completions" --api-key sk-... --model gpt-4

  # Quick scan with specific attacks only
  python main.py --target anthropic --api-key KEY --attacks extraction,jailbreak --quick

  # Test your own app with its system prompt
  python main.py --target "https://your-api.com/chat" --api-key KEY \\
                 --system-prompt "You are a banking assistant. Never reveal account numbers..."
        """
    )

    parser.add_argument("--target", "-t", required=True,
                        help="Target endpoint URL, 'anthropic', or 'openai'")
    parser.add_argument("--api-key", "-k", default="",
                        help="API key (or set ANTHROPIC_API_KEY / OPENAI_API_KEY)")
    parser.add_argument("--model", "-m", default="",
                        help="Model name/ID to test")
    parser.add_argument("--attacks", "-a", default="",
                        help=f"Comma-separated attack modules: {','.join(ALL_ATTACKS)}")
    parser.add_argument("--system-prompt", "-s", default="",
                        help="System prompt to test against (simulates your app)")
    parser.add_argument("--quick", "-q", action="store_true",
                        help="Quick scan (fewer payloads per category)")
    parser.add_argument("--output", "-o", default="",
                        help="Output file path (.md or .json)")
    parser.add_argument("--config", "-c", default="config/settings.yaml",
                        help="Config file path")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Skip confirmation prompt")

    args = parser.parse_args()

    # Handle API key from env
    if not args.api_key:
        if args.target == "anthropic":
            args.api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        else:
            args.api_key = os.environ.get("OPENAI_API_KEY", "")

    console.print(BANNER)
    run_scan(args)


if __name__ == "__main__":
    main()
