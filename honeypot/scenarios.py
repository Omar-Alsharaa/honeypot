"""Scenario definitions for the training honeypot."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class Scenario:
    """Description of a training scenario.

    Attributes
    ----------
    name:
        Internal identifier used on the command line.
    title:
        Human readable label that appears in logs and dashboards.
    description:
        Overview of the lab environment and what the trainee should learn.
    recommended_challenges:
        Ordered list of difficulty presets that make sense for this scenario.
    objectives:
        Bullet-style learning goals that can be rendered in documentation.
    hints:
        Quick suggestions (tools, commands, mindset) that get a student
        unstuck without giving away the solution.
    """

    name: str
    title: str
    description: str
    recommended_challenges: List[str]
    objectives: List[str]
    hints: List[str]


SCENARIOS: Dict[str, Scenario] = {}


def _register(scenario: Scenario) -> None:
    SCENARIOS[scenario.name] = scenario


_register(
    Scenario(
        name="baseline",
        title="Baseline Recon",
        description=(
            "Default deployment focused on service discovery and initial "
            "enumeration. Ideal for demonstrating how reconnaissance logs "
            "are captured in the honeypot."
        ),
        recommended_challenges=["easy", "normal"],
        objectives=[
            "Connect to the fake SSH service and capture the banner.",
            "Trigger an HTTP request and inspect the log entry it generates.",
            "Record source IPs and map them to actions in the scoreboard.",
        ],
        hints=[
            "Use `nc 127.0.0.1 2222` or `ssh -vv` to provoke SSH activity.",
            "Send simple GET requests with `curl` to collect baseline data.",
        ],
    )
)

_register(
    Scenario(
        name="web-basic",
        title="Web Exploitation Basics",
        description=(
            "Designed for introductory web exploitation labs. The scenario "
            "walks students through identifying harmless simulated bugs and "
            "understanding HTTP request telemetry."
        ),
        recommended_challenges=["easy", "normal", "hard"],
        objectives=[
            "Enumerate the `/vuln` endpoint and locate the simulated flag trigger.",
            "Experiment with SQL injection payloads to observe the scoring output.",
            "Capture at least one flag and view it on the leaderboard.",
        ],
        hints=[
            "Try `?payload=show_flag` and variations with uppercase letters.",
            "`sqlmap --crawl=0 --forms` is safe to run because inputs are never executed.",
        ],
    )
)

_register(
    Scenario(
        name="hybrid-lfi",
        title="Hybrid LFI Challenge",
        description=(
            "Combines reconnaissance with simulated local file inclusion and "
            "command injection markers. Great for intermediate ethical hacking "
            "workshops where layered detection is demonstrated."
        ),
        recommended_challenges=["normal", "hard", "expert"],
        objectives=[
            "Identify strings that resemble directory traversal or `/etc/passwd`.",
            "Trigger multiple vulnerability types and compare scoring weights.",
            "Discuss containment strategies based on the captured payloads.",
        ],
        hints=[
            "Send requests like `?payload=../../../../etc/passwd` to see LFI detection.",
            "Chain payloads with `; cat` to trigger the simulated RCE response.",
        ],
    )
)

_register(
    Scenario(
        name="gauntlet",
        title="CTF Gauntlet",
        description=(
            "High-energy capture-the-flag format that awards aggressive scoring. "
            "Use it for advanced students who want to chain multiple findings."
        ),
        recommended_challenges=["hard", "expert", "hacker"],
        objectives=[
            "Chain together multiple payload types within a single session.",
            "Trigger the rarest vulnerability type (RCE marker) at least twice.",
            "Review leaderboard telemetry and produce an after-action report.",
        ],
        hints=[
            "Mix SQL keywords with command separators such as `; ls`.",
            "Automate probing with custom scripts while keeping an eye on logs.",
        ],
    )
)


def get_scenario(name: str) -> Scenario:
    """Return the scenario definition by key.

    Raises
    ------
    KeyError
        If the scenario name is unknown.
    """

    key = name.strip().lower()
    if key not in SCENARIOS:
        raise KeyError(f"Unknown scenario: {name}")
    return SCENARIOS[key]


def list_scenarios() -> List[Scenario]:
    """Return the registered scenarios sorted by name."""

    return [SCENARIOS[k] for k in sorted(SCENARIOS.keys())]
