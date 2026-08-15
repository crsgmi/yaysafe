from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from yaysafe.config import UIConfig
from yaysafe.models import RISK_ORDER, Finding, Risk, Verdict
from yaysafe.sanitize import safe_filename, sanitize_terminal

_COLORS = {
    Risk.INFO: "\033[1;36m",
    Risk.LOW: "\033[1;32m",
    Risk.MEDIUM: "\033[1;33m",
    Risk.HIGH: "\033[1;31m",
    Risk.CRITICAL: "\033[1;31m",
    Risk.UNKNOWN: "\033[1;33m",
}


@dataclass(slots=True)
class UI:
    config: UIConfig
    out: TextIO = sys.stdout
    err: TextIO = sys.stderr

    @property
    def color(self) -> bool:
        return self.config.color and "NO_COLOR" not in os.environ and self.out.isatty()

    def _paint(self, text: str, code: str) -> str:
        return f"{code}{text}\033[0m" if self.color else text

    def section(self, message: str) -> None:
        print(
            self._paint("::", "\033[1;34m") + " " + sanitize_terminal(message),
            file=self.out,
        )

    def status(self, label: str, value: str = "") -> None:
        clean_label = sanitize_terminal(label)
        clean_value = sanitize_terminal(value)
        suffix = f" {clean_value}" if clean_value else ""
        print(self._paint("==>", "\033[1;32m") + f" {clean_label}{suffix}", file=self.out)

    def warning(self, message: str) -> None:
        print(
            self._paint("warning:", "\033[1;33m") + " " + sanitize_terminal(message),
            file=self.err,
        )

    def error(self, message: str) -> None:
        print(
            self._paint("error:", "\033[1;31m") + " " + sanitize_terminal(message),
            file=self.err,
        )

    def risk(self, risk: Risk) -> str:
        text = risk.value.upper()
        return self._paint(text, _COLORS[risk])

    def _detail(self, text: str, *, indent: int = 10) -> None:
        clean = sanitize_terminal(text, max_length=2000)
        prefix = " " * indent
        for line in textwrap.wrap(clean, width=max(40, 88 - indent)) or [""]:
            print(prefix + line, file=self.out)

    def verdict(self, verdict: Verdict, *, verbose: bool = False) -> None:
        if verdict.cached:
            self.status("Using cached security analysis")
        self.status(safe_filename(verdict.package))
        print(f"    {'Risk':<12}{self.risk(verdict.risk)}", file=self.out)
        if self.config.show_confidence and verdict.confidence is not None:
            print(f"    {'Confidence':<12}{verdict.confidence:.0%}", file=self.out)
        if verdict.llm_model:
            print(
                f"    {'Model':<12}{sanitize_terminal(verdict.llm_model, max_length=120)}",
                file=self.out,
            )
        if self.config.show_sources and verdict.metadata.source_domains:
            print(
                f"    {'Sources':<12}{', '.join(safe_filename(x) for x in verdict.metadata.source_domains)}",
                file=self.out,
            )
        if verdict.disagreement:
            assert verdict.llm_risk is not None
            self.warning(
                f"hard safety rule raised the LLM verdict from {verdict.llm_risk.value.upper()} "
                f"to {verdict.risk.value.upper()}"
            )

        if verbose:
            self.analysis_details(verdict)
            return
        if verdict.risk == Risk.UNKNOWN:
            print(file=self.out)
            self.section(
                "LLM analysis failed" if verdict.llm_error else "LLM analysis inconclusive"
            )
            self._detail(verdict.llm_error or verdict.summary, indent=4)
            print(file=self.out)
            self.section("Package safety could not be determined.")
            return
        if verdict.llm_risk == Risk.UNKNOWN:
            print(file=self.out)
            self.section(
                "LLM analysis failed" if verdict.llm_error else "LLM analysis inconclusive"
            )
            self._detail(verdict.llm_error or verdict.summary, indent=4)

        security_findings = [
            finding
            for finding in verdict.merged_findings
            if RISK_ORDER[finding.severity] >= RISK_ORDER[Risk.MEDIUM]
        ]
        notes = [
            finding
            for finding in verdict.merged_findings
            if RISK_ORDER[finding.severity] < RISK_ORDER[Risk.MEDIUM]
            and finding.assessment != "false_positive"
            and finding.rule_id != "skipped-checksum"
            and (
                finding.assessment == "contextual_but_legitimate"
                or "llm" in finding.detected_by
                or finding.rule_id == "setuid"
            )
        ]
        if security_findings:
            print(file=self.out)
            heading = (
                "Critical security finding"
                if verdict.risk == Risk.CRITICAL and len(security_findings) == 1
                else "Security findings"
            )
            self.section(heading)
            self.findings(security_findings)
        elif notes:
            print(file=self.out)
            self.section("Security notes")
            self.findings(notes, show_evidence=False)
        else:
            print(file=self.out)
            self.section("No significant security concerns detected.")

    def findings(self, findings: Iterable[Finding], *, show_evidence: bool = True) -> None:
        for finding in findings:
            location = safe_filename(finding.file)
            if finding.line:
                location += f":{finding.line}"
            print(file=self.out)
            risk_label = f"{finding.severity.value.upper():<8}"
            print(
                f"    {self._paint(risk_label, _COLORS[finding.severity])} {location}",
                file=self.out,
            )
            self._detail(finding.description)
            if finding.assessment_reason:
                self._detail(finding.assessment_reason)
            if show_evidence and finding.matched_text:
                print(file=self.out)
                self._detail(finding.matched_text)

    def analysis_details(self, verdict: Verdict) -> None:
        print(file=self.out)
        self.section("Analysis details")
        merged_by_key = {
            (finding.rule_id, finding.file, finding.line): finding
            for finding in verdict.merged_findings
        }
        assessments = {
            (item.rule_id, item.file, item.line): item for item in verdict.static_assessments
        }
        if not verdict.static_findings and not verdict.llm_findings:
            self._detail(verdict.summary, indent=4)
        for finding in verdict.static_findings:
            key = (finding.rule_id, finding.file, finding.line)
            assessment = assessments.get(key)
            impact = merged_by_key.get(key, finding).severity
            print(file=self.out)
            print("    Static scanner:", file=self.out)
            self._detail(finding.rule_id, indent=8)
            location = safe_filename(finding.file) + (f":{finding.line}" if finding.line else "")
            self._detail(location, indent=8)
            self._detail(finding.matched_text, indent=8)
            print(file=self.out)
            print("    LLM assessment:", file=self.out)
            self._detail(assessment.assessment.value if assessment else "not available", indent=8)
            if assessment:
                print(file=self.out)
                print("    Reason:", file=self.out)
                self._detail(assessment.reason, indent=8)
            print(file=self.out)
            print("    Final impact:", file=self.out)
            self._detail(impact.value.upper(), indent=8)
        for finding in verdict.merged_findings:
            if "llm" not in finding.detected_by or "static" in finding.detected_by:
                continue
            print(file=self.out)
            print("    LLM finding:", file=self.out)
            location = safe_filename(finding.file) + (f":{finding.line}" if finding.line else "")
            self._detail(location, indent=8)
            self._detail(finding.category, indent=8)
            self._detail(finding.description, indent=8)
            if finding.matched_text:
                self._detail(finding.matched_text, indent=8)
            print(file=self.out)
            print("    Final impact:", file=self.out)
            self._detail(finding.severity.value.upper(), indent=8)


def select_pager() -> list[str] | None:
    if os.environ.get("PAGER"):
        try:
            command = shlex.split(os.environ["PAGER"])
        except ValueError:
            command = []
        if command and shutil.which(command[0]):
            return command
    for candidate in ("less", "more", "cat"):
        path = shutil.which(candidate)
        if path:
            return [path]
    return None


def view_files(files: Iterable[Path]) -> bool:
    pager = select_pager()
    selected = [path for path in files if path.is_file() and not path.is_symlink()]
    if not pager or not selected:
        return False
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix="yaysafe-view-", suffix=".txt", delete=False
        ) as handle:
            temporary = Path(handle.name)
            for path in selected:
                handle.write(f"==> {safe_filename(path.name)}\n\n")
                content = path.read_text(encoding="utf-8", errors="replace")
                handle.write(sanitize_terminal(content, max_length=max(4000, len(content) * 2)))
                handle.write("\n\n")
        subprocess.run([*pager, str(temporary)], check=False)
        return True
    except OSError:
        return False
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
