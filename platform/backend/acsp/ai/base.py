from __future__ import annotations

from typing import Protocol

from acsp.schemas import AIAnalysisResult, CoreEventFields, RuleEngineResult


class AIEngine(Protocol):
    """Pluggable AI interface — swap mock for local LLM without changing the pipeline."""

    name: str

    def analyze(
        self,
        core: CoreEventFields,
        rule_engine: RuleEngineResult,
        raw_context: dict,
    ) -> AIAnalysisResult:
        ...
