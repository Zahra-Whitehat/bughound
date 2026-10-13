"""OS command injection detection (time-based and output-based)."""

from __future__ import annotations

import re

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ._util import baseline, send_with_param

# Output-based detection uses arithmetic that only evaluates if a shell runs it.
# The literal payload contains "92173*61813", never the product, so a mere
# reflection of the payload cannot trigger a false positive.
_A, _B = 92173, 61813
EXPECTED = str(_A * _B)
OUTPUT_PAYLOADS = [
    f";echo $(({_A}*{_B}))",
    f"|echo $(({_A}*{_B}))",
    f"`echo $(({_A}*{_B}))`",
    f"&& echo $(({_A}*{_B}))",
]
UNAME_RE = re.compile(r"uid=\d+\(")

# Time-based: sleep 6s
TIME_PAYLOADS = [";sleep 6;", "|sleep 6", "`sleep 6`", "&& sleep 6"]


@register
class CommandInjectionModule(Module):
    name = "command-injection"
    categories = [Category.CMD_INJECTION, Category.RCE]
    passive = False
    aggressive_required = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rt in ctx.request_targets:
            for param in rt.params:
                found = False
                for payload in OUTPUT_PAYLOADS:
                    r = await send_with_param(ctx.client, rt, param, rt.params[param] + payload)
                    if r.ok and (EXPECTED in r.text or UNAME_RE.search(r.text)):
                        findings.append(
                            Finding(
                                category=Category.CMD_INJECTION,
                                title=f"OS command injection in '{param}'",
                                severity=Severity.CRITICAL,
                                confidence="confirmed",
                                url=rt.url,
                                description=f"Injected shell command output appeared in the response via '{param}'.",
                                evidence=f"Payload {payload!r} produced marker/command output.",
                                request=f"{rt.method} {rt.url} ({param}=...{payload})",
                                response_excerpt=r.text[:300],
                                remediation="Never pass user input to a shell; use exec APIs with argument arrays and allowlists.",
                                cwe="CWE-78",
                                module=self.name,
                                verified=True,
                            )
                        )
                        found = True
                        break
                if found:
                    continue

                base = await baseline(ctx.client, rt)
                if not base.ok:
                    continue
                for payload in TIME_PAYLOADS:
                    r = await send_with_param(ctx.client, rt, param, rt.params[param] + payload)
                    if r.ok and r.elapsed > 5.0 and base.elapsed < 3.0:
                        findings.append(
                            Finding(
                                category=Category.CMD_INJECTION,
                                title=f"Possible time-based command injection in '{param}'",
                                severity=Severity.HIGH,
                                confidence="firm",
                                url=rt.url,
                                description=f"A sleep payload in '{param}' delayed the response, indicating command execution.",
                                evidence=f"baseline={base.elapsed:.1f}s, payload={r.elapsed:.1f}s ({payload!r})",
                                request=f"{rt.method} {rt.url} ({param}=...{payload})",
                                remediation="Never pass user input to a shell; use argument arrays and allowlists.",
                                cwe="CWE-78",
                                module=self.name,
                                verified=False,
                            )
                        )
                        break
        return findings
