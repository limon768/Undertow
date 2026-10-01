"""Scope model + the Stage 3 hard gate for UNDERTOW.

Absolute rule 2: a host is in-scope iff
    (IP matches scope.txt CIDR/IP  OR  FQDN matches web_scope.txt suffix)
    AND NOT (matches out-of-scope.txt)
Explicit exclusion always wins. Anything matching neither scope.txt nor
web_scope.txt is implicitly out-of-scope.

The IP/CIDR match is done with the stdlib `ipaddress` module rather than shelling
out to grepcidr: the gate is security-critical and must be deterministic even on a
box where grepcidr isn't installed. grepcidr stays in the tool registry for anyone
who wants it, but it is not on the trust path here.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

from . import runner


def _parse_networks(entries: list[str]) -> list[ipaddress._BaseNetwork]:
    nets = []
    for entry in entries:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue  # not an IP/CIDR line (e.g. an FQDN in a mixed file)
    return nets


def _parse_suffixes(entries: list[str]) -> list[str]:
    """Normalize FQDN scope entries to base suffixes.

    `*.example.com` and `example.com` both become `example.com`, which matches the
    apex and any subdomain.
    """
    suffixes = []
    for entry in entries:
        e = entry.lower().strip().rstrip(".")
        if e.startswith("*."):
            e = e[2:]
        try:
            ipaddress.ip_network(e, strict=False)
            continue  # it's an IP/CIDR, not an FQDN suffix
        except ValueError:
            pass
        if e:
            suffixes.append(e)
    return suffixes


def _host_matches_suffix(host: str, suffixes: list[str]) -> bool:
    h = host.lower().strip().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in suffixes)


def _ip_in_networks(ip: str, nets: list[ipaddress._BaseNetwork]) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in nets)


@dataclass
class Scope:
    scope_nets: list = field(default_factory=list)
    web_suffixes: list = field(default_factory=list)
    oos_nets: list = field(default_factory=list)
    oos_suffixes: list = field(default_factory=list)

    @classmethod
    def from_engagement(cls, root: Path) -> "Scope":
        scope_lines = runner.read_lines(root / "scope.txt")
        web_lines = runner.read_lines(root / "web_scope.txt")
        oos_lines = runner.read_lines(root / "out-of-scope.txt")
        return cls(
            scope_nets=_parse_networks(scope_lines),
            web_suffixes=_parse_suffixes(web_lines),
            oos_nets=_parse_networks(oos_lines),
            oos_suffixes=_parse_suffixes(oos_lines),
        )

    def is_excluded(self, host: str, ip: str) -> bool:
        return _ip_in_networks(ip, self.oos_nets) or _host_matches_suffix(host, self.oos_suffixes)

    def is_matched(self, host: str, ip: str) -> bool:
        return _ip_in_networks(ip, self.scope_nets) or _host_matches_suffix(host, self.web_suffixes)

    def classify(self, host: str, ip: str) -> tuple[bool, str]:
        """Return (in_scope, reason)."""
        if self.is_excluded(host, ip):
            return False, "matched out-of-scope.txt exclusion"
        if _ip_in_networks(ip, self.scope_nets):
            return True, "IP in scope.txt"
        if _host_matches_suffix(host, self.web_suffixes):
            return True, "FQDN matches web_scope.txt"
        return False, "not in scope.txt or web_scope.txt"

    @property
    def has_any(self) -> bool:
        return bool(self.scope_nets or self.web_suffixes)
