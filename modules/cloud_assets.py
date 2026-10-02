"""Stage 8 — Cloud Assets for UNDERTOW.

  cloud_enum -k "<client keyword>"  -> MISC/cloud_assets.txt
  (AWS S3 / Azure Blob / GCP bucket enumeration by company/brand keyword;
  each hit's access level reformatted into "<Provider> | <asset> | <status>")

  unauthenticated object listing on any bucket cloud_enum marks public
                                    -> MISC/s3_listing_<bucket>.txt
  (one file per open bucket, same convention as Stage 5's ffuf_<host>.txt —
  cloud_enum only confirms a bucket is public, this actually lists what's in it)

Dropped: "Shodan Karma" from the original spec — not a real, verifiable Shodan
CLI/API feature (checked `shodan --help` and Shodan's own docs; nothing by
that name exists). User confirmed dropping it rather than guessing at a
replacement (2026-10-01).

`aws s3 ls --no-sign-request` from the spec is implemented as a direct
unauthenticated HTTP GET against the bucket's S3 REST endpoint instead of
shelling out to the `aws` CLI — that CLI isn't installed on this box, and an
anonymous listing request is all `--no-sign-request` does under the hood
anyway, so this avoids an extra dependency for no loss of capability.

Stage 8 needs a company/brand keyword, not a domain — scope.txt/web_scope.txt
don't carry that, so it's a required explicit input (`--cloud-keyword`), never
guessed from the domain name.
"""
from __future__ import annotations

import json
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

from . import runner
from .runner import StageResult, ToolResult

PROVIDER_NAMES = {"aws": "AWS S3", "azure": "Azure", "gcp": "GCP"}
STATUS_NAMES = {"public": "PUBLIC (listable)", "protected": "protected", "disabled": "disabled"}

MAX_LISTED_KEYS = 1000

S3_HOST_SUFFIX_RE = re.compile(r"\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$", re.IGNORECASE)


def _bucket_name_from_host(bucket_host: str) -> str:
    """Virtual-hosted-style S3 hostnames break TLS SNI/cert validation for any
    bucket name containing a dot (e.g. flaws.cloud.s3.amazonaws.com — the cert
    is only valid for *.s3.amazonaws.com, one label deep). Extracting the bare
    bucket name and always using path-style requests against the generic
    endpoint sidesteps this for every bucket name, dots or not.
    """
    return S3_HOST_SUFFIX_RE.sub("", bucket_host) or bucket_host


def _run_cloud_enum(keyword: str, outfile: Path, timeout: int, engagement_root: Path) -> tuple[ToolResult, list[str]]:
    """Returns (ToolResult, [public S3 bucket hostnames found])."""
    if not runner.have("cloud_enum"):
        return ToolResult(tool="cloud_enum", ran=False, error="not installed"), []

    json_tmp = outfile.parent / ".cloud_enum_native.json"
    try:
        proc = subprocess.run(
            ["cloud_enum", "-k", keyword, "-l", str(json_tmp), "-f", "json", "-qs"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
        json_tmp.unlink(missing_ok=True)
        return ToolResult(tool="cloud_enum", ran=True, error=f"timeout after {timeout}s"), []

    runner.save_raw(engagement_root, outfile.name, proc.stdout, proc.stderr)
    hits = []
    if json_tmp.exists():
        for line in json_tmp.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue  # cloud_enum's logfile has a non-JSON date-stamp header line
            try:
                hits.append(json.loads(line))
            except ValueError:
                continue
        json_tmp.unlink(missing_ok=True)

    lines = []
    public_s3_hosts = []
    for h in hits:
        provider = PROVIDER_NAMES.get(h.get("platform", ""), h.get("platform", "unknown"))
        target = h.get("target", "")
        status = STATUS_NAMES.get(h.get("access", ""), h.get("access", "unknown"))
        lines.append(f"{provider} | {target} | {status}")
        if h.get("platform") == "aws" and h.get("access") == "public" and "s3" in h.get("msg", "").lower():
            public_s3_hosts.append(target.split("://", 1)[-1].rstrip("/"))

    runner.write_lines(outfile, sorted(set(lines)))
    result = ToolResult(tool="cloud_enum", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(lines))
    return result, sorted(set(public_s3_hosts))


def _s3_bucket_region(bucket_name: str, timeout: int) -> str:
    """The generic `s3.amazonaws.com` path-style endpoint only serves
    us-east-1 buckets directly; every other region 301s (or errors) with the
    real region in `x-amz-bucket-region` regardless. Reading that header is
    the standard way to find a bucket's actual region without guessing.
    """
    try:
        resp = requests.head(f"https://s3.amazonaws.com/{bucket_name}/", timeout=min(timeout, 10))
        region = resp.headers.get("x-amz-bucket-region")
        if region:
            return region
    except requests.RequestException:
        pass
    return "us-east-1"  # sane default if the header's ever missing


def _list_s3_bucket(bucket_host: str, outfile: Path, timeout: int) -> ToolResult:
    """Unauthenticated listing of a public S3 bucket's objects — the
    `aws s3 ls --no-sign-request` equivalent, done natively over HTTP.
    """
    bucket_name = _bucket_name_from_host(bucket_host)
    region = _s3_bucket_region(bucket_name, timeout)
    url = f"https://s3.{region}.amazonaws.com/{bucket_name}/?list-type=2&max-keys={MAX_LISTED_KEYS}"
    try:
        resp = requests.get(url, timeout=min(timeout, 20))
    except requests.RequestException as exc:
        return ToolResult(tool="s3-listing", ran=True, error=str(exc)[:200])

    if not resp.ok:
        return ToolResult(tool="s3-listing", ran=True, returncode=resp.status_code, error=f"HTTP {resp.status_code}")

    try:
        root = ET.fromstring(resp.content)
    except ET.ParseError as exc:
        return ToolResult(tool="s3-listing", ran=True, error=f"XML parse error: {exc}")

    ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
    keys = [el.text for el in root.findall(".//s3:Contents/s3:Key", ns) if el.text]
    if not keys:
        keys = [el.text for el in root.findall(".//Contents/Key") if el.text]  # namespace-less fallback

    runner.write_lines(outfile, sorted(keys))
    return ToolResult(tool="s3-listing", ran=True, returncode=0, outfile=outfile, lines=len(keys), detail=bucket_host)


# --------------------------------------------------------------- orchestrate

def run_stage8(
    keyword: str | None,
    engagement_root: Path,
    *,
    timeout: int = 180,
) -> StageResult:
    outdir = engagement_root / "MISC"
    outdir.mkdir(parents=True, exist_ok=True)

    stage = StageResult(stage="Stage 8 — Cloud Assets")

    if not keyword:
        stage.add(ToolResult(
            tool="cloud_enum", ran=False,
            error="no --cloud-keyword given — cloud_enum needs a company/brand name, not a domain, never guessed",
        ))
        return stage

    cloud_r, public_buckets = _run_cloud_enum(keyword, outdir / "cloud_assets.txt", timeout, engagement_root)
    stage.add(cloud_r)
    if cloud_r.outfile:
        stage.outputs["cloud_assets"] = cloud_r.outfile

    for bucket_host in public_buckets:
        safe_name = bucket_host.replace("/", "_")
        stage.add(_list_s3_bucket(bucket_host, outdir / f"s3_listing_{safe_name}.txt", timeout))

    return stage
