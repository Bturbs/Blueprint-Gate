"""Stable identifiers for fenced remote publication attempts."""

import re


def attempt_branch(issue_number: int, job_id: str, fencing_token: int) -> str:
    if issue_number < 1 or fencing_token < 1 or not re.fullmatch(r"[0-9a-fA-F-]{36}", job_id):
        raise ValueError("Invalid publication claim identity")
    return f"adp/issue-{issue_number}/job-{job_id.replace('-', '').lower()}-f{fencing_token}"
