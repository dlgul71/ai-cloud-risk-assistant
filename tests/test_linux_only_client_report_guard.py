"""Protect the AWS-only report guard from regression."""

import ast
from pathlib import Path


def test_aws_pdf_generation_is_guarded():
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    tree = ast.parse(app_path.read_text())

    matching_guards = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue

        condition = ast.unparse(node.test)

        if not condition.startswith("not "):
            continue

        if "aws_account_id" not in condition:
            continue

        pdf_calls = [
            item
            for branch in node.orelse
            for item in ast.walk(branch)
            if isinstance(item, ast.Call)
            and isinstance(item.func, ast.Name)
            and item.func.id == "generate_client_analyst_pdf"
        ]

        if pdf_calls:
            matching_guards.append(node)

    assert len(matching_guards) == 1
