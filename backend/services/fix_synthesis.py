"""Intelligent Fix & Explanation Synthesizer for Shipcheck AI Remediation."""

from typing import Dict, Any, Optional
import re


def synthesize_ai_remediation(finding: Dict[str, Any], code_context: str = "") -> Dict[str, Any]:
    """Generate precise, tailored AI remediation guidance and actionable code fixes."""
    title = (finding.get("title") or "").strip()
    title_lower = title.lower()
    evidence = (finding.get("evidence") or "").strip()
    file_path = finding.get("file_path") or ""
    line_number = finding.get("line_number")
    recommendation = finding.get("recommendation") or ""
    description = finding.get("description") or ""

    # 1. SQL Injection / Query string interpolation
    if "sql" in title_lower or "injection" in title_lower or ("SELECT" in evidence.upper() and ("{" in evidence or "%" in evidence or "+" in evidence)):
        summary = (
            f"Vulnerable SQL Query Construction detected in {file_path}:{line_number or ''}. "
            "Untrusted input is formatted or concatenated directly into the SQL query string, "
            "allowing attackers to manipulate query logic and bypass authentication."
        )
        root_cause = (
            "Direct string formatting (f-string, '%', or '+') embeds user input into executable SQL syntax "
            "without AST parameterization or driver-level escaping."
        )
        expected_security_effect = (
            "Completely eliminates SQL Injection (CWE-89) by treating user input as discrete query parameters rather than executable SQL syntax."
        )
        if evidence and ("select" in evidence.lower() or "where" in evidence.lower()):
            patch_diff = (
                f"# ❌ Vulnerable (Direct concatenation):\n# {evidence}\n\n"
                f"# ✅ Secure Parameterized Replacement:\n"
                f"sql = \"SELECT username, role FROM users WHERE username = ? AND password = ?\"\n"
                f"with sqlite3.connect(DATABASE_PATH) as db:\n"
                f"    user = db.execute(sql, (username, password)).fetchone()"
            )
        else:
            patch_diff = (
                "# ✅ Secure Parameterized Query Pattern:\n"
                "cursor.execute(\"SELECT * FROM users WHERE username = ? AND is_active = 1\", (username,))"
            )

    # 2. Hardcoded Credentials / Passwords / Secrets
    elif "password" in title_lower or "secret" in title_lower or "key" in title_lower or "token" in title_lower:
        if "sql" in evidence.lower() or "select" in evidence.lower() or "where" in evidence.lower():
            summary = (
                f"Plaintext Password Verification & SQL Concatenation in {file_path}:{line_number or ''}. "
                "Credentials are checked directly in an interpolated SQL statement, creating both SQL injection "
                "and plaintext credential exposure risks."
            )
            root_cause = (
                "Checking plaintext passwords directly in database queries and interpolating user input into the SQL string "
                "allows attackers to bypass authentication and exposes stored credentials."
            )
            expected_security_effect = (
                "Protects credentials at rest, neutralizes query injection, and enforces industry-standard salted hashing verification (bcrypt / argon2)."
            )
            patch_diff = (
                f"# ❌ Vulnerable code (Plaintext check in query):\n# {evidence or 'sql = f\"SELECT ... WHERE password = ...\"'}\n\n"
                f"# ✅ Secure Implementation (Parameterized Query + Salted Hash Verification):\n"
                f"import bcrypt\n\n"
                f"# 1. Query user by username using parameterized SQL (never include password in WHERE clause)\n"
                f"sql = \"SELECT username, password_hash, role FROM users WHERE username = ?\"\n"
                f"with sqlite3.connect(DATABASE_PATH) as db:\n"
                f"    user = db.execute(sql, (username,)).fetchone()\n\n"
                f"# 2. Safely verify password against stored cryptographic hash\n"
                f"if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):\n"
                f"    return {{'authenticated': True, 'user': user[0], 'role': user[2]}}\n"
                f"return {{'authenticated': False, 'message': 'Invalid credentials'}}"
            )
        else:
            summary = (
                f"Hardcoded sensitive secret/credential found in {file_path}:{line_number or ''}. "
                "Committing secrets to source repositories risks unauthorized access if code is shared or audited."
            )
            root_cause = (
                "Static assignment of sensitive cryptographic keys, API tokens, or passwords directly in source code files."
            )
            expected_security_effect = (
                "Prevents credential leakage, complies with 12-factor configuration guidelines, and enables seamless secret rotation."
            )
            patch_diff = (
                "import os\n"
                "# ✅ Load sensitive secret securely from environment variable\n"
                "SECRET_KEY = os.environ.get('APP_SECRET_KEY')\n"
                "if not SECRET_KEY:\n"
                "    raise RuntimeError('APP_SECRET_KEY environment variable is required but not set.')"
            )

    # 3. Cross-Site Scripting (XSS)
    elif "xss" in title_lower or "cross-site" in title_lower or "html" in title_lower:
        summary = (
            f"Unsanitized HTML/Script rendering detected in {file_path}:{line_number or ''}. "
            "User-controlled inputs are rendered into HTML markup or response body without contextual encoding."
        )
        root_cause = (
            "Direct inclusion of untrusted inputs into HTML markup allows attackers to execute arbitrary client-side JavaScript (CWE-79)."
        )
        expected_security_effect = (
            "Neutralizes XSS attacks by converting active HTML characters (<, >, &, \", ') into safe HTML entities."
        )
        patch_diff = (
            "import html\n"
            "# ✅ Sanitize user input before rendering\n"
            "safe_rendered_text = html.escape(untrusted_user_input)"
        )

    # 4. Command Injection / Unsafe Eval / RCE
    elif "command" in title_lower or "exec" in title_lower or "eval" in title_lower or "rce" in title_lower:
        summary = (
            f"Arbitrary Command / Dynamic Code Execution detected in {file_path}:{line_number or ''}. "
            "Unsanitized input is passed to an execution sink (`os.system`, `subprocess`, or `eval`)."
        )
        root_cause = (
            "Executing shell commands with shell=True or string evaluation enables command chaining via metacharacters (|;&$). (CWE-78 / CWE-95)."
        )
        expected_security_effect = (
            "Eliminates OS Command Injection by invoking explicit binaries with isolated argument lists without shell evaluation."
        )
        patch_diff = (
            "import subprocess\n"
            "# ✅ Safe invocation: pass arguments as an explicit list with shell=False\n"
            "result = subprocess.run(['/usr/bin/executable', arg1, arg2], capture_output=True, text=True, check=True)"
        )

    # 5. Path Traversal
    elif "path" in title_lower or "traversal" in title_lower:
        summary = (
            f"Directory / Path Traversal vulnerability detected in {file_path}:{line_number or ''}. "
            "Untrusted file paths could allow unauthorized reads or writes outside the intended directory."
        )
        root_cause = (
            "Lack of canonical path resolution and boundary verification permits relative traversal sequences ('../') (CWE-22)."
        )
        expected_security_effect = (
            "Enforces strict workspace sandboxing, preventing unauthorized filesystem access."
        )
        patch_diff = (
            "from pathlib import Path\n"
            "# ✅ Validate path is within allowed base directory\n"
            "base_directory = Path('/safe/base/path').resolve()\n"
            "target_path = (base_directory / user_filename).resolve()\n"
            "if not target_path.is_relative_to(base_directory):\n"
            "    raise ValueError('Access denied: Path traversal attempt detected')"
        )

    # 6. CORS Misconfiguration
    elif "cors" in title_lower:
        summary = (
            f"Overly Permissive CORS Policy in {file_path}:{line_number or ''}. Wildcard origins ('*') with credentials enabled can expose sensitive API data."
        )
        root_cause = (
            "Setting Access-Control-Allow-Origin to '*' allows any third-party website to make authenticated cross-origin requests."
        )
        expected_security_effect = (
            "Restricts resource sharing strictly to verified frontend domains, preventing cross-origin data theft."
        )
        patch_diff = (
            "# ✅ Explicit trusted origins configuration\n"
            "app.add_middleware(\n"
            "    CORSMiddleware,\n"
            "    allow_origins=['https://app.yourdomain.com'], # Explicit trusted domain\n"
            "    allow_credentials=True,\n"
            "    allow_methods=['GET', 'POST', 'PUT', 'DELETE'],\n"
            "    allow_headers=['Authorization', 'Content-Type']\n"
            ")"
        )

    # Default contextual synthesis
    else:
        summary = description or f"Security vulnerability identified: {title} in {file_path}"
        root_cause = "Potentially unsafe pattern identified during Shipcheck static & semantic analysis."
        expected_security_effect = "Hardens application defense and minimizes attack surface."
        patch_diff = (
            f"# ✅ Recommended Security Fix for: {title}\n"
            f"# {recommendation or 'Implement strict input validation and access controls.'}\n"
            + (f"# Context:\n# {evidence}\n" if evidence else "")
        )

    return {
        "finding_id": finding.get("id"),
        "summary": summary,
        "root_cause": root_cause,
        "file_path": file_path,
        "patch_diff": patch_diff,
        "recommended_tests": ["test_security_fix_regression"],
        "expected_security_effect": expected_security_effect,
        "limitations": "Ensure all unit and integration tests are verified after applying this patch."
    }
