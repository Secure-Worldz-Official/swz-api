import os
from flask import Flask, jsonify, render_template, Response
from requests import get
from libs import (
    data_time_validator,
    normalize_contact,
    normalize_expires,
    normalize_policy,
    normalize_encryption,
    normalize_language,
)
from datetime import datetime

# Configure Flask to find templates and static files in parent directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _letter_grade(score: int) -> str:
    """Convert a 0-100 composite score to a letter grade (SSL-Labs style)."""
    if score >= 90:
        return "A+"
    elif score >= 80:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 50:
        return "D"
    else:
        return "F"


def _grade_color(grade: str) -> str:
    colors = {
        "A+": "#00e676", "A": "#69f0ae",
        "B": "#ffeb3b", "C": "#ffa726",
        "D": "#ef5350", "F": "#b71c1c",
    }
    return colors.get(grade, "#90a4ae")


def _parse_security_txt(domain: str) -> dict:
    """
    Fetch and parse security.txt for the given domain.
    Returns a dict with parsed fields and a policy_score (0-20).
    """
    result = {
        "exists": False,
        "url": f"https://{domain}/.well-known/security.txt",
        "contact": "",
        "expires": {},
        "policy": "",
        "encryption": "",
        "preferred_languages": "",
        "raw_fields": [],
        "policy_score": 0,
        "policy_score_max": 20,
        "policy_breakdown": [],
    }

    try:
        resp = get(result["url"], timeout=10, allow_redirects=True)
        if resp.status_code != 200:
            # Try root security.txt as fallback
            alt = f"https://{domain}/security.txt"
            resp = get(alt, timeout=10, allow_redirects=True)
            if resp.status_code != 200:
                result["policy_breakdown"].append(
                    {"label": "security.txt exists", "earned": 0, "max": 5, "note": "File not found"}
                )
                return result

        result["exists"] = True
        pts = 5  # +5 for file existing
        result["policy_breakdown"].append(
            {"label": "security.txt exists", "earned": 5, "max": 5, "note": "File found at well-known path"}
        )

        text = resp.text
        fields = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip().lower()
                val = (":" + val).strip() if key in ("contact", "policy", "encryption") else val.strip()
                # rebuild value correctly
                key2, _, val2 = line.partition(":")
                val2 = val2.strip()
                fields.setdefault(key2.strip().lower(), []).append(val2)
                result["raw_fields"].append({"key": key2.strip(), "value": val2})

        # Contact
        contact_vals = fields.get("contact", [])
        contact_str = normalize_contact(contact_vals[0] if contact_vals else "")
        result["contact"] = contact_str
        if contact_str:
            pts += 5
            result["policy_breakdown"].append(
                {"label": "Contact field", "earned": 5, "max": 5, "note": contact_str}
            )
        else:
            result["policy_breakdown"].append(
                {"label": "Contact field", "earned": 0, "max": 5, "note": "Missing"}
            )

        # Expires
        expires_vals = fields.get("expires", [])
        expires_raw = expires_vals[0] if expires_vals else ""
        expires_info = normalize_expires(expires_raw)
        result["expires"] = expires_info
        if expires_info.get("valid"):
            pts += 5
            result["policy_breakdown"].append(
                {"label": "Expires (valid & future)", "earned": 5, "max": 5,
                 "note": expires_info.get("clean", expires_raw)}
            )
        elif expires_info.get("raw"):
            result["policy_breakdown"].append(
                {"label": "Expires (valid & future)", "earned": 0, "max": 5,
                 "note": "Expired or invalid date"}
            )
        else:
            result["policy_breakdown"].append(
                {"label": "Expires (valid & future)", "earned": 0, "max": 5, "note": "Missing"}
            )

        # Policy URL
        policy_vals = fields.get("policy", [])
        policy_str = normalize_policy(policy_vals[0] if policy_vals else "")
        result["policy"] = policy_str
        if policy_str:
            pts += 3
            result["policy_breakdown"].append(
                {"label": "Policy URL", "earned": 3, "max": 3, "note": policy_str}
            )
        else:
            result["policy_breakdown"].append(
                {"label": "Policy URL", "earned": 0, "max": 3, "note": "Missing"}
            )

        # Preferred-Languages
        lang_vals = fields.get("preferred-languages", [])
        lang_str = normalize_language(lang_vals[0] if lang_vals else "")
        result["preferred_languages"] = lang_str
        if lang_str:
            pts += 2
            result["policy_breakdown"].append(
                {"label": "Preferred-Languages", "earned": 2, "max": 2, "note": lang_str}
            )
        else:
            result["policy_breakdown"].append(
                {"label": "Preferred-Languages", "earned": 0, "max": 2, "note": "Missing"}
            )

        # Encryption
        enc_vals = fields.get("encryption", [])
        result["encryption"] = normalize_encryption(enc_vals[0] if enc_vals else "")

        result["policy_score"] = pts

    except Exception as exc:
        result["policy_breakdown"].append(
            {"label": "security.txt exists", "earned": 0, "max": 5, "note": str(exc)}
        )

    return result


def _check_platform_listing(domain: str) -> dict:
    """
    Check if the domain has a public program on HackerOne or Bugcrowd.
    Returns platform info and a platform_score (0-20).
    """
    slug = domain.split(".")[0]
    bugcrowd_url = f"https://bugcrowd.com/engagements/{slug}"
    hackerone_url = f"https://hackerone.com/{slug}"

    result = {
        "platform_score": 0,
        "platform_score_max": 20,
        "hackerone": {"url": hackerone_url, "exists": False},
        "bugcrowd": {"url": bugcrowd_url, "exists": False},
        "platform_breakdown": [],
    }

    try:
        ho_resp = get(hackerone_url, timeout=10, allow_redirects=True)
        ho_exists = ho_resp.status_code == 200
        result["hackerone"]["exists"] = ho_exists
        result["hackerone"]["status_code"] = ho_resp.status_code
    except Exception:
        ho_exists = False
        result["hackerone"]["error"] = "Request failed"

    try:
        bc_resp = get(bugcrowd_url, timeout=10, allow_redirects=True)
        bc_exists = bc_resp.status_code == 200
        result["bugcrowd"]["exists"] = bc_exists
        result["bugcrowd"]["status_code"] = bc_resp.status_code
    except Exception:
        bc_exists = False
        result["bugcrowd"]["error"] = "Request failed"

    if ho_exists or bc_exists:
        result["platform_score"] = 20
        platforms = []
        if ho_exists:
            platforms.append("HackerOne")
        if bc_exists:
            platforms.append("Bugcrowd")
        result["platform_breakdown"].append(
            {"label": "Public platform listing", "earned": 20, "max": 20,
             "note": f"Listed on {', '.join(platforms)}"}
        )
    else:
        result["platform_breakdown"].append(
            {"label": "Public platform listing", "earned": 0, "max": 20,
             "note": "Not found on HackerOne or Bugcrowd (checked by domain root slug)"}
        )

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Existing routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/get_sec_txt/<domain>')
def get_security_txt_file(domain: str):
    score = 0
    sec_file = 'https://' + domain + '/.well-known/security.txt'
    req = get(url=sec_file)
    if req.status_code == 200:
        sendreq = req.text.lower()
        datas = dict()

        for dt in sendreq.splitlines():
            getdt = dt.lower()

            if getdt.startswith('contact:'):
                data = dt.split(':', maxsplit=1)
                if 'mailto:' in data[1].strip():
                    getmail = data[1].split(':')[1]
                else:
                    getmail = data[1]

                if getmail:
                    datas.update({'contact': getmail.strip()})
                    score += 5

            if getdt.startswith('expires:'):
                data = dt.split(':', maxsplit=1)
                date = data[1].split('t')[0].split('-')
                crt_date = date[-1] + '/' + date[1] + '/' + date[0].strip()
                time = datetime.strptime(
                    data[1].split('t')[1].split('.')[0],
                    "%H:%M:%S"
                )

                is_valid = data_time_validator(
                    data[1].split('t')[0],
                    time.strftime("%H:%M:%S")
                )

                if crt_date and time:
                    datas.update({
                        'expires': {
                            'date': crt_date,
                            'time': time.strftime("%I:%M:%S %p"),
                            'valid': 'yes' if is_valid else 'no'
                        }
                    })
                    score += 5

            if getdt.startswith('policy:'):
                data = dt.split(':', maxsplit=1)
                if data[1]:
                    datas.update({'policy': data[1].strip()})
                    score += 5

            if getdt.startswith('encryption:'):
                data = dt.split(':', maxsplit=1)
                if data[1]:
                    datas.update({'encryption': data[1].strip()})
                    score += 5

            if getdt.startswith('preferred-languages:'):
                data = dt.split(':', maxsplit=1)
                lang = data[1].strip()
                if lang:
                    datas.update({
                        'preferred-languages': 'English' if lang == 'en' else lang
                    })
                    score += 5

        datas.update({'score percentage': f'{int(score/5)}/5'})
        return datas


def check_public_program(pname: str):
    pname = (pname or "").strip()
    if not pname:
        return {"error": "Program name is required"}

    bugcrowd_url = f"https://bugcrowd.com/engagements/{pname}"
    hackerone_url = f"https://hackerone.com/{pname}"

    try:
        bugcrowd_resp = get(bugcrowd_url, timeout=10)
        hackerone_resp = get(hackerone_url, timeout=10)

        return {
            "program_name": pname,
            "bugcrowd": {
                "url": bugcrowd_url,
                "status_code": bugcrowd_resp.status_code,
                "exists": bugcrowd_resp.status_code == 200,
            },
            "hackerone": {
                "url": hackerone_url,
                "status_code": hackerone_resp.status_code,
                "exists": hackerone_resp.status_code == 200,
            },
        }
    except Exception as e:
        return {"error": str(e)}


@app.route('/check_for_pp/<pname>')
def public_program_route(pname: str):
    return jsonify(check_public_program(pname))


# ─────────────────────────────────────────────────────────────────────────────
# Composite score route
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/score/<path:domain>')
def composite_score(domain: str):
    policy = _parse_security_txt(domain)
    platform = _check_platform_listing(domain)

    scaffolded_signals = [
        {
            "id": "response_time",
            "label": "Response Time Consistency",
            "description": "Median & variance of time-to-first-response from disclosed report timestamps",
            "score": 0,
            "score_max": 20,
            "pending": True,
            "breakdown": [
                {"label": "Response time data", "earned": 0, "max": 20,
                 "note": "Awaiting disclosure history ingestion (batch job)"}
            ],
        },
        {
            "id": "dupe_rate",
            "label": "Dupe Rate",
            "description": "Share of disclosed reports marked as duplicates, weighted by program size",
            "score": 0,
            "score_max": 20,
            "pending": True,
            "breakdown": [
                {"label": "Dupe rate data", "earned": 0, "max": 20,
                 "note": "Awaiting disclosure history ingestion (batch job)"}
            ],
        },
        {
            "id": "severity_downgrade",
            "label": "Severity Downgrade Pattern",
            "description": "How often final payout severity lands below reporter-submitted CVSS",
            "score": 0,
            "score_max": 20,
            "pending": True,
            "breakdown": [
                {"label": "Severity data", "earned": 0, "max": 20,
                 "note": "Awaiting disclosure history ingestion (batch job)"}
            ],
        },
    ]

    composite = policy["policy_score"] + platform["platform_score"]
    grade = _letter_grade(composite)
    grade_color = _grade_color(grade)

    signals = [
        {
            "id": "policy_completeness",
            "label": "Policy Completeness",
            "description": "Presence and validity of security.txt fields per RFC 9116",
            "score": policy["policy_score"],
            "score_max": policy["policy_score_max"],
            "pending": False,
            "breakdown": policy["policy_breakdown"],
        },
        {
            "id": "platform_listing",
            "label": "Platform Listing",
            "description": "Program publicly listed on HackerOne or Bugcrowd",
            "score": platform["platform_score"],
            "score_max": platform["platform_score_max"],
            "pending": False,
            "breakdown": platform["platform_breakdown"],
        },
        *scaffolded_signals,
    ]

    return jsonify({
        "domain": domain,
        "composite_score": composite,
        "composite_score_max": 100,
        "grade": grade,
        "grade_color": grade_color,
        "scored_at": datetime.utcnow().isoformat() + "Z",
        "signals": signals,
        "security_txt": {
            "exists": policy["exists"],
            "url": policy["url"],
            "contact": policy["contact"],
            "expires": policy["expires"],
            "policy": policy["policy"],
            "encryption": policy["encryption"],
            "preferred_languages": policy["preferred_languages"],
            "raw_fields": policy["raw_fields"],
        },
        "platforms": {
            "hackerone": platform["hackerone"],
            "bugcrowd": platform["bugcrowd"],
        },
        "badge_url": f"/badge/{domain}.svg",
        "methodology_note": (
            "Signals 3-5 (Response Time, Dupe Rate, Severity Downgrade) are pending "
            "the background disclosure-history ingestion pipeline. Scores will update "
            "automatically once ingestion runs."
        ),
    })


@app.route('/badge/<path:domain>.svg')
def score_badge(domain: str):
    try:
        policy = _parse_security_txt(domain)
        platform = _check_platform_listing(domain)
        score = policy["policy_score"] + platform["platform_score"]
        grade = _letter_grade(score)
        color = _grade_color(grade)
    except Exception:
        score, grade, color = 0, "?", "#90a4ae"

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="160" height="28">
  <rect width="80" height="28" rx="4" fill="#0d1117"/>
  <rect x="80" width="80" height="28" rx="4" fill="{color}"/>
  <text x="40" y="19" font-family="DejaVu Sans,sans-serif" font-size="11"
        fill="#ffffff" text-anchor="middle">VDP Score</text>
  <text x="120" y="19" font-family="DejaVu Sans,sans-serif" font-size="12"
        font-weight="bold" fill="#0d1117" text-anchor="middle">{grade} · {score}/100</text>
</svg>"""

    return Response(svg, mimetype="image/svg+xml",
                    headers={"Cache-Control": "no-cache, max-age=3600"})


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=False)

