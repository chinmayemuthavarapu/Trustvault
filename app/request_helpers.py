"""Request helpers shared by the routes."""
from flask import abort, request


def json_body(allowed: set[str], required: set[str] = frozenset()) -> dict:
    """Parse a JSON object and reject unknown fields (no mass assignment:
    a client cannot sneak in owner_id, role, permission, etc.)."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400, description="Expected a JSON object.")
    unknown = set(data) - allowed
    if unknown:
        abort(400, description=f"Unknown field(s): {', '.join(sorted(unknown))}.")
    missing = {f for f in required if data.get(f) in (None, "")}
    if missing:
        abort(400, description=f"Missing field(s): {', '.join(sorted(missing))}.")
    return data


def int_arg(name: str, default: int, lo: int, hi: int) -> int:
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        abort(400, description=f"{name} must be a number.")
    return max(lo, min(hi, value))
