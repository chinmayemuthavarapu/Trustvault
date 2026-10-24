"""Password hashing (scrypt, from the standard library) and password policy."""
import base64
import hashlib
import hmac
import secrets

_N, _R, _P = 2 ** 15, 8, 1
_MAXMEM = 64 * 1024 * 1024

# A short deny-list; the length rule does most of the work.
_COMMON = {
    "password", "password123", "passw0rd", "123456789012", "qwertyuiop", "letmein123",
    "trustvault", "trustvault123", "administrator", "welcome12345", "changeme1234",
}


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=_MAXMEM, dklen=32)
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p),
                                maxmem=_MAXMEM, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


# Used when the username does not exist, so a failed login costs the same time
# either way and response timing does not reveal which usernames are real.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def password_problems(password: str, username: str) -> list[str]:
    problems = []
    if not isinstance(password, str) or len(password) < 12:
        problems.append("Use at least 12 characters.")
    elif len(password) > 256:
        problems.append("Use at most 256 characters.")
    else:
        lowered = password.lower()
        if lowered in _COMMON:
            problems.append("That password is too common.")
        if username and username.lower() in lowered:
            problems.append("The password must not contain your username.")
    return problems
