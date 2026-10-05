from .base import DetectionResult


LOGIN_WORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "confirm",
    "password",
]


def detect_login_pattern(host: str, path: str):

    combined = f"{host}{path}".lower()

    found = [
        word
        for word in LOGIN_WORDS
        if word in combined
    ]

    if len(found) >= 2:

        return DetectionResult(
            detected=True,
            attack_type="SUSPICIOUS_LOGIN_STRUCTURE",
            rule="LOGIN_PATTERN",
            explanation=(
                "The URL contains multiple account or authentication-related "
                f"keywords: {', '.join(found)}."
            )
        )

    return DetectionResult(
        detected=False,
        attack_type=None,
        rule=None,
        explanation=None
    )