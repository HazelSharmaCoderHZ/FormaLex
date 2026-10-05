from .base import DetectionResult


def detect_ip_domain(host: str):

    parts = host.split(".")

    if len(parts) != 4:
        return DetectionResult(
            detected=False,
            attack_type=None,
            rule=None,
            explanation=None
        )

    try:
        valid = all(
            0 <= int(part) <= 255
            for part in parts
        )
    except ValueError:
        valid = False

    if valid:
        return DetectionResult(
            detected=True,
            attack_type="IP_AS_DOMAIN",
            rule="IP_HOST",
            explanation="The host is an IPv4 address instead of a normal domain."
        )

    return DetectionResult(
        detected=False,
        attack_type=None,
        rule=None,
        explanation=None
    )