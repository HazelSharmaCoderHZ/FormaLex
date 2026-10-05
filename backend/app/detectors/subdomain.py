from .base import DetectionResult


def detect_excessive_subdomains(host: str):

    parts = host.split(".")

    subdomain_count = max(0, len(parts) - 2)

    if subdomain_count >= 3:

        return DetectionResult(
            detected=True,
            attack_type="EXCESSIVE_SUBDOMAINS",
            rule="SUBDOMAIN_COUNT",
            explanation=(
                f"The URL contains {subdomain_count} subdomain levels."
            )
        )

    return DetectionResult(
        detected=False,
        attack_type=None,
        rule=None,
        explanation=None
    )