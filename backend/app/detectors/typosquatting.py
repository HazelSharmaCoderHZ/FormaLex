from .base import DetectionResult


PROTECTED_BRANDS = [
    "google",
    "paypal",
    "microsoft",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
]


DIGIT_SUBSTITUTIONS = {
    "0": ["o"],
    "1": ["i", "l"],
    "3": ["e"],
    "4": ["a"],
    "5": ["s"],
    "7": ["t"],
    "8": ["b"],
}


def levenshtein_distance(a, b):

    if len(a) < len(b):
        a, b = b, a

    previous = list(range(len(b) + 1))

    for i, char_a in enumerate(a, 1):

        current = [i]

        for j, char_b in enumerate(b, 1):

            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (char_a != char_b)

            current.append(min(insert, delete, replace))

        previous = current

    return previous[-1]


def normalize_leetspeak(value):

    result = ""

    for char in value:

        if char in DIGIT_SUBSTITUTIONS:
            result += DIGIT_SUBSTITUTIONS[char][0]
        else:
            result += char

    return result


def detect_typosquatting(host: str):

    host_parts = host.lower().split(".")

    for part in host_parts:

        for brand in PROTECTED_BRANDS:

            if part == brand:
                continue

            # Direct character similarity
            distance = levenshtein_distance(part, brand)

            # Leetspeak similarity
            normalized = normalize_leetspeak(part)

            normalized_distance = levenshtein_distance(
                normalized,
                brand
            )

            if distance == 1 or normalized_distance == 0:

                return DetectionResult(
                    detected=True,
                    attack_type="TYPOSQUATTING",
                    rule="MODIFIED_BRAND",
                    explanation=(
                        f"The domain '{part}' is very similar to "
                        f"the protected brand '{brand}'."
                    )
                )

    return DetectionResult(
        detected=False,
        attack_type=None,
        rule=None,
        explanation=None
    )