from .base import DetectionResult


# ==============================================
# REFERENCE BRANDS
# ==============================================

PROTECTED_BRANDS = [
    "google",
    "paypal",
    "microsoft",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
    "example",
]


# ==============================================
# LEETSPEAK
# ==============================================

DIGIT_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
}


# ==============================================
# LEVENSHTEIN DISTANCE
# ==============================================

def levenshtein_distance(a, b):

    if len(a) < len(b):

        a, b = b, a

    previous = list(
        range(len(b) + 1)
    )

    for i, char_a in enumerate(a, 1):

        current = [i]

        for j, char_b in enumerate(b, 1):

            insert = (
                current[j - 1] + 1
            )

            delete = (
                previous[j] + 1
            )

            replace = (
                previous[j - 1]
                + (char_a != char_b)
            )

            current.append(
                min(
                    insert,
                    delete,
                    replace
                )
            )

        previous = current

    return previous[-1]


# ==============================================
# LEETSPEAK NORMALIZATION
# ==============================================

def normalize_leetspeak(value):

    result = ""

    for char in value.lower():

        if char in DIGIT_SUBSTITUTIONS:

            result += DIGIT_SUBSTITUTIONS[
                char
            ]

        else:

            result += char

    return result


# ==============================================
# TYPOSQUATTING DETECTOR
# ==============================================

def detect_typosquatting(host: str):

    host_parts = host.lower().split(".")

    for part in host_parts:

        for brand in PROTECTED_BRANDS:

            # Exact match is legitimate
            # with respect to this detector.

            if part == brand:

                continue

            # ----------------------------------
            # Direct edit distance
            # ----------------------------------

            distance = levenshtein_distance(
                part,
                brand
            )

            # ----------------------------------
            # Leetspeak normalization
            # ----------------------------------

            normalized = normalize_leetspeak(
                part
            )

            normalized_distance = (
                levenshtein_distance(
                    normalized,
                    brand
                )
            )

            # ----------------------------------
            # Detection
            # ----------------------------------

            if (
                distance <= 1
                or normalized_distance == 0
            ):

                return DetectionResult(

                    True,

                    "TYPOSQUATTING",

                    "MODIFIED_BRAND",

                    (
                        f"The domain '{part}' "
                        f"is very similar to "
                        f"the protected brand "
                        f"'{brand}'."
                    )
                )

    return DetectionResult(
        False,
        None,
        None,
        None
    )