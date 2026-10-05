import unicodedata

from .base import DetectionResult


def detect_homoglyph(host: str):

    scripts = set()

    for char in host:

        if char.isascii():
            if char.isalpha():
                scripts.add("LATIN")

        else:
            try:
                name = unicodedata.name(char)

                if "CYRILLIC" in name:
                    scripts.add("CYRILLIC")

                elif "GREEK" in name:
                    scripts.add("GREEK")

                else:
                    scripts.add("OTHER")

            except ValueError:
                scripts.add("OTHER")

    if len(scripts) > 1:

        return DetectionResult(
            detected=True,
            attack_type="HOMOGLYPH",
            rule="MIXED_SCRIPT",
            explanation="The host contains characters from multiple scripts."
        )

    return DetectionResult(
        detected=False,
        attack_type=None,
        rule=None,
        explanation=None
    )