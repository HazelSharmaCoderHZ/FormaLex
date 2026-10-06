import re
import unicodedata

from urllib.parse import urlparse
from dataclasses import dataclass


@dataclass
class Token:
    type: str
    value: str
    security_flags: list = None

    def __post_init__(self):

        if self.security_flags is None:
            self.security_flags = []


class URLTokenizer:

    def tokenize(self, url: str):

        tokens = []

        parsed = urlparse(url)

        # ==========================================
        # SCHEME
        # ==========================================

        if parsed.scheme:

            tokens.append(
                Token(
                    "SCHEME",
                    parsed.scheme
                )
            )

        # ==========================================
        # SEPARATOR
        # ==========================================

        if "://" in url:

            tokens.append(
                Token(
                    "SEPARATOR",
                    "://"
                )
            )

        # ==========================================
        # HOST
        # ==========================================

        try:

            host = parsed.hostname or ""

        except ValueError:

            host = ""

        # ==========================================
        # IP ADDRESS
        # ==========================================

        if self.is_ipv4(host):

            tokens.append(
                Token(
                    "IP_ADDRESS",
                    host
                )
            )

        else:

            host_parts = host.split(".")

            # --------------------------------------
            # SUBDOMAINS
            # --------------------------------------

            if len(host_parts) > 2:

                for part in host_parts[:-2]:

                    tokens.append(
                        Token(
                            "SUBDOMAIN",
                            part
                        )
                    )

                    tokens.append(
                        Token(
                            "DOT",
                            "."
                        )
                    )

            # --------------------------------------
            # DOMAIN + TLD
            # --------------------------------------

            if len(host_parts) >= 2:

                tokens.append(
                    Token(
                        "DOMAIN",
                        host_parts[-2]
                    )
                )

                tokens.append(
                    Token(
                        "DOT",
                        "."
                    )
                )

                tokens.append(
                    Token(
                        "TLD",
                        host_parts[-1]
                    )
                )

            # --------------------------------------
            # SINGLE HOST LABEL
            # --------------------------------------

            elif host_parts and host_parts[0]:

                tokens.append(
                    Token(
                        "DOMAIN",
                        host_parts[0]
                    )
                )

        # ==========================================
        # PORT
        # ==========================================

        try:

            port = parsed.port

        except ValueError:

            port = None

        if port:

            tokens.append(
                Token(
                    "PORT",
                    str(port)
                )
            )

        # ==========================================
        # PATH
        # ==========================================

        if parsed.path:

            path_parts = parsed.path.strip("/").split("/")

            for part in path_parts:

                if not part:
                    continue

                # Every path component has its
                # own separator.

                tokens.append(
                    Token(
                        "PATH_SEPARATOR",
                        "/"
                    )
                )

                tokens.append(
                    Token(
                        "PATH_SEGMENT",
                        part
                    )
                )

        # ==========================================
        # QUERY
        # ==========================================

        if parsed.query:

            tokens.append(
                Token(
                    "QUERY",
                    parsed.query
                )
            )

        # ==========================================
        # FRAGMENT
        # ==========================================

        if parsed.fragment:

            tokens.append(
                Token(
                    "FRAGMENT",
                    parsed.fragment
                )
            )

        return tokens

    # ==============================================
    # IPv4 VALIDATION
    # ==============================================

    @staticmethod
    def is_ipv4(host):

        pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

        if not re.match(pattern, host):

            return False

        parts = host.split(".")

        return all(
            0 <= int(part) <= 255
            for part in parts
        )

    # ==============================================
    # SCRIPT DETECTION
    # ==============================================

    @staticmethod
    def detect_script(value):

        scripts = set()

        for char in value:

            # --------------------------------------
            # ASCII / LATIN
            # --------------------------------------

            if char.isascii() and char.isalpha():

                scripts.add("LATIN")

            # --------------------------------------
            # NON-ASCII
            # --------------------------------------

            elif not char.isascii():

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

        return scripts