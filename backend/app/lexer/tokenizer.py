import re
from urllib.parse import urlparse
from dataclasses import dataclass


@dataclass
class Token:
    type: str
    value: str


class URLTokenizer:

    def tokenize(self, url: str):

        tokens = []

        parsed = urlparse(url)

        # Scheme
        if parsed.scheme:
            tokens.append(Token("SCHEME", parsed.scheme))

        # Separator
        if "://" in url:
            tokens.append(Token("SEPARATOR", "://"))

        # Host
        try:
            host = parsed.hostname or ""
        except ValueError:
            host = ""

        # IP detection
        if self.is_ipv4(host):
            tokens.append(Token("IP_ADDRESS", host))

        else:
            host_parts = host.split(".")

            if len(host_parts) > 2:
                for part in host_parts[:-2]:
                    tokens.append(Token("SUBDOMAIN", part))
                    tokens.append(Token("DOT", "."))

            if len(host_parts) >= 2:
                tokens.append(Token("DOMAIN", host_parts[-2]))
                tokens.append(Token("DOT", "."))
                tokens.append(Token("TLD", host_parts[-1]))

            elif host_parts and host_parts[0]:
                tokens.append(Token("DOMAIN", host_parts[0]))

        # Port
        try:
            port = parsed.port
        except ValueError:
            port = None

        if port:
            tokens.append(Token("PORT", str(port)))

        # Path
        if parsed.path:
            tokens.append(Token("PATH_SEPARATOR", "/"))

            for part in parsed.path.strip("/").split("/"):
                if part:
                    tokens.append(Token("PATH_SEGMENT", part))

        # Query
        if parsed.query:
            tokens.append(Token("QUERY", parsed.query))

        # Fragment
        if parsed.fragment:
            tokens.append(Token("FRAGMENT", parsed.fragment))

        return tokens

    @staticmethod
    def is_ipv4(host):

        pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

        if not re.match(pattern, host):
            return False

        return all(
            0 <= int(part) <= 255
            for part in host.split(".")
        )