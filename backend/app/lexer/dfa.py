from enum import Enum


class URLState(Enum):
    START = "START"
    SCHEME = "SCHEME"
    AFTER_SCHEME = "AFTER_SCHEME"
    HOST = "HOST"
    SUBDOMAIN = "SUBDOMAIN"
    DOMAIN = "DOMAIN"
    TLD = "TLD"
    PATH = "PATH"
    QUERY = "QUERY"
    FRAGMENT = "FRAGMENT"
    INVALID = "INVALID"


class URLDFA:
    def __init__(self):
        self.state = URLState.START
        self.state_path = [self.state.value]

    def reset(self):
        self.state = URLState.START
        self.state_path = [self.state.value]

    def transition(self, new_state):
        self.state = new_state
        self.state_path.append(new_state.value)

    def process(self, url: str):
        self.reset()

        if not url:
            self.transition(URLState.INVALID)
            return False, self.state_path

        # Scheme
        if url.startswith("https://"):
            self.transition(URLState.SCHEME)
            self.transition(URLState.AFTER_SCHEME)
            host_start = 8

        elif url.startswith("http://"):
            self.transition(URLState.SCHEME)
            self.transition(URLState.AFTER_SCHEME)
            host_start = 7

        else:
            self.transition(URLState.INVALID)
            return False, self.state_path

        remaining = url[host_start:]

        if not remaining:
            self.transition(URLState.INVALID)
            return False, self.state_path

        # Host
        self.transition(URLState.HOST)

        host = remaining.split("/")[0].split("?")[0].split("#")[0]

        if "." in host:
            parts = host.split(".")

            if len(parts) >= 3:
                self.transition(URLState.SUBDOMAIN)

            self.transition(URLState.DOMAIN)
            self.transition(URLState.TLD)
        else:
            self.transition(URLState.DOMAIN)

        # Path
        if "/" in remaining:
            self.transition(URLState.PATH)

        # Query
        if "?" in remaining:
            self.transition(URLState.QUERY)

        # Fragment
        if "#" in remaining:
            self.transition(URLState.FRAGMENT)

        return True, self.state_path