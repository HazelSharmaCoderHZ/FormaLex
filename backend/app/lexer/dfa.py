from enum import Enum


class URLState(Enum):
    START = "START"
    H = "H"
    HT = "HT"
    HTT = "HTT"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    COLON = "COLON"
    SLASH_1 = "SLASH_1"
    HOST = "HOST"
    DOT = "DOT"
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

    def transition(self, state):
        self.state = state
        self.state_path.append(state.value)

    @staticmethod
    def is_letter(char):
        return char.isalpha()

    @staticmethod
    def is_digit(char):
        return char.isdigit()

    @staticmethod
    def is_host_char(char):
        return (
            char.isalnum()
            or char == "-"
        )

    def process(self, url):

        self.reset()

        if not url:
            self.transition(URLState.INVALID)
            return False, self.state_path

        i = 0
        n = len(url)

        # ==========================================
        # SCHEME
        # ==========================================

        if url.startswith("https://"):

            self.transition(URLState.H)
            self.transition(URLState.HT)
            self.transition(URLState.HTT)
            self.transition(URLState.HTTPS)

            i = 5

        elif url.startswith("http://"):

            self.transition(URLState.H)
            self.transition(URLState.HT)
            self.transition(URLState.HTT)
            self.transition(URLState.HTTP)

            i = 4

        else:
            self.transition(URLState.INVALID)
            return False, self.state_path

        # ==========================================
        # ://
        # ==========================================

        if url[i] != ":":
            self.transition(URLState.INVALID)
            return False, self.state_path

        self.transition(URLState.COLON)
        i += 1

        if i + 1 >= n or url[i:i + 2] != "//":
            self.transition(URLState.INVALID)
            return False, self.state_path

        self.transition(URLState.SLASH_1)
        self.transition(URLState.SLASH_1)

        i += 2

        # ==========================================
        # HOST
        # ==========================================

        if i >= n:
            self.transition(URLState.INVALID)
            return False, self.state_path

        host_started = False

        while i < n:

            char = url[i]

            if self.is_host_char(char):

                if not host_started:
                    self.transition(URLState.HOST)
                    host_started = True

                i += 1
                continue

            if char == ".":

                if not host_started:
                    self.transition(URLState.INVALID)
                    return False, self.state_path

                self.transition(URLState.DOT)

                host_started = False
                i += 1
                continue

            break

        if not host_started:
            self.transition(URLState.INVALID)
            return False, self.state_path

        # ==========================================
        # PORT
        # ==========================================

        if i < n and url[i] == ":":

            i += 1

            if i >= n or not self.is_digit(url[i]):
                self.transition(URLState.INVALID)
                return False, self.state_path

            while i < n and self.is_digit(url[i]):
                i += 1

        # ==========================================
        # PATH
        # ==========================================

        if i < n and url[i] == "/":

            self.transition(URLState.PATH)

            i += 1

            while i < n:

                if url[i] == "?":
                    break

                if url[i] == "#":
                    break

                i += 1

        # ==========================================
        # QUERY
        # ==========================================

        if i < n and url[i] == "?":

            self.transition(URLState.QUERY)

            i += 1

            while i < n and url[i] != "#":
                i += 1

        # ==========================================
        # FRAGMENT
        # ==========================================

        if i < n and url[i] == "#":

            self.transition(URLState.FRAGMENT)

            i += 1

            while i < n:
                i += 1

        # ==========================================
        # FINAL VALIDATION
        # ==========================================

        if i != n:

            self.transition(URLState.INVALID)
            return False, self.state_path

        return True, self.state_path