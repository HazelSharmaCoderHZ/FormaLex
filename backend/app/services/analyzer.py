from urllib.parse import urlparse

from app.lexer.dfa import URLDFA
from app.lexer.tokenizer import URLTokenizer

from app.detectors.ip_domain import detect_ip_domain
from app.detectors.typosquatting import detect_typosquatting
from app.detectors.homoglyph import detect_homoglyph
from app.detectors.subdomain import detect_excessive_subdomains
from app.detectors.login_pattern import detect_login_pattern

from app.grammar.parser import GrammarParser


class URLAnalyzer:

    def __init__(self):
        self.dfa = URLDFA()
        self.tokenizer = URLTokenizer()
        self.parser = GrammarParser()

    def analyze(self, url: str):

        # -------------------------
        # 1. DFA VALIDATION
        # -------------------------

        valid, state_path = self.dfa.process(url)

        if not valid:
            return {
                "url": url,
                "verdict": "INVALID",
                "attack_type": None,
                "rule": None,
                "tokens": [],
                "state_path": state_path,
                "parse_tree": None,
                "explanation": "Invalid URL structure."
            }

        # -------------------------
        # 2. TOKENIZATION
        # -------------------------

        tokens = self.tokenizer.tokenize(url)

        token_dict = [
            {
                "type": token.type,
                "value": token.value
            }
            for token in tokens
        ]

        # -------------------------
        # 3. URL COMPONENTS
        # -------------------------

        parsed = urlparse(url)

        host = parsed.hostname or ""
        path = parsed.path or ""

        # -------------------------
        # 4. PHISHING DETECTORS
        # -------------------------

        detectors = [

            detect_ip_domain(host),

            detect_typosquatting(host),

            detect_homoglyph(host),

            detect_excessive_subdomains(host),

            detect_login_pattern(host, path)

        ]

        detected = next(
            (
                result
                for result in detectors
                if result.detected
            ),
            None
        )

        # -------------------------
        # 5. PARSE TREE
        # -------------------------

        parse_tree = self.parser.build_tree(tokens)

        # -------------------------
        # 6. FINAL VERDICT
        # -------------------------

        if detected:

            verdict = "SUSPICIOUS"

            attack_type = detected.attack_type
            rule = detected.rule
            explanation = detected.explanation

        else:

            verdict = "LIKELY_LEGITIMATE"

            attack_type = None
            rule = "LEGITIMATE_URL"

            explanation = (
                "The URL matches the expected legitimate URL structure "
                "and no implemented phishing rule was triggered."
            )

        return {
            "url": url,
            "verdict": verdict,
            "attack_type": attack_type,
            "rule": rule,
            "tokens": token_dict,
            "state_path": state_path,
            "parse_tree": parse_tree.to_dict(),
            "explanation": explanation
        }