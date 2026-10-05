from urllib.parse import urlparse

from app.lexer.dfa import URLDFA
from app.lexer.tokenizer import URLTokenizer

from app.detectors.ip_domain import detect_ip_domain
from app.detectors.typosquatting import detect_typosquatting
from app.detectors.homoglyph import detect_homoglyph
from app.detectors.subdomain import detect_excessive_subdomains
from app.detectors.login_pattern import detect_login_pattern

from app.grammar.legitimate import LEGITIMATE_GRAMMAR
from app.grammar.membership import CFGMembershipChecker


class URLAnalyzer:

    def __init__(self):

        self.dfa = URLDFA()

        self.tokenizer = URLTokenizer()

        self.cfg_checker = CFGMembershipChecker(
            LEGITIMATE_GRAMMAR
        )

    def analyze(self, url: str):

        # ==========================================
        # 1. DFA VALIDATION
        # ==========================================

        valid, state_path = self.dfa.process(url)

        if not valid:

            return {
                "url": url,
                "verdict": "INVALID",
                "attack_type": None,
                "rule": "DFA_REJECT",
                "tokens": [],
                "state_path": state_path,
                "grammar_membership": False,
                "parse_tree": None,
                "explanation": "The URL does not follow a valid URL structure."
            }

        # ==========================================
        # 2. TOKENIZATION
        # ==========================================

        tokens = self.tokenizer.tokenize(url)

        token_dict = [
            {
                "type": token.type,
                "value": token.value
            }
            for token in tokens
        ]

        # ==========================================
        # 3. CFG MEMBERSHIP
        # ==========================================

        grammar_accepted, parse_tree = (
            self.cfg_checker.check(tokens)
        )

        # ==========================================
        # 4. URL INFORMATION
        # ==========================================

        parsed = urlparse(url)

        host = parsed.hostname or ""

        path = parsed.path or ""

        # ==========================================
        # 5. PHISHING DETECTORS
        # ==========================================

        detectors = [

            detect_ip_domain(host),

            detect_typosquatting(host),

            detect_homoglyph(host),

            detect_excessive_subdomains(host),

            detect_login_pattern(
                host,
                path
            )
        ]

        detected = next(
            (
                result
                for result in detectors
                if result.detected
            ),
            None
        )

        # ==========================================
        # 6. FINAL VERDICT
        # ==========================================

        if detected:

            verdict = "SUSPICIOUS"

            attack_type = detected.attack_type

            rule = detected.rule

            explanation = detected.explanation

        elif not grammar_accepted:

            verdict = "SUSPICIOUS"

            attack_type = "GRAMMAR_VIOLATION"

            rule = "CFG_REJECT"

            explanation = (
                "The URL passed lexical validation but "
                "does not belong to the legitimate URL grammar."
            )

        else:

            verdict = "LIKELY_LEGITIMATE"

            attack_type = None

            rule = "LEGITIMATE_URL"

            explanation = (
                "The URL was accepted by the DFA and "
                "belongs to the legitimate URL grammar. "
                "No implemented phishing rule was triggered."
            )

        # ==========================================
        # 7. RETURN RESULT
        # ==========================================

        return {

            "url": url,

            "verdict": verdict,

            "attack_type": attack_type,

            "rule": rule,

            "tokens": token_dict,

            "state_path": state_path,

            "grammar_membership": grammar_accepted,

            "parse_tree": parse_tree,

            "explanation": explanation
        }