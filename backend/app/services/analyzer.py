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

from app.grammar.phishing import PHISHING_GRAMMARS
from app.grammar.phishing_membership import PhishingGrammarChecker


class URLAnalyzer:

    def __init__(self):

        # ==========================================
        # CORE COMPONENTS
        # ==========================================

        self.dfa = URLDFA()

        self.tokenizer = URLTokenizer()

        self.cfg_checker = CFGMembershipChecker(
            LEGITIMATE_GRAMMAR
        )

        self.phishing_checker = PhishingGrammarChecker(
            PHISHING_GRAMMARS
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
                "phishing_grammar_matches": [],
                "parse_tree": None,
                "explanation": (
                    "The URL does not follow "
                    "a valid URL structure."
                )
            }

        # ==========================================
        # 2. URL INFORMATION
        # ==========================================

        parsed = urlparse(url)

        try:

            host = parsed.hostname or ""

        except ValueError:

            host = ""

        path = parsed.path or ""

        # ==========================================
        # 3. INVALID NUMERIC IPv4 CHECK
        # ==========================================

        host_parts = host.split(".")

        if (
            len(host_parts) == 4
            and all(
                part.isdigit()
                for part in host_parts
            )
            and not all(
                0 <= int(part) <= 255
                for part in host_parts
            )
        ):

            return {
                "url": url,
                "verdict": "INVALID",
                "attack_type": "INVALID_IP",
                "rule": "INVALID_IPV4",
                "tokens": [],
                "state_path": state_path,
                "grammar_membership": False,
                "phishing_grammar_matches": [],
                "parse_tree": None,
                "explanation": (
                    "The URL contains an invalid "
                    "IPv4 address."
                )
            }

        # ==========================================
        # 4. TOKENIZATION
        # ==========================================

        tokens = self.tokenizer.tokenize(url)

        # ==========================================
        # 5. SECURITY TOKEN CLASSIFICATION
        # ==========================================

        for token in tokens:

            # --------------------------------------
            # Safety fallback
            # --------------------------------------

            if not hasattr(
                token,
                "security_flags"
            ):

                token.security_flags = []

            if token.security_flags is None:

                token.security_flags = []

            # --------------------------------------
            # Mixed-script detection
            # --------------------------------------

            if token.type in {
                "DOMAIN",
                "SUBDOMAIN",
                "TLD"
            }:

                scripts = (
                    self.tokenizer.detect_script(
                        token.value
                    )
                )

                if len(scripts) > 1:

                    if "MIXED_SCRIPT" not in (
                        token.security_flags
                    ):

                        token.security_flags.append(
                            "MIXED_SCRIPT"
                        )

        # ==========================================
        # 6. TOKEN JSON
        # ==========================================

        token_dict = [

            {
                "type": token.type,

                "value": token.value,

                "security_flags": (
                    token.security_flags
                    if token.security_flags
                    else []
                )
            }

            for token in tokens
        ]

        # ==========================================
        # 7. LEGITIMATE CFG MEMBERSHIP
        # ==========================================

        grammar_accepted, legitimate_tree = (
            self.cfg_checker.check(tokens)
        )

        # ==========================================
        # 8. PHISHING CFG MEMBERSHIP
        # ==========================================

        phishing_matches = []

        for grammar_name in PHISHING_GRAMMARS:

            accepted, phishing_tree = (
                self.phishing_checker.check(
                    grammar_name,
                    tokens
                )
            )

            if accepted:

                phishing_matches.append({

                    "type": grammar_name,

                    "parse_tree": phishing_tree
                })

        # ==========================================
        # 9. ALGORITHMIC PHISHING DETECTORS
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
        # 10. FINAL VERDICT
        # ==========================================

        # ------------------------------------------
        # Priority 1: Phishing CFG
        # ------------------------------------------

        if phishing_matches:

            match = phishing_matches[0]

            verdict = "SUSPICIOUS"

            attack_type = match["type"]

            rule = "PHISHING_CFG"

            explanation = (
                f"The URL matches the "
                f"{match['type']} "
                "phishing grammar."
            )

            parse_tree = match["parse_tree"]

        # ------------------------------------------
        # Priority 2: Algorithmic detector
        # ------------------------------------------

        elif detected:

            verdict = "SUSPICIOUS"

            attack_type = detected.attack_type

            rule = detected.rule

            explanation = detected.explanation

            parse_tree = legitimate_tree

        # ------------------------------------------
        # Priority 3: CFG rejection
        # ------------------------------------------

        elif not grammar_accepted:

            verdict = "SUSPICIOUS"

            attack_type = "GRAMMAR_VIOLATION"

            rule = "CFG_REJECT"

            explanation = (
                "The URL passed DFA validation "
                "but does not belong to the "
                "legitimate URL grammar."
            )

            parse_tree = legitimate_tree

        # ------------------------------------------
        # Priority 4: Legitimate
        # ------------------------------------------

        else:

            verdict = "LIKELY_LEGITIMATE"

            attack_type = None

            rule = "LEGITIMATE_URL"

            explanation = (
                "The URL was accepted by the "
                "DFA and legitimate URL grammar. "
                "No implemented phishing rule "
                "was triggered."
            )

            parse_tree = legitimate_tree

        # ==========================================
        # 11. FINAL RESPONSE
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

            "phishing_grammar_matches": (
                phishing_matches
            ),

            "explanation": explanation
        }