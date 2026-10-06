from app.grammar.membership import CFGMembershipChecker


class PhishingGrammarChecker:

    def __init__(self, grammars):
        self.grammars = grammars

    def check(self, grammar_name, tokens):

        grammar = self.grammars.get(grammar_name)

        if grammar is None:
            return False, None

        checker = CFGMembershipChecker(grammar)

        return checker.check(tokens)