class CFGMembershipChecker:

    def __init__(self, grammar):
        self.grammar = grammar

    def check(self, tokens):

        token_types = [
            token.type
            for token in tokens
        ]

        results = self._parse(
            "URL",
            token_types,
            0
        )

        for position, tree in results:

            if position == len(token_types):
                return True, tree

        return False, None

    def _parse(self, symbol, tokens, position):

        # ==========================================
        # TERMINAL
        # ==========================================

        if symbol not in self.grammar:

            if (
                position < len(tokens)
                and tokens[position] == symbol
            ):
                return [
                    (
                        position + 1,
                        {
                            "symbol": symbol,
                            "children": []
                        }
                    )
                ]

            return []

        # ==========================================
        # NON-TERMINAL
        # ==========================================

        results = []

        for production in self.grammar[symbol]:

            # ======================================
            # EPSILON
            # ======================================

            if len(production) == 0:

                results.append(
                    (
                        position,
                        {
                            "symbol": symbol,
                            "children": []
                        }
                    )
                )

                continue

            # ======================================
            # BUILD ALL POSSIBILITIES
            # ======================================

            states = [
                (position, [])
            ]

            for child in production:

                new_states = []

                for current_position, children in states:

                    child_results = self._parse(
                        child,
                        tokens,
                        current_position
                    )

                    for (
                        next_position,
                        child_tree
                    ) in child_results:

                        new_states.append(
                            (
                                next_position,
                                children + [child_tree]
                            )
                        )

                states = new_states

                if not states:
                    break

            # ======================================
            # STORE SUCCESSFUL PARSES
            # ======================================

            for current_position, children in states:

                results.append(
                    (
                        current_position,
                        {
                            "symbol": symbol,
                            "children": children
                        }
                    )
                )

        return results