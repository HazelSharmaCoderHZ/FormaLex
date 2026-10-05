class ParseTree:

    def __init__(self, symbol, children=None):
        self.symbol = symbol
        self.children = children or []

    def to_dict(self):

        return {
            "symbol": self.symbol,
            "children": [
                child.to_dict()
                for child in self.children
            ]
        }


class GrammarParser:

    def build_tree(self, tokens):

        root = ParseTree("URL")

        scheme = next(
            (t for t in tokens if t.type == "SCHEME"),
            None
        )

        host_tokens = [
            t for t in tokens
            if t.type in {
                "SUBDOMAIN",
                "DOMAIN",
                "TLD",
                "IP_ADDRESS"
            }
        ]

        path_tokens = [
            t for t in tokens
            if t.type in {
                "PATH_SEPARATOR",
                "PATH_SEGMENT"
            }
        ]

        if scheme:
            root.children.append(
                ParseTree(
                    "SCHEME",
                    [ParseTree(scheme.type)]
                )
            )

        host_node = ParseTree("HOST")

        for token in host_tokens:
            host_node.children.append(
                ParseTree(
                    token.type,
                    [ParseTree(token.value)]
                )
            )

        root.children.append(host_node)

        if path_tokens:

            path_node = ParseTree("PATH")

            for token in path_tokens:
                path_node.children.append(
                    ParseTree(
                        token.type,
                        [ParseTree(token.value)]
                    )
                )

            root.children.append(path_node)

        return root