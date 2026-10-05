from app.lexer.tokenizer import URLTokenizer
from app.grammar.legitimate import LEGITIMATE_GRAMMAR
from app.grammar.membership import CFGMembershipChecker


tokenizer = URLTokenizer()

checker = CFGMembershipChecker(
    LEGITIMATE_GRAMMAR
)


urls = [
    "https://example.com",
    "https://example.com/products",
    "https://example.com/login",
    "https://google.com",
    "https://www.google.com",
    "https://secure.login.google.com/account",
]


for url in urls:

    tokens = tokenizer.tokenize(url)

    accepted, parse_tree = checker.check(tokens)

    print("=" * 70)

    print("URL:", url)

    print(
        "TOKENS:",
        [token.type for token in tokens]
    )

    print(
        "GRAMMAR MEMBERSHIP:",
        "ACCEPTED" if accepted else "REJECTED"
    )

    print(
        "PARSE TREE:",
        parse_tree
    )