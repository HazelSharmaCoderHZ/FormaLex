from app.lexer.dfa import URLDFA


dfa = URLDFA()


test_urls = [
    "https://example.com",
    "https://example.com/products",
    "https://example.com/login?user=1",
    "http://google.com",
    "https://paypa1.com/login",
    "https://192.168.1.10/login",

    # Invalid
    "ftp://example.com",
    "https://",
    "hello",
]


for url in test_urls:

    valid, states = dfa.process(url)

    print("=" * 70)
    print("URL:", url)
    print("VALID:", valid)
    print("STATE PATH:")
    print(" -> ".join(states))