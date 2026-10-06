import requests


BASE_URL = "http://127.0.0.1:8000/analyze"


TEST_URLS = [
    "https://www.google.com",
    "https://secure.login.google.com/account",
    "https://example.com/a/b/c",
    "https://example.com/login?user=123",
    "ftp://example.com",
    "https://",
    "hello",
    "https://999.999.999.999/login",
    "https://pay-pal.com",
    "https://g00g1e.com/login",
    # Legitimate
    "https://example.com",
    "https://google.com",
    "https://amazon.com/products",
    "https://microsoft.com/account",

    # Typosquatting
    "https://paypa1.com",
    "https://g00gle.com",
    "https://micros0ft.com",

    # IP
    "https://192.168.1.10/login",
    "http://10.0.0.1/account",

    # Excessive subdomains
    "https://login.secure.account.example.com",

    # Suspicious login
    "https://secure-login-account.example.com/verify"
]


for url in TEST_URLS:

    response = requests.post(
        BASE_URL,
        json={"url": url}
    )

    result = response.json()

    print("=" * 70)
    print("URL:", url)
    print("VERDICT:", result["verdict"])
    print("ATTACK:", result["attack_type"])
    print("RULE:", result["rule"])
    print("EXPLANATION:", result["explanation"])