LEGITIMATE_GRAMMAR = {

    "URL": [
        ["SCHEME", "SEPARATOR", "HOST", "TAIL"]
    ],

    # Host without subdomain
    "HOST": [
        ["DOMAIN", "DOT", "TLD"],

        # One or more subdomains
        ["SUBDOMAINS", "DOMAIN", "DOT", "TLD"]
    ],

    # One or more:
    #
    # www
    #
    # www.google
    #
    # secure.login.google
    #
    "SUBDOMAINS": [
        ["SUBDOMAIN", "DOT"],
        ["SUBDOMAIN", "DOT", "SUBDOMAINS"]
    ],

    # ==========================================
    # OPTIONAL URL COMPONENTS
    # ==========================================

    "TAIL": [
        [],
        ["PATH", "TAIL_AFTER_PATH"],
        ["QUERY", "TAIL_AFTER_QUERY"],
        ["FRAGMENT"]
    ],

    "TAIL_AFTER_PATH": [
        [],
        ["QUERY", "TAIL_AFTER_QUERY"],
        ["FRAGMENT"]
    ],

    "TAIL_AFTER_QUERY": [
        [],
        ["FRAGMENT"]
    ],

    # ==========================================
    # PATH
    # ==========================================

    "PATH": [
        ["PATH_SEPARATOR", "SEGMENTS"]
    ],

    "SEGMENTS": [
        ["PATH_SEGMENT"],
        ["PATH_SEGMENT", "PATH_SEPARATOR", "SEGMENTS"]
    ]
}