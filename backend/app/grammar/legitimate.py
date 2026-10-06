LEGITIMATE_GRAMMAR = {

    # ==========================================
    # URL
    # ==========================================

    "URL": [
        ["SCHEME", "SEPARATOR", "HOST", "TAIL"]
    ],

    # ==========================================
    # HOST
    # ==========================================

    "HOST": [

        # example.com
        ["DOMAIN", "DOT", "TLD"],

        # www.example.com
        # secure.login.example.com
        ["SUBDOMAINS", "DOMAIN", "DOT", "TLD"]
    ],

    # ==========================================
    # SUBDOMAINS
    # ==========================================

    "SUBDOMAINS": [

        # www.
        ["SUBDOMAIN", "DOT"],

        # secure.login.
        ["SUBDOMAIN", "DOT", "SUBDOMAINS"]
    ],

    # ==========================================
    # OPTIONAL URL COMPONENTS
    # ==========================================

    "TAIL": [

        # Nothing after host
        [],

        # /path
        ["PATH", "TAIL_AFTER_PATH"],

        # ?query
        ["QUERY", "TAIL_AFTER_QUERY"],

        # #fragment
        ["FRAGMENT"]
    ],

    # ==========================================
    # AFTER PATH
    # ==========================================

    "TAIL_AFTER_PATH": [

        [],

        ["QUERY", "TAIL_AFTER_QUERY"],

        ["FRAGMENT"]
    ],

    # ==========================================
    # AFTER QUERY
    # ==========================================

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

    # ==========================================
    # PATH SEGMENTS
    # ==========================================

    "SEGMENTS": [

        # /products
        ["PATH_SEGMENT"],

        # /products/item/details
        [
            "PATH_SEGMENT",
            "PATH_SEPARATOR",
            "SEGMENTS"
        ]
    ]
}