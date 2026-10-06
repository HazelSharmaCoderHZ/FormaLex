PHISHING_GRAMMARS = {

    # ==========================================
    # IP AS DOMAIN
    # ==========================================

    "IP_AS_DOMAIN": {

        "URL": [
            ["SCHEME", "SEPARATOR", "IP_ADDRESS", "TAIL"]
        ],

        "TAIL": [
            [],
            ["PATH", "TAIL_AFTER_PATH"],
            ["QUERY"],
            ["FRAGMENT"]
        ],

        "PATH": [
            ["PATH_SEPARATOR", "SEGMENTS"]
        ],

        "SEGMENTS": [
            ["PATH_SEGMENT"],
            ["PATH_SEGMENT", "PATH_SEPARATOR", "SEGMENTS"]
        ],

        "TAIL_AFTER_PATH": [
            [],
            ["QUERY"],
            ["FRAGMENT"]
        ]
    },

    # ==========================================
    # EXCESSIVE SUBDOMAINS
    # ==========================================

    "EXCESSIVE_SUBDOMAINS": {

        "URL": [
            [
                "SCHEME",
                "SEPARATOR",
                "SUBDOMAIN",
                "DOT",
                "SUBDOMAIN",
                "DOT",
                "SUBDOMAIN",
                "DOT",
                "DOMAIN",
                "DOT",
                "TLD"
            ]
        ]
    },

    # ==========================================
    # SUSPICIOUS LOGIN STRUCTURE
    # ==========================================
    
    # IMPORTANT:
    # This grammar is intentionally NOT based on
    # arbitrary PATH_SEGMENT anymore.
    #
    # Login detection remains handled by the
    # lexical LOGIN_PATTERN detector.
}