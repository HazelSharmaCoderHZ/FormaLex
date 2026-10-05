LEGITIMATE_GRAMMAR = {

    "URL": [
        ["SCHEME", "HOST", "PATH"]
    ],

    "SCHEME": [
        ["HTTPS"],
        ["HTTP"]
    ],

    "HOST": [
        ["DOMAIN", "TLD"],
        ["SUBDOMAIN", "DOMAIN", "TLD"]
    ],

    "PATH": [
        [],
        ["PATH_SEPARATOR", "SEGMENTS"]
    ],

    "SEGMENTS": [
        ["PATH_SEGMENT"],
        ["SEGMENTS", "PATH_SEPARATOR", "PATH_SEGMENT"]
    ]
}