"""
Allow ``python -m burp2har`` to invoke the CLI.

    python -m burp2har --help
    python -m burp2har convert export.xml
"""
from burp2har.cli import run

if __name__ == "__main__":
    run()
