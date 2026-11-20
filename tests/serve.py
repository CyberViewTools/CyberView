"""Static server for the tests. GitHub Pages sends no custom headers, so neither does this: the
Content-Security-Policy is a meta tag in every page (checked by scripts/security-check.mjs) and the browser
tests see exactly what visitors get.
Usage: python3 tests/serve.py PORT   (serves the current directory)"""
import functools, http.server, os, sys


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1])
    http.server.ThreadingHTTPServer(("127.0.0.1", port), functools.partial(Handler, directory=os.getcwd())).serve_forever()
