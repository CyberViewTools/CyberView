"""Static server for the tests that sends the same headers Netlify does (read from netlify.toml),
so a Content Security Policy violation shows up in the browser tests instead of only in production.
Usage: python3 tests/serve.py PORT   (serves the current directory)"""
import functools, http.server, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def site_headers():
    toml = open(os.path.join(ROOT, "netlify.toml")).read()
    out = {}
    for block in re.split(r"\[\[headers\]\]", toml)[1:]:
        m = re.search(r'for\s*=\s*"([^"]+)"', block)
        if not m or m.group(1) != "/*":
            continue
        for k, v in re.findall(r'^\s*([A-Za-z-]+)\s*=\s*"([^"]*)"\s*$', block, re.M):
            if k != "for":
                out[k] = v
    return out


class Handler(http.server.SimpleHTTPRequestHandler):
    HEADERS = site_headers()

    def end_headers(self):
        for k, v in self.HEADERS.items():
            self.send_header(k, v)
        super().end_headers()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1])
    http.server.ThreadingHTTPServer(("127.0.0.1", port), functools.partial(Handler, directory=os.getcwd())).serve_forever()
