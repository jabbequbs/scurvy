#!/usr/bin/env python3

import argparse
import base64
import hashlib
import importlib
import json
import logging
import mimetypes
import os
import re
import shlex
import ssl
import subprocess
import sys

from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler, make_server, demo_app
from wsgiref.util import shift_path_info

response_codes = {k:"%s %s" % (int(k), v[0]) for k,v in BaseHTTPRequestHandler.responses.items()}
mimetypes.types_map[".js"] = "application/javascript"

contents_page = """\
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Folder contents</title>
  <style type="text/css">
    * { font-family: Verdana, sans-serif; line-height: 1.3; }
    table { border-collapse: collapse; width: 100%%; border: 1px solid silver; }
    td { padding: 8px; border-top: 1px solid silver; border-bottom: 1px solid silver; }
    td:nth-child(2) { width: 100%%; }
    td:nth-child(3) { text-align: right; }
    img { height: 1.3em; }
    div { text-align: center; font-size: x-small; }
  </style>
</head>
<body>
  <h3></h3>
  <table>
    <tr>
      <td><img id="folder" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA\
ADAAAAAwCAYAAABXAvmHAAAABmJLR0QA/wD/AP+gvaeTAAABPElEQVRoge2YMUoDQRRA38xsETYbBR\
USJI14AIsUOYKFl9BjpFJP4BG0sBLBxkb0EhaCiL0gKBgQU4SMRax2VphdZP6C/5V/luG95W+zoCiK\
ovxnTNXQnzNkzgmwC/SibvIcmwOO/k4tjiDgR/4eWKt9m0CEDSbLN19fHsBw6E+lA5Zr05zEEeEKne\
HJMhj0oeiCrWpMiF94vmYvfM72zd7rbfk4tMsy2N6ClZ68PICxhjzfZH31xl9vjMrHoeGgD84lcauF\
dYYivwrGwYNFN4lPIzqdYXkUBrRhbX7D2uCbbbFtHBogjQZIowHSaIA0GiCNBkijAdJogDQaIE1VwD\
S5RTwf5UFVwF0CkWZ4In5seSbAWwqfmryTuUl5GASY8eMT88UOmAvasU5TPJc4Nzajh2dpGUVRFKVd\
fANy2ze3gaJntAAAAABJRU5ErkJggg=="></td>
      <td><a href="../">..</a></td>
      <td>-</td>
    </tr>
  </table>
  <p>
    <div><a href="https://github.com/jabbequbs/scurvy-web">Scurvy</a></div>
    <div><a href="https://icons8.com/icon/12160/folder">Folder icon by Icons8</a></div>
  </p>

  <script type="text/javascript">
    const create = el => document.createElement(el);

    let imgUrl = document.querySelector("#folder").src,
      table = document.querySelector("table"),
      parents = %(parents)s,
      folders = %(folders)s,
      filenames = %(filenames)s,
      filesizes = %(filesizes)s;
    document.title = "Contents of " + parents.join("");
    document.querySelector("h3").textContent = document.title;
    for (let i = 0; i < folders.length; i++){
      let tr = create("tr");
      table.appendChild(tr);

      let td = create("td");
      td.appendChild(Object.assign(create("img"), {"src": imgUrl}));
      tr.appendChild(td);

      td = create("td");
      td.appendChild(Object.assign(create("a"),
          {href: encodeURIComponent(folders[i])+"/", textContent: folders[i]}));
      tr.appendChild(td)

      tr.appendChild(Object.assign(create("td"), {"textContent": "-"}));
    }
    for (let i = 0; i < filenames.length; i++){
      let tr = create("tr");
      table.appendChild(tr);

      tr.appendChild(create("td"));

      let td = create("td");
      td.appendChild(Object.assign(create("a"),
          {href: encodeURIComponent(filenames[i]), textContent: filenames[i]}));
      tr.appendChild(td)

      tr.appendChild(Object.assign(create("td"), {"textContent": filesizes[i]}));
    }

    if (parents.length == 1){
      let parentRow = document.querySelector("#folder").parentElement.parentElement;
      parentRow.parentNode.removeChild(parentRow);
    }
  </script>
</body>
</html>"""

def text_response(start_response, code, message, headers=None):
    start_response(response_codes[code],
        [("Content-Type", "text/plain; charset=utf-8")]+(headers or []))
    if type(message) is str:
        return [message.encode("utf-8")]
    else:
        return message

def html_response(start_response, code, message):
    start_response(response_codes[code],
        [("Content-Type", "text/html; charset=utf-8")])
    if type(message) is str:
        return [message.encode("utf-8")]
    else:
        return message

def json_response(start_response, code, data=None, formatted=None, headers=None):
    start_response(response_codes[code],
        [("Content-Type", "application/json")]+(headers or []))
    if formatted is not None:
        return [formatted.encode("utf-8") if type(formatted) is str else formatted]
    else:
        return [json.dumps(data, default=str).encode("utf-8")]

def empty_response(start_response, code, headers=None):
    start_response(response_codes[code], headers or [])
    return []

class StaticFileApp(object):
    def __init__(self, root, browse=False, cgi=False):
        logging.debug("Creating StaticFileApp at %s" % root)
        self.root = os.path.abspath(root)
        self.browse = browse
        self.cgi = cgi
        self.cgi_handlers = {}

    @staticmethod
    def get_filename(root, path_info):
        filename = os.path.abspath(os.path.join(root, *path_info.split("/")))
        if not filename.lower().startswith(root.lower()):
            return None
        elif os.path.exists(filename):
            return filename
        return None

    def __call__(self, environ, start_response):
        if self.cgi and re.search(r"\bcgi-bin\b", environ["PATH_INFO"], re.I):
            match = re.search(r"/cgi-bin/[^\/]+(/|$)", environ["PATH_INFO"], re.I)
            logging.debug(str(match))
            truncCount = 1 if match.group(0)[-1] == "/" else 0
            filename = environ["PATH_INFO"][:match.span()[-1]-truncCount]
            logging.debug(f"{filename =}")
            environ["SCRIPT_NAME"] += filename
            logging.debug(f'{environ["SCRIPT_NAME"] =}')
            environ["PATH_INFO"] = environ["PATH_INFO"][len(filename):] or "/"
            logging.debug(f'{environ["PATH_INFO"] =}')
            handler = os.path.abspath(os.path.join(self.root, *environ["SCRIPT_NAME"].split("/")))
            logging.debug(f"{handler =}")
            if not handler.lower().startswith(self.root.lower()):
                return text_response(start_response, 404, [b"404 Not found"])
            elif not os.path.isfile(handler):
                return text_response(start_response, 403, [b"Forbidden"])
            if handler not in self.cgi_handlers:
                self.cgi_handlers[handler] = CGIApp(handler)
            return self.cgi_handlers[handler](environ, start_response)
        elif not self.cgi:
            logging.debug("Not a CGI request")

        filename = StaticFileApp.get_filename(self.root, environ["PATH_INFO"])
        if not filename:
            return text_response(start_response, 404, [b"404 Not found"])
        elif os.path.isfile(filename):
            mimetype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
            if mimetype.startswith("text/"):
                mimetype += "; charset=utf-8"
            start_response("200 OK", [("Content-Type", mimetype)])
            with open(filename, "rb") as f:
                return [f.read()]
        elif os.path.isdir(filename):
            if not environ["PATH_INFO"][-1] == "/":
                return empty_response(start_response, 301,
                    [("Location", environ["PATH_INFO"]+"/")])
            elif os.path.isfile(os.path.join(filename, "index.html")):
                return empty_response(start_response, 301,
                    [("Location", environ["PATH_INFO"]+"index.html")])
            elif self.browse:
                for root, dirnames, filenames in os.walk(filename):
                    dirnames = sorted(dirnames)
                    filenames = sorted(filenames)
                    break
                # There should always be an empty trailing element, since PATH_INFO ends with /
                parents = [el+"/" for el in environ["PATH_INFO"].split("/")[:-1]]
                sizes = [os.path.getsize(os.path.join(filename, f)) for f in filenames]
                page = contents_page % {"parents": parents, "folders": dirnames,
                    "filenames": filenames, "filesizes": sizes}
                return html_response(start_response, 200, page)
            else:
                return text_response(start_response, 404, [b"404 Not found"])
        else:
            return text_response(start_response, 404, [b"404 Not found"])

class CGIApp(object):
    def __init__(self, handler):
        logging.debug("Creating CGIApp with %s" % handler)
        self.command = shlex.split(handler, posix=False)
        self.cwd = os.getcwd()
        if self.command[0].lower().endswith(".py"):
            py = sys.executable
            if py.lower().endswith("w.exe"):
                py = os.path.join(os.path.dirname(sys.executable), "python.exe")
            self.command = [py] + self.command

    def __call__(self, environ, start_response):
        cgi_env = os.environ.copy()
        for k in environ:
            if not k.startswith("wsgi"):
                cgi_env[k] = environ[k]
        cgi_env["HTTPS"] = "1" if environ["wsgi.url_scheme"] == "https" else "0"
        cgi_env["PYTHONPATH"] = os.pathsep.join(os.path.abspath(p or ".") for p in sys.path)
        data = None
        data_length = int(environ.get("CONTENT_LENGTH", 0) or 0)
        if data_length:
            data = environ["wsgi.input"].read(data_length)
        kwargs = dict(
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.cwd,
            env=cgi_env)
        if os.name == "nt":
            kwargs["creationflags"] = 0x08000000 # CREATE_NO_WINDOW
        logging.debug("Executing subprocess %s" % (self.command,))
        worker = subprocess.Popen(self.command, **kwargs)
        try:
            stdout, stderr = worker.communicate(data, timeout=10)
        except subprocess.TimeoutExpired:
            worker.terminate()
            return text_response(start_response, 400, [b"The CGI script timed out"])

        if stderr:
            try:
                stderr = stderr.decode("utf-8").strip().replace("\r\n", "\n")
            except:
                stderr = repr(stderr)
            logging.error("CGI script: %s\n%s" % (self.command, "\n".join(
                "  stderr: %s" % line for line in stderr.splitlines())))

        if worker.wait() == 0:
            newline = stdout.find(b"\n")
            if newline == -1:
                logging.error("Failed to parse CGI output:")
                logging.error(stdout)
                return text_response(start_response, 500, [b"Failed to parse CGI output"])
            if stdout[newline-1] == ord("\r"):
                newline = b"\r\n"
            else:
                newline = b"\n"
            status = "200 OK"
            headers = []
            while True:
                header, stdout = stdout.split(newline, 1)
                if not header:
                    break
                key, value = header.decode("utf-8").split(": ", 1)
                if key.lower() == "status":
                    status = value
                else:
                    headers.append((key, value))
            start_response(status, headers)
            return [stdout]
        else:
            return text_response(start_response, 500, [
                b"The CGI script failed.",
                b"\n\nstdout:\n", stdout or b"",
                b"\n\nstderr:\n", stderr or b""])

class HttpsMiddleware(object):
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        environ["HTTPS"] = "1"
        environ["wsgi.url_scheme"] = "https"
        return self.app(environ, start_response)

class MasterApp(object):
    def __init__(self, config):
        if config.www:
            self.root = StaticFileApp(config.www, config.browse, config.cgi)
        else:
            self.root = lambda e, r: text_response(r, 404, [b"No such application"])
        self.paths = []
        # path => (regex, set(authorizations))
        self.authentication = {}
        for entry in config.wsgi:
            try:
                path, handler_name = entry.split(maxsplit=1)
                module, handler = handler_name.rsplit(".", maxsplit=1)
                module = importlib.import_module(module)
                handler = getattr(module, handler)
            except Exception as e:
                logging.error("Failed to load WSGI handler %s: %s" % (handler_name, e))
            else:
                self.paths.append((self._get_path_regex(path), handler))
                logging.debug("Loaded WSGI application %s" % handler_name)
        if config.basic_auth:
            for entry in config.basic_auth:
                parts = entry.strip().split()
                if len(parts) == 2:
                    if parts[0] not in self.authentication:
                        self.authentication[parts[0]] = (
                            self._get_path_regex(parts[0]), set())
                    self.authentication[parts[0]][1].add(parts[1])
                else:
                    logging.error("Invalid config for basic auth: %s" % entry)
        if config.demo:
            self.paths.append(
                    (self._get_path_regex("**/demo_app"), demo_app))

    def _get_path_regex(self, pattern):
        regex = re.escape(pattern).replace(r"\*\*", r"(.*)")
        regex = regex.replace(r"\*", r"([^/]*)")+r"(\b|$)"
        logging.debug("Regex (caseless): %s => %s" % (pattern, regex))
        return re.compile(regex, re.I)

    def __call__(self, environ, start_response):
        for pattern in self.authentication:
            match = self.authentication[pattern][0].match(environ["PATH_INFO"])
            if match:
                logging.debug("Authenticating (matched %s)" % pattern)
                user_auth = environ.get("HTTP_AUTHORIZATION")
                if not user_auth:
                    return text_response(start_response, 401, [b"401 Unauthorized"],
                        [("WWW-Authenticate", "Basic")])
                parts = user_auth.split()
                if len(parts) != 2 or parts[0] != "Basic":
                    return text_response(start_response, 401, [b"401 Unauthorized"],
                        [("WWW-Authenticate", "Basic")])
                user_auth = base64.b64decode(parts[1].encode("utf-8"))
                users = self.authentication[pattern][1]
                user_auth_hash = hashlib.sha256(user_auth).hexdigest()
                if user_auth_hash not in users:
                    return text_response(start_response, 401, [b"401 Unauthorized"],
                        [("WWW-Authenticate", "Basic")])
                else:
                    if not environ.get("REMOTE_USER"):
                        environ["REMOTE_USER"] = user_auth.split(b":")[0].decode("utf-8")

        for pattern, app in self.paths:
            match = pattern.match(environ["PATH_INFO"])
            if match:
                logging.debug("Found matching application (%s, %s)" % (pattern, app))
                script_name = environ["PATH_INFO"][:match.end()]
                path_info = environ["PATH_INFO"][match.end():] or "/"
                environ["SCRIPT_NAME"] += script_name
                environ["PATH_INFO"] = path_info
                if not environ["PATH_INFO"].startswith("/"):
                    environ["PATH_INFO"] = "/" + environ["PATH_INFO"]
                try:
                    result = app(environ, start_response)
                except Exception as e:
                    from traceback import format_exc
                    logging.error(format_exc().strip())
                    return text_response(start_response, 500, [b"Server error"])
                else:
                    if result is None:
                        logging.error("No result from %s" % app)
                        return text_response(start_response, 500, [b"No result"])
                    return result

        logging.debug("Using root application %s" % self.root)
        return self.root(environ, start_response)

class ThreadPoolWSGIServer(WSGIServer):
    _futures = {}
    _executor = ThreadPoolExecutor()

    def process_request_thread(self, request, client_address):
        """Same as in BaseServer but as a thread.

        In addition, exception handling is done here.

        """
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

    def process_request(self, request, client_address):
        """Start a new thread to process the request."""
        args = (request, client_address)
        self._executor.submit(self.process_request_thread, request, client_address)

    def server_close(self):
        super().server_close()
        self._executor.shutdown()

class LoggingHandler(WSGIRequestHandler):
    # To log requests in a different format, override log_request(self, *args)

    def log_message(self, fmt, *args):
        logging.info("%s - %s" % (
            self.address_string(),
            fmt%args))

    def log_error(self, fmt, *args):
        logging.error("%s - %s" % (
            self.address_string(),
            fmt%args))

    def get_environ(self):
        env = WSGIRequestHandler.get_environ(self)
        env["REMOTE_PORT"] = str(self.client_address[1])
        return env

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--www", type=os.path.abspath, metavar="ROOT")
    parser.add_argument("--cgi", action="store_true",
        help="Specify whether files in a 'cgi-bin' folder should be treated as CGI scripts")
    parser.add_argument("--certfile", type=os.path.abspath)
    parser.add_argument("--port", default=8000, type=int)
    # TODO: browse can be specified multiple times, with a path pattern argument
    parser.add_argument("--browse", action="store_true")
    parser.add_argument("--external", action="store_true",
        help="Host on 0.0.0.0 instead of loop back address")
    parser.add_argument("--logfile", type=os.path.abspath)
    parser.add_argument("--log-level", choices=("DEBUG", "INFO"), default="INFO")
    parser.add_argument("--demo", action="store_true",
        help="Mount wsgiref.simple_server.demo_app at **/demo_app")
    parser.add_argument("--libs", action="append", default=[],
        help="Specify a directory to add to sys.path.  Can be specified multiple times")
    parser.add_argument("--wsgi", default=[], action="append",
        help="Specify a pattern and a WSGI application to handle matching request")
    parser.add_argument("--basic-auth", default=[], action="append",
        help='Format like "/web/path sha256(user:password)"')
    parser.add_argument("--conf",
        help="Specify a config file containing one option per line")
    args = parser.parse_args()

    if args.conf and os.path.isfile(args.conf):
        conf_args = []
        with open(args.conf) as f:
            for line in f:
                if line.strip().startswith("#"):
                    continue
                conf_args.extend(map(str.strip, line.split(maxsplit=1)))
        args = parser.parse_args(sys.argv[1:]+conf_args)

    logging_config = dict(
        stream=sys.stdout,
        format="%(levelno)s %(thread)s [%(asctime)s] [%(module)s] %(message)s",
        level=getattr(logging, args.log_level))
    if args.logfile:
        logging_config["filename"] = args.logfile
        del logging_config["stream"]
    logging.basicConfig(**logging_config)

    for lib in args.libs:
        sys.path.append(os.path.abspath(lib))

    app = MasterApp(args)
    if args.certfile:
        app = HttpsMiddleware(app)
    server_info = ("0.0.0.0" if args.external else "127.0.0.1",
        args.port, app, ThreadPoolWSGIServer, LoggingHandler)
    with make_server(*server_info) as httpd:
        logging.info("Serving at %s:%s" % (server_info[0], server_info[1]))
        if args.www:
            logging.info("Serving from %s" % args.www)
        # https://gist.github.com/dergachev/7028596
        # doskey openssl="C:\Program Files\Git\mingw64\bin\openssl.exe" $*
        # openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
        # use server.pem as certfile
        if args.certfile:
            httpd.socket = ssl.wrap_socket(httpd.socket,
                certfile=args.certfile, server_side=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logging.info("Interrupt received, exiting")

if __name__ == '__main__':
    main()
