#!/usr/bin/env python3

import argparse
import base64
import hashlib
import importlib
import importlib.util
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

class G:
    debug = False

contents_page = """\
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Folder contents</title>
  <style type="text/css">
    * { font-family: Verdana, sans-serif; line-height: 1.3; }
    body { max-width: 1000px; margin: 20px auto; }
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

class StaticFileApp:
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
                return text_response(start_response, 404, [b"404 Not found"])
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

class CGIApp:
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
                stderrString = stderr.decode("utf-8").strip().replace("\r\n", "\n")
            except:
                stderrString = repr(stderr)
            logging.error("CGI script: %s\n%s" % (self.command, "\n".join(
                "  stderr: %s" % line for line in stderrString.splitlines())))

        if worker.wait() == 0:
            newline = stdout.find(b"\n")
            if newline == -1:
                logging.error("Failed to parse CGI output:")
                logging.error(stdout)
                if G.debug:
                    try:
                        stdoutString = stdout.decode("utf-8")
                    except:
                        stdoutString = repr(stdout)
                    return text_response(start_response, 500,
                        f"Failed to parse CGI output:\n\n{stdoutString}")
                else:
                    return text_response(start_response, 500, [b"Internal server error"])
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
            if G.debug:
                return text_response(start_response, 500, [
                    b"The CGI script failed.",
                    b"\n\nstdout:\n", stdout or b"",
                    b"\n\nstderr:\n", stderr or b""])
            else:
                return text_response(start_response, 500, [b"Internal server error"])

class ReloadableWSGIApp:
    def __init__(self, name):
        self.name = name
        self._load_application(self.name)

    def _load_application(self, name, module=None):
        vars(self).setdefault("timestamp", 0)
        vars(self).setdefault("module", None)
        moduleName, application = name.rsplit(":", 1)
        try:
            if not module and os.path.isfile(moduleName):
                self.module = self._load_file(moduleName)
            else:
                if module:
                    self.module = importlib.reload(module)
                else:
                    moduleName, application = name.rsplit(":", 1)
                    self.module = importlib.import_module(moduleName)
                    logging.debug(str(self.module))
            self.application = getattr(self.module, application)
        except Exception:
            from traceback import format_exc
            details = f"An error occurred while (re)loading the application {name}:\n\n{format_exc().strip()}"
            logging.error(details)
            if G.debug:
                self.application = lambda e, s: text_response(s, 500, details)
            else:
                self.application = lambda e, s: text_response(
                    s, 500, [b"Internal server error"])
        else:
            self.timestamp = os.path.getmtime(self.module.__file__)

    def _load_file(self, filename):
        module_name = os.path.basename(filename).rsplit(".", 1)[0]
        spec = importlib.util.spec_from_file_location(module_name, filename)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module

    def __call__(self, environ, start_response):
        if not self.module or os.path.getmtime(self.module.__file__) != self.timestamp:
            logging.debug(f"Reloading application {self.name}")
            self._load_application(self.name, self.module)
        return self.application(environ, start_response)

class HttpsMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        environ["HTTPS"] = "1"
        environ["wsgi.url_scheme"] = "https"
        return self.app(environ, start_response)

class DelegatorMiddleware:
    def __init__(self, routes):
        self.routes = routes
        for path, application in routes:
            if path.endswith("/"):
                logging.warning(f"Path {path}: SCRIPT_NAME and PATH_INFO will both have /")

    def __call__(self, environ, start_response):
        for path, application in self.routes:
            if environ["PATH_INFO"].lower().startswith(path.lower()):
                # /abc should match /abc/def but not /abcdef
                remainder = environ["PATH_INFO"][len(path):]
                if remainder and remainder[0] != "/" and path[-1] != "/":
                    continue
                environ["SCRIPT_NAME"] += path
                environ["PATH_INFO"] = remainder or "/"
                if environ["PATH_INFO"][0] != "/":
                    environ["PATH_INFO"] = "/" + environ["PATH_INFO"]
                logging.debug(f"Using application {application} with SCRIPT_NAME = {environ['SCRIPT_NAME']}, PATH_INFO = {environ['PATH_INFO']}")
                return application(environ, start_response)
        return text_response(start_response, 404, [b"Not found"])

class BasicAuthMiddleware(DelegatorMiddleware):
    """userfile is a file with sha256(username:password) on each line"""

    def __init__(self, userfile, routes):
        super().__init__(routes)
        with open(userfile) as f:
            self.authentication = set(line.strip() for line in f
                if line and line[0] != "#")

    def __call__(self, environ, start_response):
        user_auth = environ.get("HTTP_AUTHORIZATION")
        if not user_auth:
            return text_response(start_response, 401, [b"401 Unauthorized"],
                [("WWW-Authenticate", "Basic")])
        parts = user_auth.split()
        if len(parts) != 2 or parts[0] != "Basic":
            return text_response(start_response, 401, [b"401 Unauthorized"],
                [("WWW-Authenticate", "Basic")])
        user_auth = base64.b64decode(parts[1].encode("utf-8"))
        user_auth_hash = hashlib.sha256(user_auth).hexdigest()
        if user_auth_hash not in self.authentication:
            return text_response(start_response, 401, [b"401 Unauthorized"],
                [("WWW-Authenticate", "Basic")])
        else:
            if not environ.get("REMOTE_USER"):
                environ["REMOTE_USER"] = user_auth.split(b":")[0].decode("utf-8")
        return super().__call__(environ, start_response)

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

def serve(host, port, app, certfile=None, debug=False):
    G.debug = debug

    if certfile:
        app = HttpsMiddleware(app)
    server_info = (host, port, app, ThreadPoolWSGIServer, LoggingHandler)
    logging.info("Making server...")
    with make_server(*server_info) as httpd:
        logging.info("Serving at %s:%s" % (server_info[0], server_info[1]))
        # https://gist.github.com/dergachev/7028596
        # doskey openssl="C:\Program Files\Git\mingw64\bin\openssl.exe" $*
        # openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
        # use server.pem as certfile
        # TODO: use SSLContext.wrap_socket instead
        if certfile:
            httpd.socket = ssl.wrap_socket(httpd.socket,
                certfile=certfile, server_side=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logging.info("Interrupt received, exiting")

def main():
    parser = argparse.ArgumentParser()

    group = parser.add_argument_group("Networking")
    group.add_argument("--certfile", type=os.path.abspath,
        help="A .pem certificate to use for HTTPS")
    group.add_argument("--port", default=8000, type=int,
        help="The port to serve from (default = %(default)s)")
    group.add_argument("--external", action="store_true",
        help="Host on 0.0.0.0 instead of loop back address")

    group = parser.add_argument_group("Logging")
    group.add_argument("--logfile", type=os.path.abspath,
        help="The log file location.  Default is stdout")
    group.add_argument("--log-level", choices=("DEBUG", "INFO"), default="INFO",
        help="The starting log level.  (default = %(default)s)")

    group = parser.add_argument_group("Applications")
    group.add_argument("--libs", action="append", default=[],
        help="Specify a directory to add to sys.path.  Can be specified multiple times")
    group.add_argument("--cgi", action="store_true",
        help="When serving static files, enable CGI scripts in cgi-bin folders")
    group.add_argument("--browse", action="store_true",
        help="When serving static files, enable directory browsing")
    group.add_argument("--debug", action="store_true",
        help="Show error details and reload the WSGI application if its file changes")
    parser_group = group.add_mutually_exclusive_group(required=True)
    parser_group.add_argument("--wsgi",
        help="File and application to run (filename.py:appName or modulename:appName)")
    parser_group.add_argument("--www", type=os.path.abspath,
        help="A folder to serve static files from")
    args = parser.parse_args()

    G.debug = args.debug
    if G.debug:
        args.log_level = "DEBUG"
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
    if args.wsgi:
        if args.cgi or args.browse:
            parser.error("--cgi and --browse cannot be specified when using --wsgi")
        rootApp = ReloadableWSGIApp(args.wsgi)
        if not G.debug:
            rootApp = rootApp.application
    elif args.www:
        rootApp = StaticFileApp(args.www, args.browse, args.cgi)

    def errorHandlingWrapper(environ, start_response):
        try:
            return rootApp(environ, start_response)
        except Exception as e:
            if G.debug:
                from traceback import format_exc
                return text_response(start_response, 500, format_exc().strip())
            else:
                return text_response(start_response, 500, [b"Internal server error"])
    app = errorHandlingWrapper

    host = "0.0.0.0" if args.external else "127.0.0.1"
    serve(host, args.port, app, args.certfile, G.debug)

if __name__ == '__main__':
    main()
