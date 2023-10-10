import os
import sys

_runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(_runPath, ".."))

import multiprocessing
import logging
import gunicorn

from lib.Config import Configuration
from lib.LogHandler import AppLogger
from web.run import create_app
from web.set_version import _version

from flask import Flask
from logging.config import fileConfig, dictConfig
from gunicorn.glogging import CONFIG_DEFAULTS
from gunicorn.app.base import BaseApplication

config = Configuration()

logging.setLoggerClass(AppLogger)

__version__ = _version()


class StandaloneApplication(BaseApplication):
    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        config = {
            key: value
            for key, value in self.options.items()
            if key in self.cfg.settings and value is not None
        }
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application


class GunicornLogger(gunicorn.glogging.Logger):
    def __init__(self, cfg):
        super().__init__(cfg)

    def setup(self, cfg):
        self.loglevel = self.LOG_LEVELS.get(cfg.loglevel.lower(), logging.INFO)
        self.error_log.setLevel(self.loglevel)
        self.access_log.setLevel(logging.INFO)

        # set gunicorn.error handler
        if self.cfg.capture_output and cfg.errorlog != "-":
            for stream in sys.stdout, sys.stderr:
                stream.flush()

            self.logfile = open(cfg.errorlog, "a+")
            os.dup2(self.logfile.fileno(), sys.stdout.fileno())
            os.dup2(self.logfile.fileno(), sys.stderr.fileno())

        # Force gunicorn to produce an access log; without pushing this to stdout from this instance
        self.cfg.set("accesslog", "Y")

        if cfg.logconfig_dict:
            config = CONFIG_DEFAULTS.copy()
            config.update(cfg.logconfig_dict)
            try:
                dictConfig(config)
            except (AttributeError, ImportError, ValueError, TypeError) as exc:
                raise RuntimeError(str(exc))
        elif cfg.logconfig:
            if os.path.exists(cfg.logconfig):
                defaults = CONFIG_DEFAULTS.copy()
                defaults["__file__"] = cfg.logconfig
                defaults["here"] = os.path.dirname(cfg.logconfig)
                fileConfig(
                    cfg.logconfig, defaults=defaults, disable_existing_loggers=False
                )
            else:
                msg = "Error: log config '%s' not found"
                raise RuntimeError(msg % cfg.logconfig)


class FlaskAppManager(object):
    def __init__(self, version: str, app: Flask, *args, **kwargs):
        self.logger = logging.getLogger(__name__)

        self.logger.info("Initializing FlaskAppManager...")

        self.app = app

        if not isinstance(self.app, Flask):
            raise AttributeError(
                f"The provided app variable is not of type 'Flask' but {type(self.app)}"
            )

        self.version = version

        self.max_workers = int(os.getenv("WEB_MAX_WORKERS", 0))
        self.web_worker_timeout = int(os.getenv("WEB_WORKER_TIMEOUT", 60))

        self.web_tls_key_path = os.path.join(_runPath, "../", config.getSSLKey())
        self.web_tls_cert_path = os.path.join(_runPath, "../", config.getSSLCert())

        self.debug = config.getFlaskDebug()
        self.debug_with_ssl = config.getFlaskSSLDebug()

        self.bind_host = config.getFlaskHost()
        self.bind_port = config.getFlaskPort()

        self.logger.info(
            f"Initialization complete, call the run method to start the app!"
        )

    def run(self):
        self.logger.info("Trying to start the app...")

        try:
            self.logger.info(f"Running version: {self.version}")

            if self.debug:
                if self.debug_with_ssl:
                    self.app.run(
                        host=self.bind_host,
                        port=self.bind_port,
                        ssl_context="adhoc",
                    )
                else:
                    self.app.run(
                        host=self.bind_host,
                        port=self.bind_port,
                    )

            else:
                options = {
                    "bind": f"{self.bind_host}:{self.bind_port}",
                    "workers": self._number_of_workers(),
                    "timeout": self.web_worker_timeout,
                    "logger_class": "web.index.GunicornLogger",
                    "access_log_format": "%(t)s src_ip=%(h)s request=%(r)s request_method=%(m)s status=%(s)s "
                    "response_length=%(b)s referrer=%(f)s url=%(U)s query=?%(q)s user_agent=%(a)s t_ms=%(L)s",
                }
                if os.path.exists(self.web_tls_key_path) and os.path.exists(
                    self.web_tls_cert_path
                ):
                    options["keyfile"] = self.web_tls_key_path
                    options["certfile"] = self.web_tls_cert_path
                    StandaloneApplication(self.app, options).run()
                else:
                    # no TLS; assume running behind reverse proxy that handles TLS offloading; switching to plain http
                    StandaloneApplication(self.app, options).run()

        except Exception:
            raise

    def _number_of_workers(self):
        if self.max_workers != 0:
            return self.max_workers
        else:
            return (multiprocessing.cpu_count() * 2) + 1


app = create_app(__version__, _runPath)

if __name__ == "__main__":
    fam = FlaskAppManager(version=__version__, app=app)
    fam.run()
