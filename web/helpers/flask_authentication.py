from lib.Authentication import AuthenticationHandler


class FlaskAuthHandler:
    def __init__(self, app=None, **kwargs):
        self.kwargs = kwargs
        self.auth = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app, **kwargs):
        self.kwargs.update(kwargs)
        app.auth_handler = self

    def __getattr__(self, name):
        if self.auth is None:
            self.auth = AuthenticationHandler()
        return getattr(self.auth, name)

    def __repr__(self):
        return "<< FlaskAuthHandler >>"
