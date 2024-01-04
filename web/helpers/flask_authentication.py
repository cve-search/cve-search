from lib.Authentication import AuthenticationHandler


class FlaskAuthHandler(object):
    def __init__(self, app=None, **kwargs):
        self.kwargs = kwargs

        if app is not None:
            self.init_app(app)

    def init_app(self, app, **kwargs):
        self.kwargs.update(kwargs)

        app.auth_handler = AuthenticationHandler()

    def __repr__(self):
        return "<< FlaskAuthHandler >>"
