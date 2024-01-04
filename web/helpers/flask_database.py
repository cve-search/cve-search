from lib.DatabaseHandler import DatabaseHandler


class FlaskDatabaseHandler(object):
    def __init__(self, app=None, **kwargs):
        self.kwargs = kwargs

        if app is not None:
            self.init_app(app)

    def init_app(self, app, **kwargs):
        self.kwargs.update(kwargs)

        app.dbh = DatabaseHandler()

    def __repr__(self):
        return "<< FlaskDatabaseHandler >>"
