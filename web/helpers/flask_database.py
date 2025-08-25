from lib.DatabaseHandler import DatabaseHandler


class LazyDatabaseHandler:
    """
    Lazily instantiate DatabaseHandler to defer MongoClient creation until first use.
    This avoids PyMongo warnings when using prefork servers like Gunicorn.
    """

    def __init__(self, **kwargs):
        self._kwargs = kwargs
        self._real = None

    def _get_real(self):
        if self._real is None:
            self._real = DatabaseHandler(**self._kwargs)
        return self._real

    def __getattr__(self, name):
        return getattr(self._get_real(), name)

    def __setattr__(self, name, value):
        if name in ("_real", "_kwargs"):
            super().__setattr__(name, value)
        else:
            setattr(self._get_real(), name, value)


class FlaskDatabaseHandler:
    """
    Flask helper to attach a lazy DatabaseHandler to `app.dbh`.
    """

    def __init__(self, app=None, **kwargs):
        self._lazy_dbh = LazyDatabaseHandler(**kwargs)
        if app is not None:
            self.init_app(app)

    def init_app(self, app, **kwargs):
        # Merge extra kwargs and attach lazy db handler
        self._lazy_dbh._kwargs.update(kwargs)
        app.dbh = self._lazy_dbh

    def __repr__(self):
        return "<< FlaskDatabaseHandler >>"
