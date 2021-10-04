import shutil
from abc import abstractmethod

from lib.DownloadHandler import DownloadHandler
from lib.IJSONHandler import IJSONHandler


class JSONFileHandler(DownloadHandler):
    def __init__(self, feed_type, prefix):
        super().__init__(feed_type)

        self.is_update = True

        self.prefix = prefix

        self.ijson_handler = IJSONHandler()

    def __repr__(self):
        """ return string representation of object """
        return "<< JSONFileHandler:{} >>".format(self.feed_type)

    def file_to_queue(self, file_tuple):

        working_dir, filename = file_tuple

        # adjust the interval counter for debug logging when updating
        if self.is_update:
            interval = 500
        else:
            interval = 5000

        x = 0
        self.logger.debug("Starting processing of file: {}".format(filename))
        for cpe in self.ijson_handler.fetch(filename=filename, prefix=self.prefix):
            self.process_item(item=cpe)
            x += 1
            if x % interval == 0:
                self.logger.debug("Processed {} entries from file: {}".format(x, filename))

        try:
            self.logger.debug("Removing working dir: {}".format(working_dir))
            shutil.rmtree(working_dir)
        except Exception as err:
            self.logger.error(
                "Failed to remove working dir; error produced: {}".format(err)
            )

    @abstractmethod
    def update(self, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def populate(self, **kwargs):
        raise NotImplementedError
