from lib.Config import Configuration
import jsonpickle

from lib.db_action import DatabaseAction


class RedisQueue(object):

    def __init__(self, name, serializer=jsonpickle, namespace="queue"):
        self.__db = Configuration.getRedisQConnection()
        self.serializer = serializer
        self._key = "{}:{}".format(name, namespace)

    def __len__(self):
        return self.qsize()

    def __repr__(self):
        return "<< RedisQueue:{} >>".format(self.key)

    def __iter__(self):
        return self

    def __next__(self):
        item = self.get(timeout=1)
        if item is not None:
            if isinstance(item, DatabaseAction):
                item = item.entry
            return item
        else:
            raise StopIteration

    @property
    def key(self):
        return self._key

    def get_full_list(self):

        entries = self.__db.lrange(self.key, 0, -1)

        self.__db.delete(self.key)

        return [self.serializer.decode(entry) for entry in entries]

    def clear(self):
        """Clear the queue of all messages, deleting the Redis key."""
        self.__db.delete(self.key)

    def qsize(self):
        """
        Return size of the queue

        :return:
        :rtype:
        """
        return self.__db.llen(self.key)

    def get(self, block=False, timeout=None):
        """
        Return an item from the queue.

        :param block: Whether or not to wait for item to be available; defaults to False
        :type block: bool
        :param timeout: Time to wait for item to be available in the queue; defaults to None
        :type timeout: int
        :return: Item popped from list
        :rtype: *
        """
        if block:
            if timeout is None:
                timeout = 0
            item = self.__db.blpop(self.key, timeout=timeout)
            if item is not None:
                item = item[1]
        else:
            item = self.__db.lpop(self.key)
        if item is not None and self.serializer is not None:
            item = self.serializer.decode(item)
        return item

    def put(self, *items):
        """
        Put one or more items onto the queue.

        Example:

        q.put("my item")
        q.put("another item")

        To put messages onto the queue in bulk, which can be significantly
        faster if you have a large number of messages:

        q.put("my item", "another item", "third item")
        """
        if self.serializer is not None:
            items = map(self.serializer.encode, items)
        self.__db.rpush(self.key, *items)
