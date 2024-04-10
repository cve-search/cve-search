import logging
import sys
import time
from datetime import timedelta

from tqdm import tqdm

from lib.Config import Configuration
from lib.DatabaseLayer import (
    getCPEs,
)
from lib.cpe_conversion import split_cpe_name


class CPERedisBrowser(object):
    def __init__(self, cpes=None):
        try:
            self.__db = Configuration.getRedisVendorConnection()
        except Exception:
            sys.exit(1)

        if cpes is None:
            self.cpes = getCPEs()
        else:
            self.cpes = cpes

        self.set_debug_logging = False

        self.logger = logging.getLogger("CPERedisBrowser")

    def update(self):
        self.logger.info("Redis CPE database update started")

        start_time = time.time()
        for e in tqdm(self.cpes, desc="Inserting CPE's in redis"):
            value = e["cpeName"]
            cpe_name = split_cpe_name(value)
            (prefix, cpeversion, cpetype, vendor, product) = cpe_name[:5]
            version = ":".join(cpe_name[5:])

            if self.set_debug_logging:
                self.logger.debug("prefix: {}".format(prefix))
                self.logger.debug("cpetype: {}".format(cpetype))
                self.logger.debug("vendor: {} ".format(vendor))
                self.logger.debug("product: {} ".format(product))
                self.logger.debug("version: {}".format(version))

            self.__db.sadd("prefix:" + prefix, cpetype)
            self.__db.sadd(cpetype, vendor)
            self.__db.sadd("v:" + vendor, product)
            if version:
                self.__db.sadd("p:" + product, version)

        self.logger.info(
            "Duration: {}".format(timedelta(seconds=time.time() - start_time))
        )
