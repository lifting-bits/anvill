# Copyright (c) 2021 Trail of Bits, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import os
import sys
import logging


# Create a logger
logger = logging.getLogger(__name__)

# default log level is set to warning; It can be set
# to debug by enabling verbose mode
logger.setLevel(logging.WARNING)

log_format = logging.Formatter("%(asctime)s [%(levelname)s]: %(message)s")

try:
    # Setup console stream handler
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(log_format)
    logger.addHandler(stream_handler)

except Exception as e:
    stream_handler = None
    print("Failed to setup logger stream handler {}".format(e))


def config_logger(logfile, verbose=False):
    """Set the logger file handler and set the log
    level to verbose if required
    """

    if logfile is not None:
        if not logfile.endswith(".log"):
            logfile += ".log"

        try:
            file_handler = logging.FileHandler(logfile, mode="w")
            file_handler.setFormatter(log_format)
            logger.addHandler(file_handler)

            # remove stream handler if file handler is set successfully
            if stream_handler is not None:
                logger.removeHandler(stream_handler)
        except Exception as e:
            logger.warning("Failed to set up log file: {}".format(e))

    # enable verbose mode if it is set
    if verbose:
        logger.setLevel(logging.DEBUG)


# debug log interface
DEBUG = logger.debug

# info log
INFO = logger.info

# warning log
WARN = logger.warning

# error log
ERROR = logger.error

# fatal log
FATAL = logger.critical
