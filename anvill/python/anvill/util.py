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

try:
    """If the config file is available, configure logger"""
    config_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "logging.ini"
    )
    logging.config.fileConfig(config_file)

except Exception as e1:
    """If logging.ini is missing from the package. Setup the
    basic configuration for root logger
    """
    try:
        stream_handler = logging.StreamHandler(sys.stderr)
        logging.basicConfig(
            level=logging.ERROR,
            format="%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d]: %(message)s",
            handlers=[stream_handler],
        )

    except Exception as e2:
        print(f"Fail to configure root logger {e2}")

# debug log
DEBUG = logging.getLogger().debug

# info log
INFO = logging.getLogger().info

# warning log
WARN = logging.getLogger().warning

# error log
ERROR = logging.getLogger().error

# fatal log
FATAL = logging.getLogger().critical


def config_logger(logfile, verbose=False):
    """Set the logger file handler and set the log level
    to verbose if required
    """
    # Get root logger
    logger = logging.getLogger()

    if logfile is not None:
        try:
            log_format = logging.Formatter(
                "%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d]: %(message)s"
            )
            file_handler = logging.FileHandler(logfile, mode="w")
            file_handler.setFormatter(log_format)
            logger.addHandler(file_handler)

            # if the file handler is set; change log level of
            # all stream handlers to ERROR
            for h in logger.handlers:
                if not isinstance(h, logging.FileHandler) and isinstance(
                    h, logging.StreamHandler
                ):
                    h.setLevel(logging.ERROR)

        except Exception as e:
            logger.warning(f"Failed to set up log file: {e}")

    # enable verbose mode
    if verbose:
        logger.setLevel(logging.DEBUG)


def create_logger(name):
    """Create module level logger which can be configured using
    logging.ini files
    """
    return (
        logging.getLogger(name).info,
        logging.getLogger(name).debug,
        logging.getLogger(name).warning,
        logging.getLogger(name).error,
        logging.getLogger(name).critical,
    )
