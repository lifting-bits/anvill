#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

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
