"""
Project Sentinel logging.

This module provides a central logging interface for the application.

Responsibilities:
- Display colour-coded operational messages in the terminal.
- Write detailed events to a persistent log file.
- Apply timestamps and formatting consistently.
- Automatically identify which module created each log event.
- Separate individual Sentinel monitoring sessions in the log.
- Keep logging implementation separate from business logic.
"""

from datetime import datetime
from inspect import currentframe
from pathlib import Path

from version import (
    APPLICATION_NAME,
    STATUS,
    VERSION
)


# -----------------------------------------------------------------------------
# Logging locations
# -----------------------------------------------------------------------------

LOG_DIRECTORY = Path("logs")
LOG_FILE = LOG_DIRECTORY / "sentinel.log"


# -----------------------------------------------------------------------------
# Terminal colours
# -----------------------------------------------------------------------------

RESET = "\033[0m"

GREY = "\033[90m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
LIGHT_RED = "\033[91m"
BRIGHT_RED = "\033[31;1m"


# -----------------------------------------------------------------------------
# Console visibility
# -----------------------------------------------------------------------------

# Every level is written to the persistent log file.
#
# Only the levels listed below are displayed in the terminal.
# DEBUG remains available for deeper investigation without cluttering
# the normal user experience.
CONSOLE_LEVELS = {
    "INFO",
    "WARNING",
    "HIGH",
    "CRITICAL"
}


# -----------------------------------------------------------------------------
# Logger state
# -----------------------------------------------------------------------------

# Prevents the session heading from being written more than once during
# a single Sentinel process.
_LOGGER_INITIALISED = False


# -----------------------------------------------------------------------------
# Initialisation
# -----------------------------------------------------------------------------

def initialise_logger():
    """
    Prepare persistent logging for the current Sentinel session.

    The log directory and file are created when required.

    A session heading is written once per Sentinel process so separate
    monitoring cycles can be identified easily in the log history.
    """

    global _LOGGER_INITIALISED

    LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)
    LOG_FILE.touch(exist_ok=True)

    if _LOGGER_INITIALISED:
        return

    with LOG_FILE.open("a", encoding="utf-8") as log_file:
        log_file.write("\n")
        log_file.write("=" * 80)
        log_file.write("\n")
        log_file.write(
            f"{APPLICATION_NAME} SESSION STARTED "
            f"| Version {VERSION} "
            f"| Status {STATUS}\n"
        )
        log_file.write(
            f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        log_file.write("=" * 80)
        log_file.write("\n")

    _LOGGER_INITIALISED = True


# -----------------------------------------------------------------------------
# Internal helper functions
# -----------------------------------------------------------------------------

def _timestamp():
    """
    Return the current date and time in a consistent log format.
    """

    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _calling_module():
    """
    Identify the module that requested the log event.

    The normal call sequence is:

        application module
            ↓
        public logging function
            ↓
        _log()
            ↓
        _calling_module()

    Moving three frames backwards reaches the application module that
    originally requested the log event.
    """

    frame = currentframe()

    try:
        calling_frame = frame.f_back.f_back.f_back
        module_name = calling_frame.f_globals.get("__name__", "unknown")

        # Convert package.module names into a shorter module label.
        module_name = module_name.split(".")[-1]

        # A directly executed main.py file is identified by Python as
        # "__main__". Presenting it as "main" is clearer in Sentinel logs.
        if module_name == "__main__":
            module_name = "main"

        return module_name

    finally:
        # Removing the frame reference prevents unnecessary reference cycles.
        del frame


def _console_colour(level):
    """
    Return the terminal colour assigned to a severity level.
    """

    colours = {
        "DEBUG": GREY,
        "INFO": BLUE,
        "WARNING": YELLOW,
        "HIGH": LIGHT_RED,
        "CRITICAL": BRIGHT_RED
    }

    return colours.get(level, RESET)


def _write_log(level, module_name, message):
    """
    Append one formatted event to the persistent Sentinel log file.
    """

    # This protects Sentinel if a module records an event before main.py
    # explicitly initialises the logging framework.
    initialise_logger()

    with LOG_FILE.open("a", encoding="utf-8") as log_file:
        log_file.write(
            f"{_timestamp()} "
            f"{level:<9} "
            f"{module_name:<18} "
            f"{message}\n"
        )


def _display_console_message(level, message):
    """
    Display a colour-coded operational message in the terminal.
    """

    colour = _console_colour(level)

    print(
        f"{colour}"
        f"{level:<9}"
        f"{message}"
        f"{RESET}"
    )


def _log(level, message):
    """
    Process one Sentinel log event.

    Every event is written to the persistent log file.

    Only meaningful operational levels are displayed in the terminal.
    """

    module_name = _calling_module()
    text_message = str(message)

    _write_log(level, module_name, text_message)

    if level in CONSOLE_LEVELS:
        _display_console_message(level, text_message)


# -----------------------------------------------------------------------------
# Public logging functions
# -----------------------------------------------------------------------------

def log_debug(message):
    """
    Record detailed diagnostic information.

    DEBUG events are written to the log file but hidden from the
    normal terminal display.
    """

    _log("DEBUG", message)


def log_info(message):
    """
    Record normal operational information.
    """

    _log("INFO", message)


def log_warning(message):
    """
    Record an event that requires operator awareness or review.
    """

    _log("WARNING", message)


def log_high(message):
    """
    Record a significant security or operational issue.
    """

    _log("HIGH", message)


def log_critical(message):
    """
    Record an event requiring immediate investigation.
    """

    _log("CRITICAL", message)