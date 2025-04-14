import json
import os
import time
import traceback
from collections import OrderedDict


class LogLevel:
    NOTSET = 0
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5


class Logger:
    def __init__(
        self,
        bucket,
        filename: str
    ) -> None:
        self.error_count = 0
        self.logs = []
        self.filename = filename
        self.bucket = bucket

    def save(self) -> None:
        os.makedirs("logs", exist_ok=True)

        with open(f"logs/{self.filename}.json", "w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2)
            
    def upload_logs(self) -> None:
        self.bucket.upload_file(f"logs/{self.filename}.json", f"{self.filename}.json")

    def _log(self, level: str, message: str, **kwargs) -> None:
        """
        Log a message with a given severity level and any addional key/values.
        """
        now = time.localtime()
        asctime = f"{now.tm_year}-{now.tm_mon:02d}-{now.tm_mday:02d} {now.tm_hour:02d}:{now.tm_min:02d}:{now.tm_sec:02d}"

        # case where someone used debug, info, or warning yet also provides an 'err' kwarg with an Exception
        if (
            "err" in kwargs
            and level not in ("ERROR", "CRITICAL")
            and isinstance(kwargs["err"], Exception)
        ):
            kwargs["err"] = traceback.format_exception(kwargs["err"])

        json_order: OrderedDict[str, str] = OrderedDict(
            [("time", asctime), ("level", level), ("msg", message)]
        )
        json_order.update(kwargs)

        print(json.dumps(json_order))
        self.logs.append(json_order)

    def debug(self, message: str, **kwargs) -> None:
        """
        Log a message with severity level DEBUG.
        """
        self._log("DEBUG", message, **kwargs)

    def info(self, message: str, **kwargs) -> None:
        """
        Log a message with severity level INFO.
        """
        self._log("INFO", message, **kwargs)

    def warning(self, message: str, **kwargs) -> None:
        """
        Log a message with severity level WARNING.
        """
        self._log("WARNING", message, **kwargs)

    def error(self, message: str, err: Exception | None = None, **kwargs) -> None:
        """
        Log a message with severity level ERROR.
        """
        if err:
            kwargs["err"] = traceback.format_exception(err)
        else:
            kwargs["err"] = None

        self.error_count += 1
        self._log("ERROR", message, **kwargs)

    def critical(self, message: str, err: Exception, **kwargs) -> None:
        """
        Log a message with severity level CRITICAL.
        """
        kwargs["err"] = traceback.format_exception(err)
        self.error_count += 1
        self._log("CRITICAL", message, **kwargs)

    def get_error_count(self) -> int:
        return self.error_count

    def get_logs(self) -> list[str]:
        return self.logs
