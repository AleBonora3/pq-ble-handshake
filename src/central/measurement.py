"""Optional, payload-free observations. Inactive during ordinary Central use.

Durations describe Python/API boundaries, never controller or CPU cycle time.
The callback wrapper captures its recorder because Bleak may call from a thread
whose ContextVars differ from the protocol task. No file I/O occurs in hooks.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import inspect
import time

_active = ContextVar("pq_ble_measurement", default=None)


class Recorder:
    def __init__(self, clock=time.perf_counter_ns):
        self.clock = clock
        self.origin_ns = clock()
        self.events = []
        self.phase_timings = []
        self.gatt_operations = []
        self.mtu_observations = []
        self.observed_scenario = None

    def now(self):
        return self.clock() - self.origin_ns

    def mark(self, name):
        self.events.append({"name": name, "offset_ns": self.now()})

    @contextmanager
    def activate(self):
        token = _active.set(self)
        try:
            yield self
        finally:
            _active.reset(token)


def mark(name):
    if (recorder := _active.get()) is not None:
        recorder.mark(name)


def scenario(value):
    if (recorder := _active.get()) is not None:
        recorder.observed_scenario = value


def mtu(value):
    if (recorder := _active.get()) is not None:
        recorder.mtu_observations.append({"offset_ns": recorder.now(), "value": value})


def observe_mtu(client):
    # Do not add a property access to ordinary execution, particularly reconnect
    # backends/test doubles that expose MTU only after their protected operation.
    if _active.get() is not None:
        value = getattr(client, "mtu_size", None)
        if value is not None:
            mtu(value)


@contextmanager
def phase(name):
    recorder = _active.get()
    if recorder is None:
        yield
        return
    start = recorder.now()
    complete = False
    try:
        yield
        complete = True
    finally:
        recorder.phase_timings.append({"name": name, "start_ns": start,
            "end_ns": recorder.now(), "complete": complete})


async def io(operation, characteristic, awaitable, size=None):
    """Count API attempts/completions; Read Blob and ATT PDUs stay unknown."""
    recorder = _active.get()
    if recorder is None:
        return await awaitable
    row = {"operation": operation, "characteristic": characteristic,
           "start_ns": recorder.now(), "end_ns": None, "success": False,
           "value_bytes": size}
    recorder.gatt_operations.append(row)
    try:
        result = await awaitable
        if operation == "read":
            row["value_bytes"] = len(result)
        row["success"] = True
        return result
    finally:
        row["end_ns"] = recorder.now()


def notification_callback(callback):
    recorder = _active.get()
    if recorder is None:
        return callback

    def record(data):
        now = recorder.now()
        recorder.gatt_operations.append({"operation": "notification",
            "characteristic": "data", "start_ns": now, "end_ns": now,
            "success": True, "value_bytes": len(data)})

    if inspect.iscoroutinefunction(callback):
        @wraps(callback)
        async def async_callback(sender, data):
            record(data)
            return await callback(sender, data)
        return async_callback

    @wraps(callback)
    def sync_callback(sender, data):
        record(data)
        return callback(sender, data)
    return sync_callback


def bind_async(callback):
    """Retain measurement context across WinRT's external-thread UI callback."""
    recorder = _active.get()
    if recorder is None:
        return callback

    @wraps(callback)
    async def bound(*args, **kwargs):
        with recorder.activate():
            return await callback(*args, **kwargs)
    return bound
