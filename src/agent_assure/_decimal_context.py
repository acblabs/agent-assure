from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    DivisionByZero,
    InvalidOperation,
    Overflow,
    localcontext,
)
from functools import wraps
from typing import ParamSpec, TypeVar

_LIVE_DECIMAL_PRECISION = 34
_LIVE_DECIMAL_EMIN = -999_999
_LIVE_DECIMAL_EMAX = 999_999
_P = ParamSpec("_P")
_R = TypeVar("_R")


def live_decimal_context(
    *, precision: int = _LIVE_DECIMAL_PRECISION
) -> AbstractContextManager[Context]:
    """Return the deterministic Decimal context used by live calculations."""

    return localcontext(
        Context(
            prec=precision,
            rounding=ROUND_HALF_EVEN,
            Emin=_LIVE_DECIMAL_EMIN,
            Emax=_LIVE_DECIMAL_EMAX,
            capitals=1,
            clamp=0,
            flags=[],
            traps=[DivisionByZero, InvalidOperation, Overflow],
        )
    )


def with_live_decimal_context(function: Callable[_P, _R]) -> Callable[_P, _R]:
    """Run one complete live calculation without consulting caller Decimal state."""

    @wraps(function)
    def wrapped(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        with live_decimal_context():
            return function(*args, **kwargs)

    return wrapped
