"""
Base module interface and registration system for ReconForge.
All scan modules inherit from BaseModule and register via @register_module.
"""
from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from .context import ScanContext

logger = logging.getLogger(__name__)

# Module registry
_REGISTRY: dict[str, type["BaseModule"]] = {}


def register_module(cls: type["BaseModule"]) -> type["BaseModule"]:
    """Decorator to register a module class by its NAME attribute."""
    name = getattr(cls, "NAME", None)
    if not name:
        raise ValueError(f"Module {cls.__name__} must define a NAME class attribute")
    _REGISTRY[name] = cls
    return cls


def get_registry() -> dict[str, type["BaseModule"]]:
    """Return the global module registry."""
    return dict(_REGISTRY)


@dataclass
class ModuleResult:
    """Standardized return type from module.run()."""
    module_name: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    provides: dict[str, Any] = field(default_factory=dict)


class BaseModule(ABC):
    """
    Abstract base class for all ReconForge modules.

    Subclasses must define:
      NAME: str          - Unique module identifier
      REQUIRES: set[str] - Data keys this module needs from context
      PROVIDES: set[str] - Data keys this module produces
    """

    NAME: str = ""
    REQUIRES: set[str] = set()
    PROVIDES: set[str] = set()
    DESCRIPTION: str = ""
    ENABLED_BY_DEFAULT: bool = True

    def __init__(self, ctx: "ScanContext"):
        self.ctx = ctx
        self.logger = logging.getLogger(f"reconforge.modules.{self.NAME}")

    @abstractmethod
    async def run(self) -> ModuleResult:
        """Execute the module and return results."""
        raise NotImplementedError

    async def safe_run(self) -> ModuleResult:
        """Wrapper that catches all exceptions to ensure fail-soft behavior."""
        try:
            result = await self.run()
            await self.ctx.store.add_module(self.NAME)
            return result
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.error(f"Module {self.NAME} failed: {e}", exc_info=True)
            return ModuleResult(
                module_name=self.NAME,
                success=False,
                errors=[str(e)],
            )

    def _make_finding_id(self, suffix: str) -> str:
        """Generate a deterministic finding ID."""
        return f"{self.NAME}-{suffix}"
