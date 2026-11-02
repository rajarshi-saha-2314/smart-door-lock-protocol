from __future__ import annotations

from pathlib import Path

import pytest

from admin.register_door import register_door
from admin.register_user import register_user
from admin.setup_system import setup_system
from common.config import Config, load_config

PASSWORDS = {"fac01": "Faculty#Pass1", "stu01": "Student#Pass1", "cr01": "Cr#Pass1", "adm01": "Admin#Pass1"}


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    """A freshly set-up system (Phase 0) in a temp dir, with fast I/O timeouts."""
    c = load_config(data_dir=tmp_path, io_timeout_s=2.0)
    assert setup_system(c)
    return c


@pytest.fixture
def world(cfg: Config) -> Config:
    """Two doors and four users registered (Phases 1 and 2). Ports are assigned by the tests."""
    register_door(cfg, "CSE-101", port=0)
    register_door(cfg, "CSE-102", port=0)
    register_user(cfg, "fac01", PASSWORDS["fac01"], "faculty")
    register_user(cfg, "stu01", PASSWORDS["stu01"], "student", "CSE-4A")
    register_user(cfg, "cr01", PASSWORDS["cr01"], "cr", "CSE-4A")
    register_user(cfg, "adm01", PASSWORDS["adm01"], "admin")
    return cfg
