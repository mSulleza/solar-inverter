"""
Root is used only to bind the listeners and set up pf/sysctl; network input is
always handled as the user who ran sudo.

check_invocation() runs first: started as root, we must know which user to
become (sudo sets SUDO_UID/SUDO_GID), otherwise we refuse to run at all.
drop() then switches to that user for good -- supplementary groups cleared, gid
then uid, and a check that root can't be regained.
"""

from __future__ import annotations

import logging
import os
from typing import Mapping, Optional

log = logging.getLogger("privs")


def sudo_ids(euid: Optional[int] = None,
             env: Optional[Mapping[str, str]] = None) -> Optional[tuple[int, int]]:
    """
    (uid, gid) to drop to if running as root, None if not root.

    Raises SystemExit if running as root without a SUDO_UID/SUDO_GID naming a
    normal user (a root login shell, `sudo -u root` from root, a launchd job...).
    """
    euid = os.geteuid() if euid is None else euid
    env = os.environ if env is None else env
    if euid != 0:
        return None
    uid, gid = env.get("SUDO_UID", ""), env.get("SUDO_GID", "")
    if not (uid.isdigit() and gid.isdigit()) or int(uid) == 0:
        raise SystemExit(
            "refusing to run as root without SUDO_UID/SUDO_GID of a normal user: "
            "start it with sudo from your own account (root is only used to bind "
            "ports and set up pf, then dropped)"
        )
    return int(uid), int(gid)


def drop(ids: Optional[tuple[int, int]]) -> None:
    """Permanently become (uid, gid). No-op when ids is None (not running as root)."""
    if ids is None:
        return
    uid, gid = ids
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise SystemExit("privilege drop failed: could regain root")
    if os.geteuid() == 0 or os.getegid() != gid:
        raise SystemExit("privilege drop failed")
    log.info("dropped root; now running as uid=%d gid=%d", uid, gid)
