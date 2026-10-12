"""Fixed renderer -> binary-pipe host children with specific admission only.

Review hosts compile only exact closed sources. The separate first-validation
host admits only its complete specific session, not a boolean or supplied code.
No caller selects shell text or a C# method.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
import re
import subprocess
import tempfile

from . import menu_content_transport as content, menu_preplacement_transport as placement


class _Child:
    def __init__(self, process, directory, source_path, source_sha256):
        self._process, self._directory = process, directory
        self.source_path, self.source_sha256 = source_path, source_sha256
        self.stdin, self.stdout, self.stderr = process.stdin, process.stdout, process.stderr

    @property
    def returncode(self):
        return self._process.returncode

    def poll(self):
        return self._process.poll()

    def terminate(self):
        self._process.terminate()

    def wait(self, timeout=None):
        result = self._process.wait(timeout=timeout)
        self._directory.cleanup()
        return result

    def communicate(self, *args, **kwargs):
        result = self._process.communicate(*args, **kwargs)
        self._directory.cleanup()
        return result

    def close(self):
        if self.poll() is None:
            self.terminate()
        self.wait(timeout=5)
        for pipe in (self.stdin, self.stdout, self.stderr):
            pipe.close()


def _spawn_fixed(source, *, prefix, entry, closed_guard):
    # Names come only from the fixed producer selected below, never a CLI field.
    matches = re.findall(r"^namespace (" + re.escape(prefix) + r"[0-9a-f]{16})\s*\{?\s*$", source, re.MULTILINE)
    if len(matches) != 1 or source.count(closed_guard) != 1:
        raise ValueError("fixed renderer namespace/guard differs")
    directory = tempfile.TemporaryDirectory(prefix="x2dii-fixed-host-")
    path = Path(directory.name) / "FixedHost.cs"
    raw = source.encode("utf-8")
    digest = content._sha(raw)
    try:
        path.write_bytes(raw)
        escaped = str(path).replace("'", "''")
        script = ("$ErrorActionPreference='Stop';"
            "try{"
            f"$fixedBytes=[IO.File]::ReadAllBytes('{escaped}');"
            "$fixedHasher=[Security.Cryptography.SHA256]::Create();"
            "$fixedHash=[BitConverter]::ToString($fixedHasher.ComputeHash($fixedBytes)).Replace('-','').ToLowerInvariant();"
            "$fixedHasher.Dispose();"
            f"if($fixedHash -ne '{digest}')"
            "{throw 'FIXED_HOST_SOURCE_CHANGED'};"
            "Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString($fixedBytes));"
            f"[{matches[0]}.AdbUsbCheck]::{entry}()"
            "}catch{[Console]::Error.WriteLine($_.Exception.ToString());exit 1}")
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        process = subprocess.Popen(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
            "-EncodedCommand", encoded], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return _Child(process, directory, path, digest)
    except Exception:
        directory.cleanup()
        raise


class FixedContentHost:
    def __init__(self, plan, session, launch):
        self.plan, self.session, self.launch = deepcopy(plan), deepcopy(session), launch
        # Validate through the exact producer before any host process or file.
        content.review_content_host_source(self.plan, self.session, self.launch)
        self._attempted = False

    def start(self, phase, source):
        if self._attempted or phase != "stable-content":
            raise ValueError("fixed content child repeated or phase sequence differs")
        expected = content.review_content_host_source(self.plan, self.session, self.launch)
        if type(source) is not str or source != expected:
            raise ValueError("child differs from fixed generated source")
        self._attempted = True
        return _spawn_fixed(source, prefix="X2d2ContentStage_", entry="RunContentStage",
            closed_guard="private static readonly bool ContentQualified = false;")


class FixedPreparedHost:
    def __init__(self, preparation, launch):
        content._validate_preparation(preparation)
        if preparation.purpose not in ("temporary_menu_preparation", "temporary_menu_ready"):
            raise ValueError("only fixed first menu preparation/ready children are supported")
        self.preparation, self.launch = deepcopy(preparation), launch
        content.review_preparation_host_source(self.preparation, launch)
        self._index, self._failed = 0, False

    def start(self, phase, source):
        sequence = ("preparation", "menu-preplacement") if self.preparation.purpose == "temporary_menu_ready" else ("preparation",)
        if self._failed or self._index >= len(sequence) or phase != sequence[self._index]:
            raise ValueError("fixed prepared child failed, repeated or phase sequence differs")
        if phase == "preparation":
            expected = content.review_preparation_host_source(self.preparation, self.launch)
            prefix, entry, flag = "X2d2ContentStage_", "RunContentStage", "ContentQualified"
        else:
            expected = placement.review_host_source(json.loads(self.preparation.manifest_bytes),
                self.preparation.raw_session, launch_started_utc=self.launch)
            prefix, entry, flag = "X2d2MenuPreplace_", "RunFourFiles", "SupervisionQualified"
        if type(source) is not str or source != expected:
            raise ValueError("child differs from fixed generated source")
        self._index += 1  # A failed/lost host launch is never retried.
        try:
            return _spawn_fixed(source, prefix=prefix, entry=entry,
                closed_guard=f"private static readonly bool {flag} = false;")
        except Exception:
            self._failed = True
            raise


class FirstValidationHost:
    """Only the specific externally approved temporary-menu object may admit.

    No boolean approval or arbitrary command/entry is accepted. Revalidation
    and exact-source reconstruction occur inside that object's fixed phase,
    immediately before this same binary-pipe child boundary.
    """
    def __init__(self, validation):
        from .menu_first_validation import FirstValidationSession
        if type(validation) is not FirstValidationSession:
            raise ValueError("specific complete first-validation session required")
        self._validation = validation

    def start(self, phase, source):
        fixed, prefix, entry, guard = self._validation._native_source(phase, source)
        return _spawn_fixed(fixed, prefix=prefix, entry=entry, closed_guard=guard)
