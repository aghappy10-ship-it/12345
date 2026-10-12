"""Four exact-owned cleanup streams, never discovery or removal authorization.

Only fixed cleanup producers supply paths and commands. This local source
adapter retains the native qualification refusal and original USB deadline.
"""
import time

from . import menu_owned_cleanup as cleanup, menu_preplacement_transport as transport
from . import menu_maintenance_boundary as files


def review_cleanup_host_source(manifest, raw_session, original_identities, stock_readback, restore_receipt,
                               *, launch_started_utc):
    coordinator = cleanup.CleanupCoordinator(manifest, raw_session, original_identities,
        stock_readback, restore_receipt)
    commands = []
    raw_sha = transport._sha(raw_session)
    for index, digest in enumerate(coordinator.worker_hashes):
        path = cleanup.worker_path(manifest, raw_session, index)
        commands.append(f'set -eu; x=$(sha256sum {path}); [ "${{x%% *}}" = {digest} ]; '
            f'sh {path} {files.session_path(manifest, raw_sha)} {raw_sha}')
    return transport._review_fixed_host_source(manifest, raw_session, launch_started_utc=launch_started_utc,
        commands=commands, program_hashes=coordinator.worker_hashes, cleanup_profile="owned-cleanup")


def drive_cleanup_process(process, manifest, raw_session, original_identities, stock_readback, restore_receipt,
                         maintenance_session, *, clock=time.time):
    coordinator = cleanup.CleanupCoordinator(manifest, raw_session, original_identities,
        stock_readback, restore_receipt)
    return transport._drive_fixed_worker_process(process, manifest, raw_session, maintenance_session,
        coordinator=coordinator, clock=clock, cleanup_profile="owned-cleanup")
