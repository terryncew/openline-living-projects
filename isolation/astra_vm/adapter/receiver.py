"""Production entrypoint: strict RC5 adapter and independently running validator."""
import argparse
import os
import signal
import threading


def validate_production_entrypoint(cfg):
    if (
        cfg.get('allow_single_uid_test_harness')
        or cfg.get('allow_enosys_openat2_fallback')
        or cfg.get('require_native_openat2') is False
        or os.getuid() == 0
        or os.geteuid() == 0
        or os.getgid() == 0
        or os.getegid() == 0
    ):
        raise PermissionError('production refuses root/single-UID/fallback harness')
    if cfg.get('validator_uid') in (0, os.getuid(), os.geteuid()):
        raise PermissionError('production requires distinct non-root validator_uid')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--rc5', required=True)
    p.add_argument('--config', required=True)
    p.add_argument('--validator-socket', required=True)
    a = p.parse_args()
    from rc5_paths import load
    load(a.rc5)
    from production_config import load_production_config
    from receiver_service import OpenLineReceiverService
    from validator import SocketValidationRunner
    import durable_io

    cfg = load_production_config(a.config)
    validate_production_entrypoint(cfg)
    # Kernel probe exercises an existing receiver file before keys/DBs are loaded.
    fd = durable_io.open_beneath(cfg['paths']['root_dir'], 'keys/receiver.key', require_native_openat2=True)
    os.close(fd)
    runner = SocketValidationRunner(
        a.validator_socket,
        cfg['validator_uid'],
        cfg['paths']['validator_script'],
        allow_single_uid_test_harness=False,
        require_native_openat2=True,
    )
    service = OpenLineReceiverService(
        cfg,
        validation_runner=runner,
        require_distinct_uids=True,
        require_systemd_hardening=True,
    )
    runner.abort_check = service._should_abort_validation
    event = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: event.set())
    service.start_background()
    try:
        event.wait()
    finally:
        service.stop()


if __name__ == '__main__':
    main()
