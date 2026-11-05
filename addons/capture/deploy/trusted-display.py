import os
import signal
import subprocess
import time
from pathlib import Path


def main():
    os.environ.update(DISPLAY=":99", HOME="/home/recorder", XDG_RUNTIME_DIR="/session")
    display = subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1280x720x24", "-nolisten", "tcp"])
    window_manager = None
    service = None
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True
        if service:
            service.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for _ in range(100):
            if display.poll() is not None or stopping:
                raise RuntimeError("Display exited")
            if Path("/tmp/.X11-unix/X99").exists():
                break
            time.sleep(.1)
        else:
            raise RuntimeError("Display did not become ready")
        window_manager = subprocess.Popen(["openbox"])
        service = subprocess.Popen(["python", "-m", "tgwitness_capture", "serve", "--data", "/data",
                                    "--config", "/config.json", "--host", "0.0.0.0", "--port", "8793"])
        while service.poll() is None:
            if display.poll() is not None or window_manager.poll() is not None:
                stop()
            time.sleep(.25)
        raise SystemExit(service.returncode)
    finally:
        for process in (service, window_manager, display):
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()
