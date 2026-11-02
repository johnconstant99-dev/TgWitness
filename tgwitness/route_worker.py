import os
import subprocess
import sys
import threading


def main():
    closed = threading.Event()

    def watch_parent():
        try:
            while sys.stdin.buffer.read(1):
                pass
        finally:
            closed.set()

    threading.Thread(target=watch_parent, daemon=True).start()
    child = subprocess.Popen(sys.argv[1:], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, shell=False,
                             creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    try:
        while child.poll() is None and not closed.wait(.2):
            pass
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == "__main__":
    main()
