import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))


def pytest_addoption(parser):
    parser.addoption("--capture-browser", action="store_true", help="Run the real local Chromium capture test")
    parser.addoption("--capture-ffmpeg", default=None, help="Path to FFmpeg for the real video tests")
