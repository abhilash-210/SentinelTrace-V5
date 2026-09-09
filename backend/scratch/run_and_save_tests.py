import subprocess
import os

def run():
    out_path = "d:/SIH 2026/SENTINEL-TRACE/evidence/sprint-08b/logs/09_full_regression_tests.log"
    cmd = [r"d:\SIH 2026\SENTINEL-TRACE\backend\.venv\Scripts\python.exe", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"]
    res = subprocess.run(cmd, cwd=r"d:\SIH 2026\SENTINEL-TRACE\backend", capture_output=True, text=True, encoding="utf-8")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(res.stdout + "\n" + res.stderr)
    print("Return code:", res.returncode)

if __name__ == "__main__":
    run()
