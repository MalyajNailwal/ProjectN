# Five-minute local review

This walkthrough scans a small website bundled in this repository, so it needs no public target. It works with only the [quick start](../README.md#quick-start-app-and-dashboard-a-few-minutes) installed; scanners that are not set up appear as explicit coverage gaps instead of silent passes.

1. **Start ProjectN** from the repository folder and leave it running:

   ```sh
   .venv/bin/python scripts/run_local.py                 # macOS
   ```

   ```powershell
   .\.venv\Scripts\python.exe scripts\run_local.py       # Windows PowerShell
   ```

2. **Serve the bundled test site** in a second terminal:

   ```sh
   .venv/bin/python -m http.server 8766 --bind 127.0.0.1 --directory tests/fixtures/site
   ```

   ```powershell
   .\.venv\Scripts\python.exe -m http.server 8766 --bind 127.0.0.1 --directory tests\fixtures\site
   ```

3. **Check readiness.** Open `http://127.0.0.1:8000` and the **Tool setup** page, or run `python scripts/doctor.py` with the environment's Python. Each missing scanner shows why and the command to fix it.

4. **Run a Standard scan** of `http://127.0.0.1:8766/`. The *Current assessment* card shows the share of steps finished, the step running now with its elapsed time, and *What is happening now* lists every planned step with its outcome.

5. **Read the report.** *Findings* shows evidence, severity, remediation, and how to verify the fix. *Coverage* lists every stage and each limitation with a concrete next action, for example that template checks were not selected, the site uses HTTP, or source code was not supplied. *Coverage → Export JSON* downloads the report.

6. **Stop a scan.** Choose **Deep** (or **Full** after confirming authorization) and launch again. While a step is running, press **Stop scan**: the running scanner and its child processes are terminated, the status becomes *Cancelled*, and the partial report marks the steps that did not run.

7. **Rescan and compare.** Run the Standard scan once more. *Findings* shows whether earlier findings are still present, not observed on rescan, or not verifiable because the same check did not complete again.

8. **Optional: scan code.** Enter a local folder (for example the ProjectN folder itself) or a public GitHub URL. Source analysis, secret detection, and dependency checks need the full scanner setup.

The test site is deliberately tiny. It demonstrates the workflow, progress, and report structure; it is not evidence that every website issue is detected. Full mode performs intrusive checks and requires authorization for the target.

The same flow runs unattended: `python scripts/smoke_local.py` starts the app on a free port with a temporary data folder, scans the test site, and prints each stage's outcome.
