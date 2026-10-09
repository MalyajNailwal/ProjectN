# Five-minute local review

This walkthrough uses a website fixture in this repository, so it does not need a public scanning target or scanner binaries.

1. Clone or fork ProjectN and run the platform-specific quick start in [README.md](../README.md). Leave the ProjectN app running at `http://127.0.0.1:8000`.
2. Open another terminal in the ProjectN directory and serve the included fixture:

   macOS:

   ```sh
   .venv/bin/python -m http.server 8766 --bind 127.0.0.1 --directory tests/fixtures/site
   ```

   Windows PowerShell:

   ```powershell
   .\.venv\Scripts\python.exe -m http.server 8766 --bind 127.0.0.1 --directory tests\fixtures\site
   ```

3. In the ProjectN dashboard, scan `http://127.0.0.1:8766/` with the **Standard** profile. The report shows observed results and limitations for scanner runtimes that have not been installed. The report can be exported as JSON.
4. Visit `http://127.0.0.1:8000/api/scanners` to see exactly which scanner capabilities are ready. For code scanning, select a local folder or a public GitHub repository; that requires the relevant source scanners installed through the full setup.

The fixture is deliberately small. It demonstrates the scan workflow and report structure; it is not evidence that every website issue is detected. Full mode performs intrusive checks and requires authorization for the target.
