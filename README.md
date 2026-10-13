# TraceWeaver AI — Phase 1 Starter

TraceWeaver AI is a digital incident reconstruction prototype. This starter version loads CSV/JSON security logs, normalises fields, displays a timeline, and builds candidate relationships using transparent rules.

**Important:** The current version does not yet contain the Generative AI agents or RAG pipeline. It is the working foundation for later phases. Relationship candidates do not prove causation or a cyberattack.

## Requirements

- Python 3.9 or newer (Python 3.11 is recommended if available)
- VS Code
- Internet connection for installing packages

## Windows setup in VS Code

1. Extract the ZIP file.
2. Open the extracted `TraceWeaver_AI_Starter` folder in VS Code.
3. Select **Terminal → New Terminal**.
4. Create a virtual environment:

   ```powershell
   py -m venv .venv
   ```

5. Activate it:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, run the commands using the environment's Python directly:
   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe -m streamlit run app.py
   ```

6. Install dependencies:

   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

7. Start the app:

   ```powershell
   python -m streamlit run app.py
   ```

8. Open the local URL shown in the terminal, usually `http://localhost:8501`.

## Test

```powershell
python -m pytest -q
```

## Input format

The application expects event records with these fields (some missing columns are created as blank, but timestamps and event types are needed for useful analysis):

- `event_id`
- `timestamp`
- `source`
- `event_type`
- `user`
- `device`
- `ip_address`
- `description`

The included `data/sample_security_logs.csv` uses synthetic data and is safe for demonstration.

## Roadmap

- Phase 1: log upload, normalisation, validation, timeline and heuristic event graph.
- Phase 2: stronger correlation and evidence IDs.
- Phase 3: specialised AI agent workflow and structured LLM output.
- Phase 4: RAG over trusted cybersecurity documentation.
- Phase 5: labelled synthetic incident benchmark and comparison against a single-LLM baseline.
- Phase 6: report export, hardening and deployment.

## Security notes

- Do not upload real production logs or sensitive personal data to this prototype.
- Do not add API keys to source files or commit `.env`.
- The timeline is descriptive. Shared identifiers and nearby timestamps can suggest relationships, but do not establish causation.
