"""Convenience launcher for local development."""

import uvicorn


if __name__ == "__main__":
    # A single process is more reliable for the VS Code local-run workflow.
    # Stop it manually with Ctrl+C when you are finished.
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)
