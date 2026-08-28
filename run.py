import threading
import webbrowser
import uvicorn

URL = "http://127.0.0.1:8000"


def open_browser():
    webbrowser.open(URL)


if __name__ == "__main__":
    threading.Timer(1.5, open_browser).start()

    print()
    print("=" * 50)
    print("        CyberAudit Web Platform")
    print("=" * 50)
    print()
    print(f"  Server: {URL}")
    print()
    print("  Browser will open automatically...")
    print()
    print("  Press Ctrl+C to stop the server.")
    print()

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )