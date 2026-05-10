import sys
import os
import threading
import time
import uvicorn
from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QFileDialog
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineDownloadRequest
from PyQt6.QtCore import QUrl, QSize, Qt

# Resource path helper
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Import the server app
sys.path.append(resource_path('.'))
try:
    from server import app as fast_api_app
except ImportError:
    from fastapi import FastAPI
    fast_api_app = FastAPI()

def run_server():
    """Run uvicorn in a thread with logging"""
    base = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else "."
    log_path = os.path.join(base, "backend_debug.log")
    try:
        with open(log_path, "a") as f:
            f.write(f"\n--- {time.ctime()} Initializing SecureFS Backend ---\n")
            f.write(f"Binding to 127.0.0.1:8443\n")
        uvicorn.run(fast_api_app, host="127.0.0.1", port=8443, log_level="info")
    except Exception as e:
        with open(log_path, "a") as f:
            f.write(f"FATAL SERVER ERROR: {str(e)}\n")

class SecureFSApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('SecureFS v2 | Enterprise Grade Zero-Knowledge Storage')
        self.resize(1280, 850)
        
        # Center window
        screen = QApplication.primaryScreen().availableGeometry()
        self.move((screen.width() - 1280) // 2, (screen.height() - 850) // 2)
        
        # Web View
        self.browser = QWebEngineView()
        self.browser.setStyleSheet("background-color: #09090b;")
        
        # ENABLE DOWNLOADS
        self.browser.page().profile().downloadRequested.connect(self.on_download_requested)
        
        # Load the UI from the server directly
        self.browser.setUrl(QUrl("http://127.0.0.1:8443"))
        
        # UI Layout
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.browser)
        
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def on_download_requested(self, download: QWebEngineDownloadRequest):
        """Handles file download requests from the browser"""
        path, _ = QFileDialog.getSaveFileName(self, "Save File", download.suggestedFileName())
        if path:
            download.setDownloadDirectory(os.path.dirname(path))
            download.setDownloadFileName(os.path.basename(path))
            download.accept()

if __name__ == '__main__':
    # Fix for PyInstaller
    import multiprocessing
    multiprocessing.freeze_support()

    # Start server thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    # Start GUI
    qt_app = QApplication(sys.argv)
    qt_app.setApplicationName("SecureFS")
    
    window = SecureFSApp()
    window.show()
    sys.exit(qt_app.exec())
