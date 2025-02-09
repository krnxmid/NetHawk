import py_cui
import sys
import io
from network_recon import WifiRecon

class WifiScannerUI:
    def __init__(self, master):
        self.master = master
        self.master.set_title("Wi-Fi Scanner - NetHawk")
        
        # UI Elements
        self.output_box = self.master.add_text_block("Scan Output", 0, 0, row_span=6, column_span=6)
        self.scan_button = self.master.add_button("Run Scan", 6, 0, command=self.run_scan)
        self.exit_button = self.master.add_button("Exit", 6, 2, command=self.exit_app)

    def capture_output(self, func):
        """ Capture print output from a function """
        buffer = io.StringIO()
        sys.stdout = buffer
        try:
            func()  # Run scan
        finally:
            sys.stdout = sys.__stdout__  # Restore stdout
        return buffer.getvalue()

    def run_scan(self):
        self.output_box.set_text("Scanning...\n")
        wifirecon = WifiRecon()
        result = self.capture_output(wifirecon.scan_wifi)
        self.output_box.set_text(result)

    def exit_app(self):
        self.master.stop()

if __name__ == "__main__":
    root = py_cui.PyCUI(8, 6)  # Grid size (rows, cols)
    app = WifiScannerUI(root)
    root.start()
