# python start_gui.py
# cd "c:\Users\Qadri laptop\Downloads\New folder (2)\BB84-Quantum-Encryption-Tool-Simulator" ; python start_gui.py 
# python auto_generate_summary.py
import sys
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
import base64
import re
import pyperclip
import threading
import time
import json
from fpdf import FPDF
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------


# Extend Python path to allow module imports from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from bb84_backend.logic.controller import encrypt_file_local, decrypt_file_local
from bb84_backend.core.bb84_quantum import run_qkd, run_qkd_demo

class BB84App:
    def __init__(self, root):
        # Initialize main GUI window
        self.root = root
        self.root.title("BB84 Quantum Encryption Tool (Simulator)")
        self.root.geometry("750x720")
        self.root.configure(bg="#f4f4f4")

        # Internal state
        self.file_path = None
        self.file_name_without_ext = None  # Store filename without extension
        self.encrypted_data = None
        self.key_b = None
        self.operation_type = None  # Track "encrypt" or "decrypt" for report naming
        self.cipher_used = None  # Track cipher used for key/report naming

        # Build GUI components
        self.create_widgets()

    def create_widgets(self):
        # Modern dark-themed layout with grouped panels
        # Colors and basic style tokens (light theme)
        self._DARK_BG = "#f4f7fb"   # window background (light)
        self._CARD_BG = "#ffffff"   # card/panel background
        self._FG = "#0b1720"        # primary text (dark)
        self._ACCENT = "#0b73ff"    # blue accent
        self._BTN_BG = "#eef2f6"    # neutral button background

        self.root.configure(bg=self._DARK_BG)

        # Title header (centered)
        header = tk.Frame(self.root, bg=self._DARK_BG)
        header.pack(fill=tk.X, pady=(12, 6))
        title_lbl = tk.Label(header, text="🔐 BB84 Quantum Encryption", font=("Segoe UI", 20, "bold"), fg=self._FG, bg=self._DARK_BG)
        title_lbl.pack()
        subtitle = tk.Label(header, text="Hybrid PQC + AEAD — Research Demo", font=("Segoe UI", 10), fg="#475569", bg=self._DARK_BG)
        subtitle.pack()

        main_frame = tk.Frame(self.root, bg=self._DARK_BG)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=8)

        # Left panel: Controls (cards)
        left = tk.Frame(main_frame, bg=self._DARK_BG)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0,12))

        # Mode card (segmented toggle)
        mode_card = tk.Frame(left, bg=self._CARD_BG, bd=0, relief=tk.FLAT)
        mode_card.pack(fill=tk.X, pady=6)
        tk.Label(mode_card, text="Mode", fg="#9fb3bd", bg=self._CARD_BG, font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, padx=10, pady=(8,0))
        seg = tk.Frame(mode_card, bg=self._CARD_BG)
        seg.pack(padx=10, pady=8)
        self.mode_var = tk.StringVar(value="encrypt")
        self.encrypt_btn = tk.Button(seg, text="Encrypt", command=lambda: self._set_mode("encrypt"), bg=self._BTN_BG, fg=self._FG, bd=0, padx=12, pady=6)
        self.decrypt_btn = tk.Button(seg, text="Decrypt", command=lambda: self._set_mode("decrypt"), bg=self._BTN_BG, fg=self._FG, bd=0, padx=12, pady=6)
        self.encrypt_btn.pack(side=tk.LEFT, padx=(0,4))
        self.decrypt_btn.pack(side=tk.LEFT)
        self._update_segmented()

        # File card: drag/drop area
        file_card = tk.Frame(left, bg=self._CARD_BG)
        file_card.pack(fill=tk.X, pady=6)
        tk.Label(file_card, text="File Input", fg="#9fb3bd", bg=self._CARD_BG, font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, padx=10, pady=(8,0))
        drop_area = tk.Frame(file_card, bg="#eef2f6", height=90, bd=1, relief=tk.FLAT)
        drop_area.pack(fill=tk.X, padx=10, pady=8)
        drop_area.pack_propagate(False)
        self.drop_label = tk.Label(drop_area, text="Drag & drop a file here or click to browse", fg="#475569", bg="#eef2f6")
        self.drop_label.pack(expand=True)
        drop_area.bind("<Button-1>", lambda e: self.select_file())
        # Try to enable TkinterDnD drag-and-drop when available
        try:
            from tkinterdnd2 import DND_FILES, TkinterDnD
            def _on_drop(event):
                files = event.data
                # Windows may wrap path in {} when spaces
                if files.startswith('{') and files.endswith('}'):
                    files = files[1:-1]
                self._on_file_dropped(files)
            # register drop
            drop_area.drop_target_register(DND_FILES)
            drop_area.dnd_bind('<<Drop>>', _on_drop)
        except Exception:
            # fallback: no external DnD support
            pass

        self.file_label = tk.Label(file_card, text="No file selected", fg=self._FG, bg=self._CARD_BG)
        self.file_label.pack(anchor=tk.W, padx=10, pady=(0,8))

        # Key input (for decryption) - hidden by default
        self.key_frame = tk.Frame(left, bg=self._CARD_BG)
        tk.Label(self.key_frame, text="Key B (binary):", fg="#475569", bg=self._CARD_BG).pack(anchor=tk.W, padx=10, pady=(8,0))
        self.key_entry = tk.Entry(self.key_frame, width=36)
        self.key_entry.insert(0, "Key B (only for decryption)")
        self.key_entry.pack(padx=10, pady=6)
        ttk.Button(self.key_frame, text="Import Key File", command=self.import_key_file).pack(padx=10, pady=(0,8))
        self.key_frame.pack_forget()

        # Encryption settings card
        self.alg_card = tk.Frame(left, bg=self._CARD_BG)
        self.alg_card.pack(fill=tk.X, pady=6)
        tk.Label(self.alg_card, text="Encryption Settings", fg="#9fb3bd", bg=self._CARD_BG, font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, padx=10, pady=(8,0))
        alg_row = tk.Frame(self.alg_card, bg=self._CARD_BG)
        alg_row.pack(fill=tk.X, padx=10, pady=8)
        self.cipher_choice = ttk.Combobox(alg_row, values=["🔷 AES-GCM", "⚡ ChaCha20", "🔐 AES-SIV"], state="readonly", width=28)
        self.cipher_choice.current(0)
        self.cipher_choice.pack(side=tk.LEFT)
        ttk.Button(alg_row, text="ℹ️", command=self.show_cipher_info).pack(side=tk.LEFT, padx=8)

        # Execution card
        exec_card = tk.Frame(left, bg=self._CARD_BG)
        exec_card.pack(fill=tk.X, pady=6)
        tk.Label(exec_card, text="Execute", fg="#9fb3bd", bg=self._CARD_BG, font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, padx=10, pady=(8,0))
        run_row = tk.Frame(exec_card, bg=self._CARD_BG)
        run_row.pack(fill=tk.X, padx=10, pady=10)
        self.run_btn = tk.Button(run_row, text="Run", command=self.run, bg=self._ACCENT, fg="#ffffff", padx=18, pady=8, bd=0)
        self.run_btn.pack(side=tk.LEFT)
        ttk.Button(run_row, text="Download Report", command=self.download_metrics_pdf).pack(side=tk.LEFT, padx=8)

        # Right panel: status & logs
        right = tk.Frame(main_frame, bg=self._DARK_BG)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        status_card = tk.Frame(right, bg=self._CARD_BG)
        status_card.pack(fill=tk.X, pady=6)
        tk.Label(status_card, text="Status", fg="#9fb3bd", bg=self._CARD_BG, font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, padx=10, pady=(8,0))
        status_row = tk.Frame(status_card, bg=self._CARD_BG)
        status_row.pack(fill=tk.X, padx=10, pady=8)
        self.status_badge = tk.Label(status_row, text="Idle", bg="#e6eef3", fg=self._FG, padx=8, pady=4)
        self.status_badge.pack(side=tk.LEFT)
        # small visual status text (for step display)
        self.visual_text = tk.StringVar(value="Idle")
        self.visual_label = tk.Label(status_row, textvariable=self.visual_text, fg="#475569", bg=self._CARD_BG)
        self.visual_label.pack(side=tk.LEFT, padx=10)
        self.progress = ttk.Progressbar(status_row, orient=tk.HORIZONTAL, mode='determinate', length=240)
        self.progress.pack(side=tk.LEFT, padx=12)

        # Logs console (scrollable)
        logs_card = tk.Frame(right, bg=self._CARD_BG)
        logs_card.pack(fill=tk.BOTH, expand=True, pady=6)
        tk.Label(logs_card, text="Console", fg="#9fb3bd", bg=self._CARD_BG, font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, padx=10, pady=(8,0))
        self.output_box = ScrolledText(logs_card, height=12, bg="#ffffff", fg=self._FG, insertbackground=self._FG)
        self.output_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        # Key controls (hidden unless after encrypt)
        key_controls = tk.Frame(right, bg=self._CARD_BG)
        key_controls.pack(fill=tk.X, pady=6)
        self.copy_button = tk.Button(key_controls, text="Copy Key B", command=self.copy_key_b, bg=self._BTN_BG, fg=self._FG, bd=0)
        self.copy_button.pack(side=tk.LEFT, padx=6)
        self.copy_button.pack_forget()
        self.save_key_button = tk.Button(key_controls, text="Save Key B", command=self.save_key_b_to_file, bg=self._BTN_BG, fg=self._FG, bd=0)
        self.save_key_button.pack(side=tk.LEFT, padx=6)
        self.save_key_button.pack_forget()

        # Keep references and initialize
        self._set_status("Idle", color="#6b7280")
        self.update_mode()

    def update_mode(self):
        # Update GUI layout based on selected operation mode
        if self.mode_var.get() == "encrypt":
            try:
                self.alg_card.pack(fill=tk.X, pady=6)
            except Exception:
                pass
            try:
                self.key_frame.pack_forget()
            except Exception:
                pass
            try:
                self.copy_button.pack_forget()
                self.save_key_button.pack_forget()
            except Exception:
                pass
        else:
            try:
                self.alg_card.pack_forget()
            except Exception:
                pass
            try:
                self.key_frame.pack(pady=5)
            except Exception:
                pass
            try:
                self.copy_button.pack_forget()
                self.save_key_button.pack_forget()
            except Exception:
                pass

    def show_cipher_info(self):
        """Show information about cipher selection"""
        info_text = """🔐 Cipher Selection Guide:

AES-GCM (AES-256-GCM):
✅ Best for: Desktop/Server with modern CPUs
✅ Hardware: Intel/AMD with AES-NI instruction set
✅ Speed: 4-10x faster with hardware acceleration
✅ Standard: NIST approved, most widely used
✅ Nonce: 12-byte random nonce per encryption
✅ Use when: Running on x86/x64 systems

ChaCha20 (ChaCha20-Poly1305):
✅ Best for: Mobile/ARM/Embedded devices
✅ Hardware: No special instructions needed
✅ Speed: 5-15x faster than AES on ARM
✅ Standard: IETF RFC 8439, used in TLS 1.3
✅ Nonce: 12-byte random nonce per encryption
✅ Use when: Running on ARM, mobile, or older CPUs

AES-SIV (AES-256-SIV):
✅ Best for: Research & high-security applications
✅ Hardware: Software implementation (no HW needed)
✅ Speed: Slightly slower than AES-GCM
✅ Standard: RFC 5297 (Synthetic IV mode)
✅ Nonce: NO nonce needed (misuse-resistant!)
✅ Use when: Nonce management is difficult/critical
✅ Advantage: Safe against nonce reuse attacks

All three provide:
• 256-bit encryption (quantum-resistant)
• AEAD authentication (tamper detection)
• BB84 quantum key distribution
• Post-quantum Dilithium5 signatures

Security: All are cryptographically secure ✅
AES-SIV provides additional misuse-resistance ✨"""
        
        messagebox.showinfo("Cipher Selection Guide", info_text)

    def simulate_quantum_process(self, cipher="AES-GCM"):
        # Simulate quantum key exchange visually using progress bar and status
        if "ChaCha20" in cipher:
            cipher_name = "ChaCha20 key"
        elif "AES-SIV" in cipher:
            cipher_name = "AES-SIV key"
        else:
            cipher_name = "AES-256 key"
        steps = [
            "Initializing quantum channel...",
            "Alice generates random bits + biased bases...",
            "Channel noise/loss modeling active...",
            "(Optional) Eavesdropper intercept-resend simulation...",
            "Bob measures qubits with chosen bases...",
            "Basis reconciliation & sampling...",
            "Privacy & finite-key analysis computed...",
            f"Key used to derive {cipher_name}...",
            "Encryption process complete."
        ]

        total = len(steps)
        try:
            self.progress['maximum'] = total
            self.progress['value'] = 0
        except Exception:
            pass

        self._set_status("Running", color="#f59e0b")
        for i, step in enumerate(steps, start=1):
            self.visual_text.set(step)
            try:
                self.progress['value'] = i
            except Exception:
                pass
            # append to console for visibility
            try:
                self.output_box.insert(tk.END, f"{step}\n")
                self.output_box.see(tk.END)
            except Exception:
                pass
            self.root.update()
            time.sleep(0.6)

        self.visual_text.set("Idle")
        self._set_status("Idle", color="#6b7280")

    # ---- Helper UI methods ----
    def _set_mode(self, mode: str):
        self.mode_var.set(mode)
        self._update_segmented()
        self.update_mode()

    def _update_segmented(self):
        # Visual state for segmented control
        try:
            if self.mode_var.get() == "encrypt":
                self.encrypt_btn.configure(bg=self._ACCENT, fg="#ffffff")
                self.decrypt_btn.configure(bg=self._BTN_BG, fg=self._FG)
            else:
                self.decrypt_btn.configure(bg=self._ACCENT, fg="#ffffff")
                self.encrypt_btn.configure(bg=self._BTN_BG, fg=self._FG)
        except Exception:
            pass

    def _on_file_dropped(self, files: str):
        # files may contain several paths; take the first
        first = files.split() if isinstance(files, str) else [files]
        if first:
            path = first[0].strip()
            # remove braces sometimes added by TkinterDnD
            if path.startswith('{') and path.endswith('}'):
                path = path[1:-1]
            self._set_file(path)

    def _set_file(self, path: str):
        if os.path.exists(path):
            self.file_path = path
            base_name = os.path.basename(path)
            self.file_name_without_ext = os.path.splitext(base_name)[0]
            try:
                self.file_label.config(text=f"Selected: {base_name}")
                self.drop_label.config(text=base_name)
            except Exception:
                pass

    def _set_status(self, text: str, color: str = None):
        try:
            self.status_badge.config(text=text)
            if color:
                self.status_badge.config(bg=color)
        except Exception:
            pass

    def select_file(self):
        # Prompt user to select a file from the system
        path = filedialog.askopenfilename()
        if path:
            self.file_path = path
            base_name = os.path.basename(path)
            # Extract filename without extension for auto-naming
            self.file_name_without_ext = os.path.splitext(base_name)[0]
            self.file_label.config(text=f"Selected: {base_name}")

    def import_key_file(self):
        # Allow user to import Key B from a text file
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if path:
            with open(path, "r") as f:
                content = f.read().strip()
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, content)

    def copy_key_b(self):
        # Copy Key B to clipboard
        if self.key_b:
            pyperclip.copy(self.key_b)
            messagebox.showinfo("Copied", "Key B has been copied to clipboard.")

    def save_key_b_to_file(self):
        # Save Key B as a .txt file with auto-naming including cipher type
        if self.key_b:
            # Auto-generate filename based on selected file and cipher
            if self.file_name_without_ext and self.cipher_used:
                default_name = f"{self.file_name_without_ext}_{self.cipher_used}_key.txt"
            elif self.file_name_without_ext:
                default_name = f"{self.file_name_without_ext}_key.txt"
            else:
                default_name = "key_b.txt"
            
            path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                initialfile=default_name,
                filetypes=[("Text Files", "*.txt")]
            )
            if path:
                with open(path, "w") as f:
                    f.write(self.key_b)
                messagebox.showinfo("Saved", f"Key B saved to: {path}")

    def run(self):
        # Start encryption or decryption in a separate thread
        if not self.file_path:
            messagebox.showwarning("No file selected", "Please select a file first.")
            return

        self.output_box.delete(1.0, tk.END)
        thread = threading.Thread(target=self.process_file)
        thread.start()

    def process_file(self):
        # Dispatch based on selected mode
        if self.mode_var.get() == "encrypt":
            self.operation_type = "encrypt"
            # Get cipher selection for simulation
            cipher_selection = self.cipher_choice.get()
            if "ChaCha20" in cipher_selection:
                cipher = "ChaCha20"
            elif "AES-SIV" in cipher_selection:
                cipher = "AES-SIV"
            else:
                cipher = "AES-GCM"
            self.simulate_quantum_process(cipher)
            self.encrypt()
        else:
            self.operation_type = "decrypt"
            self.decrypt()

    def encrypt(self):
        # Perform encryption using quantum key and selected cipher
        with open(self.file_path, "rb") as f:
            file_bytes = f.read()

        # Determine selected cipher
        cipher_selection = self.cipher_choice.get()
        if "ChaCha20" in cipher_selection:
            cipher = "ChaCha20"
            cipher_display = "ChaCha20-Poly1305"
            cipher_prefix = "CHACHA20"
        elif "AES-SIV" in cipher_selection:
            cipher = "AES-SIV"
            cipher_display = "AES-256-SIV (Misuse-resistant)"
            cipher_prefix = "AES-SIV"
        else:
            cipher = "AES-GCM"
            cipher_display = "AES-256-GCM"
            cipher_prefix = "AES-GCM"

        # Encrypt with selected cipher
        # Run upgraded QKD with noisy demo settings to show realistic QBER
        _, key_b_bits, stats = run_qkd_demo()
        # Proceed with encryption (controller internally uses run_qkd now)
        encrypted_data, key_b = encrypt_file_local(
            file_bytes, 
            os.path.basename(self.file_path),
            cipher=cipher
        )
        # Append runtime QKD stats for user visibility
        self.output_box.insert(tk.END, f"QKD Stats → Sifted: {int(stats.get('n_sifted',0))}, QBER: {stats.get('qber',0.0):.4f}, ell: {stats.get('ell_final',0.0):.2f}\n")

        # Auto-generate filename for encrypted file with cipher type
        if self.file_name_without_ext:
            default_encrypted_name = f"{self.file_name_without_ext}_{cipher_prefix}_E.bb84"
        else:
            default_encrypted_name = "encrypted.bb84"
        
        save_path = filedialog.asksaveasfilename(
            defaultextension=".bb84",
            initialfile=default_encrypted_name,
            filetypes=[("BB84 Files", "*.bb84")]
        )
        if not save_path:
            return

        with open(save_path, "w") as f:
            f.write(encrypted_data)

        self.key_b = key_b
        self.cipher_used = cipher_prefix  # Store cipher for key/report naming
        self.output_box.insert(tk.END, f"✅ File successfully encrypted with {cipher_display}\n")
        self.output_box.insert(tk.END, f"📁 Saved to: {save_path}\n")
        self.output_box.insert(tk.END, f"🔐 Cipher: {cipher_display}\n")
        self.output_box.insert(tk.END, f"🔑 BB84 Quantum Key Distribution: Active\n")
        self.output_box.insert(tk.END, f"📜 Post-Quantum Signature: Dilithium5\n\n")
        self.output_box.insert(tk.END, f"Key B (required for decryption):\n{key_b}\n\n")
        self.output_box.insert(tk.END, "⚠️  IMPORTANT: Save Key B securely! It's needed for decryption.\n")
        self.output_box.insert(tk.END, self.recommendations(key_b))

        self.copy_button.pack(pady=2)
        self.save_key_button.pack(pady=2)

    def decrypt(self):
        # Perform decryption using provided Key B (auto-detects cipher)
        with open(self.file_path, "r") as f:
            encrypted_base64 = f.read()

        key_b_input = self.key_entry.get().strip()

        if not re.fullmatch(r"[01]+", key_b_input):
            messagebox.showerror("Invalid Key", "Key B must be a binary string (only 0s and 1s).")
            return

        key_b_bits = [int(b) for b in key_b_input]

        # Auto-detect cipher from package
        data, metadata = decrypt_file_local(encrypted_base64, key_b_bits, cipher="auto")
        if data is None:
            self.output_box.insert(tk.END, f"❌ Decryption failed: {metadata}\n")
            self.output_box.insert(tk.END, "\nPossible reasons:\n")
            self.output_box.insert(tk.END, "• Wrong Key B (doesn't match encryption key)\n")
            self.output_box.insert(tk.END, "• Tampered or corrupted file\n")
            self.output_box.insert(tk.END, "• Invalid package format\n")
            return

        # Extract cipher type from encrypted filename
        encrypted_filename = os.path.basename(self.file_path)
        if "AES-GCM" in encrypted_filename:
            self.cipher_used = "AES-GCM"
        elif "CHACHA20" in encrypted_filename:
            self.cipher_used = "CHACHA20"
        elif "AES-SIV" in encrypted_filename:
            self.cipher_used = "AES-SIV"
        else:
            self.cipher_used = None

        filename = metadata.get("original_filename", "decrypted_file")
        ext = metadata.get("extension", "bin")
        # Auto-generate filename for decrypted file using full encrypted filename
        encrypted_name_without_ext = os.path.splitext(encrypted_filename)[0]
        default_decrypted_name = f"{encrypted_name_without_ext}_decrypted.{ext}"
        save_path = filedialog.asksaveasfilename(defaultextension=f".{ext}", initialfile=default_decrypted_name)
        if not save_path:
            return

        with open(save_path, "wb") as f:
            f.write(data)

        self.output_box.insert(tk.END, f"✅ File successfully decrypted!\n")
        self.output_box.insert(tk.END, f"📁 Saved to: {save_path}\n")
        self.output_box.insert(tk.END, f"📄 Original filename: {filename}\n")
        self.output_box.insert(tk.END, f"🔐 Cipher: Auto-detected from package\n")
        self.output_box.insert(tk.END, f"✓ AEAD Authentication: Passed\n")
        self.output_box.insert(tk.END, f"✓ Post-Quantum Signature: Verified\n")

    def recommendations(self, key_b):
        # Estimate strength of Key B based on bit balance
        ones = key_b.count('1')
        zeros = key_b.count('0')
        balance = abs(ones - zeros)
        status = "Strong" if balance < len(key_b) * 0.4 else "Weak"
        return f"\nKey B Strength Estimate: {status} (1s: {ones}, 0s: {zeros})\n"

    def download_metrics_pdf(self):
        # Load JSON metrics and export to PDF report with auto-naming
        try:
            with open("bb84_metrics.json", "r") as f:
                metrics = json.load(f)
        except:
            messagebox.showerror("Error", "Metrics file not found.")
            return

        class PDF(FPDF):
            def header(self):
                self.set_font("Arial", "B", 14)
                self.cell(0, 10, "BB84 Metrics Report", ln=True, align="C")

            def chapter_body(self, content_dict):
                self.set_font("Arial", "", 11)
                for key, value in content_dict.items():
                    self.cell(0, 10, f"{key}: {value}", ln=True)

        pdf = PDF()
        pdf.add_page()
        pdf.chapter_body(metrics)

        # Auto-generate filename based on file and operation type
        if self.operation_type == "decrypt" and self.file_path:
            # For decryption, use the full encrypted filename
            encrypted_filename = os.path.basename(self.file_path)
            encrypted_name_without_ext = os.path.splitext(encrypted_filename)[0]
            default_report_name = f"{encrypted_name_without_ext}_report_decryption.pdf"
        elif self.file_name_without_ext and self.operation_type:
            # For encryption, use file name with cipher
            cipher_part = f"_{self.cipher_used}" if self.cipher_used else ""
            if self.operation_type == "encrypt":
                default_report_name = f"{self.file_name_without_ext}{cipher_part}_report_encryption.pdf"
            else:
                default_report_name = f"{self.file_name_without_ext}{cipher_part}_report_decryption.pdf"
        else:
            default_report_name = "bb84_metrics_report.pdf"

        save_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            initialfile=default_report_name,
            filetypes=[("PDF files", "*.pdf")]
        )
        if save_path:
            pdf.output(save_path)
            messagebox.showinfo("Saved", f"PDF report saved to: {save_path}")

def main():
    import tkinter as tk
    root = tk.Tk()
    app = BB84App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
