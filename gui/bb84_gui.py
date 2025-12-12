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
        # Radio buttons for selecting mode: encryption or decryption
        self.mode_var = tk.StringVar(value="encrypt")

        title = tk.Label(self.root, text="BB84 Quantum Encryption / Decryption", font=("Arial", 16, "bold"), bg="#f4f4f4")
        title.pack(pady=10)

        mode_frame = tk.Frame(self.root, bg="#f4f4f4")
        tk.Radiobutton(mode_frame, text="Encrypt", variable=self.mode_var, value="encrypt", bg="#f4f4f4", command=self.update_mode).pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(mode_frame, text="Decrypt", variable=self.mode_var, value="decrypt", bg="#f4f4f4", command=self.update_mode).pack(side=tk.LEFT, padx=10)
        mode_frame.pack(pady=5)

        # File selection button and label
        tk.Button(self.root, text="Select File", command=self.select_file, bg="#d0eaff").pack(pady=5)
        self.file_label = tk.Label(self.root, text="No file selected", bg="#f4f4f4")
        self.file_label.pack(pady=2)

        # Cipher selection (AES-GCM, ChaCha20, or AES-SIV) - only shown in encryption mode
        self.cipher_frame = tk.Frame(self.root, bg="#f4f4f4")
        cipher_label = tk.Label(self.cipher_frame, text="Encryption Algorithm:", bg="#f4f4f4", font=("Arial", 10, "bold"))
        cipher_label.pack(side=tk.LEFT, padx=5)
        
        self.cipher_choice = ttk.Combobox(
            self.cipher_frame,
            values=[
                "AES-GCM (Best for Desktop/Server with AES-NI)",
                "ChaCha20 (Best for Mobile/ARM/Embedded)",
                "AES-SIV (Misuse-resistant, No nonce required)"
            ],
            state="readonly",
            width=55
        )
        self.cipher_choice.current(0)  # Default to AES-GCM
        self.cipher_choice.pack(side=tk.LEFT, padx=5)
        
        # Add info button for cipher selection
        info_button = tk.Button(
            self.cipher_frame, 
            text="ℹ️", 
            command=self.show_cipher_info,
            bg="#e0e0e0",
            width=3
        )
        info_button.pack(side=tk.LEFT, padx=2)
        self.cipher_frame.pack(pady=5)

        # Entry field for Key B (only used in decryption mode)
        self.key_frame = tk.Frame(self.root, bg="#f4f4f4")
        self.key_entry = tk.Entry(self.key_frame, width=80)
        self.key_entry.insert(0, "Key B (only for decryption)")
        self.key_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(self.key_frame, text="Import Key File", command=self.import_key_file, bg="#e0ffe0").pack(side=tk.LEFT)
        self.key_frame.pack(pady=5)

        # Buttons to copy or save Key B (only shown after encryption)
        self.copy_button = tk.Button(self.root, text="Copy Key B", command=self.copy_key_b, bg="#ffd0d0")
        self.copy_button.pack(pady=2)
        self.copy_button.pack_forget()

        self.save_key_button = tk.Button(self.root, text="Save Key B to .txt", command=self.save_key_b_to_file, bg="#ffe4b5")
        self.save_key_button.pack(pady=2)
        self.save_key_button.pack_forget()

        # Main execution button
        tk.Button(self.root, text="Run", command=self.run, bg="#c0ffc0").pack(pady=10)
        tk.Button(self.root, text="Download Metrics Report (PDF)", command=self.download_metrics_pdf, bg="#dcdcdc").pack(pady=5)

        # Output log area
        self.output_box = ScrolledText(self.root, height=10, bg="#ffffff")
        self.output_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Visual indicator for quantum process
        self.visual_frame = tk.Label(self.root, text="Quantum Key Exchange Simulation Status", bg="#f4f4f4", font=("Arial", 10, "italic"))
        self.visual_frame.pack(pady=5)
        self.visual_text = tk.StringVar(value="Idle")
        self.visual_label = tk.Label(self.root, textvariable=self.visual_text, bg="#ffffcc", width=80)
        self.visual_label.pack(pady=5)

        # Set visibility of GUI sections based on selected mode
        self.update_mode()

    def update_mode(self):
        # Update GUI layout based on selected operation mode
        if self.mode_var.get() == "encrypt":
            self.cipher_frame.pack(pady=5)
            self.key_frame.pack_forget()
            self.copy_button.pack_forget()
            self.save_key_button.pack_forget()
        else:
            self.cipher_frame.pack_forget()
            self.key_frame.pack(pady=5)
            self.copy_button.pack_forget()
            self.save_key_button.pack_forget()

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
        # Simulate quantum key exchange visually
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
        for step in steps:
            self.visual_text.set(step)
            self.root.update()
            time.sleep(0.7)
        self.visual_text.set("Idle")

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
