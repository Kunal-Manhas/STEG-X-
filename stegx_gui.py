import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

import os
from stegano import lsb
from PIL import Image


class StegXGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        # ========== WINDOW SETUP ==========
        self.title("Steg-X | Advanced Steganography Tool (Text in Image)")
        self.geometry("950x630")
        self.minsize(900, 600)
        self.configure(bg="#020617")  # dark

        self._center_window()
        self.style = ttk.Style(self)
        self._setup_style()

        # StringVars
        self.hide_input_path = tk.StringVar()
        self.hide_output_path = tk.StringVar()
        self.extract_image_path = tk.StringVar()
        self.detect_image_path = tk.StringVar()

        # ========== BUILD UI ==========
        self._build_layout()

    # ---------------------- WINDOW HELPERS ----------------------

    def _center_window(self):
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _setup_style(self):
        self.style.theme_use("clam")

        bg_main = "#020617"
        bg_card = "#020617"
        bg_input = "#020617"
        border = "#1e293b"
        fg_text = "#e5e7eb"
        fg_muted = "#9ca3af"
        primary = "#22c55e"
        primary_dark = "#16a34a"

        # Frames
        self.style.configure("Main.TFrame", background=bg_main)
        self.style.configure("Card.TFrame", background=bg_card)

        # Notebook
        self.style.configure("TNotebook", background=bg_main, borderwidth=0)
        self.style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=[16, 8])
        self.style.map(
            "TNotebook.Tab",
            background=[("selected", "#111827"), ("!selected", bg_main)],
            foreground=[("selected", fg_text), ("!selected", fg_muted)],
        )

        # Labels
        self.style.configure("Title.TLabel", background=bg_main, foreground=fg_text, font=("Segoe UI", 18, "bold"))
        self.style.configure("Subtitle.TLabel", background=bg_main, foreground=fg_muted, font=("Segoe UI", 10))
        self.style.configure("FieldLabel.TLabel", background=bg_card, foreground=fg_muted, font=("Segoe UI", 10, "bold"))

        # Buttons
        self.style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=8,
                             background=primary, foreground="white", borderwidth=0)
        self.style.map("Accent.TButton", background=[("active", primary_dark)])

        self.style.configure("Ghost.TButton", font=("Segoe UI", 9), padding=6,
                             background=bg_card, foreground=fg_muted, borderwidth=1, relief="solid")
        self.style.map("Ghost.TButton", background=[("active", bg_input)])

        # Entry
        self.style.configure(
            "Modern.TEntry",
            fieldbackground=bg_input,
            background=bg_input,
            foreground=fg_text,
            bordercolor=border,
            relief="flat",
            padding=6
        )

    # ---------------------- MAIN LAYOUT ----------------------

    def _build_layout(self):
        root = ttk.Frame(self, style="Main.TFrame", padding=18)
        root.pack(fill="both", expand=True)

        # Header
        header = ttk.Frame(root, style="Main.TFrame")
        header.pack(fill="x", pady=(0, 10))

        ttk.Label(header, text="Steg-X", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Hide, extract, and detect secret text in images.", style="Subtitle.TLabel").pack(anchor="w")

        # Tabs
        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, pady=(10, 0))

        hide_tab = ttk.Frame(notebook, style="Main.TFrame", padding=16)
        extract_tab = ttk.Frame(notebook, style="Main.TFrame", padding=16)
        detect_tab = ttk.Frame(notebook, style="Main.TFrame", padding=16)

        notebook.add(hide_tab, text="🫥 Hide Text")
        notebook.add(extract_tab, text="🔓 Extract Text")
        notebook.add(detect_tab, text="🔍 Detect LSB")

        self._build_hide_tab(hide_tab)
        self._build_extract_tab(extract_tab)
        self._build_detect_tab(detect_tab)

        # Log area
        log_frame = ttk.Frame(root, style="Main.TFrame")
        log_frame.pack(fill="both", expand=False, pady=(10, 0))

        ttk.Label(log_frame, text="Activity Log", style="FieldLabel.TLabel").pack(anchor="w")

        self.log_widget = ScrolledText(
            log_frame, height=6, bg="#020617", fg="#e5e7eb",
            insertbackground="#e5e7eb", relief="solid", borderwidth=1
        )
        self.log_widget.pack(fill="both", expand=True)
        self._log("Steg-X GUI started.\n")

    # ---------------------- HIDE TAB ----------------------

    def _build_hide_tab(self, parent):
        parent.columnconfigure(1, weight=1)

        # Input image
        ttk.Label(parent, text="Input Image", style="FieldLabel.TLabel").grid(row=0, column=0, sticky="w")
        in_frame = ttk.Frame(parent, style="Card.TFrame")
        in_frame.grid(row=0, column=1, sticky="ew", pady=(0, 8))

        ttk.Entry(in_frame, textvariable=self.hide_input_path, style="Modern.TEntry").pack(side="left", fill="x", expand=True)
        ttk.Button(in_frame, text="Browse", style="Ghost.TButton", command=self._browse_hide_input).pack(side="left", padx=8)

        # Output image
        ttk.Label(parent, text="Output Image", style="FieldLabel.TLabel").grid(row=1, column=0, sticky="w")
        out_frame = ttk.Frame(parent, style="Card.TFrame")
        out_frame.grid(row=1, column=1, sticky="ew")

        ttk.Entry(out_frame, textvariable=self.hide_output_path, style="Modern.TEntry").pack(side="left", fill="x", expand=True)
        ttk.Button(out_frame, text="Save As", style="Ghost.TButton", command=self._browse_hide_output).pack(side="left", padx=8)

        # Secret text
        ttk.Label(parent, text="Secret Message", style="FieldLabel.TLabel").grid(row=2, column=0, sticky="nw")
        self.secret_text = ScrolledText(parent, height=8, bg="#020617", fg="#e5e7eb",
                                        insertbackground="#e5e7eb", relief="solid", borderwidth=1, wrap="word")
        self.secret_text.grid(row=2, column=1, sticky="nsew", pady=8)
        parent.rowconfigure(2, weight=1)

        ttk.Button(parent, text="🫥 Hide Text", style="Accent.TButton", command=self._on_hide).grid(row=3, column=1, sticky="e")

    def _browse_hide_input(self):
        path = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg *.jpeg")])
        if path:
            self.hide_input_path.set(path)
            self._log(f"Selected input image: {path}\n")

    def _browse_hide_output(self):
        path = filedialog.asksaveasfilename(defaultextension=".png")
        if path:
            self.hide_output_path.set(path)
            self._log(f"Selected output path: {path}\n")

    def _on_hide(self):
        inp = self.hide_input_path.get().strip()
        out = self.hide_output_path.get().strip()
        msg = self.secret_text.get("1.0", "end").strip()

        if not inp or not os.path.exists(inp):
            messagebox.showerror("Error", "Invalid input image.")
            return
        if not out:
            messagebox.showerror("Error", "Choose output path.")
            return
        if not msg:
            messagebox.showwarning("Warning", "Secret text empty.")
            return

        try:
            stego = lsb.hide(inp, msg)
            stego.save(out)
            self._log(f"[✔] Hidden text saved to: {out}\n")
            messagebox.showinfo("Success", "Text successfully hidden.")
        except Exception as e:
            self._log(f"[✘] Error hiding text: {e}\n")
            messagebox.showerror("Error", str(e))

    # ---------------------- EXTRACT TAB ----------------------

    def _build_extract_tab(self, parent):
        parent.columnconfigure(1, weight=1)

        ttk.Label(parent, text="Stego Image", style="FieldLabel.TLabel").grid(row=0, column=0, sticky="w")
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.grid(row=0, column=1, sticky="ew")

        ttk.Entry(frame, textvariable=self.extract_image_path, style="Modern.TEntry").pack(side="left", fill="x", expand=True)
        ttk.Button(frame, text="Browse", style="Ghost.TButton", command=self._browse_extract_image).pack(side="left", padx=8)

        ttk.Label(parent, text="Extracted Message", style="FieldLabel.TLabel").grid(row=1, column=0, sticky="nw")
        self.extract_output = ScrolledText(parent, height=12, bg="#020617", fg="#e5e7eb",
                                           insertbackground="#e5e7eb", relief="solid", borderwidth=1)
        self.extract_output.grid(row=1, column=1, sticky="nsew")
        parent.rowconfigure(1, weight=1)

        ttk.Button(parent, text="🔓 Extract Text", style="Accent.TButton", command=self._on_extract).grid(row=2, column=1, sticky="e")

    def _browse_extract_image(self):
        path = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg *.jpeg")])
        if path:
            self.extract_image_path.set(path)
            self._log(f"Selected stego image: {path}\n")

    def _on_extract(self):
        path = self.extract_image_path.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "Invalid stego image.")
            return

        try:
            hidden = lsb.reveal(path)
            self.extract_output.delete("1.0", "end")

            if hidden:
                self.extract_output.insert("1.0", hidden)
                self._log("[✔] Text extracted.\n")
            else:
                self.extract_output.insert("1.0", "[No hidden text found]")
                self._log("[!] No text found.\n")

        except Exception as e:
            self._log(f"[✘] Extraction error: {e}\n")
            messagebox.showerror("Error", str(e))

    # ---------------------- DETECT TAB ----------------------

    def _build_detect_tab(self, parent):
        parent.columnconfigure(1, weight=1)

        ttk.Label(parent, text="Image to Analyze", style="FieldLabel.TLabel").grid(row=0, column=0, sticky="w")
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.grid(row=0, column=1, sticky="ew")

        ttk.Entry(frame, textvariable=self.detect_image_path, style="Modern.TEntry").pack(side="left", fill="x", expand=True)
        ttk.Button(frame, text="Browse", style="Ghost.TButton", command=self._browse_detect_image).pack(side="left", padx=8)

        ttk.Label(parent, text="Detection Result", style="FieldLabel.TLabel").grid(row=1, column=0, sticky="nw")
        self.detect_output = ScrolledText(parent, height=12, bg="#020617", fg="#e5e7eb",
                                          insertbackground="#e5e7eb", relief="solid", borderwidth=1)
        self.detect_output.grid(row=1, column=1, sticky="nsew")
        parent.rowconfigure(1, weight=1)

        ttk.Button(parent, text="🔍 Analyze LSB", style="Accent.TButton", command=self._on_detect).grid(row=2, column=1, sticky="e")

    def _browse_detect_image(self):
        path = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg *.jpeg")])
        if path:
            self.detect_image_path.set(path)
            self._log(f"Selected detection image: {path}\n")

    def _on_detect(self):
        img_path = self.detect_image_path.get().strip()
        if not img_path or not os.path.exists(img_path):
            messagebox.showerror("Error", "Invalid image.")
            return

        try:
            with Image.open(img_path) as img:
                if img.mode not in ("RGB", "RGBA"):
                    img = img.convert("RGB")

                pixels = list(img.getdata())
                sample = pixels[:min(len(pixels), 2000)]

                lsb_bits = [p[0] & 1 for p in sample]
                ones = sum(lsb_bits)
                total = len(lsb_bits)
                zeros = total - ones

            self.detect_output.delete("1.0", "end")
            self.detect_output.insert("1.0",
                f"Sampled pixels: {total}\n"
                f"LSB 1s: {ones}\n"
                f"LSB 0s: {zeros}\n\n"
            )

            if total == 0:
                msg = "ℹ No pixels to analyze.\n"
                self._log("[!] No pixels.\n")
            else:
                ratio = ones / total
                self.detect_output.insert("end", f"Ratio of 1s: {ratio:.3f}\n")

                if 0.45 <= ratio <= 0.55:
                    msg = "⚠ Suspicious: Balanced randomness → Possible hidden data.\n"
                    self._log("[✔] Suspicious (balanced).\n")
                elif ratio <= 0.1 or ratio >= 0.9:
                    msg = "⚠ Suspicious: Extreme bias → Possible hidden data.\n"
                    self._log("[✔] Suspicious (biased).\n")
                else:
                    msg = "ℹ No obvious LSB hidden data detected.\n"
                    self._log("[i] No suspicious pattern.\n")

            self.detect_output.insert("end", msg)
            messagebox.showinfo("Detection Result", msg.split("\n")[0])

        except Exception as e:
            self._log(f"[✘] Detection error: {e}\n")
            messagebox.showerror("Error", str(e))

    # ---------------------- LOG HELPERS ----------------------

    def _log(self, text: str):
        self.log_widget.insert("end", text)
        self.log_widget.see("end")


if __name__ == "__main__":
    app = StegXGUI()
    app.mainloop()
