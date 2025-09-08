import tkinter as tk
def main():
    root = tk.Tk(); root.title("IDS Live Demo (Stub)"); root.geometry("640x360")
    tk.Label(root, text="Live Demo (stub)", font=("Arial", 16)).pack(pady=10)
    txt = tk.Text(root, height=12)
    txt.insert("end","Placeholder.\nNo capture in this stub.\n")
    txt.config(state="disabled"); txt.pack(fill="both", expand=True, padx=8, pady=8)
    root.mainloop()
if __name__ == "__main__": main()
