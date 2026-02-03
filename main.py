import tkinter as tk
from app_gui import CryptoApp

def main():
    root = tk.Tk()
    try:
        root.tk.call("tk", "scaling", 1.3)
    except Exception:
        pass

    CryptoApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
