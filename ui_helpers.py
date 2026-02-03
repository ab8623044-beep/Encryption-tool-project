import tkinter as tk

def _popup_menu_for(widget: tk.Widget):
    menu = tk.Menu(widget, tearoff=0)
    menu.add_command(label="Cut", command=lambda: widget.event_generate("<<Cut>>"))
    menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
    menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
    menu.add_separator()
    menu.add_command(label="Select All", command=lambda: widget.event_generate("<<SelectAll>>"))
    return menu

def enable_clipboard_shortcuts_for_text(widget: tk.Widget):
    """
    هذا أهم ملف في المشروع عندي حالياً:
    يضمن إن أي Text/ScrolledText يشتغل فيه اللصق والنسخ والقص بشكل طبيعي
    حتى لو Tkinter ما كان ملتزم بالاختصارات.
    """
    # اختصارات الكيبورد
    widget.bind("<Control-v>", lambda e: (widget.event_generate("<<Paste>>"), "break"))
    widget.bind("<Control-V>", lambda e: (widget.event_generate("<<Paste>>"), "break"))
    widget.bind("<Control-c>", lambda e: (widget.event_generate("<<Copy>>"), "break"))
    widget.bind("<Control-C>", lambda e: (widget.event_generate("<<Copy>>"), "break"))
    widget.bind("<Control-x>", lambda e: (widget.event_generate("<<Cut>>"), "break"))
    widget.bind("<Control-X>", lambda e: (widget.event_generate("<<Cut>>"), "break"))
    widget.bind("<Control-a>", lambda e: (widget.event_generate("<<SelectAll>>"), "break"))
    widget.bind("<Control-A>", lambda e: (widget.event_generate("<<SelectAll>>"), "break"))

    # قائمة زر يمين (Copy/Paste/Cut)
    menu = _popup_menu_for(widget)
    widget.bind("<Button-3>", lambda e: (menu.tk_popup(e.x_root, e.y_root), "break"))
