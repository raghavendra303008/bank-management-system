import tkinter as tk
from tkinter import messagebox
import json, os

# ---------------------------
# File Handling
# ---------------------------
FILE_NAME = "accounts.json"

def load_data():
    if os.path.exists(FILE_NAME):
        with open(FILE_NAME, "r") as f:
            return json.load(f)
    return {}

def save_data():
    with open(FILE_NAME, "w") as f:
        json.dump(accounts, f, indent=4)

# ---------------------------
# Data
# ---------------------------
accounts = load_data()
current_user = None

# ---------------------------
# Functions
# ---------------------------
def create_account():
    name = entry_name.get()
    acc_no = entry_acc_no.get()
    password = entry_password.get()
    try:
        balance = float(entry_balance.get())
    except:
        messagebox.showerror("Error", "Enter a valid initial deposit.")
        return

    if not name or not acc_no or not password:
        messagebox.showerror("Error", "All fields are required!")
        return

    if acc_no in accounts:
        messagebox.showerror("Error", "Account number already exists!")
    else:
        accounts[acc_no] = {"name": name, "password": password, "balance": balance}
        save_data()
        messagebox.showinfo("Success", "✅ Account created successfully!")
        entry_name.delete(0, tk.END)
        entry_acc_no.delete(0, tk.END)
        entry_password.delete(0, tk.END)
        entry_balance.delete(0, tk.END)

def login():
    global current_user
    acc_no = entry_login_acc.get()
    password = entry_login_pwd.get()
    if acc_no in accounts and accounts[acc_no]["password"] == password:
        current_user = acc_no
        messagebox.showinfo("Login", f"✅ Welcome, {accounts[acc_no]['name']}!")
        entry_login_acc.delete(0, tk.END)
        entry_login_pwd.delete(0, tk.END)
        show_user_sections(True)
    else:
        messagebox.showerror("Error", "❌ Invalid account number or password.")

def deposit():
    global current_user
    if current_user:
        try:
            amount = float(entry_deposit_amt.get())
        except:
            messagebox.showerror("Error", "Enter a valid deposit amount.")
            return
        if amount > 0:
            accounts[current_user]["balance"] += amount
            save_data()
            messagebox.showinfo("Deposit", f"💰 Deposit successful!\nNew Balance: {accounts[current_user]['balance']}")
            entry_deposit_amt.delete(0, tk.END)
    else:
        messagebox.showerror("Error", "❌ Please log in first.")

def withdraw():
    global current_user
    if current_user:
        password = entry_withdraw_pwd.get()
        try:
            amount = float(entry_withdraw_amt.get())
        except:
            messagebox.showerror("Error", "Enter a valid withdrawal amount.")
            return
        if password == accounts[current_user]["password"]:
            if amount > 0 and accounts[current_user]["balance"] >= amount:
                accounts[current_user]["balance"] -= amount
                save_data()
                messagebox.showinfo("Withdraw", f"✅ Withdrawal successful!\nNew Balance: {accounts[current_user]['balance']}")
                entry_withdraw_pwd.delete(0, tk.END)
                entry_withdraw_amt.delete(0, tk.END)
            else:
                messagebox.showerror("Error", "❌ Insufficient balance!")
        else:
            messagebox.showerror("Error", "❌ Incorrect password!")
    else:
        messagebox.showerror("Error", "❌ Please log in first.")

def check_balance():
    global current_user
    if current_user:
        password = entry_balance_pwd.get()
        if password == accounts[current_user]["password"]:
            bal = accounts[current_user]["balance"]
            messagebox.showinfo("Balance", f"👤 {accounts[current_user]['name']}\n💰 Balance: {bal}")
            entry_balance_pwd.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "❌ Incorrect password!")
    else:
        messagebox.showerror("Error", "❌ Please log in first.")

def change_password():
    global current_user
    if current_user:
        old_pwd = entry_old_pwd.get()
        new_pwd = entry_new_pwd.get()
        if old_pwd == accounts[current_user]["password"]:
            if new_pwd:
                accounts[current_user]["password"] = new_pwd
                save_data()
                messagebox.showinfo("Success", "✅ Password changed successfully!")
                entry_old_pwd.delete(0, tk.END)
                entry_new_pwd.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "❌ Incorrect current password!")
    else:
        messagebox.showerror("Error", "❌ Please log in first.")

def delete_account():
    global current_user
    if current_user:
        pwd = entry_delete_pwd.get()
        if pwd == accounts[current_user]["password"]:
            confirm = messagebox.askyesno("Confirm Delete", "⚠️ Are you sure you want to delete this account?")
            if confirm:
                name = accounts[current_user]["name"]
                del accounts[current_user]
                current_user = None
                save_data()
                messagebox.showinfo("Deleted", f"🗑️ Account of {name} has been deleted successfully!")
                entry_delete_pwd.delete(0, tk.END)
                show_user_sections(False)
        else:
            messagebox.showerror("Error", "❌ Incorrect password!")
    else:
        messagebox.showerror("Error", "❌ Please log in first.")

def logout():
    global current_user
    if current_user:
        messagebox.showinfo("Logout", f"👋 Logged out from {accounts[current_user]['name']}'s account.")
        current_user = None
        show_user_sections(False)
    else:
        messagebox.showerror("Error", "❌ No user logged in.")

def exit_app():
    root.destroy()

def toggle_password(entry_field, button):
    if entry_field.cget('show') == '':
        entry_field.config(show='*')
        button.config(text='Show')
    else:
        entry_field.config(show='')
        button.config(text='Hide')

# ---------------------------
# Show/Hide User Sections
# ---------------------------
def show_user_sections(show=True):
    frames = [frame_deposit, frame_withdraw, frame_balance, frame_changepwd, frame_delete, btn_logout]
    for widget in frames:
        if show:
            widget.pack(pady=10, fill="x", padx=20)
        else:
            widget.pack_forget()

# ---------------------------
# GUI Setup
# ---------------------------
root = tk.Tk()
root.title("🏦 Bank Management System")
root.geometry("520x800")

# Scrollable Canvas
canvas = tk.Canvas(root, bg="#f0f6ff")
canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(root, command=canvas.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
canvas.configure(yscrollcommand=scrollbar.set)

scrollable_frame = tk.Frame(canvas, bg="#f0f6ff")
window_id = canvas.create_window((0,0), window=scrollable_frame, anchor="nw")

def update_scroll(event):
    canvas.configure(scrollregion=canvas.bbox("all"))
    # Make the frame expand to canvas width
    canvas.itemconfig(window_id, width=canvas.winfo_width())

scrollable_frame.bind("<Configure>", update_scroll)

# Enable mouse wheel scrolling
def _on_mousewheel(event):
    canvas.yview_scroll(int(-1*(event.delta/120)), "units")

canvas.bind_all("<MouseWheel>", _on_mousewheel)

# Title
title = tk.Label(scrollable_frame, text="🏦 Bank Management System", font=("Arial", 18, "bold"), bg="#f0f6ff", fg="#003366")
title.pack(pady=15)

# --- CREATE ACCOUNT ---
frame_create = tk.LabelFrame(scrollable_frame, text="🆕 Create Account", font=("Arial", 12, "bold"), bg="#f0f6ff", padx=10, pady=10)
frame_create.pack(pady=10, fill="x", padx=20)

tk.Label(frame_create, text="Name:", bg="#f0f6ff").grid(row=0, column=0, sticky="w")
entry_name = tk.Entry(frame_create, width=25)
entry_name.grid(row=0, column=1, pady=5)

tk.Label(frame_create, text="Account No:", bg="#f0f6ff").grid(row=1, column=0, sticky="w")
entry_acc_no = tk.Entry(frame_create, width=25)
entry_acc_no.grid(row=1, column=1, pady=5)

tk.Label(frame_create, text="Password:", bg="#f0f6ff").grid(row=2, column=0, sticky="w")
entry_password = tk.Entry(frame_create, width=25, show="*")
entry_password.grid(row=2, column=1, pady=5)
btn_toggle_pwd = tk.Button(frame_create, text="Show", command=lambda: toggle_password(entry_password, btn_toggle_pwd))
btn_toggle_pwd.grid(row=2, column=2, padx=5)

tk.Label(frame_create, text="Initial Deposit:", bg="#f0f6ff").grid(row=3, column=0, sticky="w")
entry_balance = tk.Entry(frame_create, width=25)
entry_balance.grid(row=3, column=1, pady=5)

tk.Button(frame_create, text="Create Account", command=create_account, bg="#007acc", fg="white").grid(row=4, columnspan=3, pady=5)
tk.Button(frame_create, text="Exit", command=exit_app, bg="#d11a2a", fg="white").grid(row=5, columnspan=3, pady=5)

# --- LOGIN ---
frame_login = tk.LabelFrame(scrollable_frame, text="🔑 Login", font=("Arial", 12, "bold"), bg="#f0f6ff", padx=10, pady=10)
frame_login.pack(pady=10, fill="x", padx=20)

tk.Label(frame_login, text="Account No:", bg="#f0f6ff").grid(row=0, column=0, sticky="w")
entry_login_acc = tk.Entry(frame_login, width=25)
entry_login_acc.grid(row=0, column=1, pady=5)

tk.Label(frame_login, text="Password:", bg="#f0f6ff").grid(row=1, column=0, sticky="w")
entry_login_pwd = tk.Entry(frame_login, width=25, show="*")
entry_login_pwd.grid(row=1, column=1, pady=5)
btn_toggle_login = tk.Button(frame_login, text="Show", command=lambda: toggle_password(entry_login_pwd, btn_toggle_login))
btn_toggle_login.grid(row=1, column=2, padx=5)

tk.Button(frame_login, text="Login", command=login, bg="#007acc", fg="white").grid(row=2, columnspan=3, pady=5)
tk.Button(frame_login, text="Exit", command=exit_app, bg="#d11a2a", fg="white").grid(row=3, columnspan=3, pady=5)

# --- DEPOSIT ---
frame_deposit = tk.LabelFrame(scrollable_frame, text="💰 Deposit", font=("Arial", 12, "bold"), bg="#f0f6ff", padx=10, pady=10)
entry_deposit_amt = tk.Entry(frame_deposit, width=25)
entry_deposit_amt.grid(row=0, column=0, padx=5)
tk.Button(frame_deposit, text="Deposit", command=deposit, bg="#007acc", fg="white").grid(row=0, column=1, padx=5)
tk.Button(frame_deposit, text="Exit", command=exit_app, bg="#d11a2a", fg="white").grid(row=1, columnspan=2, pady=5)

# --- WITHDRAW ---
frame_withdraw = tk.LabelFrame(scrollable_frame, text="💸 Withdraw", font=("Arial", 12, "bold"), bg="#f0f6ff", padx=10, pady=10)
entry_withdraw_pwd = tk.Entry(frame_withdraw, width=15, show="*")
entry_withdraw_pwd.grid(row=0, column=0, padx=5)
btn_toggle_withdraw = tk.Button(frame_withdraw, text="Show", command=lambda: toggle_password(entry_withdraw_pwd, btn_toggle_withdraw))
btn_toggle_withdraw.grid(row=0, column=1, padx=5)

entry_withdraw_amt = tk.Entry(frame_withdraw, width=15)
entry_withdraw_amt.grid(row=0, column=2, padx=5)
tk.Button(frame_withdraw, text="Withdraw", command=withdraw, bg="#007acc", fg="white").grid(row=0, column=3, padx=5)
tk.Button(frame_withdraw, text="Exit", command=exit_app, bg="#d11a2a", fg="white").grid(row=1, columnspan=4, pady=5)

# --- CHECK BALANCE ---
frame_balance = tk.LabelFrame(scrollable_frame, text="📊 Check Balance", font=("Arial", 12, "bold"), bg="#f0f6ff", padx=10, pady=10)
entry_balance_pwd = tk.Entry(frame_balance, width=20, show="*")
entry_balance_pwd.grid(row=0, column=0, padx=5)
btn_toggle_balance = tk.Button(frame_balance, text="Show", command=lambda: toggle_password(entry_balance_pwd, btn_toggle_balance))
btn_toggle_balance.grid(row=0, column=1, padx=5)
tk.Button(frame_balance, text="Check Balance", command=check_balance, bg="#007acc", fg="white").grid(row=0, column=2, padx=5)
tk.Button(frame_balance, text="Exit", command=exit_app, bg="#d11a2a", fg="white").grid(row=1, columnspan=3, pady=5)

# --- CHANGE PASSWORD ---
frame_changepwd = tk.LabelFrame(scrollable_frame, text="🔒 Change Password", font=("Arial", 12, "bold"), bg="#f0f6ff", padx=10, pady=10)
entry_old_pwd = tk.Entry(frame_changepwd, width=15, show="*")
entry_old_pwd.grid(row=0, column=0, padx=5)
btn_toggle_old = tk.Button(frame_changepwd, text="Show", command=lambda: toggle_password(entry_old_pwd, btn_toggle_old))
btn_toggle_old.grid(row=0, column=1, padx=5)

entry_new_pwd = tk.Entry(frame_changepwd, width=15, show="*")
entry_new_pwd.grid(row=0, column=2, padx=5)
btn_toggle_new = tk.Button(frame_changepwd, text="Show", command=lambda: toggle_password(entry_new_pwd, btn_toggle_new))
btn_toggle_new.grid(row=0, column=3, padx=5)

tk.Button(frame_changepwd, text="Change Password", command=change_password, bg="#007acc", fg="white").grid(row=1, columnspan=4, pady=5)
tk.Button(frame_changepwd, text="Exit", command=exit_app, bg="#d11a2a", fg="white").grid(row=2, columnspan=4, pady=5)

# --- DELETE ACCOUNT ---
frame_delete = tk.LabelFrame(scrollable_frame, text="🗑️ Delete Account", font=("Arial", 12, "bold"), bg="#f0f6ff", padx=10, pady=10)
entry_delete_pwd = tk.Entry(frame_delete, width=20, show="*")
entry_delete_pwd.grid(row=0, column=0, padx=5)
btn_toggle_delete = tk.Button(frame_delete, text="Show", command=lambda: toggle_password(entry_delete_pwd, btn_toggle_delete))
btn_toggle_delete.grid(row=0, column=1, padx=5)
tk.Button(frame_delete, text="Delete Account", command=delete_account, bg="#d11a2a", fg="white").grid(row=0, column=2, padx=5)
tk.Button(frame_delete, text="Exit", command=exit_app, bg="#d11a2a", fg="white").grid(row=1, columnspan=3, pady=5)

btn_logout = tk.Button(scrollable_frame, text="🚪 Logout", command=logout, width=30, height=2, font=("Arial", 12), bg="#007acc", fg="white")


show_user_sections(False)

root.mainloop()
