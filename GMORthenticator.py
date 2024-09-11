import tkinter as tk
from tkinter import ttk
import os
from Crypto.Cipher import AES
import pyotp


class GmorthenticatorGui:
    def __init__(self):
        self.raw_list = None
        self.key = None
        self._create_window()
        self._create_table()
        self._configure_column_and_rows()
        self._create_new_otp_acc_form()
        self._create_login_form()

        self.nonce = b"none"
        self.otp_dict = {
            "example.com": ["user1", "JBSWY3DPEHPK3PXP"]
        }

        if os.path.isfile("./nonce.txt"):
            f = open("./nonce.txt", "rb")
            self.nonce = f.read()
            f.close()
        self.main_window.mainloop()

    def submit_data(self):
        print(self.nonce)
        print(self.key)
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=self.nonce)

        site = self.entry_site.get()
        username = self.entry_username.get()
        secret = self.entry_secret.get()

        print(self.raw_list)
        new_raw_row = f"{self.raw_list}{site},{username},{secret}:"
        updated_list = bytes(new_raw_row, "utf-8")
        self.raw_list += new_raw_row
        self.otp_dict[site] = [username, secret]

        try:
            encrypted_list, tag = cipher.encrypt_and_digest(updated_list)
            f = open("./acc_list.txt", "wb")
            f.write(encrypted_list)
            f.close()
        except Exception as e:
            print(e)
        self.refresh_table()

        print(f"Submitted - Site: {site}, Username: {username}, Secret: {secret}")

    def login_or_create_account(self):
        self.key = bytes(self.entry_key.get().ljust(16, '9'), "utf-8")
        if self.nonce == b"none":
            print("creating acc...")
            cipher = AES.new(self.key, AES.MODE_EAX)
            f = open("./nonce.txt", "wb")
            f.write(cipher.nonce)
            f.close()
            f = open("./acc_list.txt", "w")
            f.write("")
            f.close()
            print("created")
        else:
            print("loggining in")
            print(self.nonce)
            cipher = AES.new(self.key, AES.MODE_EAX, nonce=self.nonce)
            f = open("./acc_list.txt", "rb")
            encrypted_list = f.read()
            f.close()
            self.raw_list = cipher.decrypt(encrypted_list).decode()
            print(self.raw_list)
            for row in self.raw_list.split(":"):
                try:
                    print(row)
                    value = row.split(",")
                    self.otp_dict[value[0]] = [value[1], value[2]]
                except Exception as e:
                    print(e)
            self.refresh_table()
            print("logged in")
            print(cipher.nonce)

    def refresh_table(self):
        # Clear the current table contents
        for row in self.table.get_children():
            self.table.delete(row)
        # Populate table with new data
        for site, (username, secret) in self.otp_dict.items():
            try:
                totp = pyotp.TOTP(secret)
                self.table.insert("", "end", values=(site, username, totp.now()))
            except Exception as e:
                print(e)

        print("refreshed")

    def _create_window(self):
        # Create main window
        self.main_window = tk.Tk()
        self.main_window.title("GMOrthenticator v1.0.0")
        self.main_window.geometry("800x400")
        self.main_window.configure(bg="#C0C0C0")

    def _create_table(self):
        # Refresh Button
        self.refresh_button = tk.Button(self.main_window, text="Refresh", command=self.refresh_table, relief="raised",
                                        bg="#F0F0F0",
                                        fg="black")
        self.refresh_button.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        # Table (Treeview)
        self.columns = ("Site", "Username", "Code")
        self.table = ttk.Treeview(self.main_window, columns=self.columns, show="headings", height=10)
        self.table.heading("Site", text="Site")
        self.table.column("Site", anchor="center", width=100)
        self.table.heading("Username", text="Username")
        self.table.column("Username", anchor="center", width=100)
        self.table.heading("Code", text="Code")
        self.table.column("Code", anchor="center", width=100)
        self.table.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

    def _configure_column_and_rows(self):
        # Configure column/row expansion
        self.main_window.grid_columnconfigure(0, weight=1)
        self.main_window.grid_columnconfigure(1, weight=1)
        self.main_window.grid_rowconfigure(1, weight=1)

    def _create_new_otp_acc_form(self):
        # Frame for the form (right side)
        self.form_frame = tk.Frame(self.main_window, bg="#C0C0C0")
        self.form_frame.grid(row=1, column=1, padx=20, pady=10, sticky="nsew")

        # Labels and textboxes for "Site", "Username", and "Secret"
        self.label_site = tk.Label(self.form_frame, text="Site:", bg="#C0C0C0", fg="black")
        self.label_site.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.entry_site = tk.Entry(self.form_frame, width=30)
        self.entry_site.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        self.label_username = tk.Label(self.form_frame, text="Username:", bg="#C0C0C0", fg="black")
        self.label_username.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.entry_username = tk.Entry(self.form_frame, width=30)
        self.entry_username.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        self.label_secret = tk.Label(self.form_frame, text="Secret:", bg="#C0C0C0", fg="black")
        self.label_secret.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.entry_secret = tk.Entry(self.form_frame, width=30)
        self.entry_secret.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        # Submit Button
        self.submit_button = tk.Button(self.form_frame, text="Submit", command=self.submit_data, relief="raised",
                                       bg="#F0F0F0",
                                       fg="black")
        self.submit_button.grid(row=3, column=1, padx=10, pady=10, sticky="e")

    def _create_login_form(self):
        self.label_key = tk.Label(self.form_frame, text="Password:", bg="#C0C0C0", fg="black")
        self.label_key.grid(row=4, column=0, padx=10, pady=5, sticky="w")
        self.entry_key = tk.Entry(self.form_frame, width=30)
        self.entry_key.grid(row=4, column=1, padx=10, pady=5, sticky="w")
        # Submit Button
        self.login_button = tk.Button(self.form_frame, text="Login/Create Account",
                                      command=self.login_or_create_account,
                                      relief="raised",
                                      bg="#F0F0F0", fg="black")
        self.login_button.grid(row=4, column=2, padx=10, pady=10, sticky="e")


GmorthenticatorGui()
