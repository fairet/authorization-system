try:

    import customtkinter as ctk
    import json
    import hashlib

    from generate_hash_passwords import GenerateHash
    from PIL import Image

except Exception as e:
    print("[-] Failed imports, please install requirements.")
    print(e)

generate_hash = GenerateHash


def parse(login):
    with open("credentials.json", "r") as file:
        data = json.load(file)

    try:
        return data["credentials"][login]

    except Exception as ex:
        print(f"Exception: {ex}")
        LoginApp().label_main.configure(text="Invalid credentials", text_color="red")
        LoginApp().label_main.place(rely=0.2, relx=0.375)


class LoginApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Login Page")
        self.geometry("575x650")
        self.resizable(False, False)

        self.bg_image = ctk.CTkImage(Image.open("background.jpg"), size=(575, 650))
        self.bg_image_label = ctk.CTkLabel(master=None, image=self.bg_image, text="")
        self.bg_image_label.place(rely=0.5, relx=0.5, anchor=ctk.CENTER)

        self._frame = ctk.CTkFrame(self,
                                   height=575,
                                   width=425,
                                   corner_radius=15).pack(pady=40, padx=20)

        self.label_main = ctk.CTkLabel(self._frame,
                                       anchor=ctk.CENTER,

                                       text_color=None,
                                       font=("Century Gothic", 32),
                                       bg_color="#2b2b2b",
                                       text="Log In")
        self.label_main.place(rely=0.2, relx=0.375)

        self._entry_login = ctk.CTkEntry(self._frame,
                                         height=40,
                                         width=300,

                                         placeholder_text="Login")
        self._entry_login.place(rely=0.35, relx=0.225)

        self._entry_password = ctk.CTkEntry(self._frame, show="*",
                                            height=40,
                                            width=300,

                                            placeholder_text="Password")
        self._entry_password.place(rely=0.425, relx=0.225)

        self._button_login = ctk.CTkButton(self._frame,
                                           height=40,
                                           width=240,

                                           anchor=ctk.CENTER,
                                           command=lambda: self.log_in(login=self._entry_login.get(),
                                                                       password=self._entry_password.get()),
                                           text="Log in").place(rely=0.55, relx=0.275)

        # self.bg_image = ctk.CTkImage(Image.open("background.jpg"), size=(500, 600))
        # self.bg_image_label = ctk.CTkLabel(master=None, image=self.bg_image, text="")
        # self.bg_image_label.place(rely=0.5, relx=0.5, anchor=tkinter.CENTER)

    def login(self):
        choice = self.log_in(login=self._entry_login.get(), password=self._entry_password.get())
        if choice:
            self.withdraw()

    def log_in(self, login, password):
        if login == "" or password == "" or login and password == "":
            self.label_main.configure(text="Please enter all values", text_color="red")

        hashed_password = hashlib.sha1(password.encode()).hexdigest()
        parsed_password = parse(login=login)

        if hashed_password == parsed_password:
            print(hashed_password)
            print(parse(login))

            self.label_main.configure(text="Logging into account", text_color="green")
            self.label_main.place(relx=0.24)
            self.withdraw()
            return True


login_app = LoginApp()

if __name__ == "__main__":
    login_app.mainloop()
