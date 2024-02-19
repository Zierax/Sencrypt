import os
import getpass
import argparse
import logging
import hashlib
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(filename='encryption.log', level=logging.INFO)

def derive_key(password: bytes) -> bytes:
    key = hashlib.sha256(password).digest()
    return key

class EncryptionManager:
    def __init__(self, file_path: str, password: str, output_file: str = None):
        self.file_path = file_path
        self.password = password.encode()
        self.output_file = output_file or f"{os.path.splitext(file_path)[0]}_encrypted.bin"

    def encrypt_file(self) -> None:
        try:
            with open(self.file_path, 'rb') as file:
                file_content = file.read()

            iv = os.urandom(16)

            cipher = Cipher(algorithms.AES(derive_key(self.password)), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            encrypted_content = encryptor.update(file_content) + encryptor.finalize()

            with open(self.output_file, 'wb') as file:
                file.write(iv + encrypted_content)

            logging.info(f"Encrypted file saved as: {self.output_file}")

        except FileNotFoundError:
            logging.error(f"File not found: {self.file_path}")
            raise
        except Exception as e:
            logging.error(f"Error while encrypting file: {e}")
            raise e

class DecryptionManager:
    def __init__(self, file_path: str, password: str, output_file: str = None):
        self.file_path = file_path
        self.password = password.encode()
        self.output_file = output_file or os.path.splitext(file_path)[0] + "_decrypted.bin"

    def decrypt_file(self) -> None:
        try:
            with open(self.file_path, 'rb') as file:
                encrypted_data = file.read()

            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]

            cipher = Cipher(algorithms.AES(derive_key(self.password)), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            decrypted_content = decryptor.update(ciphertext) + decryptor.finalize()

            with open(self.output_file, 'wb') as file:
                file.write(decrypted_content)

            logging.info(f"Decrypted file saved as: {self.output_file}")

        except FileNotFoundError:
            logging.error(f"File not found: {self.file_path}")
            raise
        except Exception as e:
            logging.error(f"Error while decrypting file: {e}")
            raise e

def get_password(confirm=True) -> str:
    password = getpass.getpass("Enter the password: ")
    if confirm:
        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("Passwords do not match. Please try again.")
            return get_password(confirm=True)
    return password

def main():
    parser = argparse.ArgumentParser(description="Decrypt or encrypt a file securely using AES-CFB")
    parser.add_argument("file_path", help="Path to the file to decrypt or encrypt")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt the file")
    args = parser.parse_args()

    try:
        password = get_password(confirm=False)

        if args.decrypt:
            decryption_manager = DecryptionManager(args.file_path, password, args.output)
            decryption_manager.decrypt_file()
            print("File decrypted successfully.")
        else:
            encryption_manager = EncryptionManager(args.file_path, password, args.output)
            encryption_manager.encrypt_file()
            print("File encrypted successfully.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
