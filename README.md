File Encryption and Decryption Utility
This Python script allows you to securely encrypt and decrypt files using the AES-CFB (Cipher Feedback Mode) symmetric encryption algorithm.

Requirements
Python 3.x
cryptography library (install using pip install cryptography)
Usage
Clone or download the repository to your local machine.
Navigate to the directory containing the script (encryption.py).
Run the script with appropriate command-line arguments.
Command-line Arguments
file_path: Path to the file to decrypt or encrypt.
-o, --output: Optional. Specify the output file path for the decrypted or encrypted file.
-d, --decrypt: Optional. Flag to indicate decryption mode. If not provided, encryption mode is assumed.
Examples
Encrypt a file:
bash
Copy code
python encryption.py /path/to/file.txt
Decrypt a file:
bash
Copy code
python encryption.py /path/to/encrypted_file.bin -d
Password Prompt
When prompted, enter your password. The password will be hidden for security reasons.
You will be asked to confirm your password to ensure accuracy.
Logging
Encryption and decryption operations are logged to the encryption.log file in the same directory as the script.
Errors encountered during encryption or decryption are logged for debugging purposes.
Note
Ensure that you keep your password secure and do not share it with others.
Use this utility responsibly and ensure compliance with relevant data protection regulations.