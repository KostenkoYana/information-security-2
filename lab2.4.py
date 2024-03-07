from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def encrypt_text(plaintext, key, mode):
    cipher = None
    if mode == "ecb":
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = pad(plaintext, AES.block_size)
    elif mode == "cbc":
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = pad(plaintext, AES.block_size)
    elif mode == "cfb":
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
    else:
        raise ValueError("Unknown encryption mode")

    encrypted_text = cipher.encrypt(plaintext)
    if mode != "ecb":
        encrypted_text = iv + encrypted_text
    return encrypted_text

def decrypt_text(encrypted_text, key, mode):
    iv = None
    if mode == "ecb":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode == "cbc":
        iv = encrypted_text[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_text = encrypted_text[AES.block_size:]
    elif mode == "cfb":
        iv = encrypted_text[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        encrypted_text = encrypted_text[AES.block_size:]
    else:
        raise ValueError("Unknown encryption mode")

    decrypted_text = cipher.decrypt(encrypted_text)
    decrypted_text = unpad(decrypted_text, AES.block_size)
    return decrypted_text

def main():
    action = input("What do you want to do? Select 'encrypt' or 'decrypt': ")
    if action == "encrypt":
        plaintext = input("Enter the text to encrypt: ")
        key = input("Enter the secret key (16, 24 or 32 characters): ")
        mode = input("Select the encryption mode (ecb, cbc, or cfb): ")
        encrypted_text = encrypt_text(plaintext.encode(), key.encode(), mode)
        with open("encrypted_text.txt", "wb") as file:
            file.write(encrypted_text)
        print("The text is encrypted and saved in a file encrypted_text.txt")
    elif action == "decrypt":
        try:
            with open("encrypted_text.txt", "rb") as file:
                encrypted_text = file.read()
            key = input("Enter the secret key (16, 24 or 32 characters): ")
            mode = input("Select the decryption mode (ecb, cbc or cfb): ")
            decrypted_text = decrypt_text(encrypted_text, key.encode(), mode)
            print("Decrypted text:", decrypted_text.decode())
        except FileNotFoundError:
            print("File with ciphertext not found.")
        except ValueError as e:
            print("Error:", e)

if __name__ == "__main__":
    main()
