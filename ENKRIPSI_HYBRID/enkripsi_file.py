# import os
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives import padding as sym_padding

# def load_public_key():
#     with open("public_key.pem", "rb") as f:
#         return serialization.load_pem_public_key(f.read())

# def aes_encrypt(data, key):
#     iv = os.urandom(16)
#     cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
#     encryptor = cipher.encryptor()
#     padder = sym_padding.PKCS7(128).padder()
#     padded_data = padder.update(data) + padder.finalize()
#     return iv + encryptor.update(padded_data) + encryptor.finalize()

# def rsa_encrypt_key(aes_key, public_key):
#     return public_key.encrypt(
#         aes_key,
#         padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
#                      algorithm=hashes.SHA256(),
#                      label=None)
#     )

# def encrypt_file(input_file, output_file):
#     with open(input_file, "rb") as f:
#         data = f.read()

#     aes_key = os.urandom(32)
#     encrypted_data = aes_encrypt(data, aes_key)

#     public_key = load_public_key()
#     encrypted_key = rsa_encrypt_key(aes_key, public_key)

#     with open(output_file, "wb") as f:
#         f.write(len(encrypted_key).to_bytes(4, 'big'))
#         f.write(encrypted_key)
#         f.write(encrypted_data)

#     print(f"[✓] File terenkripsi disimpan sebagai: {output_file}")

# if __name__ == "__main__":
#     encrypt_file("1378659.png", "file_terenkripsi.bin")




from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import os

def encrypt_file_hybrid(file_path, public_key_path, output_path=None):
    """
    Mengenkripsi file menggunakan Enkripsi Hybrid RSA dan AES.
    Pengirim menggunakan kunci publik penerima untuk mengenkripsi kunci sesi AES.
    """
    if not os.path.exists(file_path):
        print(f"❌ Error: File '{file_path}' tidak ditemukan.")
        return
    if not os.path.exists(public_key_path):
        print(f"❌ Error: Kunci publik '{public_key_path}' tidak ditemukan. Pastikan sudah dibuat.")
        return

    if output_path is None:
        output_path = file_path + ".encrypted"

    try:
        with open(public_key_path, "rb") as f:
            recipient_key = RSA.import_key(f.read())

        session_key = get_random_bytes(32)

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        with open(file_path, "rb") as f_in: 
            plaintext = f_in.read()
            ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext) 

        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        with open(output_path, "wb") as f_out: 
            [f_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]

        print(f"✅ File '{file_path}' berhasil dienkripsi ke '{output_path}'.")
    except Exception as e:
        print(f"❌ Terjadi kesalahan saat enkripsi: {e}")

if __name__ == "__main__":
    # Contoh penggunaan:
    # GANTI 'nama_file_gambar_anda.jpg' dengan nama file gambar Anda
    # Misal: "1378659.png" sesuai screenshot Anda
    file_gambar = "Bahlil.jpg" # GANTI DENGAN NAMA FILE GAMBAR ANDA YANG BENAR

    if not os.path.exists(file_gambar):
        print(f"⚠️ PERINGATAN: File gambar '{file_gambar}' tidak ditemukan.")
        print("   Pastikan file gambar Anda ada di folder yang sama dengan enkripsi_file.py")
        print("   atau berikan path lengkap ke file gambar tersebut.")
    
    # Panggil fungsi enkripsi
    # Nama output: [nama_file_gambar].encrypted
    encrypt_file_hybrid(file_gambar, "public_key.pem", f"{file_gambar}.encrypted")