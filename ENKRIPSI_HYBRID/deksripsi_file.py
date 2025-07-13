# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives import padding as sym_padding

# def load_private_key():
#     with open("private_key.pem", "rb") as f:
#         return serialization.load_pem_private_key(f.read(), password=None)

# def aes_decrypt(encrypted_data, key):
#     iv = encrypted_data[:16]
#     ciphertext = encrypted_data[16:]
#     cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
#     decryptor = cipher.decryptor()
#     padded_data = decryptor.update(ciphertext) + decryptor.finalize()
#     unpadder = sym_padding.PKCS7(128).unpadder()
#     return unpadder.update(padded_data) + unpadder.finalize()

# def rsa_decrypt_key(encrypted_key, private_key):
#     return private_key.decrypt(
#         encrypted_key,
#         padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
#                      algorithm=hashes.SHA256(),
#                      label=None)
#     )

# def decrypt_file(input_file, output_file):
#     with open(input_file, "rb") as f:
#         key_length = int.from_bytes(f.read(4), 'big')
#         encrypted_key = f.read(key_length)
#         encrypted_data = f.read()

#     private_key = load_private_key()
#     aes_key = rsa_decrypt_key(encrypted_key, private_key)
#     decrypted_data = aes_decrypt(encrypted_data, aes_key)

#     with open(output_file, "wb") as f:
#         f.write(decrypted_data)

#     print(f"[✓] File berhasil didekripsi: {output_file}")

# if __name__ == "__main__":
#     decrypt_file("file_terenkripsi.bin", "file_terdekripsi.txt")






# from Crypto.Cipher import AES, PKCS1_OAEP
# from Crypto.Random import get_random_bytes
# from Crypto.PublicKey import RSA
# import os
# from PIL import Image 

# def decrypt_file_hybrid(encrypted_file_path, private_key_path, output_path=None, show_image=False):
#     """
#     Mendekripsi file yang dienkripsi secara Hybrid menggunakan RSA dan AES.
#     """
#     if not os.path.exists(encrypted_file_path):
#         print(f"❌ Error: File terenkripsi '{encrypted_file_path}' tidak ditemukan.")
#         return
#     if not os.path.exists(private_key_path):
#         print(f"❌ Error: Kunci privat '{private_key_path}' tidak ditemukan. Anda memerlukan kunci privat yang benar untuk mendekripsi.")
#         return

#     if output_path is None:
#         if encrypted_file_path.endswith(".encrypted"):
         
#             parts = encrypted_file_path.rsplit('.', 2)
#             if len(parts) == 3 and parts[1] in ['jpg', 'png', 'jpeg', 'gif', 'bmp', 'txt', 'pdf']:
#                 output_path = parts[0] + "." + parts[1]
#             else:
#                 output_path = encrypted_file_path[:-len(".encrypted")] + ".decrypted" 
#         else:
#             output_path = encrypted_file_path + ".decrypted"

#     try:
#         with open(private_key_path, "rb") as f:
#             private_key = RSA.import_key(f.read())

#         with open(encrypted_file_path, "rb") as f_in: 
#             enc_session_key_len = private_key.size_in_bytes()
#             enc_session_key = f_in.read(enc_session_key_len)
#             nonce = f_in.read(16)
#             tag = f_in.read(16)
#             ciphertext = f_in.read()

#         cipher_rsa = PKCS1_OAEP.new(private_key)
#         session_key = cipher_rsa.decrypt(enc_session_key)

#         cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
#         plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

#         with open(output_path, "wb") as f_out: 
#             f_out.write(plaintext)

#         print(f"✅ File '{encrypted_file_path}' berhasil didekripsi ke '{output_path}'.")

#         if show_image:
#             try:
#                 img = Image.open(output_path)
#                 img.show()
#                 print(f"🖼️ Gambar '{output_path}' ditampilkan.")
#             except ImportError:
#                 print("⚠️ Peringatan: Library 'Pillow' tidak terinstal. Tidak dapat menampilkan gambar.")
#                 print("   Install dengan: pip install Pillow")
#             except Exception as img_err:
#                 print(f"⚠️ Gagal menampilkan gambar dari '{output_path}': {img_err}")
#                 print("   Pastikan file yang didekripsi adalah format gambar yang valid (misal JPG, PNG).")

#     except ValueError as e:
#         print(f"❌ Error dekripsi: Kunci atau data mungkin rusak. {e}")
#         print("   Pastikan Anda menggunakan kunci privat yang benar dan file terenkripsi tidak diubah.")
#     except Exception as e:
#         print(f"❌ Terjadi kesalahan lain saat dekripsi: {e}")

# if __name__ == "__main__":
#     # Contoh penggunaan:
#     # GANTI 'nama_file_gambar_anda.jpg.encrypted' dengan nama file terenkripsi Anda
#     # Misal: "1378659.png.encrypted"
#     encrypted_gambar = "1378659.png.encrypted" 

#     # Dekripsi dan langsung tampilkan
#     decrypt_file_hybrid(encrypted_gambar, "private_key.pem", show_image=True)




from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
from PIL import Image

def decrypt_file_hybrid(encrypted_file_path, private_key_path, output_path=None, show_image=False):
    """
    Mendekripsi file yang dienkripsi secara Hybrid menggunakan RSA dan AES.
    """

    if not os.path.exists(encrypted_file_path):
        print(f"❌ Error: File terenkripsi '{encrypted_file_path}' tidak ditemukan.")
        return
    if not os.path.exists(private_key_path):
        print(f"❌ Error: Kunci privat '{private_key_path}' tidak ditemukan. Anda memerlukan kunci privat yang benar untuk mendekripsi.")
        return

    # Format output file: .encrypted -> .decrypted
    if output_path is None:
        if encrypted_file_path.endswith(".encrypted"):
            output_path = encrypted_file_path.replace(".encrypted", ".decrypted")
        else:
            output_path = encrypted_file_path + ".decrypted"

    try:
        with open(private_key_path, "rb") as f:
            private_key = RSA.import_key(f.read())

        with open(encrypted_file_path, "rb") as f_in:
            enc_session_key_len = private_key.size_in_bytes()
            enc_session_key = f_in.read(enc_session_key_len)
            nonce = f_in.read(16)
            tag = f_in.read(16)
            ciphertext = f_in.read()

        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

        with open(output_path, "wb") as f_out:
            f_out.write(plaintext)

        print(f"✅ File '{encrypted_file_path}' berhasil didekripsi ke '{output_path}'.")

        if show_image:
            try:
                img = Image.open(output_path)
                img.show()
                print(f"🖼️ Gambar '{output_path}' ditampilkan.")
            except ImportError:
                print("⚠️ Peringatan: Library 'Pillow' tidak terinstal. Tidak dapat menampilkan gambar.")
                print("   Install dengan: pip install Pillow")
            except Exception as img_err:
                print(f"⚠️ Gagal menampilkan gambar dari '{output_path}': {img_err}")
                print("   Pastikan file yang didekripsi adalah format gambar yang valid (misal JPG, PNG).")

    except ValueError as e:
        print(f"❌ Error dekripsi: Kunci atau data mungkin rusak. {e}")
        print("   Pastikan Anda menggunakan kunci privat yang benar dan file terenkripsi tidak diubah.")
    except Exception as e:
        print(f"❌ Terjadi kesalahan lain saat dekripsi: {e}")

if __name__ == "__main__":
    # Contoh penggunaan:
    # GANTI '1378659.png.encrypted' dengan nama file terenkripsi Anda
    encrypted_gambar = "Bahlil.jpg.encrypted"
    
    # Dekripsi dan langsung tampilkan
    decrypt_file_hybrid(encrypted_gambar, "private_key.pem", show_image=True)
