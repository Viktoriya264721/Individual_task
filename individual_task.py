from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from PIL import Image
from io import BytesIO
import numpy as np
import os


def generate_keys():
    """
    Generates a pair of RSA keys (private and public) with a length of 4096 bits.
    Returns:
        tuple: (private_key, public_key) - RSA key objects.
    """
    print("1. Generating RSA keys")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    public_key = private_key.public_key()
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("The keys are saved in the following files private_key.pem and public_key.pem.")
    return private_key, public_key


def read_image_bytes(path):
    """
    Reads image bytes from the specified file.
    Checks if the image exists at the specified path.
    Returns:
        bytes: The content of the image as a byte string.
    """
    if not os.path.exists(path):
        print(f"Image '{path}' not found.")
        exit()
    with open(path, "rb") as img_file:
        return img_file.read()


def sign_data(data: bytes, private_key):
    """
    The function accepts data in byte format, calculates
    its hash using SHA-256, and then encrypts this hash
    with a private RSA key, thus creating a digital signature.
    """
    print("2. Signing image")
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256())


def bytes_to_bits(data):
    """
    Converts a sequence of bytes to a list of bits.
    """
    return [int(bit) for byte in data for bit in f"{byte:08b}"]


def bits_to_bytes(bits):
    """
    Converts a list of bits to a sequence of bytes.
    """
    return bytes(int("".join(str(bit) for bit in bits[i:i+8]), 2) for i in range(0, len(bits), 8))


def embed_signature_in_lsb(image_path, signature_bytes, output_path="signed_image.png"):
    """
    The function reads an image at the specified path, converts it to RGB format, and represents it as an array of pixels.
    Each pixel in RGB format has three components: red (R), green (G), and blue (B),
    each of which occupies 1 byte (8 bits). The least significant bit (LSB) is the last, eighth bit in this byte.

    The result is an image that is visually indistinguishable from the original, but contains a hidden signature.
    """
    print("3. Embedding signature into LSB")
    image = Image.open(image_path).convert("RGB")
    data = np.array(image)

    signature_bits = bytes_to_bits(signature_bytes)
    flat_pixels = data.flatten()

    if len(signature_bits) > len(flat_pixels):
        raise ValueError("Image too small to hold the signature.")

    for i, bit in enumerate(signature_bits):
        flat_pixels[i] = (flat_pixels[i] & ~1) | bit

    modified_data = flat_pixels.reshape(data.shape)
    signed_image = Image.fromarray(modified_data.astype("uint8"), "RGB")
    signed_image.save(output_path)
    print(f"Signed image saved as {output_path}")


def extract_signature_from_lsb(image_path, signature_bit_length):
    """
    The function opens an RGB image and converts it to an array of pixels.
    Each colour component (RGB) of each pixel is stored as a byte,
    where the last bitcan contain one bit of information.
    """
    print("4. Extracting signature from LSB")
    image = Image.open(image_path).convert("RGB")
    data = np.array(image)
    flat_pixels = data.flatten()

    signature_bits = [flat_pixels[i] & 1 for i in range(signature_bit_length)]
    return bits_to_bytes(signature_bits)


def verify_signature(public_key, data_bytes, signature_bytes):
    """
    Verifies that the signature is valid for the original data.
    """
    print("5. Verifying signature")
    try:
        public_key.verify(
            signature_bytes,
            data_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature is VALID.")
    except Exception:
        print("Signature is INVALID or image has been modified.")


def main():
    image_path = "image.png"
    signed_image_path = "signed_image.png"
    private_key, public_key = generate_keys()
    original_bytes = read_image_bytes(image_path)
    signature = sign_data(original_bytes, private_key)
    embed_signature_in_lsb(image_path, signature, signed_image_path)
    bit_length = len(signature) * 8
    extracted_signature = extract_signature_from_lsb(signed_image_path, bit_length)

    verify_signature(public_key, original_bytes, extracted_signature)


if __name__ == "__main__":
    main()
