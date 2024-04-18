from Crypto.Util.number import getPrime, inverse, GCD

def generate_rsa_keys_with_hamming_weight(key_size=2048, target_hamming_weight=None):
    """
    Generates RSA keys with a private key 'd' having approximately the desired Hamming weight.

    Parameters:
    - key_size: Size of the RSA modulus in bits.
    - target_hamming_weight: Desired Hamming weight of the private key 'd'.

    Returns:
    - A dictionary containing the RSA modulus 'n', public exponent 'e',
      and private exponent 'd'.
    """
    while True:
        # Generate two prime numbers
        p = getPrime(key_size // 2)
        q = getPrime(key_size // 2)
        n = p * q
        phi = (p - 1) * (q - 1)

        # Choose public exponent
        e = 65537

        # Ensure that GCD(e, phi) is 1 for a valid private key to exist
        if GCD(e, phi) == 1:
            # Calculate private exponent
            d = inverse(e, phi)
            # Check if the Hamming weight of 'd' matches the target
            if target_hamming_weight is None or bin(d).count('1') == target_hamming_weight:
                break

    public_key = {'n': n, 'e': e}
    private_key = {'n': n, 'd': d}

    return public_key, private_key

def generate_rsa_keys(key_size=2048):
    """
    Generates RSA keys

    Parameters:
    - key_size: Size of the RSA modulus in bits.
    - target_hamming_weight: Desired Hamming weight of the private key 'd'.

    Returns:
    - A dictionary containing the RSA modulus 'n', public exponent 'e',
      and private exponent 'd'.
    """
   
    # Generate two prime numbers
    p = getPrime(key_size // 2)
    q = getPrime(key_size // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose public exponent
    e = 65537

    # Ensure that GCD(e, phi) is 1 for a valid private key to exist
    if GCD(e, phi) == 1:
        # Calculate private exponent
        d = inverse(e, phi)

    public_key = {'n': n, 'e': e}
    private_key = {'n': n, 'd': d}

    return public_key, private_key

def rsa_encrypt(public_key, plaintext):
    """
    Encrypts a plaintext message using the public key.

    Parameters:
    - public_key: A dictionary containing 'n' and 'e', representing the RSA public key.
    - plaintext: The plaintext message as an integer.

    Returns:
    - The encrypted message as an integer.
    """
    n, e = public_key['n'], public_key['e']
    ciphertext = pow(plaintext, e, n)
    return ciphertext


def rsa_decrypt(private_key, ciphertext):
    """
    Decrypts a ciphertext message using the private key, using a method
    susceptible to timing attacks.

    Parameters:
    - private_key: A dictionary containing 'n' and 'd', the RSA private key components.
    - ciphertext: The ciphertext message as an integer.

    Returns:
    - The decrypted message as an integer.
    """
    return modular_exponentiation(ciphertext, private_key['d'], private_key['n'])


def modular_exponentiation(base, exponent, modulus):
    """
    Perform modular exponentiation using a basic square-and-multiply algorithm.
    This function is inherently vulnerable to timing attacks due to its operation.
    """
    result = 1
    base = base % modulus
    
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    
    return result
