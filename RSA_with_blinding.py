from Crypto.Util.number import GCD, inverse, bytes_to_long, getRandomRange
from Crypto.Random import get_random_bytes

def secure_decrypt(ciphertext, private_key, public_key):
    """
    Secure decryption using blinding with a custom modular exponentiation 

    Parameters:
    - ciphertext: The ciphertext message as an integer.
    - private_key: A dictionary containing 'n' and 'd', the RSA private key components.
    - public_key: A dictionary containing 'n' and 'e', the RSA public key components.

    Returns:
    - The decrypted message as an integer.
    """
    # Choose a random blinding factor r such that 1 < r < n and gcd(r, n) = 1
    g = getRandomRange(2, private_key['n'])
    while GCD(g, private_key['n']) != 1:
        g = getRandomRange(2, private_key['n'])

    # Compute the blinding factor's inverse modulo n for later unblinding
    g_inv = inverse(g, private_key['n'])

    # Calculate the blinded ciphertext manually: A = (r^e * C) mod N
    g_to_e_mod_n = modular_exponentiation(g, public_key['e'], private_key['n'])
    A = (g_to_e_mod_n * ciphertext) % private_key['n']

    # Decrypt the blinded ciphertext manually: (A^d) mod N
    decrypted_A = modular_exponentiation(A, private_key['d'], private_key['n'])

    # Unblind the decrypted message to retrieve the original plaintext
    plaintext = (decrypted_A * g_inv) % private_key['n']

    return plaintext

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

def montgomery_ladder(base, exponent, modulus):
    """
    Perform modular exponentiation using the Montgomery Ladder technique, 
    which is designed to execute in constant time.
    
    Parameters:
    - base: The base number.
    - exponent: The exponent to raise the base to.
    - modulus: The modulus to perform the exponentiation under.
    
    Returns:
    - The result of the modular exponentiation.
    """
    r0, r1 = 1, base
    for bit in reversed(bin(exponent)[2:]):  # Process the exponent bits from MSB to LSB
        if bit == '0':
            r1 = (r0 * r1) % modulus
            r0 = (r0 * r0) % modulus
        else:
            r0 = (r0 * r1) % modulus
            r1 = (r1 * r1) % modulus
    return r0