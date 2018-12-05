from Crypto.Cipher import AES


def aes_enc(k, m):
    """
    Encrypt a message m with a key k in ECB mode using AES as follows:
    c = AES(k, m)

    Args:
      m should be a bytestring multiple of 16 bytes (i.e. a sequence of characters such as 'Hello...' or '\x02\x04...')
      k should be a bytestring of length exactly 16 bytes.

    Return:
      The bytestring ciphertext c
    """
    aes = AES.new(k)
    c = aes.encrypt(m)

    return c


def aes_dec(k, c):
    """
    Decrypt a ciphertext c with a key k in ECB mode using AES as follows:
    m = AES(k, c)

    Args:
      c should be a bytestring multiple of 16 bytes (i.e. a sequence of characters such as 'Hello...' or '\x02\x04...')
      k should be a bytestring of length exactly 16 bytes.

    Return:
      The bytestring message m
    """
    aes = AES.new(k)
    m = aes.decrypt(c)

    return m


def aes_enc_cbc(k, m, iv):
    """
    Encrypt a message m with a key k in CBC mode using AES as follows:
    c = AES(k, m)

    Args:
      m should be a bytestring multiple of 16 bytes (i.e. a sequence of characters such as 'Hello...' or '\x02\x04...')
      k should be a bytestring of length exactly 16 bytes.
      iv should be a bytestring of length exactly 16 bytes.

    Return:
      The bytestring ciphertext c
    """
    aes = AES.new(k, AES.MODE_CBC, iv)
    c = aes.encrypt(m)

    return c


def aes_dec_cbc(k, c, iv):
    """
    Decrypt a ciphertext c with a key k in CBC mode using AES as follows:
    m = AES(k, c)

    Args:
      c should be a bytestring multiple of 16 bytes (i.e. a sequence of characters such as 'Hello...' or '\x02\x04...')
      k should be a bytestring of length exactly 16 bytes.
      iv should be a bytestring of length exactly 16 bytes.

    Return:
      The bytestring message m
    """
    aes = AES.new(k, AES.MODE_CBC, iv)
    m = aes.decrypt(c)

    return m
