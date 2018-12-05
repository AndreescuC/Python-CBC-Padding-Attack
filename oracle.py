import aes

IV = 'Hristos a inviat'


def check_cbcpad(c):
    """
    Oracle for checking if a given ciphertext has correct CBC-padding.
    That is, it checks that the last n bytes all have the value n.

    Args:
      c is the ciphertext to be checked. Note: the key is supposed to be
      known just by the oracle.

    Return 1 if the pad is correct, 0 otherwise.
    """
    ko = 'Sfantul Gheorghe'
    m = aes.aes_dec_cbc(ko, c, IV)
    lm = len(m)
    lb = ord(m[lm - 1])

    if lb > lm:
        return 0

    for k in range(lb):
        if ord(m[lm - 1 - k]) != lb:
            return 0

    return 1