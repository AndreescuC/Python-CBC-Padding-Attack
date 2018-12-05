import oracle

IV = 'Hristos a inviat'


def ascii_list_to_string(ascii_list):
    return ''.join([chr(x) for x in ascii_list])


def split_cypher(cypher):
    return cypher[0:16], cypher[16:32], cypher[32:48], cypher[48:64]


def brute_force_byte(which_byte, brute_force_list, c2, intermediate_state):
    discovered_so_far = ''.join([
        chr(intermediate_state[padding_byte] ^ (16 - which_byte))
        for padding_byte in range(which_byte + 1, 16)
    ])
    for value in brute_force_list:
        cipher = '0' * which_byte
        cipher += chr(value)
        cipher += discovered_so_far
        if oracle.check_cbcpad(cipher + c2):
            return value


def cbc_decrypt(cypher_block1, cypher_block2, parity):
    brute_force_list = range(256) if parity == 1 else range(255, -1, -1)
    intermediate_state = 16 * ['0']
    plain_text = 16 * ['0']
    for forced_byte in range(15, -1, -1):
        value = brute_force_byte(forced_byte, brute_force_list, cypher_block2, intermediate_state)
        intermediate_state[forced_byte] = value ^ (16 - forced_byte) if value is not None else 0
        plain_text[forced_byte] = ord(cypher_block1[forced_byte]) ^ intermediate_state[forced_byte]
    return plain_text


def main():
    # Find the message corresponding to this ciphertext by using the cbc-padding attack
    c = '553b43d4b821332868fece8149eea14a2b0a98c7bed43cc1cf75f4e778cb315dc1d928d0340e0aab4900ca8af9adaee761e2affa3e9996d81483e950b913492b'
    ct = c.decode('hex')
    c1, c2, c3, c4 = split_cypher(ct)

    plain_text_ascii_1 = cbc_decrypt(IV, c1, parity=0)
    plain_text_ascii_2 = cbc_decrypt(c1, c2, parity=1)
    plain_text_ascii_3 = cbc_decrypt(c2, c3, parity=0)
    plain_text_ascii_4 = cbc_decrypt(c3, c4, parity=1)

    print("Resulted plaintext:")
    print(ascii_list_to_string(
        plain_text_ascii_1 +
        plain_text_ascii_2 +
        plain_text_ascii_3 +
        plain_text_ascii_4)
    )


if __name__ == "__main__":
    main()
