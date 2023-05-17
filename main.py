import string
import sys


def hex_to_bin(hexadecimal):
    # функція що приймає стрінг з цифрою шістнадцятирічної системи і повептає стрінг з тим же числом у двійковій системі
    hex_bin = {
        "0": "0000",
        "1": "0001",
        "2": "0010",
        "3": "0011",
        "4": "0100",
        "5": "0101",
        "6": "0110",
        "7": "0111",
        "8": "1000",
        "9": "1001",
        "a": "1010",
        "b": "1011",
        "c": "1100",
        "d": "1101",
        "e": "1110",
        "f": "1111",
    }
    return hex_bin[hexadecimal]


def bin_to_hex(binary):
    # функція що приймає стрінг з числом від 0 до 15 записане у двійковій системі і повертає стрінг з тим же числом у шістнадцятирічній системі
    bin_hex = {
        "0000": "0",
        "0001": "1",
        "0010": "2",
        "0011": "3",
        "0100": "4",
        "0101": "5",
        "0110": "6",
        "0111": "7",
        "1000": "8",
        "1001": "9",
        "1010": "a",
        "1011": "b",
        "1100": "c",
        "1101": "d",
        "1110": "e",
        "1111": "f",
    }
    return bin_hex[binary]


def p_blocks_encryption(plaintext, key, plaintext_type="ascii"):
    """
    функція що зашифровує повідомлення методом p-блоків
    :param plaintext: оригінальне повідомлення, може бути у вигляді ascii тексту або стрінгом парної довжини,
    що складається з шістнадцятирічних цифр
    :param key: ключ щифрувння, може бути цілим числом (тоді буде виконано циклічний зсув на модуль цього числа,
    в право якщо число додатне, в ліво - якщо від'ємне, що по суті теж є перестановкою), або стрінгом зі зазначеним порядка перестановки
    :param plaintext_type: тип оригінального повідомлення, може бути 'ascii', або 'hex' (hexadecimal)
    :return: зашифроване повідомлення
    """
    # перевірка валідності ключа шифрування
    if type(key) == int:
        key %= 8
        key_string = ""
        for i in range(8):
            key_string += str((i + 8 - key) % 8)
        key = key_string
    elif type(key) != str:
        t = type(key)
        raise Exception(f"Invalid key type, {t.__name__} is not string or integer")
    if key == "01234567":
        raise Exception("Invalid key, encryption does not make changes")
    if len(key) != 8:
        raise Exception("Invalid key, key length should be 8")
    for i in range(8):
        if str(i) not in key:
            raise Exception("Invalid key, key should be combination of such signs: '0', '1', '2', '3', '4', '5', '6'," 
                            "'7'")
    hex_signs = "0123456789abcdef"
    # перевірка валідності вхідного повідомлення
    if plaintext_type == "hex":
        plaintext = plaintext.lower()
        if len(plaintext) % 2 != 0:
            raise Exception("Invalid plaintext, hexadecimal plaintext length should be even")
        for char in plaintext:
            if char not in hex_signs:
                raise Exception(f"Invalid plaintext, {char} is not hexadecimal")
    # перетворення ascii віхдного повідомлення у hexadecimal
    elif plaintext_type == "ascii":
        buf = ""
        for char in plaintext:
            if char not in string.printable:
                raise Exception(f"Invalid plaintext, {char} is not ascii character")
            char = ord(char)
            if char < 16:
                buf += "0"+format(char, "x")
            else:
                buf += format(char, "x")
        plaintext = buf
    else:
        raise Exception(f"Invalid plaintext_type, {plaintext_type} is not hex or ascii")
    buf = ""
    # ділим вхідне повідомлення на блоки по 8 біт і до кожного блоку застосовуєм шифрування
    for i, j in zip(plaintext[0::2], plaintext[1::2]):
        buf += single_p_block_encryption(i+j, key)
    return buf


def single_p_block_encryption(plaintext, key):
    """
    функція, що шифрує окремі блоки вхідного повідомлення
    :param plaintext: блок вхідного повідомлення
    :param key: ключ
    :return: зашифрований блок
    """
    # отримуєм представлення вхідного блоку у двійковому коді
    bin_plaintext = hex_to_bin(plaintext[:1]) + hex_to_bin(plaintext[1:])
    bin_result = ""
    # виконуєм перестановку бітів у блоці, відповідно до ключа
    for char in key:
        bin_result += bin_plaintext[int(char)]
    # повертаємо результат у шистнадцятирічному представлені
    result = bin_to_hex(bin_result[:4]) + bin_to_hex(bin_result[4:])
    return result


def p_blocks_decryption(cipher, key, plaintext_type="ascii"):
    """
    функція, що розшифровує шифротекст, зашифрований методом p-блоків
    :param cipher: шифротекст
    :param key: ключ шифрування
    :param plaintext_type: тип оригінального повідомлення
    :return: повертає оригінальне повідомлення
    """
    # перевірка валідності ключа шифрування
    if type(key) == int:
        key %= 8
        key_string = ""
        for i in range(8):
            key_string += str((i + 8 - key) % 8)
        key = key_string
    elif type(key) != str:
        t = type(key)
        raise Exception(f"Invalid key type, {t.__name__} is not string or integer")
    if key == "01234567":
        raise Exception("Invalid key, encryption does not make changes")
    if len(key) != 8:
        raise Exception("Invalid key, key length should be 8")
    for i in range(8):
        if str(i) not in key:
            raise Exception("Invalid key, key should be combination of such signs: '0', '1', '2', '3', '4', '5', '6',"
                            "'7'")
    hex_signs = "0123456789abcdef"
    cipher = cipher.lower()
    # перевірка валідності шифру
    if len(cipher) % 2 != 0:
        raise Exception("Invalid cipher, cipher length should be even")
    for char in cipher:
        if char not in hex_signs:
            raise Exception(f"Invalid cipher, {char} is not hexadecimal")
    if plaintext_type != "hex" and plaintext_type != "ascii":
        raise Exception(f"Invalid plaintext_type, {plaintext_type} is not hex or ascii")
    result = ""
    # ділим шифротекст на блоки по 8 біт і до кожного блоку застосовуєм дешифрування
    for i, j in zip(cipher[0::2], cipher[1::2]):
        result += single_p_block_decryption(i+j, key)
    # якщо тип оригінального повідомлення - ascii переводемо шестнадцятирічне представлення результату у ascii
    if plaintext_type == "ascii":
        buf = ""
        for i, j in zip(result[0::2], result[1::2]):
            buf += chr(int(i+j, 16))
        result = buf
    return result


def single_p_block_decryption(cipher, key):
    """
    функція, що дешифровує 8-бітний блок шифру
    :param cipher: блок шифру
    :param key: ключ шифрування
    :return: розшифрований блок
    """
    # отримуєм представлення вхідного блоку у двійковому коді
    bin_cipher = hex_to_bin(cipher[:1]) + hex_to_bin(cipher[1:])
    result_bin_list = ["0"] * 8
    # виконуєм перестановку бітів у блоці, відповідно до ключа
    for i, j in enumerate(key):
        result_bin_list[int(j)] = bin_cipher[i]
    bin_result = "".join(result_bin_list)
    # повертаємо результат у шистнадцятирічному представлені
    result = bin_to_hex(bin_result[:4]) + bin_to_hex(bin_result[4:])
    return result


def s_blocks_encryption(plaintext, key, plaintext_type="ascii"):
    """
    функція, що зашифровує повідомлення методом s-блоків
    :param plaintext: оригінальне повідомлення, може бути у вигляді ascii тексту або стрінгом парної довжини,
    що складається з шістнадцятирічних цифр
    :param key: ключ шифрування
    :param plaintext_type: тип оригінального повідомлення, може бути 'ascii', або 'hex' (hexadecimal)
    :return: зашифроване повідомлення
    :return: шифротекст повідомлення
    """
    hex_signs = "0123456789abcdef"
    # перевірка валідності ключа
    if type(key) != list:
        raise Exception("Invalid key, key should be a 16x16 list")
    if len(key) != 16:
        raise Exception("Invalid key, key should be a 16x16 list")
    for i in key:
        if type(i) != list:
            raise Exception("Invalid key, key should be a 16x16 list")
        if len(i) != 16:
            raise Exception("Invalid key, key should be a 16x16 list")
    # перевірка валідності вхідного повідомлення
    if plaintext_type == "hex":
        plaintext = plaintext.lower()
        if len(plaintext) % 2 != 0:
            raise Exception("Invalid plaintext, hexadecimal plaintext length should be even")
        for char in plaintext:
            if char not in hex_signs:
                raise Exception(f"Invalid plaintext, {char} is not hexadecimal")
    # перетворення ascii віхдного повідомлення у hexadecimal
    elif plaintext_type == "ascii":
        buf = ""
        for char in plaintext:
            if char not in string.printable:
                raise Exception(f"Invalid plaintext, {char} is not ascii character")
            char = ord(char)
            if char < 16:
                buf += "0"+format(char, "x")
            else:
                buf += format(char, "x")
        plaintext = buf
    else:
        raise Exception(f"Invalid plaintext_type, {plaintext_type} is not hex or ascii")
    result = ""
    # розбиваєм вхідне повідомлення на 8-бітні блоки і застосовуєм до них шифрування підстановкою
    for i, j in zip(plaintext[0::2], plaintext[1::2]):
        result += single_s_block(i+j, key)
    return result


def single_s_block(plaintext, key):
    """
    функція, що шифрує або дешефрує окремий 8-бітний блок вхідного повідомлення
    :param plaintext: 8-бітний блок
    :param key: ключ
    :return: зашифрований, або дешифрований блок
    """
    # виконуєм підстановку згідно таблиці-ключа
    i = int(plaintext[0], 16)
    j = int(plaintext[1], 16)
    result = key[i][j]
    return result


def s_blocks_decryption(cipher, key, plaintext_type="ascii"):
    """
    функція, що розшифровує шифротекст, зашифрований методом s-блоків
    :param cipher: шифротекст
    :param key: ключ
    :param plaintext_type: тип оригінального повідомлення
    :return: дешифроване повідомлення
    """
    hex_signs = "0123456789abcdef"
    # перевірка валідності ключа
    if type(key) != list:
        raise Exception("Invalid key, key should be a 16x16 list")
    if len(key) != 16:
        raise Exception("Invalid key, key should be a 16x16 list")
    for i in key:
        if type(i) != list:
            raise Exception("Invalid key, key should be a 16x16 list")
        if len(i) != 16:
            raise Exception("Invalid key, key should be a 16x16 list")
    cipher = cipher.lower()
    # перевірка валідності шифру
    if len(cipher) % 2 != 0:
        raise Exception("Invalid cipher, cipher length should be even")
    for char in cipher:
        if char not in hex_signs:
            raise Exception(f"Invalid cipher, {char} is not hexadecimal")
    if plaintext_type != "hex" and plaintext_type != "ascii":
        raise Exception(f"Invalid plaintext_type, {plaintext_type} is not hex or ascii")
    # створюємо таблицю дешифрування на основі таблиці шифрування
    decryption_key = [["0" for i in range(16)] for j in range(16)]
    for row in range(16):
        for column in range(16):
            hexadecimal = key[row][column]
            i = int(hexadecimal[0], 16)
            j = int(hexadecimal[1], 16)
            decryption_key[i][j] = hex_signs[row] + hex_signs[column]
    result = ""
    # розбиваємо шифр на блоки по 8-біт і застосовуємо дешифрування підстановкою
    for i, j in zip(cipher[0::2], cipher[1::2]):
        result += single_s_block(i+j, decryption_key)
    # якщо тип оригінального повідомлення - ascii переводемо шестнадцятирічне представлення результату у ascii
    if plaintext_type == "ascii":
        buf = ""
        for i, j in zip(result[0::2], result[1::2]):
            buf += chr(int(i+j, 16))
        result = buf
    return result


if __name__ == '__main__':
    if len(sys.argv) > 1:
        plaintext_p = sys.argv[1]
        p_blocks_key = sys.argv[2]
        plaintext_type_p = sys.argv[3]
        plaintext_s = sys.argv[4]
        plaintext_type_s = sys.argv[5]
        s_block_key = [["1b", "d4", "6b", "e6", "a6", "e4", "96", "59", "29", "94", "69", "19", "2b", "d6", "5b", "a4"],
                       ["47", "88", "d7", "57", "62", "06", "f6", "f7", "ff", "31", "c0", "1e", "c1", "6f", "54", "ae"],
                       ["d0", "0f", "db", "7a", "75", "b9", "12", "18", "83", "5f", "d1", "39", "ce", "51", "cf", "aa"],
                       ["af", "58", "23", "cc", "f2", "a8", "93", "1d", "45", "3c", "9b", "0b", "42", "bb", "ef", "08"],
                       ["ea", "d5", "6d", "14", "60", "41", "53", "f8", "2c", "36", "80", "79", "f5", "27", "b1", "cd"],
                       ["c9", "d2", "35", "a5", "f1", "bf", "4b", "3d", "ec", "9d", "01", "cb", "16", "1c", "4a", "d8"],
                       ["64", "32", "04", "33", "e0", "97", "05", "26", "63", "c2", "55", "81", "48", "20", "d3", "49"],
                       ["38", "e9", "07", "7f", "34", "c4", "b5", "df", "e3", "e8", "8e", "30", "1f", "7e", "de", "e5"],
                       ["f3", "9a", "eb", "fd", "73", "fb", "e1", "dd", "5a", "3f", "90", "9e", "b7", "b4", "c8", "4c"],
                       ["02", "6c", "72", "ac", "24", "87", "e2", "a7", "7c", "8a", "0d", "17", "76", "43", "c6", "ad"],
                       ["b6", "2f", "9f", "0a", "bd", "dc", "6a", "a1", "f0", "da", "8b", "37", "86", "d9", "4e", "fe"],
                       ["7d", "0e", "b8", "03", "40", "82", "66", "6e", "15", "78", "13", "ed", "44", "2d", "2a", "f4"],
                       ["95", "09", "67", "a2", "70", "b3", "91", "71", "61", "ca", "e7", "4d", "50", "89", "3a", "a9"],
                       ["21", "8d", "c5", "25", "9c", "5d", "bc", "28", "10", "2e", "7b", "b0", "ba", "0c", "99", "74"],
                       ["5e", "92", "84", "a3", "fc", "11", "65", "00", "f9", "68", "ab", "c7", "fa", "c3", "b2", "52"],
                       ["8c", "85", "ee", "3e", "3b", "1a", "a0", "46", "be", "98", "77", "8f", "5c", "4f", "56", "22"]]
        dec = "0123456789"
        if (len(p_blocks_key) == 1 and p_blocks_key in dec) \
                or (len(p_blocks_key) == 2 and p_blocks_key[1] in dec and p_blocks_key[0] == "-"):
            p_blocks_key = int(p_blocks_key)
        cipher_p = p_blocks_encryption(plaintext_p, p_blocks_key, plaintext_type_p)
        cipher_s = s_blocks_encryption(plaintext_s, s_block_key, plaintext_type_s)
        print("Шифрування за допомогою p-блоків:")
        print(f"оригінальне повідомлення: {plaintext_p};\nотриманий шифротекст: {cipher_p};")
        print()
        print("Шифрування за допомогою s-блоків:")
        print(f"оригінальне повідомлення: {plaintext_s};\nотриманий шифротекст: {cipher_s};")
        plaintext_p = p_blocks_decryption(cipher_p, p_blocks_key, plaintext_type_p)
        plaintext_s = s_blocks_decryption(cipher_s, s_block_key, plaintext_type_s)
        print()
        print("Розшифрування за допомогою p-блоків:")
        print(f"шифротекст: {cipher_p};\nотримане дешифроване повідомлення: {plaintext_p};")
        print()
        print("Розшифрування за допомогою s-блоків:")
        print(f"шифротекст: {cipher_s};\nотримане дешифроване повідомлення: {plaintext_s};")


