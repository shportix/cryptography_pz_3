# cryptography_pz_3
програма виконаного завдання складається з 9 функцій:
- p_blocks_encryption (функція, що шифрує повідомлення методом p-блоків)
- single_p_block_encryption (функція, що шифрує окремі 8-бітні блоки вхідного повідомлення)
- p_blocks_decryption (функція, що розшифровує шифротекст, зашифрований методом p-блоків)
- single_p_block_decryption (функція, що дешифровує 8-бітний блок шифру)
- s_blocks_encryption (функція, що зашифровує повідомлення методом s-блоків)
- single_s_block (функція, що шифрує або дешефрує окремий 8-бітний блок вхідного повідомлення)
- s_blocks_decryption (функція, що розшифровує шифротекст, зашифрований методом s-блоків)
- hex_to_bin (функція що приймає стрінг з цифрою шістнадцятирічної системи і повептає стрінг з тим же числом у двійковій системі)
- bin_to_hex (функція що приймає стрінг з числом від 0 до 15 записане у двійковій системі і повертає стрінг з тим же числом у шістнадцятирічній системі)

# запуск коду програми
для того щоб запустити код треба викликати файл main.py з п'ятью аргументами
аргументи:
- перший аргумент - це повідомлення, що буде використовуватись у шифрувані p-блоками
- другий аргумент - це ключ, що буде використовуватись у шифрувані p-блоками. Ключ може бути цілим числом тоді буде виконано циклічний зсув на модуль цього числа,  право якщо число додатне, в ліво - якщо від'ємне, що по суті теж є перестановкою), або стрінгом зі зазначеним порядка перестановки
- третій аргумент - це тип повідомлення, що буде використовуватись у шифрувані p-блоками. Тип може бути ascii, або hex (тобто hexadecimal)
- четвертий аргумент - це повідомлення, що буде використовуватись у шифрувані s-блоками
- п'ятий аргумент - це тип повідомлення, що буде використовуватись у шифрувані s-блоками. Тип може бути ascii, або hex (тобто hexadecimal)
Так як ключ для шифрування s-блоками - це таблиця 16х16, передавати його в консолі буде не зручно, тому буде використовуватись завчасно написаний ключ, а саме акий список:
[
["1b", "d4", "6b", "e6", "a6", "e4", "96", "59", "29", "94", "69", "19", "2b", "d6", "5b", "a4"],
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
["8c", "85", "ee", "3e", "3b", "1a", "a0", "46", "be", "98", "77", "8f", "5c", "4f", "56", "22"]
]
Після запуску програма виконає шифрування заданих повідомлень, виведе результати. Після цього, для перевірки коректності,програма виконає розшиірування отриманих шифротекстів і виведе результати, що мають збігатись з початково заданими повідомленнями.
Скріншоти прикладів запуску програми з результатами її виконання:
![image](https://github.com/shportix/cryptography_pz_3/assets/56202290/5d7fc5e4-62f9-4cd7-9955-6d17499ce4d0)

![image](https://github.com/shportix/cryptography_pz_3/assets/56202290/7dfad4d1-7052-4253-9430-0e8bb161b476)




