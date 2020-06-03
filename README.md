# hashcrack
Use a dictionary file to crack either a MD5, SHA1, SHA256 or a SHA512 hash.

## Usage
```
./hashcrack -d DICT_FILENAME -m MODE_NUMBER HASH

  Options:
   -d  Specify a file containing the wordlist split by newline
   -m  0: md5, 1: sha1, 2: sha256, 3: sha512
```

## Requirements
To compile correctly you have to install the developer version of OpenSSL: \
`sudo apt install libssl-dev`

## Compile
In order to compile you have to include the ssl and crypto libraries: \
`gcc main.c -lssl -lcrypto -o hashcrack`