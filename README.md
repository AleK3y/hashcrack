# hashcrack
Use a dictionary file to crack either a MD5, SHA1, SHA256 or a SHA512 hash.

## Usage
```
./hashcrack -d DICT_FILENAME -m MODE_NUMBER HASH

  Options:
   -d  Specify a file containing the wordlist split by newline
   -m  0: md5, 1: sha1, 2: sha256, 3: sha512
```

## Compilation

### Linux
First, you have to install the developer version of OpenSSL: \
`sudo apt install libssl-dev`

Then you'll be able to compile using this command: \
`gcc main.c -lcrypto -o hashcrack`

### Windows
This time you have to install the complete package from [GnuWin32's OpenSSL](http://gnuwin32.sourceforge.net/packages/openssl.htm).
Make sure you don't change any configuration during the installation (other than the Start Menu folder and such, if you want).

Then you can run this command to correctly compile the source: \
`gcc -m32 -I "C:\Program Files (x86)\GnuWin32\include" -L "C:\Program Files (x86)\GnuWin32\lib" main.c -lcrypto -o hashcrack.exe` \
Bear in mind though, the compiled binary is 32bit (even if you're on a 64bit architecture) because of GnuWin32.
