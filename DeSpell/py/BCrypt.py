import ctypes
from ctypes import POINTER
from ctypes.wintypes import LPVOID, LPWSTR, ULONG, DWORD, LPCWSTR, PCHAR, ULARGE_INTEGER, CHAR

# Stores all the call we want/need
bcrypt = ctypes.windll.bcrypt

BCRYPT_CHAINING_MODE = "ChainingMode"
BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM"
BCRYPT_AUTH_TAG_LENGTH = "AuthTagLength"
BCRYPT_BLOCK_LENGTH = "BlockLength"

BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION = 1

# Structs
class BCRYPT_AUTH_TAG_LENGTHS_STRUCT(ctypes.Structure):
    _fields_ = [
        ("dwMinLength", ULONG),
        ("dwMaxLength", ULONG),
        ("dwIncrement", ULONG)
    ]


class BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", ULONG),
        ("dwInfoVersion", ULONG),
        ("pbNonce", LPVOID),
        ("cbNonce", ULONG),
        ("pbAuthData", LPVOID),
        ("cbAuthData", ULONG),
        ("pbTag", LPVOID),
        ("cbTag", ULONG),
        ("pbMacContext", ULONG),
        ("pbMacContext", LPVOID),
        ("cbMacContext", ULONG),
        ("cbAAD", ULONG),
        ("cbData", ULARGE_INTEGER),
        ("dwFlags", ULONG)
    ]


# Function with BCrypt functions to decrypt passwords above Chrome v80
# Definitions of functions are online here:https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/
def BCryptDecrypt(secret, nonce, cipher):
    # Step one OpenAlgorithm: The BCryptOpenAlgorithmProvider function loads and initializes a CNG provider
    bcrypt.BCryptOpenAlgorithmProvider.restype = DWORD  # restype == return type
    bcrypt.BCryptOpenAlgorithmProvider.argtypes = [
        POINTER(LPVOID),
        LPWSTR,
        LPWSTR,
        ULONG
    ]

    algHandle = LPVOID()
    status = bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(algHandle),
                                                "AES",
                                                None,
                                                0)
    # print(f"\nBCryptOpenAlgorithmProvider: {hex(status)}")
    # print(f"handle is {algHandle}\n")

    bcrypt.BCryptSetProperty.restype = DWORD
    bcrypt.BCryptSetProperty.argtypes = [
        LPVOID,  # hCryptHandle
        LPCWSTR,  # pszProperty
        LPVOID,  # pbInput
        ULONG,  # cbInput
        ULONG  # dwFlags
    ]

    # Set mode to GCM
    status = bcrypt.BCryptSetProperty(algHandle,
                                      BCRYPT_CHAINING_MODE,
                                      BCRYPT_CHAIN_MODE_GCM,
                                      (len(BCRYPT_CHAIN_MODE_GCM) + 1) * 2,  # This is sizeof(BCRYPT_CHAIN_MODE_GCM)
                                      0)
    # print(f"BCryptSetProperty: {hex(status)}")

    bcrypt.BCryptGetProperty.restype = DWORD
    bcrypt.BCryptGetProperty.argtypes = [
        LPVOID,  # hObject,
        LPCWSTR,  # pszProperty,
        LPVOID,  # pbOutput,
        ULONG,  # cbOutput,
        POINTER(ULONG),  # pcbResult,
        ULONG,  # dwFlags
    ]

    # to store pcbResult
    bytesDone = ULONG()  # needs to be length of the cipherText

    authTagLengths = BCRYPT_AUTH_TAG_LENGTHS_STRUCT()

    status = bcrypt.BCryptGetProperty(algHandle,
                                      BCRYPT_AUTH_TAG_LENGTH,
                                      ctypes.byref(authTagLengths),
                                      ctypes.sizeof(authTagLengths),
                                      ctypes.byref(bytesDone),
                                      0)
    # print(f"BCryptGetProperty authTagLengths: {hex(status)}")

    bcrypt.BCryptGenerateSymmetricKey.argtypes = [
        LPVOID,  # BCRYPT_ALG_HANDLE hAlgorithm,
        POINTER(LPVOID),  # BCRYPT_KEY_HANDLE * phKey,
        PCHAR,  # PUCHAR            pbKeyObject,
        ULONG,  # ULONG             cbKeyObject,
        PCHAR,  # PUCHAR            pbSecret,
        ULONG,  # ULONG             cbSecret,
        ULONG,  # ULONG             dwFlags
    ]
    bcrypt.BCryptGenerateSymmetricKey.restype = DWORD

    pKeyHandle = LPVOID()
    status = bcrypt.BCryptGenerateSymmetricKey(algHandle,
                                               ctypes.byref(pKeyHandle),
                                               None,
                                               0,
                                               secret,
                                               len(secret),
                                               0)
    # print(f"BCryptGenerateSymmetricKey: {hex(status)}")
    # print(f"key handle: {pKeyHandle}\n")

    authTagType = CHAR * authTagLengths.dwMinLength
    authTag = authTagType()

    origNonceType = (CHAR * len(nonce))
    origNonce = origNonceType(*tuple(nonce))
    # print(f"origNonceTypeLen: {origNonceType}\norigNonceText: {origNonce.raw}\norigNonce location: {origNonce}\n")

    cipherType = (CHAR * len(cipher))
    cipher = cipherType(*tuple(cipher))
    # print(f"cipherTypeLen: {cipherType}\ncipherText: {cipher.raw}\ncipher location:{cipher}\n")

    # print(f"bytesDone: {bytesDone}")
    # Decryption
    bcrypt.BCryptDecrypt.restype = DWORD
    bcrypt.BCryptDecrypt.argtypes = [
        LPVOID,  # BCRYPT_KEY_HANDLE hKey,
        PCHAR,  # PUCHAR  pbInput,
        ULONG,  # cbInput,
        LPVOID,  # pPaddingInfo,
        LPVOID,  # PUCHAR  pbIV,
        ULONG,  # cbIV,
        LPVOID,  # PUCHAR  pbOutput,
        ULONG,  # cbOutput,
        POINTER(ULONG),  # pcbResult,
        ULONG  # dwFlags
    ]

    # Struct info
    authInfo = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
    authInfo.cbSize = ctypes.sizeof(authInfo)
    authInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION
    authInfo.pbNonce = ctypes.cast(origNonce, LPVOID)
    authInfo.cbNonce = ctypes.sizeof(origNonce)
    # print(f"authInfo.cbNonce: {authInfo.cbNonce}")
    authInfo.pbTag = ctypes.cast(authTag, LPVOID)
    authInfo.cbTag = ctypes.sizeof(authTag)

    # Holds the length of the decrypted password, which is the same size of as the cipher text
    decrypted = (CHAR * len(cipher))()

    status = bcrypt.BCryptDecrypt(pKeyHandle,
                                  cipher,
                                  len(cipher),
                                  ctypes.byref(authInfo),
                                  ctypes.byref(origNonce),
                                  ctypes.sizeof(origNonce),
                                  decrypted,
                                  ctypes.sizeof(decrypted),
                                  ctypes.byref(bytesDone),
                                  0)
    # print("BCryptDecrypt: %s" % hex(status))
    # print("bytesDone ", bytesDone)
    # print("decrypted: ", decrypted.raw[:bytesDone.value])
    return decrypted.raw[:bytesDone.value]

