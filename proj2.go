package proj2

// CS 161 Project 2.

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

func encryptThenMAC(cryptKey []byte, MACKey []byte, data []byte) (encryptedThenMACedDataByteArray []byte) {

	IV := userlib.RandomBytes(16)

	var padding_bytes byte = byte(userlib.AESBlockSizeBytes - len(data)%userlib.AESBlockSizeBytes)
	if len(data)%userlib.AESBlockSizeBytes == 0 {
		for i := 0; i < userlib.AESBlockSizeBytes; i++ {
			data = append(data, userlib.AESBlockSizeBytes)
		}
	} else {
		for len(data)%userlib.AESBlockSizeBytes != 0 {
			data = append(data, padding_bytes)
		}
	}
	//pad plaintext using method from class

	encryptedData := userlib.SymEnc(cryptKey, IV, data)
	//encrypt

	MAC, _ := userlib.HMACEval(MACKey, encryptedData)

	var encryptedAndMACedData DataWithMACorSig
	encryptedAndMACedData.Contents = encryptedData
	encryptedAndMACedData.MACorSig = MAC
	//store in struct with separate fields for contents and signature/MAC

	encryptedThenMACedDataByteArray, _ = json.Marshal(encryptedAndMACedData)
	//marshal this struct into byte array

	return

}

func checkMACandDecrypt(cryptKey []byte, MACkey []byte, encryptedAndMACedDataByteArray []byte) (jsonData []byte, MACError bool) {

	var encryptedAndMACedData DataWithMACorSig
	json.Unmarshal(encryptedAndMACedDataByteArray, &encryptedAndMACedData)
	//unmarshall into struct with contents and MAC

	claimedMAC := encryptedAndMACedData.MACorSig
	encryptedData := encryptedAndMACedData.Contents

	actualMAC, _ := userlib.HMACEval(MACkey, encryptedData)

	//claimed MAC is stored MAC, actual MAC is result of applying MAC to encrypted data

	matchingMACs := userlib.HMACEqual(actualMAC, claimedMAC)
	//check if MACing data with our key gives us same MAC

	if !matchingMACs {
		return nil, false
	}
	//if not a match, integrity has been breached

	dataWithPadding := userlib.SymDec(cryptKey, encryptedData)
	padding_size := int(dataWithPadding[len(dataWithPadding)-1])
	dataWithoutPadding := dataWithPadding[:len(dataWithPadding)-padding_size]
	//depad now that we've decrypted

	return dataWithoutPadding, true
}

func encryptThenSign(encryptKey userlib.PKEEncKey, signKey userlib.DSSignKey, data []byte) (encryptedAndSignedDataByteArray []byte) {

	encryptedData, _ := userlib.PKEEnc(encryptKey, data)
	signature, _ := userlib.DSSign(signKey, encryptedData)
	//encrypt and generate signature

	var encryptedAndSignedData DataWithMACorSig
	encryptedAndSignedData.Contents = encryptedData
	encryptedAndSignedData.MACorSig = signature
	encryptedAndSignedDataByteArray, _ = json.Marshal(encryptedAndSignedData)
	return
}

func checkSigAndDecrypt(decryptKey userlib.PKEDecKey, verifyKey userlib.DSVerifyKey, encryptedAndSignedDataByteArray []byte) (jsonData []byte, sigError bool) {

	var encryptedAndSignedData DataWithMACorSig
	json.Unmarshal(encryptedAndSignedDataByteArray, &encryptedAndSignedData)

	actualSig := encryptedAndSignedData.MACorSig
	encryptedData := encryptedAndSignedData.Contents
	//actual MAC is MAC we are checking that's attached to data

	matchingSigs := userlib.DSVerify(verifyKey, encryptedData, actualSig)
	//check if MACing data with our key gives us same MAC

	if matchingSigs != nil {
		return nil, false
	}

	plaintextByteArray, _ := userlib.PKEDec(decryptKey, encryptedData)
	return plaintextByteArray, true
}

type FileMetadata struct {
	CryptKey []byte
	MACKey   []byte
	Location uuid.UUID
}

// Use= is the structure definition for a user record.
type User struct {
	Username         string
	Namespace        map[string]FileMetadata //Map, hashed file name -> FileMetadata
	SecretSignKey    userlib.DSSignKey
	SecretDecryptKey userlib.PKEDecKey
}

//struct with fields for marshalled struct to store as well as MAC/signature
type DataWithMACorSig struct {
	Contents []byte
	MACorSig []byte
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {

	cryptKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	//deterministically get symmetric key for encryption/decryption of user struct
	// from password w/ username salt

	MacKey, _ := userlib.HashKDF(cryptKey, []byte("mac for user's personal user struct"))
	MacKey = MacKey[:16]
	//get MAC key deterministically from first symmetric key

	var pk_encrypt_key userlib.PKEEncKey
	var sk_decrypt_key userlib.PKEDecKey
	pk_encrypt_key, sk_decrypt_key, _ = userlib.PKEKeyGen()
	//create public/private encryption/decryption keys

	var pk_verify_key userlib.DSVerifyKey
	var sk_sign_key userlib.DSSignKey
	sk_sign_key, pk_verify_key, _ = userlib.DSKeyGen()
	//create public/private verify/sign keys

	_, ok := userlib.KeystoreGet(username + "_verify_key")
	if ok {
		return nil, errors.New(strings.ToTitle("User already exists"))
	}

	userlib.KeystoreSet(username+"_verify_key", pk_verify_key)
	userlib.KeystoreSet(username+"_encrypt_key", pk_encrypt_key)
	//store user's public keys in keystore

	var userdata User
	userdataptr = &userdata
	userdata.Username = username
	userdata.Namespace = make(map[string]FileMetadata)
	userdata.SecretSignKey = sk_sign_key
	userdata.SecretDecryptKey = sk_decrypt_key
	//set user struct data (namespace is empty)

	userStructByteArray, _ := json.Marshal(userdata)
	encryptedThenMACedStruct := encryptThenMAC(cryptKey, MacKey, userStructByteArray)
	//marshall,encrypt, mac user struct

	usernameHashBytes := userlib.Hash([]byte(username))[:16]
	structLocation, _ := uuid.FromBytes(usernameHashBytes)
	//get uuid for user struct deterministically from username

	userlib.DatastoreSet(structLocation, encryptedThenMACedStruct)
	//store user struct in datastore

	return &userdata, nil
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {

	cryptKey := userlib.Argon2Key([]byte(password), []byte(username), 16)

	MacKey, _ := userlib.HashKDF(cryptKey, []byte("mac for user's personal user struct"))
	MacKey = MacKey[:16]
	//get keys same way as in InitUser (deterministic)

	usernameHashBytes := userlib.Hash([]byte(username))[:16]
	structLocation, _ := uuid.FromBytes(usernameHashBytes)
	//get location of user struct in datastore same way as in InitUser (deterministic)

	encryptedThenMACedStruct, ok := userlib.DatastoreGet(structLocation)

	if !ok {
		return nil, errors.New(strings.ToTitle("User does not exist"))
	}

	byteArrayUserData, ok2 := checkMACandDecrypt(cryptKey, MacKey, encryptedThenMACedStruct)

	if !ok2 {
		return nil, errors.New(strings.ToTitle("MAC Error: Invalid Credentials or struct compromised"))
	}

	//get struct, check MAC, decrypt

	var userdata User

	json.Unmarshal(byteArrayUserData, userdata)
	//Unmarshal struct

	userdataptr = &userdata

	return userdataptr, nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	fileNameHashed := hex.EncodeToString(userlib.Hash([]byte(filename)))
	//key for namespace map corresponding to filename

	newCryptKey := userlib.RandomBytes(16)
	newMACKey := userlib.RandomBytes(16)
	newFileLoc := uuid.New()
	//randomly create encrypt/decrypt and MAC keys, randomly generate location for file in Datastore

	userdata.Namespace[fileNameHashed] = FileMetadata{CryptKey: newCryptKey, MACKey: newMACKey, Location: newFileLoc}
	//create key-value pair in namespace with file name (hashed) as key,
	//and put new keys and location in FileMetadata struct as value

	jsonData, _ := json.Marshal(data)

	encryptedThenMACedData := encryptThenMAC(newCryptKey, newMACKey, jsonData)
	//marshall,encrypt, mac file

	userlib.DatastoreSet(userdata.Namespace[fileNameHashed].Location, encryptedThenMACedData)
	//store file in datastore

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	fileNameHashed := hex.EncodeToString(userlib.Hash([]byte(filename)))
	//key for namespace map corresponding to filename

	fileMetadataStruct, ok := userdata.Namespace[fileNameHashed]
	if !ok {
		return nil, errors.New(strings.ToTitle("File does not exist in namespace"))
	}
	//try to find file metadata via namespace, if not there file doesn't exist

	fileLoc := fileMetadataStruct.Location
	fileDecryptKey := fileMetadataStruct.CryptKey
	fileMACKey := fileMetadataStruct.MACKey
	//extract file's metadata from user struct

	encryptedThenMACedFile, ok2 := userlib.DatastoreGet(fileLoc)
	if !ok2 {
		return nil, errors.New(strings.ToTitle("Could not load file"))
	}
	dataJSON, ok3 := checkMACandDecrypt(fileDecryptKey, fileMACKey, encryptedThenMACedFile)
	if !ok3 {
		return nil, errors.New(strings.ToTitle("MAC error: unauthorized modifications to file"))
	}
	//get file, check mac, decrypt

	json.Unmarshal(dataJSON, &dataBytes)

	return dataBytes, nil

}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {

	fileNameHashed := hex.EncodeToString(userlib.Hash([]byte(filename)))
	fileToShareMetadata, ok := userdata.Namespace[fileNameHashed]
	if !ok {
		return uuid.New(), errors.New(strings.ToTitle("File does not exist in namespace"))
	}
	//error if file we want to share doesnt exist

	fileToShareMetadataByteArray, _ := json.Marshal(fileToShareMetadata)
	encryptKey, _ := userlib.KeystoreGet(recipient + "_encrypt_key")
	//public encrypt key of recipient

	signKey := userdata.SecretSignKey
	//private sign key of sender

	encryptedAndSignedMetadata := encryptThenSign(encryptKey, signKey, fileToShareMetadataByteArray)
	inviteLoc := uuid.New()
	userlib.DatastoreSet(inviteLoc, encryptedAndSignedMetadata)
	//store file metadata in random location encrypted and signed and we'll send location to recipient (fine if location intercepted)
	return inviteLoc, nil
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	//add to namespace map

	fileNameHashed := hex.EncodeToString(userlib.Hash([]byte(filename)))
	_, ok := userdata.Namespace[fileNameHashed]
	if ok {
		return errors.New(strings.ToTitle("File name already in namespace"))
	}
	//error if file already in namespace

	encryptedAndSignedInvite, ok2 := userlib.DatastoreGet(accessToken)
	if !ok2 {
		return errors.New(strings.ToTitle("Invitation file not found"))
	}

	verifyKey, _ := userlib.KeystoreGet(sender + "_verify_key")
	//public verify key of sender
	decryptKey := userdata.SecretDecryptKey
	//private decrypt key of recipient

	inviteFileMetadataJSON, ok3 := checkSigAndDecrypt(decryptKey, verifyKey, encryptedAndSignedInvite)
	if !ok3 {
		return errors.New(strings.ToTitle("Integrity of invitation compromised or invitation not from sender"))
	} //invite compromised if signature not verified

	var inviteFileMetadata FileMetadata

	json.Unmarshal(inviteFileMetadataJSON, &inviteFileMetadata)

	userdata.Namespace[fileNameHashed] = inviteFileMetadata
	//load file metadata from invite into namespace with hashed filename as key

	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	return
}
