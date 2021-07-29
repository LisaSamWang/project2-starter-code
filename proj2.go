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

	//deterministically get symmetric key for encryption/decryption of user struct
	// from password w/ username salt
	cryptKey := userlib.Argon2Key([]byte(password), []byte(username), 16)

	//get MAC key deterministically from first symmetric key
	//these first two keys are for storing user struct
	MacKey, _ := userlib.HashKDF(cryptKey, []byte("mac for user's personal user struct"))
	MacKey = MacKey[:16]

	//create public/private encryption/decryption keys
	var pk_encrypt_key userlib.PKEEncKey
	var sk_decrypt_key userlib.PKEDecKey
	pk_encrypt_key, sk_decrypt_key, _ = userlib.PKEKeyGen()

	//create public/private verify/sign keys
	var pk_verify_key userlib.DSVerifyKey
	var sk_sign_key userlib.DSSignKey
	sk_sign_key, pk_verify_key, _ = userlib.DSKeyGen()

	//check if user already exists-maybe useless
	_, ok := userlib.KeystoreGet(username + "_verify_key")
	if ok {
		return nil, errors.New(strings.ToTitle("User already exists"))
	}

	//store user's public keys in keystore
	userlib.KeystoreSet(username+"_verify_key", pk_verify_key)
	userlib.KeystoreSet(username+"_encrypt_key", pk_encrypt_key)

	//set user struct data (namespace is empty)
	var userdata User
	userdataptr = &userdata
	userdata.Username = username
	userdata.Namespace = make(map[string]FileMetadata)
	userdata.SecretSignKey = sk_sign_key
	userdata.SecretDecryptKey = sk_decrypt_key

	//marshal ,encrypt, mac user struct
	userStructByteArray, _ := json.Marshal(userdata)
	encryptedThenMACedStruct := encryptThenMAC(cryptKey, MacKey, userStructByteArray)

	//get uuid for user struct deterministically from username (where to store in Datastore)
	usernameHashBytes := userlib.Hash([]byte(username))[:16]
	structLocation, _ := uuid.FromBytes(usernameHashBytes)

	//store user struct in datastore
	userlib.DatastoreSet(structLocation, encryptedThenMACedStruct)

	return &userdata, nil
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {

	//get keys same way as in InitUser (deterministic)
	cryptKey := userlib.Argon2Key([]byte(password), []byte(username), 16)

	MacKey, _ := userlib.HashKDF(cryptKey, []byte("mac for user's personal user struct"))
	MacKey = MacKey[:16]

	//get location of user struct in datastore same way as in InitUser (deterministic)
	usernameHashBytes := userlib.Hash([]byte(username))[:16]
	structLocation, _ := uuid.FromBytes(usernameHashBytes)

	//grab struct as byte array
	encryptedThenMACedStruct, ok := userlib.DatastoreGet(structLocation)

	//sketchy, maybe useless
	if !ok {
		return nil, errors.New(strings.ToTitle("User does not exist"))
	}

	//checking struct valid
	byteArrayUserData, ok2 := checkMACandDecrypt(cryptKey, MacKey, encryptedThenMACedStruct)

	//error if not
	if !ok2 {
		return nil, errors.New(strings.ToTitle("MAC Error: Invalid Credentials or struct compromised"))
	}

	var userdata User

	//Unmarshal struct
	json.Unmarshal(byteArrayUserData, &userdata)

	userdataptr = &userdata

	return userdataptr, nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	//DNE case, needs helper
	//key for namespace map corresponding to filename

	fileNameHashed := hex.EncodeToString(userlib.Hash([]byte(filename)))

	//randomly create encrypt/decrypt and MAC keys, randomly generate location for file in Datastore
	newCryptKey := userlib.RandomBytes(16)
	newMACKey := userlib.RandomBytes(16)
	newFileLoc := uuid.New()

	//create key-value pair in namespace with file name (hashed) as key,
	//and put new keys and location in FileMetadata struct as value
	userdata.Namespace[fileNameHashed] = FileMetadata{CryptKey: newCryptKey, MACKey: newMACKey, Location: newFileLoc}

	jsonData, _ := json.Marshal(data)

	//marshall,encrypt, mac file
	encryptedThenMACedData := encryptThenMAC(newCryptKey, newMACKey, jsonData)

	//store file in datastore
	userlib.DatastoreSet(userdata.Namespace[fileNameHashed].Location, encryptedThenMACedData)

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

	//mapkey for namespace map corresponding to filename
	fileNameHashed := hex.EncodeToString(userlib.Hash([]byte(filename)))

	//try to find file metadata via namespace, if not there file doesn't exist
	fileMetadataStruct, ok := userdata.Namespace[fileNameHashed]
	if !ok {
		return nil, errors.New(strings.ToTitle("File does not exist in namespace"))
	}

	//extract file's metadata from user struct
	fileLoc := fileMetadataStruct.Location
	fileDecryptKey := fileMetadataStruct.CryptKey
	fileMACKey := fileMetadataStruct.MACKey

	//get file, check mac, decrypt
	encryptedThenMACedFile, ok2 := userlib.DatastoreGet(fileLoc)
	if !ok2 {
		return nil, errors.New(strings.ToTitle("Could not load file"))
	}
	dataJSON, ok3 := checkMACandDecrypt(fileDecryptKey, fileMACKey, encryptedThenMACedFile)
	if !ok3 {
		return nil, errors.New(strings.ToTitle("MAC error: unauthorized modifications to file"))
	}

	//unpack, return file to user
	json.Unmarshal(dataJSON, &dataBytes)

	return dataBytes, nil

}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {

	//access file keys and location via namespace
	fileNameHashed := hex.EncodeToString(userlib.Hash([]byte(filename)))
	fileToShareMetadata, ok := userdata.Namespace[fileNameHashed]

	//error if file we want to share doesnt exist
	if !ok {
		return uuid.New(), errors.New(strings.ToTitle("File does not exist in namespace"))
	}

	//public encrypt key of recipient
	encryptKey, _ := userlib.KeystoreGet(recipient + "_encrypt_key")

	//private sign key of sender
	signKey := userdata.SecretSignKey

	//prepare to store invite contents
	fileToShareMetadataByteArray, _ := json.Marshal(fileToShareMetadata)
	encryptedAndSignedMetadata := encryptThenSign(encryptKey, signKey, fileToShareMetadataByteArray)

	//random location for invite
	inviteLoc := uuid.New()

	//store invite contents in random location, return location, we're done
	// (fine if location intercepted)
	userlib.DatastoreSet(inviteLoc, encryptedAndSignedMetadata)

	return inviteLoc, nil
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {

	//check if in namespace
	fileNameHashed := hex.EncodeToString(userlib.Hash([]byte(filename)))
	_, ok := userdata.Namespace[fileNameHashed]

	//error if file already in namespace
	if ok {
		return errors.New(strings.ToTitle("File name already in namespace"))
	}

	//public verify key of sender
	verifyKey, _ := userlib.KeystoreGet(sender + "_verify_key")

	//private decrypt key of recipient
	decryptKey := userdata.SecretDecryptKey

	//get invite
	encryptedAndSignedInvite, ok2 := userlib.DatastoreGet(accessToken)
	if !ok2 {
		return errors.New(strings.ToTitle("Invitation file not found"))
	}

	//check signature, decrypt invite contents
	inviteFileMetadataJSON, ok3 := checkSigAndDecrypt(decryptKey, verifyKey, encryptedAndSignedInvite)

	//invite compromised if signature not correct
	if !ok3 {
		return errors.New(strings.ToTitle("Integrity of invitation compromised or invitation not from sender"))
	}

	var inviteFileMetadata FileMetadata

	json.Unmarshal(inviteFileMetadataJSON, &inviteFileMetadata)

	//load file metadata from invite into namespace with hashed filename as key
	userdata.Namespace[fileNameHashed] = inviteFileMetadata

	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	return
}
