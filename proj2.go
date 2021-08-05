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

	//generate random IV for encryption (required to make IND-CPA secure)
	IV := userlib.RandomBytes(16)

	//number of bytes of padding needed (for example, if plaintext is 13 bytes, 3 bytes of padding needed to make multiple of 16)
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
	//pad plaintext using method from class: find # of bytes of padding needed, add to end of plaintext until padded: for example, mycoolmessage333.

	encryptedData := userlib.SymEnc(cryptKey, IV, data)
	//encrypt

	MAC, _ := userlib.HMACEval(MACKey, encryptedData)
	//generate MAC

	var encryptedAndMACedData DataWithMACorSig
	encryptedAndMACedData.Contents = encryptedData
	encryptedAndMACedData.MACorSig = MAC
	//store in struct with separate fields for ciphertext and MAC

	encryptedThenMACedDataByteArray, _ = json.Marshal(encryptedAndMACedData)
	//marshal this struct into byte array

	return

}

func checkMACandDecrypt(cryptKey []byte, MACkey []byte, encryptedAndMACedDataByteArray []byte) (jsonData []byte, MACError bool) {

	var encryptedAndMACedData DataWithMACorSig
	json.Unmarshal(encryptedAndMACedDataByteArray, &encryptedAndMACedData)
	//unmarshall into struct with ciphertext and MAC

	claimedMAC := encryptedAndMACedData.MACorSig
	encryptedData := encryptedAndMACedData.Contents

	actualMAC, _ := userlib.HMACEval(MACkey, encryptedData)

	//claimed MAC is MAC stored in Datastore with ciphertext, actual MAC is result of applying MAC function to encrypted data. If these match MAC is valid

	matchingMACs := userlib.HMACEqual(actualMAC, claimedMAC)
	//check if MACing data with our key gives us same MAC

	if !matchingMACs {
		return nil, false
	}
	//if not a match, integrity has been breached. We return false.

	dataWithPadding := userlib.SymDec(cryptKey, encryptedData)
	//decrypt into plaintext

	padding_size := int(dataWithPadding[len(dataWithPadding)-1])
	dataWithoutPadding := dataWithPadding[:len(dataWithPadding)-padding_size]
	//depad plaintext now that we've decrypted, for example mycoolmessage333 ---> mycoolmessage

	return dataWithoutPadding, true
}

func encryptThenSign(encryptKey userlib.PKEEncKey, signKey userlib.DSSignKey, data []byte) (encryptedAndSignedDataByteArray []byte) {

	encryptedData, _ := userlib.PKEEnc(encryptKey, data)
	signature, _ := userlib.DSSign(signKey, encryptedData)
	//encrypt and generate signature

	var encryptedAndSignedData DataWithMACorSig
	encryptedAndSignedData.Contents = encryptedData
	encryptedAndSignedData.MACorSig = signature
	//store in struct with separate fields for ciphertext and signature

	encryptedAndSignedDataByteArray, _ = json.Marshal(encryptedAndSignedData)
	//marshal this struct into byte array
	return
}

func checkSigAndDecrypt(decryptKey userlib.PKEDecKey, verifyKey userlib.DSVerifyKey, encryptedAndSignedDataByteArray []byte) (jsonData []byte, sigError bool) {

	var encryptedAndSignedData DataWithMACorSig
	json.Unmarshal(encryptedAndSignedDataByteArray, &encryptedAndSignedData)
	//unmarshall into struct with ciphertext and MAC

	actualSig := encryptedAndSignedData.MACorSig
	encryptedData := encryptedAndSignedData.Contents
	//actual Sig is Sig we are checking that's attached to data

	matchingSigs := userlib.DSVerify(verifyKey, encryptedData, actualSig)
	//check signature

	if matchingSigs != nil {
		return nil, false
	} //if verify fails integrity has been breached

	plaintextByteArray, _ := userlib.PKEDec(decryptKey, encryptedData)

	//decrypt into plaintext
	return plaintextByteArray, true
}

type Invite struct {
	FileKeysDecryptKey        []byte
	FileKeysMACKey            []byte
	FileKeysLocation          uuid.UUID
	FileLocationsListLocation uuid.UUID
}

type HybridEncryptionInvite struct {
	InviteToSend []byte
	CryptKey     []byte
	MACKey       []byte
}

type FileMetadata struct {
	IsOwner        bool
	ReceivedInvite Invite
	SharingMap     map[string]Invite
}

type FileKeys struct {
	CryptKey []byte
	MACKey   []byte
}

//file metadata includes symmetric key used to encrypt it, symmetric key used to MAC it, and location/UUID in Datastore

// Use= is the structure definition for a user record.
type User struct {
	Username         string
	Namespace        map[string]FileMetadata //Map, hashed file name -> FileMetadata
	SecretSignKey    userlib.DSSignKey
	SecretDecryptKey userlib.PKEDecKey
}

//User struct contains username, namespace (personal file directory), personal secret signing key, personal secret decrypting key

//struct with fields for marshalled struct to store as well as MAC/signature (TA advice)
type DataWithMACorSig struct {
	Contents []byte
	MACorSig []byte
}

func StoreInvite(invite Invite, encryptKey userlib.PKEEncKey, signKey userlib.DSSignKey, location uuid.UUID) {
	//create symm keys
	symmKey := userlib.RandomBytes(16)
	MACKey := userlib.RandomBytes(16)

	//marshal invite, encrypt and mac with symm keys
	inviteByteArray, _ := json.Marshal(invite)
	encryptedThenMACedInvite := encryptThenMAC(symmKey, MACKey, inviteByteArray)

	//sign symm keys with public encryption key and private sign key
	encryptedThenSignedSymmKey := encryptThenSign(encryptKey, signKey, symmKey)
	encryptedThenSignedMACKey := encryptThenSign(encryptKey, signKey, MACKey)

	//create struct with invite and symm keys, marshall, store in datastore
	var hybInvite HybridEncryptionInvite
	hybInvite.InviteToSend = encryptedThenMACedInvite
	hybInvite.CryptKey = encryptedThenSignedSymmKey
	hybInvite.MACKey = encryptedThenSignedMACKey
	hybInviteByteArray, _ := json.Marshal(hybInvite)
	userlib.DatastoreSet(location, hybInviteByteArray)

}

func StoreFileLocations(locations []uuid.UUID, encryptKey []byte, MACKey []byte, storeLocation uuid.UUID) {
	locationsByteArray, _ := json.Marshal(locations)
	encryptedThenMACedLocations := encryptThenMAC(encryptKey, MACKey, locationsByteArray)
	userlib.DatastoreSet(storeLocation, encryptedThenMACedLocations)

}

func AppendToFileLocations(appendValue uuid.UUID, cryptKey []byte, MACKey []byte, location uuid.UUID) (err bool) {
	locations, err := GetFileLocations(cryptKey, MACKey, location)
	//problem getting locations
	if !err {
		return false
	}

	//add new location
	locations = append(locations, appendValue)

	//store updated locations
	StoreFileLocations(locations, cryptKey, MACKey, location)
	return true

}

func GetFileLocations(decryptKey []byte, MACKey []byte, location uuid.UUID) (locations []uuid.UUID, err bool) {
	encryptedThenSignedLocations, err := userlib.DatastoreGet(location)
	if !err {
		return nil, false
	}

	locationsByteArray, err := checkMACandDecrypt(decryptKey, MACKey, encryptedThenSignedLocations)

	if !err {
		return nil, false
	}

	json.Unmarshal(locationsByteArray, &locations)

	return locations, true
}

func StoreFileData(data []byte, encryptKey []byte, MACKey []byte, location uuid.UUID) {
	dataByteArray, _ := json.Marshal(data)
	encryptedThenMACedData := encryptThenMAC(encryptKey, MACKey, dataByteArray)
	userlib.DatastoreSet(location, encryptedThenMACedData)

}

func GetFileData(encryptKey []byte, MACKey []byte, locations []uuid.UUID) (fileContents []byte, err bool) {
	fileContents = nil
	for _, loc := range locations {
		pieceByteArray, err := GetFilePieceData(encryptKey, MACKey, loc)
		if !err {
			return nil, false
		}
		fileContents = append(fileContents, pieceByteArray...)

	}
	return fileContents, true
}

func (userdata *User) UpdateFileKeys(hashedFilename string) (err bool) {

	newCryptKey := userlib.RandomBytes(16)
	newMACKey := userlib.RandomBytes(16)
	var newKeys FileKeys
	newKeys.CryptKey = newCryptKey
	newKeys.MACKey = newMACKey
	personalInvite := userdata.Namespace[hashedFilename].ReceivedInvite
	oldKeys, err := GetFileKeys(personalInvite.FileKeysDecryptKey, personalInvite.FileKeysMACKey, personalInvite.FileKeysLocation)
	if !err {
		return false
	}
	oldEncryptKey := oldKeys.CryptKey
	oldMACKey := oldKeys.MACKey

	locations, err := GetFileLocations(oldEncryptKey, oldMACKey, personalInvite.FileLocationsListLocation)
	if !err {
		return false
	}
	for _, loc := range locations {
		pieceByteArray, err := GetFilePieceData(oldEncryptKey, oldMACKey, loc)
		if !err {
			return false
		}
		StoreFileData(pieceByteArray, newKeys.CryptKey, newKeys.MACKey, loc)
	}
	StoreFileLocations(locations, newKeys.CryptKey, newKeys.MACKey, personalInvite.FileLocationsListLocation)

	StoreFileKeys(newKeys, personalInvite.FileKeysDecryptKey, personalInvite.FileKeysMACKey, personalInvite.FileKeysLocation)

	for key := range userdata.Namespace[hashedFilename].SharingMap {
		branchInvite := userdata.Namespace[hashedFilename].SharingMap[key]
		fileKeysCryptKey := branchInvite.FileKeysDecryptKey
		fileKeysMACKey := branchInvite.FileKeysMACKey
		keysLocation := branchInvite.FileKeysLocation

		StoreFileKeys(newKeys, fileKeysCryptKey, fileKeysMACKey, keysLocation)
	}
	return true
}

func GetFilePieceData(encryptKey []byte, MACKey []byte, location uuid.UUID) (pieceContent []byte, err bool) {
	encryptedThenMACedContent, err := userlib.DatastoreGet(location)
	if !err {
		return nil, false
	}
	contentByteArray, err := checkMACandDecrypt(encryptKey, MACKey, encryptedThenMACedContent)
	if !err {
		return nil, false
	}
	json.Unmarshal(contentByteArray, &pieceContent)
	return pieceContent, true
}

func GetInvite(decryptKey userlib.PKEDecKey, verifyKey userlib.DSVerifyKey, location uuid.UUID) (inviteContent Invite, err bool) {
	encryptedThenSignedHybInvite, err := userlib.DatastoreGet(location)
	if !err {
		return inviteContent, false
	}
	var hybInvite HybridEncryptionInvite
	json.Unmarshal(encryptedThenSignedHybInvite, &hybInvite)
	symmCryptKey, err := checkSigAndDecrypt(decryptKey, verifyKey, hybInvite.CryptKey)
	if !err {
		return inviteContent, false
	}
	symmMACKey, err := checkSigAndDecrypt(decryptKey, verifyKey, hybInvite.MACKey)
	if !err {
		return inviteContent, false
	}
	inviteByteArray, err := checkMACandDecrypt(symmCryptKey, symmMACKey, hybInvite.InviteToSend)

	if !err {
		return inviteContent, false
	}

	json.Unmarshal(inviteByteArray, &inviteContent)

	return inviteContent, true
}

func StoreFileKeys(fileKeys FileKeys, cryptKey []byte, MACKey []byte, location uuid.UUID) {
	fileKeysByteArray, _ := json.Marshal(fileKeys)
	encryptedThenMACedFileKeys := encryptThenMAC(cryptKey, MACKey, fileKeysByteArray)
	userlib.DatastoreSet(location, encryptedThenMACedFileKeys)
}

func GetFileKeys(cryptKey []byte, MACKey []byte, location uuid.UUID) (fileKeys FileKeys, err bool) {
	encryptedThenMACedFileKeys, err := userlib.DatastoreGet(location)
	if !err {
		return fileKeys, false
	}
	fileKeysByteArray, err := checkMACandDecrypt(cryptKey, MACKey, encryptedThenMACedFileKeys)
	if !err {
		return fileKeys, false
	}
	json.Unmarshal(fileKeysByteArray, &fileKeys)
	return fileKeys, true
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {

	cryptKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	// deterministically get symmetric key for encryption/decryption of user struct
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
	userdata.Namespace = make(map[string]FileMetadata) //empty map from string to file metadata struct (type of map is going to change after talking to TAs)
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

	json.Unmarshal(byteArrayUserData, &userdata)
	//Unmarshal struct

	userdataptr = &userdata

	return userdataptr, nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	fileNameHashed := hex.EncodeToString(userlib.Hash([]byte(filename)))
	//key for namespace map corresponding to filename

	fileMetadataStruct, ok := userdata.Namespace[fileNameHashed]
	if !ok {

		newCryptKey := userlib.RandomBytes(16)
		newMACKey := userlib.RandomBytes(16)
		newFileLoc := []uuid.UUID{uuid.New()}
		newFileLocationsListLoc := uuid.New()

		newFileKeysCryptKey := userlib.RandomBytes(16)
		newFileKeysMACKey := userlib.RandomBytes(16)
		newFileKeysLocation := uuid.New()
		//randomly create encrypt/decrypt and MAC keys, randomly generate location for file in Datastore

		var selfInvite = Invite{FileLocationsListLocation: newFileLocationsListLoc, FileKeysDecryptKey: newFileKeysCryptKey, FileKeysMACKey: newFileKeysMACKey, FileKeysLocation: newFileKeysLocation}
		userdata.Namespace[fileNameHashed] = FileMetadata{IsOwner: true, ReceivedInvite: selfInvite, SharingMap: make(map[string]Invite)}

		var selfFileKeys = FileKeys{CryptKey: newCryptKey, MACKey: newMACKey}

		StoreFileKeys(selfFileKeys, newFileKeysCryptKey, newFileKeysMACKey, newFileKeysLocation)
		//store file in datastore

		StoreFileLocations(newFileLoc, newCryptKey, newMACKey, newFileLocationsListLoc)

		StoreFileData(data, newCryptKey, newMACKey, newFileLoc[0])

		return

	} else {

		inviteStruct := fileMetadataStruct.ReceivedInvite
		keysLocation := inviteStruct.FileKeysLocation
		keysDecryptKey := inviteStruct.FileKeysDecryptKey
		keysMACKey := inviteStruct.FileKeysMACKey
		fileKeys, ok2 := GetFileKeys(keysDecryptKey, keysMACKey, keysLocation)
		if !ok2 {
			return errors.New(strings.ToTitle("err"))
		}
		cryptKey := fileKeys.CryptKey
		MACKey := fileKeys.MACKey

		newFileLoc := []uuid.UUID{uuid.New()}

		fileLocationsListLoc := inviteStruct.FileLocationsListLocation

		StoreFileData(data, cryptKey, MACKey, newFileLoc[0])

		StoreFileLocations(newFileLoc, cryptKey, MACKey, fileLocationsListLoc)

		return

	}
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	fileNameHashed := hex.EncodeToString(userlib.Hash([]byte(filename)))

	//key for namespace map corresponding to filename
	fileMetadataStruct, ok := userdata.Namespace[fileNameHashed]
	if !ok {
		return errors.New(strings.ToTitle("File does not exist in namespace1"))
	}
	inviteStruct := fileMetadataStruct.ReceivedInvite
	keysLocation := inviteStruct.FileKeysLocation
	keysDecryptKey := inviteStruct.FileKeysDecryptKey
	keysMACKey := inviteStruct.FileKeysMACKey
	fileLocationsListLoc := inviteStruct.FileLocationsListLocation
	newFilePieceLoc := uuid.New()

	keysStruct, ok := GetFileKeys(keysDecryptKey, keysMACKey, keysLocation)
	if !ok {
		return errors.New(strings.ToTitle("File does not exist in namespace2"))
	}
	cryptKey := keysStruct.CryptKey
	MACKey := keysStruct.MACKey

	ok = AppendToFileLocations(newFilePieceLoc, cryptKey, MACKey, fileLocationsListLoc)
	if !ok {
		return errors.New(strings.ToTitle("File does not exist in namespace3"))
	}
	StoreFileData(data, cryptKey, MACKey, newFilePieceLoc)

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
	inviteStruct := fileMetadataStruct.ReceivedInvite
	keysLocation := inviteStruct.FileKeysLocation
	keysDecryptKey := inviteStruct.FileKeysDecryptKey
	keysMACKey := inviteStruct.FileKeysMACKey
	fileLocationsListLoc := inviteStruct.FileLocationsListLocation

	keysStruct, ok := GetFileKeys(keysDecryptKey, keysMACKey, keysLocation)
	if !ok {
		return nil, errors.New(strings.ToTitle("Couldn't get keys"))
	}
	cryptKey := keysStruct.CryptKey
	MACKey := keysStruct.MACKey
	fileLocations, ok := GetFileLocations(cryptKey, MACKey, fileLocationsListLoc)
	if !ok {
		return nil, errors.New(strings.ToTitle("Keys MAC Invalid"))
	}
	data, ok := GetFileData(cryptKey, MACKey, fileLocations)
	if !ok {
		return nil, errors.New(strings.ToTitle("File MAC Invalid"))
	}
	return data, nil

}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {

	fileNameHashed := hex.EncodeToString(userlib.Hash([]byte(filename)))
	fileMetadata, ok := userdata.Namespace[fileNameHashed]

	if !ok {
		return uuid.New(), errors.New(strings.ToTitle("File does not exist in namespace"))
	}

	if fileMetadata.IsOwner {
		newFileKeysLocation := uuid.New()
		newBranchFileKeysCryptKey := userlib.RandomBytes(16)
		newBranchFileKeysMACKey := userlib.RandomBytes(16)
		var fileKeys, ok = GetFileKeys(fileMetadata.ReceivedInvite.FileKeysDecryptKey, fileMetadata.ReceivedInvite.FileKeysMACKey, fileMetadata.ReceivedInvite.FileKeysLocation)
		if !ok {
			return uuid.New(), errors.New(strings.ToTitle("err"))
		}

		var invite = Invite{FileKeysLocation: newFileKeysLocation, FileKeysDecryptKey: newBranchFileKeysCryptKey, FileKeysMACKey: newBranchFileKeysMACKey, FileLocationsListLocation: fileMetadata.ReceivedInvite.FileLocationsListLocation}

		fileMetadata.SharingMap[recipient] = invite

		StoreFileKeys(fileKeys, newBranchFileKeysCryptKey, newBranchFileKeysMACKey, newFileKeysLocation)
		inviteLoc := uuid.New()
		recipientEncryptKey, err := userlib.KeystoreGet(recipient + "_encrypt_key")
		if !err {
			return uuid.New(), errors.New(strings.ToTitle("File name already in namespace"))
		}
		StoreInvite(invite, recipientEncryptKey, userdata.SecretSignKey, inviteLoc)

		return inviteLoc, nil
	} else {
		inviteLoc := uuid.New()

		var invite = fileMetadata.ReceivedInvite

		recipientEncryptKey, err := userlib.KeystoreGet(recipient + "_encrypt_key")
		if !err {
			return uuid.New(), errors.New(strings.ToTitle("File name already in namespace"))
		}

		StoreInvite(invite, recipientEncryptKey, userdata.SecretSignKey, inviteLoc)

		return inviteLoc, nil
	}

	//store file metadata in random location encrypted and signed and we'll send location to recipient (fine if location intercepted)

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

	verifyKey, err := userlib.KeystoreGet(sender + "_verify_key")
	if !err {
		return errors.New(strings.ToTitle("gderr"))
	}
	//public verify key of sender
	decryptKey := userdata.SecretDecryptKey
	//private decrypt key of recipient
	invite, err := GetInvite(decryptKey, verifyKey, accessToken)
	if !err {
		return errors.New(strings.ToTitle("essrr"))
	}

	userdata.Namespace[fileNameHashed] = FileMetadata{IsOwner: false, ReceivedInvite: invite, SharingMap: nil}
	_, ok = GetFileKeys(invite.FileKeysDecryptKey, invite.FileKeysMACKey, invite.FileKeysLocation)
	//load file metadata from invite into namespace with hashed filename as key
	if !ok {
		return errors.New(strings.ToTitle("eddrr"))
	}
	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {

	fileNameHashed := hex.EncodeToString(userlib.Hash([]byte(filename)))
	_, ok := userdata.Namespace[fileNameHashed]
	if !ok {
		return errors.New(strings.ToTitle("Err"))
	}
	delete(userdata.Namespace[fileNameHashed].SharingMap, targetUsername)
	userdata.UpdateFileKeys(fileNameHashed)

	return nil
}
