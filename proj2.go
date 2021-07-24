package proj2

// CS 161 Project 2

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



type FileMetadata struct
{
	CryptKey []byte
	MACKey []byte
	Location UUID
}



// Use= is the structure definition for a user record.
type User struct {
	Username string
	Namespace map[[]byte]FileMetadata

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}





// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {


	cryptKey := userlib.Argon2Key(password,username,16)
	


	MacKey := userlib.HashKDF(cryptKey,[]byte("mac for user's personal user struct"))
	MacKey=MacKey[:16]



	var pk_encrypt_key userlib.PKEEncKey
	var sk_decrypt_key userlib.PKEDecKey
	pk_encrypt_key, sk_decrypt_key, _ = userlib.PKEKeyGen()




	var pk_verify_key userlib.DSVerifyKey
	var sk_sign_key userlib.DSSignKey
	pk_verify_key, sk_sign_key, _ = userlib.DSKeyGen()

	


	KeystoreSet(username+"_verify_key",pk_verify_key)
	KeystoreSet(username+"_encrypt_key",pk_encrypt_key)
	



	var userdata User 
	userdataptr = &userdata
	userdata.Username := username
	userdata.Namespace:= make(map[[]byte]FileMetadata)
	userdata.secretSignKey:=sk_sign_key
	userdata.secretDecryptKey:=sk_decrypt_key


	userStructByteArray:=json.Marshal(userdata)




	encryptedThenMACedStruct=encryptThenMAC(userStructByteArray,cryptKey,MacKey)


	usernameHashBytes:=Hash(username)[:16]
	structLocation:=uuid.FromBytes(usernameHashBytes)


	userlib.DatastoreSet(structLocation,encryptedThenMACedStruct)




	return &userdata, nil
}






// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	
	cryptKey := userlib.Argon2Key(password,username,16)


	MacKey := userlib.HashKDF(cryptKey,[]byte("mac for user's personal user struct"))
	MacKey=MacKey[:16]


	usernameHashBytes:=userlib.Hash([]byte(username))[:16]
	structLocation:=uuid.FromBytes(usernameHashBytes)
	
	encryptedThenMACedStruct:=userlib.DatastoreGet(structLocation)
	byteArrayUserData=checkMACandDecrypt(encryptedThenMACedStruct,cryptKey,MacKey)  
	var userdata User := json.Unmarshal(byteArrayUserData)
	userdataptr = &userdata


	return userdataptr, nil
}






// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	fileNameHashed:=userlib.Hash([]byte(filename))
	

	newCryptKey=userlib.RandomBytes(16)
	newMACKey=userlib.RandomBytes(16)
	newFileLoc=uuid.New()

	userdata.Namespace[fileNameHashed]=FileMetadata{CryptKey:newCryptKey,MacKey:newMACKey, UUID:newFileLoc}

	jsonData, _ := json.Marshal(data)
	
	encryptedThenMACedData:= encryptThenMAC(newCryptKey,newMACKey,jsonData)


	userlib.DatastoreSet(userdata.Namespace[fileNameHashed].UUID, encryptedThenMACedData)
	//End of toy implementation

	return
}


func encryptThenMAC(byte[] cryptKey, byte[] MACKey, byte[] data)
{
	IV:= userlib.RandomBytes(16)
	encryptedData:= userlib.SymEnc(cryptKey,IV,data)
	encryptedThenMACedData:= HMACEval(MACKey,encryptedData)+encryptedData
	return encryptedThenMACedData
} 

func checkMACandDecrypt(byte[] cryptKey, byte[] MACkey, byte[] encryptedThenMACedData)
{
	
	actualMAC:=encryptedThenMACedData[:16]
	encryptedData:=encryptedThenMACedData[16:]

	matchingMACs :=HMACEqual(  actualMAC,  userlib.HMACEval(encryptedData)  )

	if !matchingMACs {
		return nil, errors.New(strings.ToTitle("MAC error"))
	}

	return SymDec(cryptKey,encryptedStruct)
}

func encryptThenSign()
{

}

func checkSigAndDecrypt()
{

}



// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {


	fileNameHashed:=userlib.Hash([]byte(filename))
	fileMetadataStruct:= userdata.Namespace[fileNameHashed]
	fileLoc=fileMetadataStruct.Location
	fileDecryptKey=fileMetadataStruct.CryptKey
	fileMACKey=fileMetadataStruct.MACKey

	

	encryptedThenMACedFile:=userlib.DatastoreGet(fileLoc)
	


	
	dataJSON, ok := checkMACandDecrypt(encryptedThenMACedFile,fileDecryptKey,FileMacKey) 

	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(dataJSON, &dataBytes)
	return dataBytes, nil
	

	
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {
	userlib.KeystoreGet()
	return
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	return
}
