package client

// Errors to fix:
// - KeyStore.get returns a value of PKEEncKey/DSVerifyKey and KeyStore.set takes in a value of PKEEncKey/DSVerifyKey
// - Need to change all the "byte" to "[]byte"

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string //username provided
	Password string //password provided
	PrivateDecKey userlib.PKEDecKey //a private key for accepting for decrypting invitations received (NEW)
	PrivateSignKey userlib.DSSignKey //a private key to sign invitation structs. Can be verified with a public key by anyone
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
	FilesAndAccessors map[string][]AccessorInfoStruct //a dictionary where the keys are the filenames and values are lists of 2nd layer accessors' [FileEntry UUID, HMACK, Dk, recipient]
	NotTampered string
}
type UserFile struct{ 
	FileEntryUUID uuid.UUID  //UUID for the file entry struct for this specific user/file pair
	FileEntryEncK []byte// decryption key for that entry struct
	FileEntryHMACK []byte
}
type FileEntry struct{
	BaseFileUUID uuid.UUID  //this may be the old UUID of the file depending on if this user has been revoked or not
	BaseFileEncK []byte //decryption key for this ^^BaseFile struct. Both of these are given in the Invitation
	BaseFileHMACK []byte
} 
type Invitation struct{
	SigU uuid.UUID //SignatureToVerify
	INS uuid.UUID //Invitation_without_sig
	FEHk []byte //FileEntryHMACK 
	FEEk []byte //FileEntryEncK
	NFEU uuid.UUID //NewFileEntryUUID
}
type InvitePointer struct{
	UUIDOfInvitation uuid.UUID // we will encrypt this entire struct and send it over
}
type BaseFile struct{
	BaseUUID uuid.UUID  // This is the starting UUID for the first block in the file
	NoOfBlocks int // Represents the number of blocks that we have in our file, each append creates a new block
}
type Enc_HMAC struct{
	UserHMACStruct []byte //HMAC of the encrypted User Struct
	UserEncStruct []byte //The encrypted User Struct
}
type AccessorInfoStruct struct {
	Accessors_UUID uuid.UUID
	Accessors_HMACK []byte
	Accessors_DK []byte
	Accessors_username string 
}
type FileContent struct {
	ContentBytes []byte 
	NextBlockUUID uuid.UUID
	LastBlockUUID uuid.UUID //this is the uuid for the next block of contents to be appended to 
	Marker int
}
// NOTE: The following methods have toy (insecure!) implementations.

// For init user, we have steps:
// - Store pw and username
// - Use the password and the username to derive one key using PBKDF
// - Use this key to derive two more keys using HKBDF, one for Ek and HMAC
// - For IV, use random bytes 
// - Encrypt and HMAC both
// - Calculate the UUID from the hash of the username and 

func InitUser(username string, password string) (userdataptr *User, err error) {
	err = nil
	var userdata User
	userdata.Username = username
	if (username == "") {
		err = errors.New("Username cannot be empty")
		return &userdata, err
	}
	userdata.NotTampered = "Not Tampered"
	userdata.Password = password
	userdata.FilesAndAccessors = make(map[string][]AccessorInfoStruct) 
	//generate a public and pivate keys for each user and store public in keystore and private in user struct (for invitation/accept)
	var PublicEncKey userlib.PKEEncKey
	var PrivateDecKey userlib.PKEDecKey
	PublicEncKey, ok := userlib.KeystoreGet(username + "PublicEncryptionKey")// Check if this user exists already. If the the PublicEncKey exist already, that means user already exists.
	if ok{
		err = errors.New("The username already exists")
		return &userdata, err
	}
	PublicEncKey, PrivateDecKey, err = userlib.PKEKeyGen() //generate public/private keys 
	userdata.PrivateDecKey = PrivateDecKey 
	err = userlib.KeystoreSet(username + "PublicEncryptionKey", PublicEncKey) //store public key in Keystore with "username" + "PublicEncryptionKey"
	//generate a sign and verify keys for each user and store verify in keystore and sign in user struct (for invitation/accept)
	var SignKey userlib.DSSignKey
	var VerifyKey userlib.DSVerifyKey
	SignKey, VerifyKey, err = userlib.DSKeyGen()  //generate sign/verify keys 
	userdata.PrivateSignKey = SignKey
	err = userlib.KeystoreSet(username + "PublicVerifyKey", VerifyKey) //store sign key in Keystore with "username" + "PublicSignKey"
	var passwordBytes []byte
	var usernameBytes []byte
	//make keys for HMAC and Encryption
	passwordBytes, err = json.Marshal(password)
	usernameBytes, err = json.Marshal(username)
	var PBKDF []byte = userlib.Argon2Key(passwordBytes, usernameBytes, 16)
	var HMACPurpose []byte
	HMACPurpose, err = json.Marshal("HMAC key for User Struct")
	var EncPurpose []byte
	EncPurpose, err = json.Marshal("Encryption key for User Struct")
	var HMACKey []byte
	HMACKey, err = userlib.HashKDF(PBKDF, HMACPurpose)
	HMACKey = HMACKey[:16]
	var EncryptKey []byte
	EncryptKey, err = userlib.HashKDF(PBKDF, EncPurpose)
	EncryptKey = EncryptKey[:16]
	var IV []byte = userlib.RandomBytes(16)
	//encrypt and mac the user struct
	var userDataBytes []byte
	userDataBytes, err = json.Marshal(userdata) //convert the user struct into bytes
	var userDataEncrypted []byte = userlib.SymEnc(EncryptKey, IV, userDataBytes)
	var userDataHMAC []byte
	userDataHMAC, err = userlib.HMACEval(HMACKey, userDataBytes)
	//store both Enc and HMAC version of struct in a single struct
	var CombineStructs Enc_HMAC
	CombineStructs.UserEncStruct = userDataEncrypted
	CombineStructs.UserHMACStruct = userDataHMAC
	var CombineStructsByte []byte
	CombineStructsByte, err = json.Marshal(CombineStructs)
	//store the combined struct into datastore database
	
	var UserStructUUID uuid.UUID 
	hash := userlib.Hash(usernameBytes)
	UserStructUUID, err = uuid.FromBytes(hash[:16]) 
	
	userlib.DatastoreSet(UserStructUUID, CombineStructsByte) 
	return &userdata, err
}

//Goal is to rederive the key given the username and password
//Use the string and password to rederive the keys using the same process as inituser
//Find the UUID
//Decrypt the encryption and run HMAC on the data
//Check if HMACs are equal, if not, throw an error
func GetUser(username string, password string) (userdataptr *User, err error) {
	err = nil
	var userdata User
	userdataptr = &userdata
	var passwordBytes []byte
	var usernameBytes []byte
	passwordBytes, err = json.Marshal(password)
	usernameBytes, err = json.Marshal(username)
	//Rederive the keys from the provided username and password
	var PBKDF []byte = userlib.Argon2Key(passwordBytes, usernameBytes, 16)
	var HMACPurpose []byte
	HMACPurpose, err = json.Marshal("HMAC key for User Struct")
	var EncPurpose []byte
	EncPurpose, err = json.Marshal("Encryption key for User Struct")
	var HMACKey []byte
	HMACKey, err = userlib.HashKDF(PBKDF, HMACPurpose)
	HMACKey = HMACKey[:16]
	var DecryptKey []byte
	DecryptKey, err = userlib.HashKDF(PBKDF, EncPurpose)
	DecryptKey = DecryptKey[:16]
	//Get UUID
	var UserStructUUID uuid.UUID 
	hash := userlib.Hash(usernameBytes)
	UserStructUUID, err = uuid.FromBytes(hash[:16]) 
	
	//Get combined User struct from the UUID in the DataStore database
	var ok bool
	var RetrievedCombinedStructBytes []byte
	RetrievedCombinedStructBytes, ok = userlib.DatastoreGet(UserStructUUID)
	if !ok {
		err = errors.New("User does not exist")
		return &userdata, err
	}
	var RetrievedCombinedStruct Enc_HMAC
	json.Unmarshal(RetrievedCombinedStructBytes, &RetrievedCombinedStruct)
	var ReferenceHMACStruct []byte = RetrievedCombinedStruct.UserHMACStruct //the HMAC struct already stored at the UUID
	var ReferenceEncStruct []byte = RetrievedCombinedStruct.UserEncStruct //the Enc struct already stored at the UUID
	if len(ReferenceEncStruct) < 10 {
		err = errors.New("User has been tampered")
		return &userdata, err
	}
	var DecryptedStruct []byte = userlib.SymDec(DecryptKey, ReferenceEncStruct)
	var HMACStruct []byte
	HMACStruct, err = userlib.HMACEval(HMACKey, DecryptedStruct)
	//Compare this derived HMACStruct with what was originally stored at the CombinedStruct UUID. If they are equal, then you decrypted the correct file
	var CompareHMACs bool = userlib.HMACEqual(HMACStruct, ReferenceHMACStruct)
	if (CompareHMACs == false){
		err = errors.New("Invalid credentials")
		return &userdata, err
	}
	var ReturnUserStruct User
	err = json.Unmarshal(DecryptedStruct, &ReturnUserStruct)
	if CompareHMACs {
		userdataptr = &ReturnUserStruct
	} 
	if (ReturnUserStruct.NotTampered != "Not Tampered") {
		err = errors.New("User has been tampered")
		return &userdata, err
	}
	return userdataptr, err
}
//Check if UserFile struct exists at hash(filename + username)
	//If it does not exist, initialize a UserFile struct, File Entry and a BaseFile struct
	//Else, access UUID of UserFile struct = hash(filename + usernamne) and retrieve the UserEntry struct, and then BaseFile struct
//Place content in the first UUID block of BaseFile and set number of blocks to 1
//Retrieve username + password from UserStruct
//Derive a key using PBKDF(username + password) and use it to generate 6 new keys using HashKDF; for UserFile, FileEntry, and BaseFile
//Encrypt-then-HMAC BaseFile Struct and store the keys in the FileEntry struct
//Encrypt-then-HMAC FileEntry Struct and store the keys in the UserFile struct
//Encrypt-then-HMAC UserFile Struct. No storage for these keys as we can rederive them using username+password
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	err = nil
	if (userdata.NotTampered != "Not Tampered") {
		err = errors.New("User has been tampered")
		return err
	}
	var username string = userdata.Username
	var password string = userdata.Password
	passwordBytes, err := json.Marshal(password)
	usernameBytes, err := json.Marshal(username)
	var UUID_hash uuid.UUID 
	UUID_hash, err = uuid.FromBytes(userlib.Hash([]byte(filename + username))[0:16]) //attempting to retrieve UseFile Struct's UUID
	var PBKDF []byte = userlib.Argon2Key(passwordBytes, usernameBytes, 16) //rederive hmac key using password + "username, password, userfile struct, hmac"

	var CombinedUserFile []byte 
	var ok bool
	CombinedUserFile, ok = userlib.DatastoreGet(UUID_hash)
	
	 //Get UserFile struct value (encrypted)
	if !ok{ //case where userfile has not been initialized in datastore ; create the structs
		var UserFileObject UserFile
		var FileEntryObject FileEntry
		var BaseFileObject BaseFile

		//Now store the contents into the basefile struct
		BaseFileObject.BaseUUID = uuid.New()
		BaseFileObject.NoOfBlocks = 1

		//Generate a new FileContent Struct with content = content and next block UUID as a random UUID
		var NewFileContent FileContent
		NewFileContent.Marker = 12345 + 1
		NewFileContent.ContentBytes = content
		NewFileContent.NextBlockUUID =  uuid.New()
		NewFileContent.LastBlockUUID = NewFileContent.NextBlockUUID 
		var NewFileContentBytes []byte
		NewFileContentBytes, err = json.Marshal(NewFileContent)

		userlib.DatastoreSet(BaseFileObject.BaseUUID, NewFileContentBytes) //STORE the first FileContent Struct at the BaseUUID
		//Encrypt the BaseFile Object now with the BaseUUID and no of blocks and store it in datastore
		var HMACPurpose []byte
		HMACPurpose, err = json.Marshal(username + password + filename + "BaseFileHMAC")
		var EncPurpose []byte
		EncPurpose, err = json.Marshal(username + password + filename + "BaseFileEncrypt")
		var BaseHMACK []byte
		BaseHMACK, err = userlib.HashKDF(PBKDF, HMACPurpose) 
		BaseHMACK = BaseHMACK[:16]
		var BaseEncK []byte
		BaseEncK, err = userlib.HashKDF(PBKDF, EncPurpose)
		BaseEncK = BaseEncK[:16]
		var BaseFileObjectByte []byte
		BaseFileObjectByte, err = json.Marshal(BaseFileObject)
		var CombinedBaseFile Enc_HMAC 
		CombinedBaseFile, err = EncryptWithKeys(BaseHMACK, BaseEncK, BaseFileObjectByte)
		//Set UUID and Keys of BaseFile Struct in File Entry to random bytes and put it in data store
		FileEntryObject.BaseFileUUID = uuid.New()
		FileEntryObject.BaseFileEncK = BaseEncK
		FileEntryObject.BaseFileHMACK = BaseHMACK
		var CombinedBaseFileBytes []byte
		CombinedBaseFileBytes, err = json.Marshal(CombinedBaseFile)
		userlib.DatastoreSet(FileEntryObject.BaseFileUUID, CombinedBaseFileBytes)

		//Repeat process to encrypt-hmac and store the file entry struct
		HMACPurpose, err = json.Marshal(username + password + filename + "FileEntryHMAC")
		EncPurpose, err = json.Marshal(username + password + filename + "FileEntryEncrypt")
		var FileEntryHMACK []byte
		FileEntryHMACK, err = userlib.HashKDF(PBKDF, HMACPurpose)
		FileEntryHMACK = FileEntryHMACK[:16]
		var FileEntryEncK []byte
		FileEntryEncK, err = userlib.HashKDF(PBKDF, EncPurpose) 
		FileEntryEncK = FileEntryEncK[:16]
		var CombinedFileEntry Enc_HMAC 
		var FileEntryObjectByte []byte
		FileEntryObjectByte, err = json.Marshal(FileEntryObject)
		CombinedFileEntry, err = EncryptWithKeys(FileEntryHMACK, FileEntryEncK, FileEntryObjectByte)
		//Set UUID and Keys of FileEntry Struct in UserFile to random bytes and put it in data store
	    UserFileObject.FileEntryUUID = uuid.New()
		UserFileObject.FileEntryEncK = FileEntryEncK
		UserFileObject.FileEntryHMACK = FileEntryHMACK
		var CombinedFileEntryBytes []byte
		CombinedFileEntryBytes, err = json.Marshal(CombinedFileEntry)
		userlib.DatastoreSet(UserFileObject.FileEntryUUID, CombinedFileEntryBytes)
		
		//Finally encrypt-hmac the userfile struct and store in datastore
		HMACPurpose, err = json.Marshal(username + password + filename + "UserFileHMAC")
		EncPurpose, err = json.Marshal(username + password + filename + "UserFileEncrypt")
		var UserFileHMACK []byte
		UserFileHMACK, err = userlib.HashKDF(PBKDF, HMACPurpose) 
		UserFileHMACK = UserFileHMACK[:16]
		var UserFileEncK []byte
		UserFileEncK, err = userlib.HashKDF(PBKDF, EncPurpose) 
		UserFileEncK = UserFileEncK[:16]
		var UserFileObjectByte []byte
		UserFileObjectByte, err = json.Marshal(UserFileObject)
		var CombinedUserFile Enc_HMAC 
		CombinedUserFile, err = EncryptWithKeys(UserFileHMACK, UserFileEncK, UserFileObjectByte)
		CombinedUserFileBytes, err := json.Marshal(CombinedUserFile)
		var UserFileUUID uuid.UUID 
		UserFileUUID, err = uuid.FromBytes(userlib.Hash([]byte(filename + username))[0:16])
		userlib.DatastoreSet(UserFileUUID, CombinedUserFileBytes) //*******************May need to slice the bytes
		return err
	} else { //case where userfile exists. Derive keys and retrieve the userfile, fileentry, and basefile structs
		
		var HMACPurpose []byte
		HMACPurpose, err = json.Marshal(username + password + filename + "UserFileHMAC")
		var EncPurpose []byte
		EncPurpose, err = json.Marshal(username + password + filename + "UserFileEncrypt")
		var HMACKey []byte
		HMACKey, err = userlib.HashKDF(PBKDF, HMACPurpose) //rederive hmac key using password + "username, password, userfile struct, encrypt"
		HMACKey = HMACKey[:16]
		var DecryptKey []byte
		DecryptKey, err = userlib.HashKDF(PBKDF, EncPurpose) 
		DecryptKey = DecryptKey[:16]
		//Using the keys, decrypt the userfile stuct and retrieve user entry + basefile struct
		var UserFileDecrypted []byte
		UserFileDecrypted, err := DecryptAndCompare(HMACKey, DecryptKey, CombinedUserFile)

		//Unmarshal and retrieve actual UserFile Struct object
		var UserFileObject UserFile
		err = json.Unmarshal(UserFileDecrypted, &UserFileObject)
		//Now retrieve FileEntry struct and BaseFile struct with the keys
		var ok bool
		var FileEntryEncrypted []byte
		FileEntryEncrypted, ok = userlib.DatastoreGet(UserFileObject.FileEntryUUID)
		if !ok {
			err = errors.New("User access to this file has been revoked")
			return err
		}
		var FileEntryEncDk []byte = UserFileObject.FileEntryEncK
		var FileEntryHMACDk []byte = UserFileObject.FileEntryHMACK
		var FileEntryBytes []byte
		FileEntryBytes, err = DecryptAndCompare(FileEntryHMACDk, FileEntryEncDk, FileEntryEncrypted)

		var FileEntryObject FileEntry
		err = json.Unmarshal(FileEntryBytes, &FileEntryObject) //Retrieved FileEntry Struct object. Repeat process for BaseFile *****

		var BaseFileB []byte 
		BaseFileB, ok = userlib.DatastoreGet(FileEntryObject.BaseFileUUID)

		var BaseFileEncDk []byte = FileEntryObject.BaseFileEncK
		var BaseFileHMACDk []byte = FileEntryObject.BaseFileHMACK
		var BaseFileBytes []byte 
		BaseFileBytes, err = DecryptAndCompare(BaseFileHMACDk, BaseFileEncDk, BaseFileB)
		if !ok {
			err = errors.New("User access to this file has been revoked")
			return err
		}
		var BaseFileObject BaseFile
		err = json.Unmarshal(BaseFileBytes, &BaseFileObject) //Retrieved BaseFile Struct object ******

		//Now store the contents into the basefile struct
		BaseFileObject.NoOfBlocks = 1

		//Generate a new FileContent Struct with content = content and next block UUID as a random UUID
		var NewFileContent FileContent
		NewFileContent.Marker = 12345 + 1
		NewFileContent.ContentBytes = content
		NewFileContent.NextBlockUUID =  uuid.New()
		NewFileContent.LastBlockUUID = NewFileContent.NextBlockUUID 
		var NewFileContentBytes []byte
		NewFileContentBytes, err = json.Marshal(NewFileContent)
		userlib.DatastoreSet(BaseFileObject.BaseUUID, NewFileContentBytes) //STORE the first FileContent Struct at the BaseUUID
		
		var BaseFileObjectByte []byte
		BaseFileObjectByte, err = json.Marshal(BaseFileObject)
		//Encrypt-HMAC from bottom to top and store into datastore
		var CombinedBaseFile Enc_HMAC 
		CombinedBaseFile, err = EncryptWithKeys(BaseFileHMACDk, BaseFileEncDk, BaseFileObjectByte)
		var CombinedBaseFileBytes []byte
		CombinedBaseFileBytes, err = json.Marshal(CombinedBaseFile)
		userlib.DatastoreSet(FileEntryObject.BaseFileUUID, CombinedBaseFileBytes)
		return err
	}
	
}


func EncryptWithKeys(HMACK []byte, EncK []byte, data []byte) (combined Enc_HMAC, err error) {
	err = nil
	var IV []byte = userlib.RandomBytes(16)
	var userDataEncrypted []byte = userlib.SymEnc(EncK, IV, data)
	var userDataHMAC []byte
	userDataHMAC, err = userlib.HMACEval(HMACK, data)
	var CombineStructs Enc_HMAC
	CombineStructs.UserEncStruct = userDataEncrypted
	CombineStructs.UserHMACStruct = userDataHMAC

	return CombineStructs, err
} 
func DecryptAndCompare(HMACKey []byte, DecryptKey []byte, Combined_Struct []byte) (decrypted []byte, err error) {
	err = nil
	var DecryptedStruct []byte
	//Unmarshall the combined struct so we can access the Enc and HMAC version of the struct
	var CombinedStructUnmarshall Enc_HMAC
	err = json.Unmarshal(Combined_Struct, &CombinedStructUnmarshall)
	var EncVersion []byte = CombinedStructUnmarshall.UserEncStruct
	var HMACVersion []byte = CombinedStructUnmarshall.UserHMACStruct
	//Decrypt-HMAC Compare
	if (len(EncVersion) < 10) {
		err = errors.New("Database has been tampered")
		return DecryptedStruct, err
	}
	DecryptedStruct = userlib.SymDec(DecryptKey, EncVersion)
	var HMACStruct []byte
	HMACStruct, err = userlib.HMACEval(HMACKey, DecryptedStruct)
	var CompareHMACs bool = userlib.HMACEqual(HMACStruct, HMACVersion)
	if CompareHMACs {
		return DecryptedStruct, nil
	} else {
		return DecryptedStruct, err
	}
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	if (userdata.NotTampered != "Not Tampered") {
		err := errors.New("User has been tampered")
		return err
	}
	var username string = userdata.Username
	var password string = userdata.Password
	passwordBytes, err := json.Marshal(password)
	usernameBytes, err := json.Marshal(username)
	var UUID_hash uuid.UUID 
	UUID_hash, err = uuid.FromBytes(userlib.Hash([]byte(filename + username))[0:16]) //attempting to retrieve UseFile Struct's UUID
	
	//Attempt retrieving User Info: from User Struct to FileEntry; If this fails, the database has been tampered
	_, err = UserToFile(userdata, filename)
	if err != nil {
		return err
	}

	var PBKDF []byte = userlib.Argon2Key(passwordBytes, usernameBytes, 16) //rederive hmac key using password + "username, password, userfile struct, hmac"
	
	var CombinedUserFile []byte
	var ok bool
	CombinedUserFile, ok = userlib.DatastoreGet(UUID_hash) //Get UserFile struct value (encrypted)
	if !ok {
		err = errors.New("The file does not exist")
		return err
	}
	var HMACPurpose []byte
	HMACPurpose, err = json.Marshal(username + password + filename + "UserFileHMAC")
	var EncPurpose []byte
	EncPurpose, err = json.Marshal(username + password + filename + "UserFileEncrypt")
	var HMACKey []byte
	HMACKey, err = userlib.HashKDF(PBKDF, HMACPurpose) //rederive hmac key using password + "username, password, userfile struct, encrypt"
	HMACKey  = HMACKey[:16]
	var DecryptKey []byte
	DecryptKey, err = userlib.HashKDF(PBKDF, EncPurpose) 
	DecryptKey = DecryptKey[:16]
	//Using the keys, decrypt the userfile stuct and retrieve user entry + basefile struct
	var UserFileDecrypted []byte
	UserFileDecrypted, err = DecryptAndCompare(HMACKey, DecryptKey, CombinedUserFile)
	//Unmarshal and retrieve actual UserFile Struct object
	var UserFileObject UserFile
	err = json.Unmarshal(UserFileDecrypted, &UserFileObject)
	//Now retrieve UserEntry struct and BaseFile struct with the keys
	var FileEntryB []byte
	FileEntryB, ok = userlib.DatastoreGet(UserFileObject.FileEntryUUID)
	if !ok {
		err = errors.New("User does not have access to the file")
		return err
	}
	var FileEntryEncDk []byte = UserFileObject.FileEntryEncK
	var FileEntryHMACDk []byte = UserFileObject.FileEntryHMACK
	var FileEntryBytes []byte
	FileEntryBytes, err = DecryptAndCompare(FileEntryHMACDk, FileEntryEncDk, FileEntryB)
	var FileEntryObject FileEntry
	err = json.Unmarshal(FileEntryBytes, &FileEntryObject) //Retrieved FileEntry Struct object. Repeat process for BaseFile *****

	var BaseFileB []byte
	BaseFileB, ok = userlib.DatastoreGet(FileEntryObject.BaseFileUUID)
	if !ok {
		err = errors.New("User access has been revoked")
		return err
	}
	var BaseFileEncDk []byte = FileEntryObject.BaseFileEncK
	var BaseFileHMACDk []byte = FileEntryObject.BaseFileHMACK
	var BaseFileBytes []byte
	BaseFileBytes, err = DecryptAndCompare(BaseFileHMACDk, BaseFileEncDk, BaseFileB)
	var BaseFileObject BaseFile
	err = json.Unmarshal(BaseFileBytes, &BaseFileObject) //Retrieved BaseFile Struct object ******

	//Do the append operation
	var FirstFileContentBytes []byte //The first block of content at BaseUUID
	FirstFileContentBytes, ok = userlib.DatastoreGet(BaseFileObject.BaseUUID)
	if !ok {
		err = errors.New("Cannot access file")
		return err
	}
	var FirstFileContent FileContent 
	err = json.Unmarshal(FirstFileContentBytes, &FirstFileContent)
	var NextFileContent FileContent //Since we have the UUID to the last empty block, put a new FileContent there with new contents and uuid
	NextFileContent.Marker = 12345 + BaseFileObject.NoOfBlocks + 1
	NextFileContent.ContentBytes = content
	NextFileContent.NextBlockUUID = uuid.New()
	var NextFileContentBytes []byte  
	NextFileContentBytes, err = json.Marshal(NextFileContent)
	userlib.DatastoreSet(FirstFileContent.LastBlockUUID, NextFileContentBytes) //store this new filecontent struct at the last empty block
	//Remember: since we added a new block, we need to update the uuid to the last block stored at in BaseUUID(the first content)
	FirstFileContent.LastBlockUUID = NextFileContent.NextBlockUUID 
	FirstFileContentBytes, err = json.Marshal(FirstFileContent)
	userlib.DatastoreSet(BaseFileObject.BaseUUID, FirstFileContentBytes) //store the updated first block back into database

	BaseFileObject.NoOfBlocks += 1

	//Encrypt-HMAC BaseFile and store into datastore
	var CombinedBaseFile Enc_HMAC 
	var BaseFileObjectBytes []byte
	BaseFileObjectBytes, err = json.Marshal(BaseFileObject)
	CombinedBaseFile, err = EncryptWithKeys(BaseFileHMACDk, BaseFileEncDk, BaseFileObjectBytes)
	var CombinedBaseFileBytes []byte
	CombinedBaseFileBytes, err = json.Marshal(CombinedBaseFile)
	userlib.DatastoreSet(FileEntryObject.BaseFileUUID, CombinedBaseFileBytes)
	return err
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	if (userdata.NotTampered != "Not Tampered") {
		var tamperReturn []byte
		err = errors.New("User has been tampered")
		return tamperReturn, err
	}
	var ok bool
	var username string = userdata.Username
	var password string = userdata.Password
	passwordBytes, err := json.Marshal(password)
	usernameBytes, err := json.Marshal(username)
	var UUID_hash uuid.UUID 
	UUID_hash, err = uuid.FromBytes(userlib.Hash([]byte(filename + username))[0:16]) //attempting to retrieve UseFile Struct's UUID
	var PBKDF []byte = userlib.Argon2Key(passwordBytes, usernameBytes, 16) //rederive hmac key using password + "username, password, userfile struct, hmac"

	//Attempt retrieving User Info: from User Struct to FileEntry; If this fails, the database has been tampered
	_, err = UserToFile(userdata, filename)
	if err != nil {
		var randoReturn []byte
		return randoReturn, err
	}

	var ReturnContent []byte
	var CombinedUserFile []byte
	CombinedUserFile, ok = userlib.DatastoreGet(UUID_hash) //Get UserFile struct value (encrypted)
	if !ok {
		err = errors.New("The file does not exist")
		return ReturnContent, err
	}
	var HMACPurpose []byte
	HMACPurpose, err = json.Marshal(username + password + filename + "UserFileHMAC")
	var EncPurpose []byte
	EncPurpose, err = json.Marshal(username + password + filename + "UserFileEncrypt")
	var HMACKey []byte
	HMACKey, err = userlib.HashKDF(PBKDF, HMACPurpose) //rederive hmac key using password + "username, password, userfile struct, encrypt"
	HMACKey = HMACKey[:16]
	var DecryptKey []byte
	DecryptKey, err = userlib.HashKDF(PBKDF, EncPurpose) 
	DecryptKey = DecryptKey[:16]
	//Using the keys, decrypt the userfile stuct and retrieve user entry + basefile struct
	var UserFileDecrypted []byte
	UserFileDecrypted, err = DecryptAndCompare(HMACKey, DecryptKey, CombinedUserFile)
	//Unmarshal and retrieve actual UserFile Struct object
	var UserFileObject UserFile
	err = json.Unmarshal(UserFileDecrypted, &UserFileObject)
	//Now retrieve UserEntry struct and BaseFile struct with the keys
	
	var FileEntryB []byte
	FileEntryB, ok = userlib.DatastoreGet(UserFileObject.FileEntryUUID)
	if !ok {
		err = errors.New("User does not have access to the file")
		return ReturnContent, err
	}
	var FileEntryEncDk []byte = UserFileObject.FileEntryEncK
	var FileEntryHMACDk []byte = UserFileObject.FileEntryHMACK
	var FileEntryBytes []byte 
	FileEntryBytes, err = DecryptAndCompare(FileEntryHMACDk, FileEntryEncDk, FileEntryB)
	var FileEntryObject FileEntry
	err = json.Unmarshal(FileEntryBytes, &FileEntryObject) //Retrieved FileEntry Struct object. Repeat process for BaseFile *****

	var BaseFileB []byte
	BaseFileB, ok = userlib.DatastoreGet(FileEntryObject.BaseFileUUID)
	if !ok {
		err = errors.New("User access has been revoked")
		var RC []byte
		return RC, err
	}
	var BaseFileEncDk []byte = FileEntryObject.BaseFileEncK
	var BaseFileHMACDk []byte = FileEntryObject.BaseFileHMACK
	var BaseFileBytes []byte
	BaseFileBytes, err = DecryptAndCompare(BaseFileHMACDk, BaseFileEncDk, BaseFileB)
	var BaseFileObject BaseFile
	err = json.Unmarshal(BaseFileBytes, &BaseFileObject) //Retrieved BaseFile Struct object ******

	var CurrentBlockUUID uuid.UUID = BaseFileObject.BaseUUID
	var i int = BaseFileObject.NoOfBlocks 
	var j int = 1
	for i > 0 { //WE DO NEED THE NOOFBLOCKS. 
		var CurrentFileContentBytes []byte
		CurrentFileContentBytes, ok = userlib.DatastoreGet(CurrentBlockUUID) 
		if !ok {
			err = errors.New("Could not retrieve all file contents")
			return ReturnContent, err
		}
		var CurrentFileContent FileContent
		err = json.Unmarshal(CurrentFileContentBytes, &CurrentFileContent) //Got the ith File Content
		tamperMessage := 12345 + j
		if (CurrentFileContent.Marker != tamperMessage ) {
			err = errors.New("File is tampered")
			return CurrentFileContentBytes, err
		}
		//Got through each byte of the content and add it into the ReturnContent. One byte at a time
		var lengthOfContent int = 0
		for lengthOfContent < len(CurrentFileContent.ContentBytes){
			ReturnContent = append(ReturnContent, CurrentFileContent.ContentBytes[lengthOfContent])
			lengthOfContent += 1
		}
		CurrentBlockUUID = CurrentFileContent.NextBlockUUID

		i -= 1
		j += 1
	}

	return ReturnContent, err
}

func UserToFile(userdata *User, filename string) (ReturnFileEntry FileEntry, err error){
	//attempt to get user
	var FileEntryObject FileEntry
	_, err = GetUser(userdata.Username, userdata.Password)
	if (err != nil) {
		err = errors.New("User has been tampered")
		return FileEntryObject, err
	}
	var username string = userdata.Username
	var password string = userdata.Password
	passwordBytes, err := json.Marshal(password)
	usernameBytes, err := json.Marshal(username)
	var UUID_hash uuid.UUID
	UUID_hash, err = uuid.FromBytes(userlib.Hash([]byte(filename + username))[0:16]) //attempting to retrieve UseFile Struct's UUID
	
	var PBKDF []byte = userlib.Argon2Key(passwordBytes, usernameBytes, 16)
	var ok bool
	var CombinedUserFile []byte 
	CombinedUserFile, ok = userlib.DatastoreGet(UUID_hash) //Do we have to check this??
	if !ok {
		err = errors.New("Given username or file does not exist")
		return FileEntryObject, err
	}
	var HMACPurpose []byte
	HMACPurpose, err = json.Marshal(username + password + filename + "UserFileHMAC")
	var EncPurpose []byte
	EncPurpose, err = json.Marshal(username + password + filename + "UserFileEncrypt")
	var HMACKey []byte
	HMACKey, err = userlib.HashKDF(PBKDF, HMACPurpose) //rederive hmac key using password + "username, password, userfile struct, encrypt"
	HMACKey = HMACKey[:16]
	var DecryptKey []byte
	DecryptKey, err = userlib.HashKDF(PBKDF, EncPurpose) 
	DecryptKey = DecryptKey[:16]
	//Using the keys, decrypt the userfile stuct and retrieve user entry + basefile struct
	var UserFileDecrypted []byte
	UserFileDecrypted, err = DecryptAndCompare(HMACKey, DecryptKey, CombinedUserFile)
	//Unmarshal and retrieve actual UserFile Struct object
	var UserFileObject UserFile
	err = json.Unmarshal(UserFileDecrypted, &UserFileObject)
	//Now retrieve UserEntry struct and BaseFile struct with the keys
	var FileEntryB []byte 
	FileEntryB, ok = userlib.DatastoreGet(UserFileObject.FileEntryUUID)
	if !ok {
		err = errors.New("User does not have access to the file")
		return FileEntryObject, err
	}
	var FileEntryEncDk []byte = UserFileObject.FileEntryEncK
	var FileEntryHMACDk []byte = UserFileObject.FileEntryHMACK
	var FileEntryBytes []byte
	FileEntryBytes, err = DecryptAndCompare(FileEntryHMACDk, FileEntryEncDk, FileEntryB)
	err = json.Unmarshal(FileEntryBytes, &FileEntryObject) //Retrieved FileEntry Struct object. Repeat process for BaseFile *****
	
	return FileEntryObject, err //Returns the struct
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	if (userdata.NotTampered != "Not Tampered") {
		var tamperReturn uuid.UUID
		err = errors.New("User has been tampered")
		return tamperReturn, err
	}
	var username string = userdata.Username
	var password string = userdata.Password
	var recipient string = recipientUsername
	passwordBytes, err := json.Marshal(password)
	recipientBytes, err := json.Marshal(recipient)	

	//Attempt retrieving User Info: from User Struct to FileEntry; If this fails, the database has been tampered
	_, err = UserToFile(userdata, filename)
	if err != nil {
		var randoReturn uuid.UUID = uuid.New()
		return randoReturn, err
	}

	var Invite Invitation
	var NewFileEntry FileEntry
	//Fill in FileEntry struct with: 1. UUID of BaseFile, EncDk + HMACK of BaseFile
	var SenderFileEntry FileEntry
	SenderFileEntry, err = UserToFile(userdata, filename)
	if err != nil {
		var randomUUID uuid.UUID = uuid.New()
		return randomUUID, err
	}
	NewFileEntry.BaseFileUUID = SenderFileEntry.BaseFileUUID
	NewFileEntry.BaseFileHMACK = SenderFileEntry.BaseFileHMACK
	NewFileEntry.BaseFileEncK = SenderFileEntry.BaseFileEncK
	//Generate keys for the NewFileEntry Encryption and send the decryption keys for it through the invitation struct
	//PBKDF(filenanme + usernanme + recipient username + password) <-- HashKDF that to generate more keys
	//The recipient will have these keys and store them in the userfile struct in the accept method
	var PBKDF []byte = userlib.Argon2Key(passwordBytes, recipientBytes, 16) // REMOVED USERNAMEBYTES FROM MIDDLE VALUE
	var HMACPurpose []byte
	HMACPurpose, err = json.Marshal(username + password + recipient + filename + "FileEntryHMAC")
	var EncPurpose []byte
	EncPurpose, err = json.Marshal(username + password + recipient + filename + "FileEntryEncrypt")
	var FileEntryHMACK []byte
	FileEntryHMACK, err = userlib.HashKDF(PBKDF, HMACPurpose)
	FileEntryHMACK = FileEntryHMACK[:16]
	var FileEntryEncK []byte
	FileEntryEncK, err = userlib.HashKDF(PBKDF, EncPurpose) 
	FileEntryEncK = FileEntryEncK[:16]
	var NewFileEntryBytes []byte
	NewFileEntryBytes, err = json.Marshal(NewFileEntry)
	var NewFileEntryComb Enc_HMAC
	NewFileEntryComb, err = EncryptWithKeys(FileEntryHMACK, FileEntryEncK, NewFileEntryBytes)
	var FileEntryUUID uuid.UUID = uuid.New() //new UUID for recipient file entry
	//Store the file entry object at this uuid. First marshal the combined FE and then put it at uuid
	var NewFileEntryCombByte []byte
	NewFileEntryCombByte, err = json.Marshal(NewFileEntryComb)
	userlib.DatastoreSet(FileEntryUUID, NewFileEntryCombByte)

	//FileEntryUUID contains the UUID for the FileEntry, whilst NewFileEntry is the FileEntry struct itself.
	
	//Add this new FileEntry UUID and its Dk into the mapping in User struct of owner
	var NewAccessorInfoStruct AccessorInfoStruct //Create a new struct with all of the accessors info in it and add it to the list 
	NewAccessorInfoStruct.Accessors_UUID = FileEntryUUID
	NewAccessorInfoStruct.Accessors_HMACK = FileEntryHMACK
	NewAccessorInfoStruct.Accessors_DK= FileEntryEncK
	NewAccessorInfoStruct.Accessors_username= recipientUsername
	var AccessorsList []AccessorInfoStruct = userdata.FilesAndAccessors[filename]
	userdata.FilesAndAccessors[filename] = append(AccessorsList, NewAccessorInfoStruct)


	//Add the New File Entry into Invitation
	Invite.FEHk = FileEntryHMACK
	Invite.FEEk = FileEntryEncK
	Invite.NFEU = FileEntryUUID
	
	//Store the current Invitation without the signature in the struct itself
	var InviteBytes []byte
	InviteBytes, err = json.Marshal(Invite) //convert invitation struct to bytes (this is before putting signature in)
	Invite.INS = uuid.New()
	userlib.DatastoreSet(Invite.INS, InviteBytes)

	//Sign the Invitation stuct with sender's public key and store that in the struct
	var SignedStruct []byte
	SignedStruct, err = userlib.DSSign(userdata.PrivateSignKey, InviteBytes)
	Invite.SigU = uuid.New()
	userlib.DatastoreSet(Invite.SigU, SignedStruct)

	InviteBytes, err = json.Marshal(Invite) //convert invitation struct to bytes(this is diff from above cuz it contains the signature)

	//Encrypt the Invitation struct with recipient's public encryption key
	var RecipientPublicEncKey userlib.PKEEncKey
	var ok bool
	RecipientPublicEncKey, ok = userlib.KeystoreGet(recipientUsername + "PublicEncryptionKey")
	if !ok {
		var randomUUID uuid.UUID = uuid.New()
		err = errors.New("Invalid Recipient Username")
		return randomUUID, err
	}

	var InvitationUUID uuid.UUID = uuid.New() //Generate UUID for actual Invitation struct
	userlib.DatastoreSet(InvitationUUID, InviteBytes)

	var InvitePointerStruct InvitePointer
	InvitePointerStruct.UUIDOfInvitation =  InvitationUUID
	var InvitePointerStructBytes []byte
	InvitePointerStructBytes, err = json.Marshal(InvitePointerStruct) 
	var EncryptedInvite []byte
	EncryptedInvite, err = userlib.PKEEnc(RecipientPublicEncKey, InvitePointerStructBytes) 
	//store the encrypted + hmaced + signed invitation in datastore and return the UUID
	var InvitationPointerUUID uuid.UUID = uuid.New()
	userlib.DatastoreSet(InvitationPointerUUID, EncryptedInvite)
	Update_userdata_in_Datastore(userdata)
	return InvitationPointerUUID, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	if (userdata.NotTampered != "Not Tampered") {
		err := errors.New("User has been tampered")
		return err
	}
	var username string = userdata.Username
	var password string = userdata.Password
	passwordBytes, err := json.Marshal(password)
	usernameBytes, err := json.Marshal(username) //this is the recipients ^^^
	var PBKDF []byte = userlib.Argon2Key(passwordBytes, usernameBytes, 16)
	var ok bool

	//Check if given filename already exists under receiver's namespace
	UUID_hash, err := uuid.FromBytes(userlib.Hash([]byte(filename + username))[0:16]) //attempting to retrieve UseFile Struct's UUID
	var InviteBytes []byte 
	InviteBytes, ok = userlib.DatastoreGet(UUID_hash)
	if ok {
		err = errors.New("Given file already exists")
		return err
	}
	
	//Use Bob's Dk to generate decrypt invitebytes
	var EncryptedInvitePointerBytes []byte
	EncryptedInvitePointerBytes, ok = userlib.DatastoreGet(invitationPtr)
	if !ok {
		err = errors.New("The invitation does not exist")
		return err
	}

	var RecipientPrivateDecKey userlib.PKEDecKey = userdata.PrivateDecKey
	InviteBytes, err = userlib.PKEDec(RecipientPrivateDecKey, EncryptedInvitePointerBytes)

	//Unmarshall the bytes to get the invite pointer struct
	var InvitePointerStruct InvitePointer
	err = json.Unmarshal(InviteBytes, &InvitePointerStruct) 

	//Retrieve the Invite Struct from uuid stored in the pointerstruct
	InviteBytes, ok = userlib.DatastoreGet(InvitePointerStruct.UUIDOfInvitation)
	if !ok {
		err = errors.New("The invitation does not exist")
		return err
	}
	var InviteStruct Invitation
	err = json.Unmarshal(InviteBytes, &InviteStruct) 

	//Try accessing FileEntry given and if this user has already been revoked, it should error because FE should have been deleted.
	TestFE, ok := userlib.DatastoreGet(InviteStruct.NFEU) //Using a random variable name cuz of "declared but not used error"
	if !ok {
		err = errors.New("User has been revoked. Cannot access file")
		return err
	}
	//Try accessing BaseFile given and if this user has already been revoked, it should error because BF should have been deleted.
	//First decrypt the file entry then try accessing the basefile
	var TestFEDecBytes []byte
	TestFEDecBytes, err = DecryptAndCompare(InviteStruct.FEHk, InviteStruct.FEEk, TestFE)
	var TestFEDec FileEntry
	err = json.Unmarshal(TestFEDecBytes, &TestFEDec)
	_, ok = userlib.DatastoreGet(TestFEDec.BaseFileUUID) //Using a random variable name cuz of "declared but not used error"
	if !ok {
		err = errors.New("User has been revoked. Cannot access file")
		return err
	}

	//Grab Alice's Public Verify key and
	//Use it to verify the signature stored inside the invite struct, else error
	var SenderVerifyKey userlib.DSVerifyKey
	SenderVerifyKey, ok = userlib.KeystoreGet(senderUsername + "PublicVerifyKey")
	SignatureToVerify, ok := userlib.DatastoreGet(InviteStruct.SigU)
	var Invitation_without_sig []byte
	Invitation_without_sig, ok = userlib.DatastoreGet(InviteStruct.INS)
	err = userlib.DSVerify(SenderVerifyKey, Invitation_without_sig, SignatureToVerify)
	if !ok {
		err = errors.New("Cannot verify if invitation was sent by the authenticated user")
		return err
	}
	//Done Accepting the Invitation. Now Create UserFile and store relevant keys 
	
	//Set UUID and Keys of FileEntry Struct in UserFile to random bytes and put it in data store
	var UserFileObject UserFile
	UserFileObject.FileEntryUUID = InviteStruct.NFEU
	UserFileObject.FileEntryEncK = InviteStruct.FEEk
	UserFileObject.FileEntryHMACK = InviteStruct.FEHk
	//Encrypt the UserFile struct and store it at hash(username + filename)
	var HMACPurpose []byte
	HMACPurpose, err = json.Marshal(username + password + filename + "UserFileHMAC")
	var EncPurpose []byte
	EncPurpose, err = json.Marshal(username + password + filename + "UserFileEncrypt")
	var UserFileHMACK []byte
	UserFileHMACK, err = userlib.HashKDF(PBKDF, HMACPurpose)
	UserFileHMACK = UserFileHMACK[:16]
	var UserFileEncK []byte
	UserFileEncK, err = userlib.HashKDF(PBKDF, EncPurpose) 
	UserFileEncK = UserFileEncK[:16]
	var CombinedUserFile Enc_HMAC
	var UserFileObjectBytes []byte
	UserFileObjectBytes, err = json.Marshal(UserFileObject)
	CombinedUserFile, err = EncryptWithKeys(UserFileHMACK, UserFileEncK, UserFileObjectBytes)
	var CombinedUserFileBytes []byte
	CombinedUserFileBytes, err = json.Marshal(CombinedUserFile)
	var CombinedUserFileBytesUUID uuid.UUID
	CombinedUserFileBytesUUID, err = uuid.FromBytes(userlib.Hash([]byte(filename + username))[0:16])
	userlib.DatastoreSet(CombinedUserFileBytesUUID, CombinedUserFileBytes)

	return err
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	if (userdata.NotTampered != "Not Tampered") {
		err := errors.New("User has been tampered")
		return err
	}
	//***Same as UserToFile Function: Just need to get the UUID of FileEntry
	var username string = userdata.Username //Getting the current user's username and password
	var password string = userdata.Password 
	passwordBytes, err := json.Marshal(password)
	usernameBytes, err := json.Marshal(username)

	if username == recipientUsername {
		err = errors.New("Owner tried to revoke themself")
		return err
	}
	//Attempt retrieving User Info: from User Struct to FileEntry; If this fails, the database has been tampered
	_, err = UserToFile(userdata, filename)
	if err != nil {
		return err
	}

	var UUID_hash uuid.UUID
	UUID_hash, err = uuid.FromBytes(userlib.Hash([]byte(filename + username))[0:16]) //attempting to retrieve UseFile Struct's UUID
	var PBKDF []byte = userlib.Argon2Key(passwordBytes, usernameBytes, 16)
	var CombinedUserFile []byte 
	var ok bool
	CombinedUserFile, ok = userlib.DatastoreGet(UUID_hash) //Do we have to check this??
	if !ok {
		err = errors.New("Given recipient does not have access to file or file does not exist")
		return err
	}
	var HMACPurpose []byte
	HMACPurpose, err = json.Marshal(username + password + filename + "UserFileHMAC")
	var EncPurpose []byte
	EncPurpose, err = json.Marshal(username + password + filename + "UserFileEncrypt")
	var HMACKey []byte
	HMACKey, err = userlib.HashKDF(PBKDF, HMACPurpose) //rederive hmac key using password + "username, password, userfile struct, encrypt"
	HMACKey = HMACKey[:16]
	var DecryptKey []byte
	DecryptKey, err = userlib.HashKDF(PBKDF, EncPurpose) 
	DecryptKey = DecryptKey[:16]
	//Using the keys, decrypt the userfile stuct and retrieve user entry + basefile struct
	var UserFileDecrypted []byte
	UserFileDecrypted, err = DecryptAndCompare(HMACKey, DecryptKey, CombinedUserFile)
	//Unmarshal and retrieve actual UserFile Struct object
	var UserFileObject UserFile
	err = json.Unmarshal(UserFileDecrypted, &UserFileObject)
	//****End


	//Calculate a new UUID for the BaseFile Struct of with uuid.NewUUID()
	var UsersRetrieveFileEntry FileEntry
	UsersRetrieveFileEntry, err = UserToFile(userdata, filename) //FileEntry struct object
	var RetrieveBaseFileBytes []byte 
	RetrieveBaseFileBytes, ok = userlib.DatastoreGet(UsersRetrieveFileEntry.BaseFileUUID) //The UUID of BaseFile, stored as UUID.
	if !ok {
		err = errors.New("Given filename does not exist")
		return err
	}
	var RetrieveBaseFiles []byte
	RetrieveBaseFiles, err = DecryptAndCompare(UsersRetrieveFileEntry.BaseFileHMACK, UsersRetrieveFileEntry.BaseFileEncK, RetrieveBaseFileBytes)//Retrieving the baseFile struct in bytes
	if err != nil{
		return err
	}
	var RetrieveBaseFile BaseFile
	err = json.Unmarshal(RetrieveBaseFiles, &RetrieveBaseFile) // basefile struct object
	var NewBaseFileUUID uuid.UUID = uuid.New() // create a new basefile UUID
	var NewBaseFile BaseFile // create a new basefile

	//Create a new base uuid 
	var NewBaseUUID uuid.UUID = uuid.New() // create a new base UUID(start of content, first block UUID)
	NewBaseFile.BaseUUID = NewBaseUUID // set the NewBaseFile Struct's BaseUUID pointer to the newly created BaseUUID
	NewBaseFile.NoOfBlocks = RetrieveBaseFile.NoOfBlocks // set the number of blocks
	
	//Loop through the blocks and copy over the contents of original file to the new location
	var NewCurrentBlockUUID uuid.UUID = NewBaseFile.BaseUUID
	var OldCurrentBlockUUID uuid.UUID = RetrieveBaseFile.BaseUUID
	var i int = 0
	var j int = 1
	for (i < RetrieveBaseFile.NoOfBlocks) { 
		var OldCurrentFileContentBytes []byte
		OldCurrentFileContentBytes, ok = userlib.DatastoreGet(OldCurrentBlockUUID) //OldCurrentBlockUUID is the first block
		
		var OldCurrentFileContent FileContent
		err = json.Unmarshal(OldCurrentFileContentBytes, &OldCurrentFileContent) //Retrieve file content struct from old UUID

		//Check for tampering:
		tamperMessage := 12345 + j
		if (OldCurrentFileContent.Marker != tamperMessage) {
			err = errors.New("File is tampered")
			return err
		}
		var NewFileContent FileContent
		NewFileContent.Marker = tamperMessage
		NewFileContent.ContentBytes = OldCurrentFileContent.ContentBytes
		NewFileContent.NextBlockUUID = uuid.New() //Set the vals of struct

		var NewFileContentBytes []byte 
		NewFileContentBytes, err = json.Marshal(NewFileContent) 
		userlib.DatastoreSet(NewCurrentBlockUUID, NewFileContentBytes) //marshal and store it in datastore. Move to next content

		OldCurrentBlockUUID = OldCurrentFileContent.NextBlockUUID
		//userlib.DatastoreDelete(OldCurrentBlockUUID)
		NewCurrentBlockUUID = NewFileContent.NextBlockUUID
		
		i += 1
		j += 1
	}
	userlib.DatastoreDelete(UsersRetrieveFileEntry.BaseFileUUID)
	//One more thing: go to the first filecontent struct at new location and set its LastBlockUUID to the last block
	var ForTheLastBlockBytes []byte //Get the first block at base uuid
	ForTheLastBlockBytes, ok = userlib.DatastoreGet(NewBaseFile.BaseUUID) 
	var ForTheLastBlock FileContent
	err = json.Unmarshal(ForTheLastBlockBytes, &ForTheLastBlock) 
	ForTheLastBlock.LastBlockUUID = NewCurrentBlockUUID //Set the val
	ForTheLastBlockBytes, err = json.Marshal(ForTheLastBlock) 
	userlib.DatastoreSet(NewBaseFile.BaseUUID, ForTheLastBlockBytes) //store it back


	//Store the new BaseFile struct in datastore after encrypting it
	var NewBaseFileBytes []byte
	NewBaseFileBytes, err = json.Marshal(NewBaseFile)
	var Enc_HMAC_NewBF Enc_HMAC
	Enc_HMAC_NewBF, err = EncryptWithKeys(UsersRetrieveFileEntry.BaseFileHMACK, UsersRetrieveFileEntry.BaseFileEncK, NewBaseFileBytes)
	var Enc_HMAC_NewBF_Bytes []byte 
	Enc_HMAC_NewBF_Bytes, err = json.Marshal(Enc_HMAC_NewBF)
	userlib.DatastoreSet(NewBaseFileUUID, Enc_HMAC_NewBF_Bytes)

	//Change the Owner's FileEntry to point to the new BaseFile struct
	var OwnerNewFileEntry FileEntry
	OwnerNewFileEntry.BaseFileUUID = NewBaseFileUUID
	OwnerNewFileEntry.BaseFileEncK = UsersRetrieveFileEntry.BaseFileEncK
	OwnerNewFileEntry.BaseFileHMACK = UsersRetrieveFileEntry.BaseFileHMACK
	
	//Store the new FileEntry struct of the owner in datastore after encrypting it
	var OwnerNewFileEntryBytes []byte 
	OwnerNewFileEntryBytes, err = json.Marshal(OwnerNewFileEntry)
	var Enc_HMAC_OwnerNewFileEntry Enc_HMAC
	Enc_HMAC_OwnerNewFileEntry, err = EncryptWithKeys(UserFileObject.FileEntryHMACK, UserFileObject.FileEntryEncK, OwnerNewFileEntryBytes)
	var Enc_HMAC_OwnerNewFileEntry_Bytes []byte 
	Enc_HMAC_OwnerNewFileEntry_Bytes, err = json.Marshal(Enc_HMAC_OwnerNewFileEntry) //Marshalling the Enc_HMAC
	userlib.DatastoreSet(UserFileObject.FileEntryUUID, Enc_HMAC_OwnerNewFileEntry_Bytes)

	//Loop through the dictionary, check if username != revokeduser, and change the FileEntry contents to point to new BaseFile
		//As we loop through the dictionary list, we create a new list and all users except for the person revoked. Replace the old list with this new one
	var Accessors []AccessorInfoStruct  //Current list
	Accessors = userdata.FilesAndAccessors[filename] //retrieve the list accessors to this file which is in form [FEUUID, Hk, Dk, username]
	var NewAccessors []AccessorInfoStruct //The new list containing everybody except the revoked user
	for i := range Accessors {
		var AccessorInfo AccessorInfoStruct = Accessors[i] 
		//Get nanme
		var AccessorName string = AccessorInfo.Accessors_username

		if AccessorName != recipientUsername {
			NewAccessors = append(NewAccessors, AccessorInfo) //Add this user back in list
			//get his UUID to File Entry
			var AccessorFEUUID uuid.UUID = AccessorInfo.Accessors_UUID
			//get HMAC and Dec Keys of Accessor
			var AccessorHMACK []byte = AccessorInfo.Accessors_HMACK
			var AccessorEncK []byte = AccessorInfo.Accessors_DK

			//Now go to accessor's File Entry UUID and update the UUID pointer to BaseFile
			var AccessorFE_Encrypted []byte
			AccessorFE_Encrypted, ok = userlib.DatastoreGet(AccessorFEUUID) //Enc_HMAC of FileEntry in bytes
			if !ok {
				err = errors.New("Recipient does not exist or does not have access to file already")
				return err
			}
			var AccessorFE_Bytes []byte
			AccessorFE_Bytes, err = DecryptAndCompare(AccessorHMACK, AccessorEncK, AccessorFE_Encrypted) // Decrypted FileEntry in bytes
			var AccessorFE FileEntry
			err = json.Unmarshal(AccessorFE_Bytes, &AccessorFE) //Get the actual FileEntry struct
			AccessorFE.BaseFileUUID = NewBaseFileUUID //Update the old BaseFile UUID with the new one. Keep the same Dk

			//After updating BaseFile UUID, encrypt + hmac and store it back in Datastore
			var NewAccesorFE_Bytes []byte 
			NewAccesorFE_Bytes, err = json.Marshal(AccessorFE) //Turn the updated FileEntry into bytes
			var NewAccesorFE Enc_HMAC
			NewAccesorFE, err = EncryptWithKeys(AccessorHMACK, AccessorEncK, NewAccesorFE_Bytes) //Encrypt those bytes
			var NewAccesorFE_Encrypted []byte 
			NewAccesorFE_Encrypted, err = json.Marshal(NewAccesorFE) //Turn the resulting Enc_HMAC struct into bytes
			userlib.DatastoreSet(AccessorFEUUID, NewAccesorFE_Encrypted)  // store those bytes in datastore
		} else {
			AccessorFEUUID := AccessorInfo.Accessors_UUID
			userlib.DatastoreDelete(AccessorFEUUID)
		}
	}
	userdata.FilesAndAccessors[filename] = NewAccessors//update the new list of accessors(removed the revoked) in the user dictionary

	//Store the userdata back into the datastore so that this new accessors map will be updated in the database
		//Encrypt the userdata and store at the uuid of current user struct
	Update_userdata_in_Datastore(userdata)
	return nil
}


func Update_userdata_in_Datastore(userdata *User) error{
	var password string = userdata.Password
	var username string = userdata.Username
	passwordBytes, err := json.Marshal(password)
	usernameBytes, err := json.Marshal(username)
	var PBKDF []byte = userlib.Argon2Key(passwordBytes, usernameBytes, 16)
	var HMACPurpose []byte 
	HMACPurpose, err = json.Marshal("HMAC key for User Struct")
	var EncPurpose []byte 
	EncPurpose, err = json.Marshal("Encryption key for User Struct")
	var HMACKey []byte
	HMACKey, err = userlib.HashKDF(PBKDF, HMACPurpose)
	HMACKey = HMACKey[:16]
	var EncryptKey []byte
	EncryptKey, err = userlib.HashKDF(PBKDF, EncPurpose)
	EncryptKey = EncryptKey[:16]
	var userdataBytes []byte
	userdataBytes, err = json.Marshal(userdata)
	var userdata_EncHMAC Enc_HMAC
	userdata_EncHMAC, err = EncryptWithKeys(HMACKey, EncryptKey, userdataBytes)
	var storing []byte
	storing, err = json.Marshal(userdata_EncHMAC)
	var UserStructUUID uuid.UUID 
	hash := userlib.Hash(usernameBytes)
	UserStructUUID, err = uuid.FromBytes(hash[:16]) 
	userlib.DatastoreSet(UserStructUUID, storing)
	return err
}



















