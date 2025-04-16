package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
	//how to import?
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
	Username          string
	Salt              []byte
	AuthenticationKey []byte
	PrivateKey        userlib.PKEDecKey
	InvitedUsers      map[string][]uuid.UUID
	SignKey           userlib.DSSignKey
}

type HMACUser struct {
	EncryptedUser []byte
	HmacOfUser    []byte
}

type File struct {
	Filename  string
	SourceKey []byte
	Head      uuid.UUID
	Tail      uuid.UUID
	FileTag   []byte
}

type Block struct {
	Content  []byte
	Next     uuid.UUID
	BlockTag []byte
}

type Invitation struct {
	Signature             []byte
	Subkey                []byte
	InvitationKey         []byte
	InvitedUserStructAddr []byte
	IsOwner               bool
}

type InvitedUserToFileRouter struct {
	FileKey      []byte
	FileLocation uuid.UUID
	IUTag        []byte
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	var jsonUser []byte
	var e error
	var FinalUserStruct HMACUser

	e = nil
	userdata.Username = username
	if len(username) == 0 {
		e = errors.New("username must be more than 0 characters long")
	} else {
		hashedUsername := userlib.Hash([]byte(username))
		usernameUUID, err := uuid.FromBytes(hashedUsername[0:16])
		if err != nil {
			e = errors.New("error creating username uuid")
		}
		if _, ok := userlib.DatastoreGet(usernameUUID); ok {
			e = errors.New("username is already taken")
		} else {
			userdata.Username = string(hashedUsername)
			userdata.Salt = userlib.Hash([]byte(username))
			userdata.AuthenticationKey = userlib.Argon2Key([]byte(password), userdata.Salt, 16)

			//public/private key creation
			var PKEEncrypt userlib.PKEEncKey
			var SKDecrypt userlib.PKEDecKey
			PKEEncrypt, SKDecrypt, _ = userlib.PKEKeyGen()
			signkey, verifykey, err := userlib.DSKeyGen()
			if err != nil {
				e = errors.New("error generating key")
			}
			uuid := username + "verification_key"
			userdata.SignKey = signkey
			userlib.KeystoreSet(uuid, verifykey)
			userdata.PrivateKey = SKDecrypt
			if err := userlib.KeystoreSet(usernameUUID.String(), PKEEncrypt); err != nil {
				e = errors.New("error retrieving from keystore")
			}

			//encryption & hmac of user struct
			IV := userlib.RandomBytes(16)
			jsonUser, err = json.Marshal(userdata)
			if err != nil {
				e = errors.New("error during json marshal of user struct")
			}
			EncryptedUserStruct := userlib.SymEnc(userdata.AuthenticationKey, IV, jsonUser)
			HmacUser, err := userlib.HMACEval(userdata.AuthenticationKey, EncryptedUserStruct)
			if err != nil {
				e = errors.New("error during hmac of user struct")
			}
			FinalUserStruct.EncryptedUser = EncryptedUserStruct
			FinalUserStruct.HmacOfUser = HmacUser
			jsonFinalUser, err := json.Marshal(FinalUserStruct)
			if err != nil {
				e = errors.New("error during json marshal of user struct")
			}
			Final := userlib.SymEnc(userdata.AuthenticationKey, IV, jsonFinalUser)
			userlib.DatastoreSet(usernameUUID, Final)
		}
	}
	return userdataptr, e
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var e error
	var finalUserStruct HMACUser
	var returnedUser User

	e = nil
	hashedUsername := userlib.Hash([]byte(username))
	usernameUUID, err := uuid.FromBytes(hashedUsername[:16])
	if err != nil {
		e = errors.New("error creating username uuid")
		return nil, e
	}
	encryptedFinalUserStruct, ok := userlib.DatastoreGet(usernameUUID)
	if !ok {
		e = errors.New("username does not exist")
		return nil, e
	}

	// Compute symmetric key
	salt := userlib.Hash([]byte(username))
	authKey := userlib.Argon2Key([]byte(password), salt, 16)

	// Decrypt to get FinalUserStruct
	decryptedFinalUserBytes := userlib.SymDec(authKey, encryptedFinalUserStruct)
	err = json.Unmarshal(decryptedFinalUserBytes, &finalUserStruct)
	if err != nil {
		e = errors.New("error during json unmarshal of final user struct")
		return nil, e
	}

	// Integrity check of the user struct
	hmac, err := userlib.HMACEval(authKey, finalUserStruct.EncryptedUser)
	if err != nil || !userlib.HMACEqual(hmac, finalUserStruct.HmacOfUser) {
		e = errors.New("integrity check failed for the user struct")
		return nil, e
	}

	// Decrypt the actual User struct
	decryptedUserBytes := userlib.SymDec(authKey, finalUserStruct.EncryptedUser)
	err = json.Unmarshal(decryptedUserBytes, &returnedUser)
	if err != nil {
		e = errors.New("error during json unmarshal of user struct")
		return nil, e
	}

	return &returnedUser, e
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var e error
	e = nil
	var user User = *userdata

	//check if file already exists
	_, exists := user.InvitedUsers[filename]
	if exists { //update existing file
		file, err := UnlockFile(user, filename)
		if err != nil {
			e = errors.New("error unlocking file")
		}
		jsonFile, err := json.Marshal(file)
		if err != nil {
			e = errors.New("error during json marshal of file struct")
		}
		//check integrity of file struct
		if IsTampered(file.FileTag, jsonFile, file.SourceKey) {
			e = errors.New("hmac of decryted file struct does not match actual file struct")
		} else {
			//create new block and updates
			blockUUID, err := CreateBlock(content, file)
			if err != nil {
				e = errors.New("error creating block")
			}
			file.Head = blockUUID
			file.Tail = blockUUID
			UpdateFile(file, filename, user)

		}
	} else { //create new file
		err := userdata.CreateFile(filename, content)
		if err != nil {
			e = errors.New("error during creation of file struct")
		}
		usernameUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[0:16])
		if err != nil {
			e = errors.New("error creating username uuid")
		}
		user.InvitedUsers[filename] = []uuid.UUID{usernameUUID}
	}
	return e
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var user User
	var e error
	user = *userdata
	file, err := UnlockFile(user, filename)
	if err != nil {
		e = errors.New("error unlocking file")
	}
	jsonFile, err := json.Marshal(file)
	if err != nil {
		e = errors.New("error during json marshal of file struct")
	}
	if IsTampered(file.FileTag, jsonFile, file.SourceKey) {
		e = errors.New("file has been tampered")
	}
	blockUUID, err := CreateBlock(content, file)
	if err != nil {
		e = errors.New("error creating block")
	}
	file.Tail = blockUUID
	err = UpdateFile(file, filename, user)
	if err != nil {
		e = errors.New("error updating file")
	}
	return e
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var user User
	var file File
	var jsonFile []byte
	user = *userdata
	var e error
	e = nil

	//locate the file
	file, err = UnlockFile(user, filename)
	if err != nil {
		e = errors.New("error unlocking file")
	}
	jsonFile, err = json.Marshal(file)
	if err != nil {
		e = errors.New("error during json marshal of file struct")
	}
	//check integrity of file struct
	if IsTampered(file.FileTag, jsonFile, file.SourceKey) {
		e = errors.New("file has been tampered")
	}
	//retrive contents
	content, err = RetrieveContents(file)
	if err != nil {
		e = errors.New("error during retrieving file")
	}
	return content, e
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	var sendingUser User
	var invitedUserSubkey []byte
	var file File
	sendingUser = *userdata
	var e error
	e = nil
	//retrieve file
	file, err = UnlockFile(*userdata, filename)
	if err != nil {
		e = errors.New("error during retrieving file")
	}
	//retrieve recipient public key
	hashedUsername := userlib.Hash([]byte(recipientUsername))
	usernameUUID, err := uuid.FromBytes(hashedUsername[0:16])
	if err != nil {
		e = errors.New("error creating username uuid")
	}
	recipientPK, ok := userlib.KeystoreGet(usernameUUID.String())
	if !ok {
		e = errors.New("recipient public key not found")
	}
	//check if user is original creator
	if _, ok := sendingUser.InvitedUsers[filename]; ok {
		//created new invited user struct & invitation
		invitedUserSubkey, err = userlib.HashKDF(file.SourceKey, []byte(recipientUsername))
		if err != nil {
			e = errors.New("error hashing sourcekey")
		}
		senderkey, err := RetreiveUserKey(sendingUser, filename)
		if err != nil {
			e = errors.New("error retrieving user key")
		}
		_, err = CreateInvitedUserStruct(sendingUser.Username, recipientUsername, filename, invitedUserSubkey, senderkey)
		if err != nil {
			e = errors.New("error creating invited user struct")
		}
		invitationPtr, err = CreateInvitation(filename, sendingUser, recipientUsername, invitedUserSubkey, recipientPK, true)
		if err != nil {
			e = errors.New("error creating invitation struct")
		}
	} else {
		//locate existing invited user struct & invitation
		senderkey, err := RetreiveUserKey(sendingUser, filename)
		if err != nil {
			e = errors.New("error retreiving subkey")
		}
		invitationPtr, err = CreateInvitation(filename, sendingUser, recipientUsername, senderkey, recipientPK, false)
		if err != nil {
			e = errors.New("error creating invitation")
		}
	}
	return invitationPtr, e
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	recipient := *userdata
	var invitationStruct Invitation
	var recipientPK userlib.PKEDecKey
	var jsonFileKey []byte
	var jsonInvitedUser []byte
	var e error
	e = nil
	//decrypt & unmarshal invitation struct
	recipientPK = recipient.PrivateKey
	encryptedInvitationStruct, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		e = errors.New("error retrieving invitation struct")
	}
	jsonInvitationStruct, err := userlib.PKEDec(recipientPK, encryptedInvitationStruct)
	if err != nil {
		e = errors.New("error decrypting invitation struct")
	}
	err = json.Unmarshal(jsonInvitationStruct, &invitationStruct)
	if err != nil {
		e = errors.New("error during json unmarshal of invitation struct")
	}
	//obtain verify key of sender
	senderVerifyKey, ok := userlib.KeystoreGet(senderUsername + "verification_key")
	if !ok {
		e = errors.New("error during json unmarshal of invitation struct")
	}
	err = userlib.DSVerify(senderVerifyKey, jsonInvitationStruct, invitationStruct.Signature)
	if err != nil {
		e = errors.New("invitation cannot be verified")
	}
	//obtain file key
	fileKey, err := UnlockInvitation(recipient, invitationStruct, filename)
	if err != nil {
		e = errors.New("error obtaining file key")
	}
	if invitationStruct.IsOwner {
		//decrypt subkey & create router
		subkey := userlib.SymDec(invitationStruct.InvitationKey, invitationStruct.Subkey)
		routerUUID, err := uuid.FromBytes(userlib.Hash([]byte(subkey))[0:16])
		if err != nil {
			e = errors.New("error calculating uuid of router")
		}
		jsonFileKey, err = json.Marshal(fileKey)
		if err != nil {
			e = errors.New("error creating marshal of file key")
		}
		userlib.DatastoreSet(routerUUID, jsonFileKey)
	} else {
		//look for existing router
		subkey := userlib.SymDec(invitationStruct.InvitationKey, invitationStruct.Subkey)
		invitedUserStructUUID, err := FindInvitedUserStruct(subkey)
		if err != nil {
			e = errors.New("error finding existing invited user strruct uuid")
		}
		routerUUID, err := uuid.FromBytes(userlib.Hash([]byte(subkey))[0:16])
		if err != nil {
			e = errors.New("error calculating uuid of router")
		}
		jsonInvitedUser, err = json.Marshal(invitedUserStructUUID)
		if err != nil {
			e = errors.New("error calculating json of invited user")
		}
		userlib.DatastoreSet(routerUUID, jsonInvitedUser)
	}
	return e
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
