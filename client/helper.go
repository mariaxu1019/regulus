package client

import (
	"encoding/json"
	"fmt"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

func UnlockFile(user User, filename string) (file File, err error) {
	var e error
	var f File
	fileKey, e1 := RetreiveUserKey(user, filename)
	if e1 != nil {
		e = e1
	}
	encryptedFile, e2 := FindFile(user, filename)
	if e2 != nil {
		e = e2
	}
	//unlock file
	DecryptedFile := userlib.SymDec(fileKey, encryptedFile) //byte to uuid?
	err = json.Unmarshal(DecryptedFile, &f)
	if err != nil {
		e = errors.New("error during json unmarshal of file struct")
	}
	return f, e
}

func RetreiveUserKey(user User, filename string) (key []byte, err error) {
	var e error
	e = nil
	encryptedKeyUUID, err := uuid.FromBytes([]byte(user.Username + "-" + filename))
	if err != nil {
		e = errors.New("error generating key uuid")
	}
	encryptedKey, ok := userlib.DatastoreGet(encryptedKeyUUID)
	if !ok {
		e = errors.New("error retreiving encrypted key")
	}
	fileKey, err := userlib.PKEDec(user.PrivateKey, encryptedKey)
	if err != nil {
		e = errors.New("error retreieving file key")
	}
	return fileKey, e
}

func FindFile(user User, filename string) (encryptedFile []byte, err error) {
	var e error
	e = nil
	var fileUUID uuid.UUID
	routerUUID, err := uuid.FromBytes(userlib.Hash([]byte(user.Username + "/" + filename)))
	if err != nil {
		e = errors.New("error generating router uuid")
	}
	jsonFileUUID, ok := userlib.DatastoreGet(routerUUID)
	if !ok {
		e = errors.New("error retreiving from router")
	}
	err = json.Unmarshal(jsonFileUUID, &fileUUID)
	if err != nil {
		e = errors.New("error during unmarshal of file uuid")
	}
	encFile, ok := userlib.DatastoreGet(fileUUID) //how to turn to uuid??
	if !ok {
		e = errors.New("error retreiving from file")
	}
	return encFile, e
}

func IsTampered(original []byte, checking []byte, key []byte) (result bool) {
	result = false
	decrypted, err := userlib.HMACEval(key, checking)
	if err != nil {
		fmt.Println("error during hmac eval")
	}
	if !userlib.HMACEqual(original, decrypted) {
		result = true
	}
	return result
}

func (userdata *User) CreateFile(filename string, content []byte) (err error) {
	var block Block
	var file File
	var jsonFile []byte
	var jsonBlock []byte
	user := *userdata
	var e error
	e = nil
	file.SourceKey = userlib.RandomBytes(16)
	blockUUID := uuid.New()
	block.Content = content
	block.Next, err = uuid.FromBytes(uuid.Nil[:])
	if err != nil {
		e = errors.New("error calculating uuid of block.next")
	}
	block.BlockTag, err = userlib.HMACEval(file.SourceKey, block.Content)
	if err != nil {
		e = errors.New("hmac of block does not match")
	}
	jsonBlock, err = json.Marshal(block)
	if err != nil {
		e = errors.New("error during json marshal of block struct")
	}
	userlib.DatastoreSet(blockUUID, jsonBlock) //do we need to encrypt every block if file struct is already encrypted?

	//create file struct
	file.Filename = filename
	fileUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename)))
	if err != nil {
		e = errors.New("error calculating file uuid")
	}
	file.Head = blockUUID
	file.Tail = blockUUID
	jsonFile, err = json.Marshal(file)
	if err != nil {
		e = errors.New("error during json marshal of file struct")
	}
	file.FileTag, err = userlib.HMACEval(file.SourceKey, jsonFile)
	if err != nil {
		e = errors.New("error during hmac of file struct")
	}
	IV := userlib.RandomBytes(16)
	EncryptedFileStruct := userlib.SymEnc(file.SourceKey, IV, jsonFile)
	userlib.DatastoreSet(fileUUID, EncryptedFileStruct)

	//save filekey
	userPublicKey, ok := userlib.KeystoreGet(user.Username)
	if !ok {
		e = errors.New("error retrieving public key")
	}
	encryptedFileKey, err := userlib.PKEEnc(userPublicKey, file.SourceKey)
	if err != nil {
		e = errors.New("error encrypting file key")
	}
	encryptedFileKeyUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "-" + filename)))
	if err != nil {
		e = errors.New("error encrypting file uuid")
	}
	userlib.DatastoreSet(encryptedFileKeyUUID, encryptedFileKey)

	//encrypt file struct
	IV = userlib.RandomBytes(16)
	jsonFile, err = json.Marshal(file)
	if err != nil {
		e = errors.New("error during json marshal of file struct")
	}
	EncryptedFileStruct = userlib.SymEnc(file.SourceKey, IV, jsonFile)
	userlib.DatastoreSet(fileUUID, EncryptedFileStruct)

	//create router to file
	//should we HMAC this ??
	routerUUID, err := uuid.FromBytes(userlib.Hash([]byte(user.Username + "/" + filename))[:16])
	if err != nil {
		e = errors.New("error calculating uuid of router")
	}
	jsonFileUUID, err := json.Marshal(fileUUID)
	if err != nil {
		e = errors.New("error calculating marshal of file uuid")
	}
	userlib.DatastoreSet(routerUUID, jsonFileUUID)
	return e
}

func RetrieveContents(file File) (contents []byte, err error) {
	var e error
	var block Block
	e = nil
	beginning := file.Head
	blockdata, ok := userlib.DatastoreGet(beginning)
	if !ok {
		e = errors.New("error retreiving from file")
	}
	err = json.Unmarshal(blockdata, &block)
	if err != nil {
		e = errors.New("error during unmarshal of block data")
	}
	for block.Next != uuid.Nil {
		if IsTampered(block.BlockTag, file.SourceKey, block.Content) {
			e = errors.New("block has been tampered")
			return contents, e
		} else {
			contents = append(contents, block.Content...)
		}
	}
	return contents, e
}

func CreateBlock(contents []byte, file File) (blockuuid uuid.UUID, err error) {
	var block Block
	var e error
	block.Content = contents
	block.Next, err = uuid.FromBytes(uuid.Nil[:])
	if err != nil {
		e = errors.New("error calculating uuid of block.next")
	}
	block.BlockTag, err = userlib.HMACEval(file.SourceKey, block.Content)
	if err != nil {
		e = errors.New("error creating block hmac")
	}
	jsonBlock, err := json.Marshal(block)
	if err != nil {
		e = errors.New("error during json marshal of block struct")
	}
	blockUUID := uuid.New()
	userlib.DatastoreSet(blockUUID, jsonBlock)
	if err != nil {
		e = errors.New("error saving block struct to datastore")
	}
	return blockUUID, e
}

func UpdateFile(file File, filename string, user User) (err error) {
	var e error
	jsonFile, err := json.Marshal(file)
	if err != nil {
		e = errors.New("error during json marshal of file struct")
	}
	file.FileTag, err = userlib.HMACEval(user.AuthenticationKey, jsonFile)
	if err != nil {
		e = errors.New("error creating file hmac")
	}
	fileUUID, err := uuid.FromBytes(userlib.Hash([]byte(user.Username + "/" + filename)))
	if err != nil {
		e = errors.New("error calculating file uuid")
	}
	jsonFile2, err := json.Marshal(file)
	if err != nil {
		e = errors.New("error during json marshal of file struct")
	}
	IV := userlib.RandomBytes(16)
	EncryptedFileStruct := userlib.SymEnc(file.SourceKey, IV, jsonFile2)
	userlib.DatastoreSet(fileUUID, EncryptedFileStruct)

	return e
}

func CreateInvitedUserStruct(senderUsername string, recipientUsername string, filename string,
	fileSubkey []byte, encryptKey []byte) (address userlib.UUID, err error) {
	var IUStruct InvitedUserToFileRouter
	var e error
	e = nil

	IUStructUUID, err := uuid.FromBytes(userlib.Hash([]byte(fileSubkey)[:16]))
	if err != nil {
		e = errors.New("error calculating uuid of invited user struct")
	}
	IUStruct.FileKey = fileSubkey
	IUStruct.FileLocation, err = uuid.FromBytes(userlib.Hash([]byte(senderUsername + "/" + filename)[:16]))
	if err != nil {
		e = errors.New("error calculating file location uuid")
	}

	IV := userlib.RandomBytes(16)
	jsonIUStruct, err := json.Marshal(IUStruct)
	if err != nil {
		e = errors.New("error during json marshal of invited user struct")
	}
	IUStruct.IUTag, err = userlib.HMACEval(encryptKey, jsonIUStruct)
	if err != nil {
		e = errors.New("error creating hmac of invited user struct")
	}
	EncryptedIUStruct := userlib.SymEnc(encryptKey, IV, jsonIUStruct)
	userlib.DatastoreSet(IUStructUUID, EncryptedIUStruct)
	if err != nil {
		e = errors.New("error saving invited user struct to datastore")
	}
	return IUStructUUID, e
}

func CreateInvitation(filename string, sendingUser User, recipientUsername string, key []byte,
	recipientPK userlib.PKEEncKey, isSenderOwner bool) (address userlib.UUID, err error) {
	var e error
	e = nil
	var invitation Invitation
	var invitationJSON []byte
	//var IUStruct InvitedUserToFileRouter
	symkey := userlib.RandomBytes(16)
	encryptedSymKey, err := userlib.PKEEnc(recipientPK, symkey)
	if err != nil {
		e = errors.New("error encrypting symmetric key")
	}
	encryptedSubkey := userlib.SymEnc(encryptedSymKey, userlib.RandomBytes(16), key)
	invitation.Subkey = encryptedSubkey
	invitation.IsOwner = isSenderOwner
	invitation.InvitationKey = encryptedSymKey
	invitationJSON, err = json.Marshal(invitation)
	if err != nil {
		e = errors.New("error creating json marshal of invitation")
	}
	signature, err := userlib.DSSign(sendingUser.SignKey, invitationJSON)
	if err != nil {
		e = errors.New("error creating signature")
	}
	invitation.Signature = signature

	invitationJSON2, err := json.Marshal(invitation)
	if err != nil {
		e = errors.New("error creating json of invitation struct")
	}

	encryptedInvitation, err := userlib.PKEEnc(recipientPK, invitationJSON2)
	if err != nil {
		e = errors.New("error encrypting invitation")
	}
	invitationUUID := uuid.New()

	userlib.DatastoreSet(invitationUUID, encryptedInvitation)
	return invitationUUID, e
}

func UnlockInvitation(user User, invitation Invitation, filename string) (filekey []byte, err error) {
	var e error
	e = nil
	symKey, err := userlib.PKEDec(user.PrivateKey, invitation.InvitationKey)
	if err != nil {
		e = errors.New("error retreiving symmetric key")
	}
	fileKey := userlib.SymDec(symKey, invitation.Subkey)

	hashedUsername := userlib.Hash([]byte(user.Username))
	usernameUUID, err := uuid.FromBytes(hashedUsername[0:16])
	if err != nil {
		e = errors.New("error creating username uuid")
	}
	userPK, ok := userlib.KeystoreGet(usernameUUID.String())
	if !ok {
		e = errors.New("error getting user public key")
	}
	//store filekey
	encFileKey, err := userlib.PKEEnc(userPK, fileKey)
	if err != nil {
		e = errors.New("error encrypting filekey")
	}
	encFileKeyUUID, err := uuid.FromBytes([]byte(user.Username + "-" + filename))
	if err != nil {
		e = errors.New("error generating uuid")
	}
	userlib.DatastoreSet(encFileKeyUUID, encFileKey)

	return fileKey, e
}

func FindInvitedUserStruct(filekey []byte) (invitedUserStruct uuid.UUID, err error) {
	var e error
	e = nil
	invitedUserStructUUID, err := uuid.FromBytes(userlib.Hash(filekey)[:16])
	if err != nil {
		e = errors.New("error generating uuid")
	}
	return invitedUserStructUUID, e
}
