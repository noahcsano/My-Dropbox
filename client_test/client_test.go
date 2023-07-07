package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"


	"github.com/google/uuid"
	
	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	malloryFile := "malloryFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {
		
		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot store to the file.", contentOne)
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).ToNot(BeNil()) //check storefile usage by revoked user
		})

	})
	//My tests: Functionality
	Describe("Functionality 1", func() {
		measureBandwidth := func(probe func()) (bandwidth int) {
			before := userlib.DatastoreGetBandwidth()
			probe()
			after := userlib.DatastoreGetBandwidth()
			return after - before
		 }
		Specify("Functionality: Testing error for attempting to set same username or empty username", func() {
			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil()) //GetUser username not there in the datastore

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			bob, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil()) //InitUser duplicate userrname

			userlib.DebugMsg("Initializing user Alice.")
			charles, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil()) //InitUser empty usernamne

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", "dwdw")
			Expect(err).ToNot(BeNil()) //GetUser wrong password

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("ehge", defaultPassword)
			Expect(err).ToNot(BeNil()) //GetUser wrong username
		})

		Specify("Functionality: Testing errors for StoreFile", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil()) 

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil()) //check error for append to a nonexistent file

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil()) 

			
		})

		Specify("Functionality: Testing errors for LoadFile", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...") 
			data, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())//error loading non existent file
			Expect(data).ToNot(Equal([]byte(contentOne + contentTwo + contentThree))) 
		})

		Specify("Usernames are Case Sensitive", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})
		
		Specify("Usernames should have length greater than 0", func() {
			userlib.DebugMsg("Initializing user with empty username.")
			alice, err = client.InitUser(emptyString, defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Weird usernames should work", func() {
			userlib.DebugMsg("Initializing user with weird username.")
			alice, err = client.InitUser("1*;353$2^!", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Multiple Users Can Have the Same Password", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Users should have a 0 length Password or more", func() {
			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", emptyString)
			Expect(err).To(BeNil())
		})

		Specify("The client app should have different users at the same time, making their own changes", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
		})

		Specify("Multiple user sessions at the same time for the same user, with same file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file data: %s", contentTwo)
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("The number of keys in Keystore must be a small constant", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Finding the keys per user in the keystore using KeystoreGetMap")
			KeysPerUserInKS := len(userlib.KeystoreGetMap())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for the file %s, and Bob accepting the invite under the name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			CurrentNumOfKeys := len(userlib.KeystoreGetMap())
			Expect(CurrentNumOfKeys / 2).To(Equal(KeysPerUserInKS))
		})

		Specify("Users without access can't access the file", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob should not be able to access alicefile")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Other Users should not be able to accept invites intended for a different users", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user charles.")
			charles, err := client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles tries to accept alice's invitation for bob.")
			err = charles.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("bob accepts alice's invitation.")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
		})

		Specify("Filenames may be any length, including zero", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", contentOne)
			err = alice.StoreFile(emptyString, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice should be able to load the given file")
			data, err := alice.LoadFile(emptyString)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Filenames are not globally unique", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = bob.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("Filenames are not globally unique when shared as well", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob accepts alice's invitation.")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})


		Specify("Testing revoke functionality amongst four users", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err := client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite_atob, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Charles.")
			invite_atoc, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite_atob, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepts invite from Alice under filename %s.", charlesFile)
			err = charles.AcceptInvitation("alice", invite_atoc, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = bob.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())

			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree)))

			userlib.DebugMsg("Initializing user mallory.")
			mallory, err := client.InitUser("mallory", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob creating invite for mallory.")
			invite_btom, err := bob.CreateInvitation(bobFile, "mallory")
			Expect(err).To(BeNil())

			userlib.DebugMsg("mallory accepting invite from Bob under filename %s.", malloryFile)
			err = mallory.AcceptInvitation("bob", invite_btom, malloryFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob should not be able to access since he was revoked")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Mallory should not be able to access since Bob was revoked")
			data, err = mallory.LoadFile(malloryFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob should not be able to append to file since he was revoked")
			err = bob.AppendToFile(bobFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Mallory should not be able to append to file since Bob was revoked")
			err = mallory.AppendToFile(malloryFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob should not be able to store file since he was revoked")
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())

			// userlib.DebugMsg("Mallory should not be able to store file since Bob was revoked")
			// err = mallory.StoreFile(malloryFile, []byte(contentOne))
			// Expect(err).ToNot(BeNil())

			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree)))
		})

		Specify("A revoked user's invite to another user must be invalid", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creates file %s with content: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err := client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creates invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts Alice's invitation.")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creates invite for Charles.")
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepts Bob's invitation. Should not work since Bob was removed")
			err = charles.AcceptInvitation("bob", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Error cases from the spec", func() {
			userlib.DebugMsg("Initializing user aliceLaptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Start session with invalid password.")
			aliceDesktop, err = client.GetUser("alice", "adsfjasdkl;fjvbn")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Tries to get bob without calling inituser.")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Tries to make another alice")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

		})


		Specify("Tampering with Datastore User and File", func() {
			userlib.DebugMsg("Initializing user Alice (aliceLaptop).")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Datastore values are being changed by the attacker")
			DataStoreMap := userlib.DatastoreGetMap()
			for key, _ := range DataStoreMap {
				userlib.DatastoreDelete(key)
			}

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceDesktop")
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			_, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})
		
		Specify("Try to access file without access", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creates file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob tries to create an invite for alice.")
			_, err = bob.CreateInvitation(aliceFile, "alice")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries to load file but should fail")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries to append file data: %s", contentThree)
			err = bob.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries to revoke alice's access from %s.", aliceFile)
			err = bob.RevokeAccess(aliceFile, "alice")
			Expect(err).ToNot(BeNil())
		})

		Specify("Tampering an Invitation", func() {
			userlib.DebugMsg("Initializing user AliceLaptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("AliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("AliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DatastoreSet(invite, []byte(contentTwo))

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceDesktop")
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			_, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Deleting all Datastore values.", func() {
			userlib.DebugMsg("Initializing user Alice (aliceLaptop).")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Datastore values are being changed by the attacker")

			DataStoreMap := userlib.DatastoreGetMap()
			for key := range DataStoreMap {
				userlib.DatastoreDelete(key)
			}

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop creating invite for Bob.")
			invite, err := aliceDesktop.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceDesktop")
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			_, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})
		
		Specify("Testing if Efficiency scales by the number of files", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice Storing file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking initial bandwidth")
			BandWidth := measureBandwidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			for j := 0; j < 15; j += 1 {
				err = alice.AppendToFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			}

			NewBandWidth := measureBandwidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			value := NewBandWidth <= 15*BandWidth //using 15 as the append operation should scale linearly.

			Expect(value).To(Equal(true))

		})

		Specify("Testing if Efficiency scales by the number of Users", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice Storing file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking initial bandwidth")
			BandWidth := measureBandwidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})
			for i := 0; i < 10; i += 1 {
				userlib.DebugMsg("Initializing a random user.")
				RandomUser := string(byte(i))
				Rando, err := client.InitUser(RandomUser, defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Alice creating invite for RandomUser.")
				invite, err := alice.CreateInvitation(aliceFile, RandomUser)
				Expect(err).To(BeNil())

				err = Rando.AcceptInvitation("alice", invite, aliceFile)
				Expect(err).To(BeNil())
			}

			NewBandWidth := measureBandwidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(contentTwo))
				Expect(err).To(BeNil())
			})

			value := NewBandWidth <= 10*BandWidth

			Expect(value).To(Equal(true))

		})

		Specify("Removing Datastore Invitation", func() {
			userlib.DebugMsg("Initializing user aliceLaptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DatastoreDelete(invite)

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceDesktop")
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceLaptop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			_, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Sharing files with the same name", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user charles.")
			charles, err := client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob storing file %s with content: %s", bobFile, contentTwo)
			err = bob.StoreFile(bobFile, []byte(contentTwo)) //both bob and alice use the same filename
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", bobFile, contentOne)
			err = alice.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for charles.")
			invite_atoc, err := alice.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob creating invite for mallory.")
			invite_btoc, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles accepting invite from alice")
			err = charles.AcceptInvitation("alice", invite_atoc, "Alicefile")
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles accepting invite from bob")
			err = charles.AcceptInvitation("bob", invite_btoc, "Bobfile")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Load file 1.")
			Alicefile, err := charles.LoadFile("Alicefile")
			Expect(Alicefile).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Load file 2.")
			Bobfile, err := charles.LoadFile("Bobfile")
			Expect(Bobfile).To(Equal([]byte(contentTwo)))
		})

		Specify("Create invitation for user that doesn't exist", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Share invite to fake user")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Tampering a block right after appending", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			DatastoreMapBeforeAppend := make(map[uuid.UUID][]byte)
			for key, val := range userlib.DatastoreGetMap() {
				DatastoreMapBeforeAppend[key] = val
			} //Getting the DatastoreMap before append.

			userlib.DebugMsg("Alice appends file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			DatastoreMapAfterAppend := make(map[uuid.UUID][]byte)
			for key, val := range userlib.DatastoreGetMap() {
				_, ok := DatastoreMapBeforeAppend[key]
				if !ok {
					DatastoreMapAfterAppend[key] = val
				}
			}

			for key, _ := range DatastoreMapAfterAppend {
				userlib.DatastoreSet(key, []byte(contentThree)) //tampering with the values afterappend to be different
			}

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob") //should error because the DataStore has been tampered with.
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice trying to load file %s", aliceFile)
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Try to accept 2 files under the same name", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile1", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = alice.StoreFile("aliceFile2", []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice tries to share File1 with bob")
			invite, err := alice.CreateInvitation("aliceFile1", "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts the invite for aliceFile1 under filename %s.", bobFile)
			err = bob.AcceptInvitation("aliceFile1", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice tries to share File2 with bob")
			invite, err = alice.CreateInvitation("aliceFile2", "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from aliceFile2 under filename %s.", bobFile)
			err = bob.AcceptInvitation("aliceFile2", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})


		Specify("Swapping blocks", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			DatastoreMapBeforeAppend := make(map[uuid.UUID][]byte)
			for key, val := range userlib.DatastoreGetMap() {
				DatastoreMapBeforeAppend[key] = val
			}

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			FirstBlock := make(map[uuid.UUID][]byte)
			for key, val := range userlib.DatastoreGetMap() {
				_, ok := DatastoreMapBeforeAppend[key]
				if !ok {
					FirstBlock[key] = val
				}
			}

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			SecondBlock := make(map[uuid.UUID][]byte)
			for key, val := range userlib.DatastoreGetMap() {
				_, ok := DatastoreMapBeforeAppend[key]
				if !ok {
					_, ok2 := SecondBlock[key]
					if !ok2 {
						SecondBlock[key] = val
					}
				}
			}

			var key1 uuid.UUID
			var key2 uuid.UUID
			var val1 []byte
			var val2 []byte
			for k1, v1 := range FirstBlock {
				for k2, v2 := range SecondBlock {
					key1 = k1
					val1 = v1 
					key2 = k2 
					val2 = v2

					userlib.DatastoreSet(key1, val2)
					userlib.DatastoreSet(key2, val1)
				}
			}		

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice trying to load file data")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Tampering with Datastore File", func() {
			userlib.DebugMsg("Initializing user aliceLaptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user charles.")
			charles, err := client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for charles.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles accepting invite from Alice under filename %s.", aliceFile)
			err = charles.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			DatastoreMap := make(map[uuid.UUID][]byte)
			for key, val := range userlib.DatastoreGetMap() {
				DatastoreMap[key] = val
			}

			userlib.DebugMsg("Alice should be able to revoke access", aliceFile)//should not?
			err = aliceLaptop.RevokeAccess(aliceFile, "alice")
			Expect(err).ToNot(BeNil())

			DatastoreMapwithFile := make(map[uuid.UUID][]byte)
			for key, val := range userlib.DatastoreGetMap() {
				_, found := DatastoreMap[key]
				if !found {
					DatastoreMapwithFile[key] = val
				}
			}

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err = aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", aliceFile)
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			datastoreValues := userlib.DatastoreGetMap()

			for key, val := range DatastoreMapwithFile {
				datastoreValues[key] = []byte(contentOne)

				userlib.DebugMsg("Checking that alice can't load file.")
				_, err = aliceLaptop.LoadFile(aliceFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Alice should not be able to revoke access", aliceFile)
				err = aliceDesktop.RevokeAccess(aliceFile, "bob")
				Expect(err).To(BeNil())

				userlib.DebugMsg("Bob storing %s, content: %s", aliceFile, contentThree)
				err = bob.StoreFile(aliceFile, []byte(contentThree))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Checking that Bob sees expected file data.")
				_, err = bob.LoadFile(aliceFile)
				Expect(err).To(BeNil())


				datastoreValues[key] = val
			}
		})

	})
})

