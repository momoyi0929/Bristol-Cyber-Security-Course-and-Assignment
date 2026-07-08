/**
It is a POC project to use argon2id algorithm for password verification
Important Links:
	1. "https://github.com/alexedwards/argon2id"
	2. "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
*/

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/argon2"
)

/*
*

	Create a structure that will store values for argon2id representation of the password
	Argon2id Docs: "https://github.com/alexedwards/argon2id"
*/
type Password struct {
	Hashedpassword string `json:"hashedPassword"`
	Salt           string `json:"salt"`
	Algo           string `json:"algo"`
	Memory         uint32 `json:"m"` // The amount of memory used by the Argon2 algorithm (in kibibytes).
	Iterations     uint32 `json:"t"` // The number of iterations (or passes) over the memory.
	Parallelism    uint8  `json:"p"` // The number of threads (or lanes) used by the algorithm.
	KeyLength      uint32 `json:"k"` // Length of the generated key (or password hash). 16 bytes or more is recommended.
	SaltLength     uint32 `json:"s"` // Length of the random salt. 16 bytes is recommended for password hashing.
}

//Runs before main func() and initializes the execution
func init() {
	byts, err := ioutil.ReadFile("db.json")
	if os.IsNotExist(err) {
		ioutil.WriteFile("db.json", []byte("{}"), 0600)
		return
	}
	if os.IsExist(err) {
		panic(err)
	}
	store := map[string]Password{}
	if err := json.Unmarshal(byts, &store); err != nil {
		panic(err)
	}
}

/*
*

	HashPassword function hashes the provided password update the hashedPassword obj.
	It returns error object if any error encounters
*/
func hashPassword(password string, obj *Password) error {
	/**
	Set the parameters of argon2id algorithm as per the recomendaation OWASP
	OWASP Link: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
	*/
	obj.Memory = 15 * 1024 // 64 Mb
	obj.Iterations = 2
	obj.Parallelism = 1
	obj.SaltLength = 32
	obj.KeyLength = 64

	// Generate a random Salt
	randByts := make([]byte, obj.SaltLength)
	_, err := rand.Read(randByts)
	if err != nil {
		return err
	}
	obj.Salt = hex.EncodeToString(randByts) // Convert random bytes into hex encoded string

	// Hash the transaction with argon2id algorithm
	hashed := argon2.IDKey([]byte(password), randByts, obj.Iterations, obj.Memory, obj.Parallelism, obj.KeyLength)
	obj.Hashedpassword = hex.EncodeToString(hashed) // Hex digest of hashed bytes of
	obj.Algo = "argon2id"
	return nil

}

/*
*

	This function create and stores the password in a key-value json pair and saved into db.json file.
	If any error encounters, it returns the error, otherwise hash the password and store it against the provided username
*/
func store(username, password string) error {
	// Read the database file which is basically a JSON file
	byts, err := ioutil.ReadFile("db.json")
	if os.IsNotExist(err) {
		return err
	}

	// Unmarshal the db.json into a map of string to password
	store := map[string]Password{}
	if err := json.Unmarshal(byts, &store); err != nil {
		return err
	}

	obj := Password{}
	if err := hashPassword(password, &obj); err != nil {
		return err
	}

	// update the password
	store[username] = obj

	// Save the db.json with updated values
	byts, err = json.Marshal(store)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile("db.json", byts, 0600); err != nil {
		return err
	}
	return nil
}

/*
*

	This function verifies the provided password agains a username.
	If the username is not found into the storage it prints "Record not found".
	If the provided password is not valid, then it prints "Password not matched".
	If any other error encounters, it returns the error, otherwise prints "Password matched".
*/
func verify(username, password string) error {
	// Read the db.json where hashed passwords has been stored
	byts, err := ioutil.ReadFile("db.json")
	if os.IsNotExist(err) {
		return err
	}

	store := map[string]Password{}
	if err := json.Unmarshal(byts, &store); err != nil {
		return err
	}

	// Get the record of provided username
	obj, ok := store[username]
	if !ok {
		println("Record not found.")
		return nil
	}

	// Decode the hex encoded salt
	salt, err := hex.DecodeString(obj.Salt)
	if err != nil {
		return err
	}
	var rehashed string
	// Rehash the provided password as per the stored algorithm
	switch obj.Algo {
	case "argon2id":
		{
			hashBytes := argon2.IDKey([]byte(password), salt, obj.Iterations, obj.Memory, obj.Parallelism, obj.KeyLength)
			rehashed = hex.EncodeToString(hashBytes)
		}
	case "argon2i":
		{
			hashBytes := argon2.Key([]byte(password), salt, obj.Iterations, obj.Memory, obj.Parallelism, obj.KeyLength)
			rehashed = hex.EncodeToString(hashBytes)
		}
	}

	// Compared the rehashed password
	if obj.Hashedpassword == rehashed {
		fmt.Println("Password matched")
	} else {
		fmt.Println("Password not matched")

	}

	return nil
}

/*
*

	This function retrives the record stored into db.json against a username.
	If the username is not found into the storage it prints "Record not found".
	If any other error encounters, it returns the error, otherwise prints the "Salt" and "HashedPassword"
*/
func get(username string) error {
	byts, err := ioutil.ReadFile("db.json")
	if os.IsNotExist(err) {
		return err
	}

	store := map[string]Password{}
	if err := json.Unmarshal(byts, &store); err != nil {
		return err
	}
	obj, ok := store[username]
	if ok {
		fmt.Printf("Salt: %v\nHashedPassword: %v\n", obj.Salt, string(obj.Hashedpassword))
	} else {
		println("Record not found.")
	}

	return nil
}

/*
*

	It is the entrypoint of the application
	This main function basically takes command-line arguments to
	1. store() password against a username
	2. verify() password of a stored password record against username
	3. get() the stored hashed password into the storage against a username

	Syntax
	go run <command> <param1> <param2> ... <paramN>

	Available Command
	-----------------
		store <username> <password> : To store password
		verify <username> <password> : To verify a stored password
		get <username> : Print the Salt and HashedPassword of stored password record
*/
func main() {

	if len(os.Args) < 2 {
		panic("Not enough arguments. try to \n go run main.go store [username] [password] \n go run main.go get [username] \n go run main.go verify [username] [password]")
	}

	switch os.Args[1] {
	// If first command-line argument is "store", then execute store() function
	case "store":
		{
			if len(os.Args) < 4 {
				panic("Not enough arguments. try to \n go run main.go store [username] [password]")
			}
			if err := store(os.Args[2], os.Args[3]); err != nil {
				panic(err)
			}
		}
		// If first command-line argument is "get", then execute get() function

	case "get":
		{
			if len(os.Args) < 3 {
				panic("Not enough arguments. try to \n go run main.go get [username]")
			}
			if err := get(os.Args[2]); err != nil {
				panic(err)
			}
		}
		// If first command-line argument is "verify", then execute verify() function
	case "verify":
		{
			if len(os.Args) < 4 {
				panic("Not enough arguments. try to \n go run main.go verify [username] [password]")
			}
			if err := verify(os.Args[2], os.Args[3]); err != nil {
				panic(err)
			}
		}

	}

}
