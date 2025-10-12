package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/omept/decrypt-file-aes256/utils/checkerr"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file") // create a .env file with the attached .env.example as template
	}

	//start decrypts a file
	start()

}

// start decrypts a disk file and saves the new original copy
func start() {

	fileName := os.Getenv("FILE_NAME") // file to decrypt
	file, err := os.Open(fileName)
	checkerr.Check(err)

	key := os.Getenv("ENCRYPT_DECRYPT_KEY") // key lenght of 32 to use AES-256
	var bucket [1024 * 10]byte              // copy to memory by reading chuncks of 1024 * 10 bytes (10kb) from the file
	var memFile bytes.Buffer
	for {
		n, err := file.Read(bucket[:])
		if n == 0 {
			break
		}
		log.Printf("read %d bytes from file\n", n)
		if err == io.EOF {
			// copy to memory
			memFile.Write(bucket[:n])
			break
		}
		// copy to memory
		memFile.Write(bucket[:n])
	}
	file.Close()
	log.Printf("✅ File completly copied to memory")

	decBytes, err := decrypt(memFile.Bytes(), key)
	checkerr.Check(err)

	// save to new file
	newFileName := os.Getenv("DECRPTED_FILE_NAME")
	err = os.WriteFile(newFileName, decBytes, 0666)
	checkerr.Check(err)
	log.Printf("💪🏽 Decryption Complete")

}

// decrypt decrypts a AES encrypted byte slice from the recipient server and returns the original byte slice
func decrypt(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
