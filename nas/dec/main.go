package main

import (
	"fmt"
	"os"

	"path/filepath"
	"strings"

	"crypto/sha256"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
)

var m_priv = [32]byte{0x63, 0x75, 0x72, 0x76, 0x70, 0x61, 0x74, 0x74, 0x65, 0x72, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

func i64tob(val uint64) []byte {
	r := make([]byte, 8)
	for i := uint64(0); i < 8; i++ {
		r[i] = byte((val >> (i * 8)) & 0xff)
	}
	return r
}

func decrypt_file(path string) {
	var shared [32]byte
	var publicKey [32]byte

	var file_flag = make([]byte, 6)

	err := os.Rename(path, path[:len(path)-6])
	if err != nil {
		fmt.Println(err)
		return
	}

	file, err := os.OpenFile(path[:len(path)-6], os.O_RDWR, 0)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	fi, err := file.Stat()
	if err != nil {
		fmt.Println(err)
		return
	}

	var offset int64 = 0
	var file_size = fi.Size()
	if file_size > 38 {
		file.ReadAt(file_flag, file_size-6)
		if file_flag[0] == 0xAB &&
			file_flag[1] == 0xBC &&
			file_flag[2] == 0xCD &&
			file_flag[3] == 0xDE &&
			file_flag[4] == 0xEF &&
			file_flag[5] == 0xF0 {

			file.ReadAt(publicKey[:], file_size-38)
			curve25519.ScalarMult(&shared, &m_priv, &publicKey)

			var cc20_k = sha256.Sum256([]byte(shared[:]))
			var cc20_n = sha256.Sum256([]byte(cc20_k[:]))

			stream, err := chacha20.NewUnauthenticatedCipher(cc20_k[:], cc20_n[10:22])
			if err != nil {
				fmt.Println(err)
				return
			}

			file_size -= 38
			if file_size > 0x1400000 {
				var chunks int64 = file_size / 0xA00000
				var buffer = make([]byte, 0x100000)

				var i int64
				for i = 0; i < chunks; i++ {
					offset = i * 0xA00000
					file.ReadAt(buffer, offset)
					stream.XORKeyStream(buffer, buffer)
					file.WriteAt(buffer, offset)
				}
			} else {
				var size_to_encrypt int64 = 0
				if file_size > 0x400000 {
					size_to_encrypt = 0x400000
				} else {
					size_to_encrypt = file_size
				}

				var buffer = make([]byte, size_to_encrypt)
				r, _ := file.ReadAt(buffer, offset)
				if int64(r) != size_to_encrypt {
					fmt.Printf("ERROR: %d != %d\n", r, size_to_encrypt)
					return
				}

				stream.XORKeyStream(buffer, buffer)
				file.WriteAt(buffer, offset)
			}

			file.Truncate(file_size)
		}
	}
}

func main() {
	if len(os.Args) == 2 {
		err := filepath.Walk(os.Args[1], func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() == false && strings.Contains(path, ".babyk") == true {
				fmt.Printf("Decrypt: %s\n", path)
				decrypt_file(path)
			}
			return nil
		})
		if err != nil {
			fmt.Println(err)
		}
	} else {
		fmt.Printf("%s /path/to/be/decrypted\n", os.Args[0])
	}
}
