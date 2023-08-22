package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

func generateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// Générer une paire de clés RSA
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

func savePrivateKey(privateKey *rsa.PrivateKey, filename string) error {
	// Sauvegarder la clé privée dans un fichier
	privateKeyFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return err
	}
	return nil
}

func savePublicKey(publicKey *rsa.PublicKey, filename string) error {
	// Sauvegarder la clé publique dans un fichier
	publicKeyFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()
	publicKeyPEM, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	publicKeyBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyPEM}
	if err := pem.Encode(publicKeyFile, publicKeyBlock); err != nil {
		return err
	}
	return nil
}

func encryptFile(publicKF string, inputFile, outputFile string) error {
	// Charger la clé publique depuis le fichier
	publicKeyFile, err := os.Open(publicKF)
	if err != nil {
		fmt.Println("Erreur lors de l'ouverture du fichier de clé publique:", err)
	}
	defer publicKeyFile.Close()
	publicKeyPEM, err := io.ReadAll(publicKeyFile)
	if err != nil {
		fmt.Println("Erreur lors de la lecture du fichier de clé publique:", err)
	}
	publicKeyBlock, _ := pem.Decode(publicKeyPEM)
	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
	if err != nil {
		fmt.Println("Erreur lors de la lecture de la clé publique:", err)
	}

	// Lire le fichier à chiffrer
	fileContent, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	// Chiffrer le contenu du fichier
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, fileContent)
	if err != nil {
		return err
	}

	// Écrire le contenu chiffré dans un fichier de sortie
	err = os.WriteFile(outputFile, ciphertext, 0644)
	if err != nil {
		return err
	}
	return nil
}

func decryptFile(privateKF string, inputFile, outputFile string) error {
	// Charger la clé privée depuis le fichier
	privateKeyFile, err := os.Open(privateKF)
	if err != nil {
		fmt.Println("Erreur lors de l'ouverture du fichier de clé privée:", err)
	}
	defer privateKeyFile.Close()
	privateKeyPEM, err := io.ReadAll(privateKeyFile)
	if err != nil {
		fmt.Println("Erreur lors de la lecture du fichier de clé privée:", err)
	}
	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		fmt.Println("Erreur lors de la lecture de la clé privée:", err)
	}

	// Lire le fichier chiffré
	ciphertext, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	// Déchiffrer le contenu du fichier
	decryptedContent, err := rsa.DecryptPKCS1v15(nil, privateKey, ciphertext)
	if err != nil {
		return err
	}

	// Écrire le contenu déchiffré dans un fichier de sortie
	err = os.WriteFile(outputFile, decryptedContent, 0644)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	fmt.Println("Menu:")
	fmt.Println("1. Générer une paire de clés")
	fmt.Println("2. Chiffrer un fichier")
	fmt.Println("3. Déchiffrer un fichier")
	fmt.Print("Choisissez une option (1/2/3): ")

	var choice int
	_, err := fmt.Scan(&choice)
	if err != nil {
		fmt.Println("Erreur de saisie:", err)
		main()
	}

	switch choice {
	case 1:
		privateKey, publicKey, err := generateKeyPair()
		if err != nil {
			fmt.Println("Erreur lors de la génération de la paire de clés:", err)
			return
		}

		err = savePrivateKey(privateKey, "rsa_gen/private.pem")
		if err != nil {
			fmt.Println("Erreur lors de la sauvegarde de la clé privée:", err)
			return
		}

		err = savePublicKey(publicKey, "rsa_gen/public.pem")
		if err != nil {
			fmt.Println("Erreur lors de la sauvegarde de la clé publique:", err)
			return
		}
		fmt.Println("Paire de clés générée avec succès.")
		main()

	case 2:
		err = encryptFile("rsa_gen/public.pem", "test_file/test.txt", "test_file/encrypted.bin")
		if err != nil {
			fmt.Println("Erreur lors du chiffrement:", err)
			return
		}
		fmt.Println("Fichier chiffré avec succès.")
		main()

	case 3:
		err = decryptFile("rsa_gen/private.pem", "test_file/encrypted.bin", "test_file/decrypted.txt")
		if err != nil {
			fmt.Println("Erreur lors du déchiffrement:", err)
			return
		}
		fmt.Println("Fichier déchiffré avec succès.")
		main()

	default:
		fmt.Println("Option invalide.")
	}
}
