package lightspark_crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetMnemonicSeedPhrase(t *testing.T) {
	entropy, err := base64.StdEncoding.DecodeString("geVgqn+RALV+fPe1fvra9SNotfA/e2BprRqu2ub/6wg=")
	require.NoError(t, err, "Failed to decode base64 entropy")

	mnemonicSeedPhrase, err := GetMnemonicSeedPhrase(entropy)
	require.NoError(t, err, "Failed to get mnemonic seed phrase")

	expectedMnemonic := []string{
		"limit",
		"climb",
		"clever",
		"you",
		"avoid",
		"follow",
		"wheat",
		"page",
		"rely",
		"water",
		"repeat",
		"tumble",
		"custom",
		"foot",
		"science",
		"urge",
		"gather",
		"estate",
		"effort",
		"frozen",
		"purpose",
		"lend",
		"promote",
		"anchor"}

	require.Equal(t, expectedMnemonic, mnemonicSeedPhrase)
}

func TestDerivePublicKey(t *testing.T) {
	privateKeySeed, err := hex.DecodeString("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
	require.NoError(t, err, "Failed to decode private key")

	derivationPath := "m/0/2147483647'/1"

	publicKey, err := DerivePublicKey(privateKeySeed, derivationPath)

	require.NoError(t, err, "Failed to derive public key")
	require.Equal(t, "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon", publicKey)
}

func TestSignMessage(t *testing.T) {
	message := sha256.Sum256([]byte("Hello Crypto World"))

	privateKeySeed, err := hex.DecodeString("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
	require.NoError(t, err, "Failed to decode private key")

	derivationPath := "m/0/2147483647'/1"

	signedMessage, err := SignMessage(message[:], privateKeySeed, derivationPath, nil, nil)
	require.NoError(t, err, "Failed to sign message")
	require.Equal(t, "fagpGOb9o/E8g62yL6jV5wtpTVzJ7R4rh0Xt2Uw4fPVd1Q+2ZJbkSrRBRj0bvk1qTSiCvoiCfD5CMEHZL4fAlA==", base64.StdEncoding.EncodeToString(signedMessage))
}
