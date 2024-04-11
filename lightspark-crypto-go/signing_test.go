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

	publicKey, err := DerivePublicKey(privateKeySeed, Mainnet, derivationPath)

	require.NoError(t, err, "Failed to derive public key")
	require.Equal(t, "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon", publicKey)
}

func TestDeriveKeyAndSign(t *testing.T) {
	message := sha256.Sum256([]byte("Hello Crypto World"))

	privateKeySeed, err := hex.DecodeString("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
	require.NoError(t, err, "Failed to decode private key")

	derivationPath := "m/0/2147483647'/1"

	signedMessage, err := DeriveKeyAndSign(privateKeySeed, Mainnet, message[:], derivationPath, false, nil, nil)
	require.NoError(t, err, "Failed to sign message")
	require.Equal(t, "fagpGOb9o/E8g62yL6jV5wtpTVzJ7R4rh0Xt2Uw4fPVd1Q+2ZJbkSrRBRj0bvk1qTSiCvoiCfD5CMEHZL4fAlA==", base64.StdEncoding.EncodeToString(signedMessage))
}

func TestSignTransactions(t *testing.T) {
	    data := `{"commitment_tx": "0200000000010187748372b3dfb3d47c2bb0a02848a327c77f5c982d036626c6de0a958af56069000000000025cee5800236ad03000000000016001415f586897037ded59858ccb1d24d4fbe7602692e90d00300000000002200204a30a8d4aba2d9d2e245052fc3566e1e18c49c1f364351481bfdd3e4d3a60da00400473044022066dbda605a766bc8143e15825c878b3b9444637b04678da42fe8f0c317c41fc70220482bb1a741497b14650c1e07ec4a00803855ff0f6a1434c88ae068f51567e94201004752210315496a93245ab6a7373b4e7297a30e2a20feefc50c59484dce93b6685e3ec0302103e65fcacf66816c0cb7d85726944463efe1466184a01d99949aed8a8b0676009a52aee1158720", "sweep_tx": "020000000001016d0d0c47799e62541fc4bb51461b4bed8a5ed978ebe4f52d4c168a5b950d6f5401000000009000000001fbb80300000000001600146b0009af85b18052eb83afbdc9c45521c552588f0300004d632102a299258a6ac6b9be6b7ee879a87aca8a30e05d15e915b7af722f09d44c5014a867029000b2752103c74ec665bd1547f4a3dccee02c104677c7e880c6b0bdaec0cea195680d3cb62768ac00000000", "htlc_tx": [], "serialized_htlc_sweep_tx": [], "channel_point": "6960f58a950adec62666032d985c7fc727a34828a0b02b7cd4b3dfb372837487:0", "sweep_tx_add_tweak": "201d490866cdcc50199497d98b699f4ae367b23e801ffe405f3f983deef42f56", "htlc_tx_add_tweak": "146d304968ba398899c7147fb641a6e20d4134b2c78abf4a2eb67e094fd730c1", "funding_private_key_derivation_path": "m/3/599143572/0", "delayed_payment_base_key_derivation_path": "m/3/599143572/3", "htlc_base_key_derivation_path": "m/3/599143572/4", "channel_capacity": 500000, "nonces": [], "commitment_number": 1}`
        seed := "f520e5271623fe21c76b0212f855c97a"

		_, err := SignTransactions(seed, data, Regtest)
		require.NoError(t, err, "Failed to sign transactions")
}