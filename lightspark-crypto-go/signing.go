package lightspark_crypto

// TODO(mhr): Add support for other OS.

// #cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/libs/darwin/amd64 -llightspark_crypto
// #cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/libs/darwin/arm64 -llightspark_crypto
import "C"
import (
	"strings"

	"github.com/lightsparkdev/lightspark-crypto-uniffi/lightspark-crypto-go/internal"
)

func GetMnemonicSeedPhrase(entropy []byte) ([]string, error) {
	mnemonic, err := internal.MnemonicFromEntropy(entropy)
	if err != nil {
		return nil, err
	}
	defer mnemonic.Destroy()

	return strings.Split(mnemonic.AsString(), " "), nil
}

func MnemonicToSeed(mnemonic []string) ([]byte, error) {
	mnemonicObj, err := internal.MnemonicFromPhrase(strings.Join(mnemonic, " "))
	if err != nil {
		return nil, err
	}
	defer mnemonicObj.Destroy()

	seed := internal.SeedFromMnemonic(mnemonicObj)
	defer seed.Destroy()

	return seed.AsBytes(), nil
}

func Ecdh(seedBytes []byte, derivationPath string, otherPubKey string) ([]byte, error) {
	signer := internal.NewLightsparkSigner()
	defer signer.Destroy()

	seed := internal.NewSeed(seedBytes)
	defer seed.Destroy()

	return signer.Ecdh(seed, derivationPath, otherPubKey)
}

func DerivePublicKey(seedBytes []byte, derivationPath string) (string, error) {
	seed := internal.NewSeed(seedBytes)
	defer seed.Destroy()

	signer := internal.NewLightsparkSigner()
	defer signer.Destroy()

	return signer.DerivePublicKey(seed, derivationPath)
}

func SignMessage(message []byte, seedBytes []byte, derivationPath string, multTweak *[]byte, addTweak *[]byte) ([]byte, error) {
	seed := internal.NewSeed(seedBytes)
	defer seed.Destroy()

	signer := internal.NewLightsparkSigner()
	defer signer.Destroy()

	signature, err := signer.DeriveKeyAndSign(seed, message, derivationPath, addTweak, multTweak)
	if err != nil {
		return nil, err
	}

	return signature, nil
}