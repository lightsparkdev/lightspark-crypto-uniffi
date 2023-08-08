package lightspark_crypto

// TODO(mhr): Add support for other OS.

// #cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/libs/darwin/amd64 -llightspark_crypto
// #cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/libs/darwin/arm64 -llightspark_crypto
// #cgo linux,amd64 LDFLAGS: -L${SRCDIR}/libs/linux/amd64 -Wl,-Bstatic -llightspark_crypto -Wl,-Bdynamic
// #cgo linux,arm64 LDFLAGS: -L${SRCDIR}/libs/linux/arm64 -Wl,-Bstatic -llightspark_crypto -Wl,-Bdynamic
import "C"
import (
	"strings"

	"github.com/lightsparkdev/lightspark-crypto-uniffi/lightspark-crypto-go/internal"
)

type BitcoinNetwork uint

const (
	Mainnet BitcoinNetwork = 1
	Testnet BitcoinNetwork = 2
	Regtest BitcoinNetwork = 3
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

func Ecdh(seedBytes []byte, network BitcoinNetwork, otherPubKey []byte) ([]byte, error) {
	seed := internal.NewSeed(seedBytes)
	defer seed.Destroy()

	signer := internal.NewLightsparkSigner(seed, toFfiNetwork(network))
	defer signer.Destroy()

	return signer.Ecdh(otherPubKey)
}

func DerivePublicKey(seedBytes []byte, network BitcoinNetwork, derivationPath string) (string, error) {
	seed := internal.NewSeed(seedBytes)
	defer seed.Destroy()

	signer := internal.NewLightsparkSigner(seed, toFfiNetwork(network))
	defer signer.Destroy()

	return signer.DerivePublicKey(derivationPath)
}

func SignMessage(seedBytes []byte, network BitcoinNetwork, message []byte, derivationPath string, isRaw bool, addTweak *[]byte, multTweak *[]byte) ([]byte, error) {
	seed := internal.NewSeed(seedBytes)
	defer seed.Destroy()

	signer := internal.NewLightsparkSigner(seed, toFfiNetwork(network))
	defer signer.Destroy()

	signature, err := signer.DeriveKeyAndSign(message, derivationPath, isRaw, addTweak, multTweak)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func toFfiNetwork(network BitcoinNetwork) internal.Network {
	var ffiNetwork internal.Network

	switch network {
	case Mainnet:
		ffiNetwork = internal.NetworkBitcoin
	case Testnet:
		ffiNetwork = internal.NetworkTestnet
	case Regtest:
		ffiNetwork = internal.NetworkRegtest
	}

	return ffiNetwork
}
