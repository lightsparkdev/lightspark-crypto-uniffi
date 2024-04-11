package lightspark_crypto

// TODO(mhr): Dynamic linking?

// #cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/libs/darwin/amd64 -llightspark_crypto -pthread
// #cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/libs/darwin/arm64 -llightspark_crypto -pthread
// #cgo linux,amd64 LDFLAGS: -L${SRCDIR}/libs/linux/amd64 -Wl,-Bstatic -llightspark_crypto -Wl,-Bdynamic -pthread
// #cgo linux,arm64 LDFLAGS: -L${SRCDIR}/libs/linux/arm64 -Wl,-Bstatic -llightspark_crypto -Wl,-Bdynamic -pthread
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
	signer, err := getLightsparkSigner(seedBytes, network)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()

	return signer.Ecdh(otherPubKey)
}

func DerivePublicKey(seedBytes []byte, network BitcoinNetwork, derivationPath string) (string, error) {
	signer, err := getLightsparkSigner(seedBytes, network)
	if err != nil {
		return "", err
	}
	defer signer.Destroy()

	return signer.DerivePublicKey(derivationPath)
}

func DerivePrivateKey(seedBytes []byte, network BitcoinNetwork, derivationPath string) (string, error) {
	signer, err := getLightsparkSigner(seedBytes, network)
	if err != nil {
		return "", err
	}
	defer signer.Destroy()

	return signer.DerivePrivateKey(derivationPath)
}

func DeriveKeyAndSign(seedBytes []byte, network BitcoinNetwork, message []byte, derivationPath string, isRaw bool, addTweak *[]byte, multTweak *[]byte) ([]byte, error) {
	signer, err := getLightsparkSigner(seedBytes, network)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()

	signature, err := signer.DeriveKeyAndSign(message, derivationPath, isRaw, addTweak, multTweak)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

type SignedInvoice struct {
	RecoveryId int32
	Signature  []byte
}

func SignInvoice(seedBytes []byte, network BitcoinNetwork, unsignedInvoice string) (*SignedInvoice, error) {
	signer, err := getLightsparkSigner(seedBytes, network)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()

	signature, err := signer.SignInvoice(unsignedInvoice)
	if err != nil {
		return nil, err
	}

	defer signature.Destroy()

	return &SignedInvoice{
		RecoveryId: signature.GetRecoveryId(),
		Signature:  signature.GetSignature(),
	}, nil
}

func SignInvoiceHash(seedBytes []byte, network BitcoinNetwork, unsignedInvoice []byte) (*SignedInvoice, error) {
	signer, err := getLightsparkSigner(seedBytes, network)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()

	signature, err := signer.SignInvoiceHash(unsignedInvoice)
	if err != nil {
		return nil, err
	}

	defer signature.Destroy()

	return &SignedInvoice{
		RecoveryId: signature.GetRecoveryId(),
		Signature:  signature.GetSignature(),
	}, nil
}

func GetPerCommitmentPoint(seedBytes []byte, network BitcoinNetwork, derivationPath string, perCommitmentPointIdx uint64) ([]byte, error) {
	signer, err := getLightsparkSigner(seedBytes, network)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()

	return signer.GetPerCommitmentPoint(derivationPath, perCommitmentPointIdx)
}

func ReleasePerCommitmentSecret(seedBytes []byte, network BitcoinNetwork, derivationPath string, perCommitmentPointIdx uint64) ([]byte, error) {
	signer, err := getLightsparkSigner(seedBytes, network)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()

	return signer.ReleasePerCommitmentSecret(derivationPath, perCommitmentPointIdx)
}

func GeneratePreimageNonce(seedBytes []byte) ([]byte, error) {
	// Note that the bitcoin network doesn't matter for the preimage stuff because it doesn't actually
	// have to do with the real node details or seed.
	signer, err := getLightsparkSigner(seedBytes, Mainnet)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()

	return signer.GeneratePreimageNonce(), nil
}

func GeneratePreimage(seedBytes []byte, nonce []byte) ([]byte, error) {
	signer, err := getLightsparkSigner(seedBytes, Mainnet)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()

	return signer.GeneratePreimage(nonce)
}

func GeneratePreimageHash(seedBytes []byte, nonce []byte) ([]byte, error) {
	signer, err := getLightsparkSigner(seedBytes, Mainnet)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()

	return signer.GeneratePreimageHash(nonce)
}

func SignEcdsa(message []byte, privateKey []byte) ([]byte, error) {
	return internal.SignEcdsa(message, privateKey)
}

func VerifyEcdsa(message []byte, signature []byte, publicKey []byte) (bool, error) {
	return internal.VerifyEcdsa(message, signature, publicKey)
}

func EncryptEcies(message []byte, publicKey []byte) ([]byte, error) {
	return internal.EncryptEcies(message, publicKey)
}

func DecryptEcies(message []byte, privateKey []byte) ([]byte, error) {
	return internal.DecryptEcies(message, privateKey)
}

func GenerateMultiSigAddress(network BitcoinNetwork, publicKey1 []byte, publicKey2 []byte) (string, error) {
	ffiNetwork := toInternalNetwork(network)

	return internal.GenerateMultisigAddress(ffiNetwork, publicKey1, publicKey2)
}

func DeriveAndTweakPubkey(pubkey string, derivationPath string, addTweak *[]uint8, mulTweak *[]uint8) ([]uint8, error) {
	return internal.DeriveAndTweakPubkey(pubkey, derivationPath, addTweak, mulTweak)
}

func getLightsparkSigner(seedBytes []byte, network BitcoinNetwork) (*internal.LightsparkSigner, error) {
	seed := internal.NewSeed(seedBytes)
	defer seed.Destroy()

	ffiNetwork := toInternalNetwork(network)

	return internal.NewLightsparkSigner(seed, ffiNetwork)
}

type Pair struct {
	First  string
	Second string
}

type FundsRecoveryResponse struct{
	CommitmentTx string
	SweepTx string
	HtlcInboundTx []Pair
	HtlcOutboundTx []Pair
	CounterpartyHtlcInboundTx []string
	CounterpartyHtlcOutboundTx []string
}

func SignTransactions (masterSeed string, data string, network BitcoinNetwork) (*FundsRecoveryResponse, error) {
	ffiNetwork := toInternalNetwork(network)

	resp, err := internal.SignTransactions(masterSeed, data, ffiNetwork)
	if err != nil {
		return nil, err
	}

	return &FundsRecoveryResponse{
		CommitmentTx: resp.CommitmentTx,
		SweepTx: resp.SweepTx,
		HtlcInboundTx: toPairArray(resp.HtlcInboundTx),
		HtlcOutboundTx: toPairArray(resp.HtlcOutboundTx),
		CounterpartyHtlcInboundTx: resp.CounterpartyHtlcInboundTx,
		CounterpartyHtlcOutboundTx: resp.CounterpartyHtlcOutboundTx,
	}, nil

}

func toInternalNetwork(network BitcoinNetwork) internal.Network {
	switch network {
	case Mainnet:
		return internal.NetworkBitcoin
	case Testnet:
		return internal.NetworkTestnet
	case Regtest:
		return internal.NetworkRegtest
	default:
		return internal.NetworkBitcoin
	}
}

func toPairArray(array []internal.StringTuple) []Pair {
	var pairs []Pair
	for _, pair := range array {
		pairs = append(pairs, Pair{First: pair.First, Second: pair.Second})
	}
	return pairs
}