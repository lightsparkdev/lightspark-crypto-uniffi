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
	mnemonic, uniffiErr := internal.MnemonicFromEntropy(entropy)
	if err := uniffiErr.AsError(); err != nil {
		return nil, err
	}
	defer mnemonic.Destroy()

	return strings.Split(mnemonic.AsString(), " "), nil
}

func MnemonicToSeed(mnemonic []string) ([]byte, error) {
	mnemonicObj, uniffiErr := internal.MnemonicFromPhrase(strings.Join(mnemonic, " "))
	if err := uniffiErr.AsError(); err != nil {
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

	ecdhResult, uniffiErr := signer.Ecdh(otherPubKey)
	if err := uniffiErr.AsError(); err != nil {
		return nil, err
	}
	return ecdhResult, nil
}

func DerivePublicKey(seedBytes []byte, network BitcoinNetwork, derivationPath string) (string, error) {
	signer, err := getLightsparkSigner(seedBytes, network)
	if err != nil {
		return "", err
	}
	defer signer.Destroy()

	publicKey, uniffiErr := signer.DerivePublicKey(derivationPath)
	if err := uniffiErr.AsError(); err != nil {
		return "", err
	}
	return publicKey, nil
}

func DerivePrivateKey(seedBytes []byte, network BitcoinNetwork, derivationPath string) (string, error) {
	signer, err := getLightsparkSigner(seedBytes, network)
	if err != nil {
		return "", err
	}
	defer signer.Destroy()

	privateKey, uniffiErr := signer.DerivePrivateKey(derivationPath)
	if err := uniffiErr.AsError(); err != nil {
		return "", err
	}
	return privateKey, nil
}

func DeriveKeyAndSign(seedBytes []byte, network BitcoinNetwork, message []byte, derivationPath string, isRaw bool, addTweak *[]byte, multTweak *[]byte) ([]byte, error) {
	signer, err := getLightsparkSigner(seedBytes, network)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()

	signature, uniffiErr := signer.DeriveKeyAndSign(message, derivationPath, isRaw, addTweak, multTweak)
	if err := uniffiErr.AsError(); err != nil {
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

	signature, uniffiErr := signer.SignInvoice(unsignedInvoice)
	if err := uniffiErr.AsError(); err != nil {
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

	signature, uniffiErr := signer.SignInvoiceHash(unsignedInvoice)
	if err := uniffiErr.AsError(); err != nil {
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

	perCommitmentPoint, uniffiErr := signer.GetPerCommitmentPoint(derivationPath, perCommitmentPointIdx)
	if err := uniffiErr.AsError(); err != nil {
		return nil, err
	}
	return perCommitmentPoint, nil
}

func ReleasePerCommitmentSecret(seedBytes []byte, network BitcoinNetwork, derivationPath string, perCommitmentPointIdx uint64) ([]byte, error) {
	signer, err := getLightsparkSigner(seedBytes, network)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()

	commitmentSecret, uniffiErr := signer.ReleasePerCommitmentSecret(derivationPath, perCommitmentPointIdx)
	if err := uniffiErr.AsError(); err != nil {
		return nil, err
	}
	return commitmentSecret, nil
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

	preimage, uniffiErr := signer.GeneratePreimage(nonce)
	if err := uniffiErr.AsError(); err != nil {
		return nil, err
	}
	return preimage, nil
}

func GeneratePreimageHash(seedBytes []byte, nonce []byte) ([]byte, error) {
	signer, err := getLightsparkSigner(seedBytes, Mainnet)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()

	preimageHash, uniffiErr := signer.GeneratePreimageHash(nonce)
	if err := uniffiErr.AsError(); err != nil {
		return nil, err
	}
	return preimageHash, nil
}

func SignEcdsa(message []byte, privateKey []byte) ([]byte, error) {
	signature, uniffiErr := internal.SignEcdsa(message, privateKey)
	if err := uniffiErr.AsError(); err != nil {
		return nil, err
	}
	return signature, nil
}

func VerifyEcdsa(message []byte, signature []byte, publicKey []byte) (bool, error) {
	verified, uniffiErr := internal.VerifyEcdsa(message, signature, publicKey)
	if err := uniffiErr.AsError(); err != nil {
		return false, err
	}
	return verified, nil
}

func EncryptEcies(message []byte, publicKey []byte) ([]byte, error) {
	encrypted, uniffiErr := internal.EncryptEcies(message, publicKey)
	if err := uniffiErr.AsError(); err != nil {
		return nil, err
	}
	return encrypted, nil
}

func DecryptEcies(message []byte, privateKey []byte) ([]byte, error) {
	decrypted, uniffiErr := internal.DecryptEcies(message, privateKey)
	if err := uniffiErr.AsError(); err != nil {
		return nil, err
	}
	return decrypted, nil
}

func GenerateMultiSigAddress(network BitcoinNetwork, publicKey1 []byte, publicKey2 []byte) (string, error) {
	ffiNetwork := toInternalNetwork(network)

	multisigAddress, uniffiErr := internal.GenerateMultisigAddress(ffiNetwork, publicKey1, publicKey2)
	if err := uniffiErr.AsError(); err != nil {
		return "", err
	}
	return multisigAddress, nil
}

func DeriveAndTweakPubkey(pubkey string, derivationPath string, addTweak *[]uint8, mulTweak *[]uint8) ([]uint8, error) {
	derivedPubkey, uniffiErr := internal.DeriveAndTweakPubkey(pubkey, derivationPath, addTweak, mulTweak)
	if err := uniffiErr.AsError(); err != nil {
		return nil, err
	}
	return derivedPubkey, nil
}

func getLightsparkSigner(seedBytes []byte, network BitcoinNetwork) (*internal.LightsparkSigner, error) {
	seed := internal.NewSeed(seedBytes)
	defer seed.Destroy()

	ffiNetwork := toInternalNetwork(network)

	signer, uniffiErr := internal.NewLightsparkSigner(seed, ffiNetwork)
	if err := uniffiErr.AsError(); err != nil {
		return nil, err
	}
	return signer, nil
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
	CounterpartySweepTx string
	CounterpartyHtlcInboundTx []string
	CounterpartyHtlcOutboundTx []string
}

func SignTransactions (masterSeed string, data string, network BitcoinNetwork) (*FundsRecoveryResponse, error) {
	ffiNetwork := toInternalNetwork(network)

	resp, uniffiErr := internal.SignTransactions(masterSeed, data, ffiNetwork)
	if err := uniffiErr.AsError(); err != nil {
		return nil, err
	}

	return &FundsRecoveryResponse{
		CommitmentTx: resp.CommitmentTx,
		SweepTx: resp.SweepTx,
		HtlcInboundTx: toPairArray(resp.HtlcInboundTx),
		HtlcOutboundTx: toPairArray(resp.HtlcOutboundTx),
		CounterpartySweepTx: resp.CounterpartySweepTx,
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
