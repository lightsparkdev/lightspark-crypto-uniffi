package internal

// #include <lightspark_crypto.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"
)

type RustBuffer = C.RustBuffer

type RustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() int
	Capacity() int
}

func RustBufferFromExternal(b RustBufferI) RustBuffer {
	return RustBuffer{
		capacity: C.int(b.Capacity()),
		len:      C.int(b.Len()),
		data:     (*C.uchar)(b.Data()),
	}
}

func (cb RustBuffer) Capacity() int {
	return int(cb.capacity)
}

func (cb RustBuffer) Len() int {
	return int(cb.len)
}

func (cb RustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.data)
}

func (cb RustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.data), C.int(cb.len))
	return bytes.NewReader(b)
}

func (cb RustBuffer) Free() {
	rustCall(func(status *C.RustCallStatus) bool {
		C.ffi_lightspark_crypto_rustbuffer_free(cb, status)
		return false
	})
}

func (cb RustBuffer) ToGoBytes() []byte {
	return C.GoBytes(unsafe.Pointer(cb.data), C.int(cb.len))
}

func stringToRustBuffer(str string) RustBuffer {
	return bytesToRustBuffer([]byte(str))
}

func bytesToRustBuffer(b []byte) RustBuffer {
	if len(b) == 0 {
		return RustBuffer{}
	}
	// We can pass the pointer along here, as it is pinned
	// for the duration of this call
	foreign := C.ForeignBytes{
		len:  C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}

	return rustCall(func(status *C.RustCallStatus) RustBuffer {
		return C.ffi_lightspark_crypto_rustbuffer_from_bytes(foreign, status)
	})
}

type BufLifter[GoType any] interface {
	Lift(value RustBufferI) GoType
}

type BufLowerer[GoType any] interface {
	Lower(value GoType) RustBuffer
}

type FfiConverter[GoType any, FfiType any] interface {
	Lift(value FfiType) GoType
	Lower(value GoType) FfiType
}

type BufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type BufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

type FfiRustBufConverter[GoType any, FfiType any] interface {
	FfiConverter[GoType, FfiType]
	BufReader[GoType]
}

func LowerIntoRustBuffer[GoType any](bufWriter BufWriter[GoType], value GoType) RustBuffer {
	// This might be not the most efficient way but it does not require knowing allocation size
	// beforehand
	var buffer bytes.Buffer
	bufWriter.Write(&buffer, value)

	bytes, err := io.ReadAll(&buffer)
	if err != nil {
		panic(fmt.Errorf("reading written data: %w", err))
	}
	return bytesToRustBuffer(bytes)
}

func LiftFromRustBuffer[GoType any](bufReader BufReader[GoType], rbuf RustBufferI) GoType {
	defer rbuf.Free()
	reader := rbuf.AsReader()
	item := bufReader.Read(reader)
	if reader.Len() > 0 {
		// TODO: Remove this
		leftover, _ := io.ReadAll(reader)
		panic(fmt.Errorf("Junk remaining in buffer after lifting: %s", string(leftover)))
	}
	return item
}

func rustCallWithError[U any](converter BufLifter[error], callback func(*C.RustCallStatus) U) (U, error) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)

	return returnValue, err
}

func checkCallStatus(converter BufLifter[error], status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		return converter.Lift(status.errorBuf)
	case 2:
		// when the rust code sees a panic, it tries to construct a rustbuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(status.errorBuf)))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func checkCallStatusUnknown(status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		panic(fmt.Errorf("function not returning an error returned an error"))
	case 2:
		// when the rust code sees a panic, it tries to construct a rustbuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(status.errorBuf)))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func rustCall[U any](callback func(*C.RustCallStatus) U) U {
	returnValue, err := rustCallWithError(nil, callback)
	if err != nil {
		panic(err)
	}
	return returnValue
}

func writeInt8(writer io.Writer, value int8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint8(writer io.Writer, value uint8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt16(writer io.Writer, value int16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint16(writer io.Writer, value uint16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt32(writer io.Writer, value int32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint32(writer io.Writer, value uint32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt64(writer io.Writer, value int64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint64(writer io.Writer, value uint64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat32(writer io.Writer, value float32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat64(writer io.Writer, value float64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func readInt8(reader io.Reader) int8 {
	var result int8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint8(reader io.Reader) uint8 {
	var result uint8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt16(reader io.Reader) int16 {
	var result int16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint16(reader io.Reader) uint16 {
	var result uint16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt32(reader io.Reader) int32 {
	var result int32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint32(reader io.Reader) uint32 {
	var result uint32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt64(reader io.Reader) int64 {
	var result int64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint64(reader io.Reader) uint64 {
	var result uint64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat32(reader io.Reader) float32 {
	var result float32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat64(reader io.Reader) float64 {
	var result float64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func init() {

	(&FfiConverterCallbackInterfaceValidation{}).register()
	uniffiCheckChecksums()
}

func uniffiCheckChecksums() {
	// Get the bindings contract version from our ComponentInterface
	bindingsContractVersion := 24
	// Get the scaffolding contract version by calling the into the dylib
	scaffoldingContractVersion := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.ffi_lightspark_crypto_uniffi_contract_version(uniffiStatus)
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("lightspark_crypto: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_func_decrypt_ecies(uniffiStatus)
		})
		if checksum != 32002 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_func_decrypt_ecies: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_func_derive_and_tweak_pubkey(uniffiStatus)
		})
		if checksum != 44901 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_func_derive_and_tweak_pubkey: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_func_encrypt_ecies(uniffiStatus)
		})
		if checksum != 57526 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_func_encrypt_ecies: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_func_generate_keypair(uniffiStatus)
		})
		if checksum != 35394 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_func_generate_keypair: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_func_generate_multisig_address(uniffiStatus)
		})
		if checksum != 10348 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_func_generate_multisig_address: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_func_handle_remote_signing_webhook_event(uniffiStatus)
		})
		if checksum != 38991 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_func_handle_remote_signing_webhook_event: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_func_sign_ecdsa(uniffiStatus)
		})
		if checksum != 6804 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_func_sign_ecdsa: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_func_sign_transactions(uniffiStatus)
		})
		if checksum != 40198 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_func_sign_transactions: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_func_verify_ecdsa(uniffiStatus)
		})
		if checksum != 51190 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_func_verify_ecdsa: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_invoicesignature_get_recovery_id(uniffiStatus)
		})
		if checksum != 44059 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_invoicesignature_get_recovery_id: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_invoicesignature_get_signature(uniffiStatus)
		})
		if checksum != 1363 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_invoicesignature_get_signature: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_keypair_get_private_key(uniffiStatus)
		})
		if checksum != 333 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_keypair_get_private_key: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_keypair_get_public_key(uniffiStatus)
		})
		if checksum != 28794 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_keypair_get_public_key: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_lightsparksigner_derive_key_and_sign(uniffiStatus)
		})
		if checksum != 55840 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_lightsparksigner_derive_key_and_sign: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_lightsparksigner_derive_private_key(uniffiStatus)
		})
		if checksum != 44534 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_lightsparksigner_derive_private_key: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_lightsparksigner_derive_public_key(uniffiStatus)
		})
		if checksum != 1950 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_lightsparksigner_derive_public_key: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_lightsparksigner_derive_public_key_hex(uniffiStatus)
		})
		if checksum != 47918 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_lightsparksigner_derive_public_key_hex: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_lightsparksigner_ecdh(uniffiStatus)
		})
		if checksum != 65526 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_lightsparksigner_ecdh: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_lightsparksigner_generate_preimage(uniffiStatus)
		})
		if checksum != 10846 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_lightsparksigner_generate_preimage: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_lightsparksigner_generate_preimage_hash(uniffiStatus)
		})
		if checksum != 12248 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_lightsparksigner_generate_preimage_hash: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_lightsparksigner_generate_preimage_nonce(uniffiStatus)
		})
		if checksum != 2599 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_lightsparksigner_generate_preimage_nonce: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_lightsparksigner_get_master_public_key(uniffiStatus)
		})
		if checksum != 48490 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_lightsparksigner_get_master_public_key: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_lightsparksigner_get_per_commitment_point(uniffiStatus)
		})
		if checksum != 55465 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_lightsparksigner_get_per_commitment_point: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_lightsparksigner_release_per_commitment_secret(uniffiStatus)
		})
		if checksum != 25475 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_lightsparksigner_release_per_commitment_secret: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_lightsparksigner_sign_invoice(uniffiStatus)
		})
		if checksum != 19232 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_lightsparksigner_sign_invoice: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_lightsparksigner_sign_invoice_hash(uniffiStatus)
		})
		if checksum != 11162 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_lightsparksigner_sign_invoice_hash: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_mnemonic_as_string(uniffiStatus)
		})
		if checksum != 15466 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_mnemonic_as_string: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_seed_as_bytes(uniffiStatus)
		})
		if checksum != 32338 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_seed_as_bytes: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_constructor_lightsparksigner_from_bytes(uniffiStatus)
		})
		if checksum != 57207 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_constructor_lightsparksigner_from_bytes: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_constructor_lightsparksigner_new(uniffiStatus)
		})
		if checksum != 65101 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_constructor_lightsparksigner_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_constructor_mnemonic_from_entropy(uniffiStatus)
		})
		if checksum != 54958 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_constructor_mnemonic_from_entropy: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_constructor_mnemonic_from_phrase(uniffiStatus)
		})
		if checksum != 46204 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_constructor_mnemonic_from_phrase: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_constructor_mnemonic_random(uniffiStatus)
		})
		if checksum != 3686 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_constructor_mnemonic_random: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_constructor_seed_from_mnemonic(uniffiStatus)
		})
		if checksum != 17860 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_constructor_seed_from_mnemonic: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_constructor_seed_new(uniffiStatus)
		})
		if checksum != 15664 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_constructor_seed_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_lightspark_crypto_checksum_method_validation_should_sign(uniffiStatus)
		})
		if checksum != 52762 {
			// If this happens try cleaning and rebuilding your project
			panic("lightspark_crypto: uniffi_lightspark_crypto_checksum_method_validation_should_sign: UniFFI API checksum mismatch")
		}
	}
}

type FfiConverterUint8 struct{}

var FfiConverterUint8INSTANCE = FfiConverterUint8{}

func (FfiConverterUint8) Lower(value uint8) C.uint8_t {
	return C.uint8_t(value)
}

func (FfiConverterUint8) Write(writer io.Writer, value uint8) {
	writeUint8(writer, value)
}

func (FfiConverterUint8) Lift(value C.uint8_t) uint8 {
	return uint8(value)
}

func (FfiConverterUint8) Read(reader io.Reader) uint8 {
	return readUint8(reader)
}

type FfiDestroyerUint8 struct{}

func (FfiDestroyerUint8) Destroy(_ uint8) {}

type FfiConverterInt32 struct{}

var FfiConverterInt32INSTANCE = FfiConverterInt32{}

func (FfiConverterInt32) Lower(value int32) C.int32_t {
	return C.int32_t(value)
}

func (FfiConverterInt32) Write(writer io.Writer, value int32) {
	writeInt32(writer, value)
}

func (FfiConverterInt32) Lift(value C.int32_t) int32 {
	return int32(value)
}

func (FfiConverterInt32) Read(reader io.Reader) int32 {
	return readInt32(reader)
}

type FfiDestroyerInt32 struct{}

func (FfiDestroyerInt32) Destroy(_ int32) {}

type FfiConverterUint64 struct{}

var FfiConverterUint64INSTANCE = FfiConverterUint64{}

func (FfiConverterUint64) Lower(value uint64) C.uint64_t {
	return C.uint64_t(value)
}

func (FfiConverterUint64) Write(writer io.Writer, value uint64) {
	writeUint64(writer, value)
}

func (FfiConverterUint64) Lift(value C.uint64_t) uint64 {
	return uint64(value)
}

func (FfiConverterUint64) Read(reader io.Reader) uint64 {
	return readUint64(reader)
}

type FfiDestroyerUint64 struct{}

func (FfiDestroyerUint64) Destroy(_ uint64) {}

type FfiConverterBool struct{}

var FfiConverterBoolINSTANCE = FfiConverterBool{}

func (FfiConverterBool) Lower(value bool) C.int8_t {
	if value {
		return C.int8_t(1)
	}
	return C.int8_t(0)
}

func (FfiConverterBool) Write(writer io.Writer, value bool) {
	if value {
		writeInt8(writer, 1)
	} else {
		writeInt8(writer, 0)
	}
}

func (FfiConverterBool) Lift(value C.int8_t) bool {
	return value != 0
}

func (FfiConverterBool) Read(reader io.Reader) bool {
	return readInt8(reader) != 0
}

type FfiDestroyerBool struct{}

func (FfiDestroyerBool) Destroy(_ bool) {}

type FfiConverterString struct{}

var FfiConverterStringINSTANCE = FfiConverterString{}

func (FfiConverterString) Lift(rb RustBufferI) string {
	defer rb.Free()
	reader := rb.AsReader()
	b, err := io.ReadAll(reader)
	if err != nil {
		panic(fmt.Errorf("reading reader: %w", err))
	}
	return string(b)
}

func (FfiConverterString) Read(reader io.Reader) string {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading string, expected %d, read %d", length, read_length))
	}
	return string(buffer)
}

func (FfiConverterString) Lower(value string) RustBuffer {
	return stringToRustBuffer(value)
}

func (FfiConverterString) Write(writer io.Writer, value string) {
	if len(value) > math.MaxInt32 {
		panic("String is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := io.WriteString(writer, value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing string, expected %d, written %d", len(value), write_length))
	}
}

type FfiDestroyerString struct{}

func (FfiDestroyerString) Destroy(_ string) {}

// Below is an implementation of synchronization requirements outlined in the link.
// https://github.com/mozilla/uniffi-rs/blob/0dc031132d9493ca812c3af6e7dd60ad2ea95bf0/uniffi_bindgen/src/bindings/kotlin/templates/ObjectRuntime.kt#L31

type FfiObject struct {
	pointer      unsafe.Pointer
	callCounter  atomic.Int64
	freeFunction func(unsafe.Pointer, *C.RustCallStatus)
	destroyed    atomic.Bool
}

func newFfiObject(pointer unsafe.Pointer, freeFunction func(unsafe.Pointer, *C.RustCallStatus)) FfiObject {
	return FfiObject{
		pointer:      pointer,
		freeFunction: freeFunction,
	}
}

func (ffiObject *FfiObject) incrementPointer(debugName string) unsafe.Pointer {
	for {
		counter := ffiObject.callCounter.Load()
		if counter <= -1 {
			panic(fmt.Errorf("%v object has already been destroyed", debugName))
		}
		if counter == math.MaxInt64 {
			panic(fmt.Errorf("%v object call counter would overflow", debugName))
		}
		if ffiObject.callCounter.CompareAndSwap(counter, counter+1) {
			break
		}
	}

	return ffiObject.pointer
}

func (ffiObject *FfiObject) decrementPointer() {
	if ffiObject.callCounter.Add(-1) == -1 {
		ffiObject.freeRustArcPtr()
	}
}

func (ffiObject *FfiObject) destroy() {
	if ffiObject.destroyed.CompareAndSwap(false, true) {
		if ffiObject.callCounter.Add(-1) == -1 {
			ffiObject.freeRustArcPtr()
		}
	}
}

func (ffiObject *FfiObject) freeRustArcPtr() {
	rustCall(func(status *C.RustCallStatus) int32 {
		ffiObject.freeFunction(ffiObject.pointer, status)
		return 0
	})
}

type InvoiceSignature struct {
	ffiObject FfiObject
}

func (_self *InvoiceSignature) GetRecoveryId() int32 {
	_pointer := _self.ffiObject.incrementPointer("*InvoiceSignature")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterInt32INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int32_t {
		return C.uniffi_lightspark_crypto_fn_method_invoicesignature_get_recovery_id(
			_pointer, _uniffiStatus)
	}))
}

func (_self *InvoiceSignature) GetSignature() []uint8 {
	_pointer := _self.ffiObject.incrementPointer("*InvoiceSignature")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_invoicesignature_get_signature(
			_pointer, _uniffiStatus)
	}))
}

func (object *InvoiceSignature) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterInvoiceSignature struct{}

var FfiConverterInvoiceSignatureINSTANCE = FfiConverterInvoiceSignature{}

func (c FfiConverterInvoiceSignature) Lift(pointer unsafe.Pointer) *InvoiceSignature {
	result := &InvoiceSignature{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_lightspark_crypto_fn_free_invoicesignature(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*InvoiceSignature).Destroy)
	return result
}

func (c FfiConverterInvoiceSignature) Read(reader io.Reader) *InvoiceSignature {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterInvoiceSignature) Lower(value *InvoiceSignature) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*InvoiceSignature")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterInvoiceSignature) Write(writer io.Writer, value *InvoiceSignature) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerInvoiceSignature struct{}

func (_ FfiDestroyerInvoiceSignature) Destroy(value *InvoiceSignature) {
	value.Destroy()
}

type KeyPair struct {
	ffiObject FfiObject
}

func (_self *KeyPair) GetPrivateKey() []uint8 {
	_pointer := _self.ffiObject.incrementPointer("*KeyPair")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_keypair_get_private_key(
			_pointer, _uniffiStatus)
	}))
}

func (_self *KeyPair) GetPublicKey() []uint8 {
	_pointer := _self.ffiObject.incrementPointer("*KeyPair")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_keypair_get_public_key(
			_pointer, _uniffiStatus)
	}))
}

func (object *KeyPair) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterKeyPair struct{}

var FfiConverterKeyPairINSTANCE = FfiConverterKeyPair{}

func (c FfiConverterKeyPair) Lift(pointer unsafe.Pointer) *KeyPair {
	result := &KeyPair{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_lightspark_crypto_fn_free_keypair(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*KeyPair).Destroy)
	return result
}

func (c FfiConverterKeyPair) Read(reader io.Reader) *KeyPair {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterKeyPair) Lower(value *KeyPair) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*KeyPair")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterKeyPair) Write(writer io.Writer, value *KeyPair) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerKeyPair struct{}

func (_ FfiDestroyerKeyPair) Destroy(value *KeyPair) {
	value.Destroy()
}

type LightsparkSigner struct {
	ffiObject FfiObject
}

func NewLightsparkSigner(seed *Seed, network Network) (*LightsparkSigner, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_lightspark_crypto_fn_constructor_lightsparksigner_new(FfiConverterSeedINSTANCE.Lower(seed), FfiConverterTypeNetworkINSTANCE.Lower(network), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *LightsparkSigner
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterLightsparkSignerINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func LightsparkSignerFromBytes(seed []uint8, network Network) (*LightsparkSigner, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_lightspark_crypto_fn_constructor_lightsparksigner_from_bytes(FfiConverterSequenceUint8INSTANCE.Lower(seed), FfiConverterTypeNetworkINSTANCE.Lower(network), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *LightsparkSigner
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterLightsparkSignerINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func (_self *LightsparkSigner) DeriveKeyAndSign(message []uint8, derivationPath string, isRaw bool, addTweak *[]uint8, mulTweak *[]uint8) ([]uint8, error) {
	_pointer := _self.ffiObject.incrementPointer("*LightsparkSigner")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_lightsparksigner_derive_key_and_sign(
			_pointer, FfiConverterSequenceUint8INSTANCE.Lower(message), FfiConverterStringINSTANCE.Lower(derivationPath), FfiConverterBoolINSTANCE.Lower(isRaw), FfiConverterOptionalSequenceUint8INSTANCE.Lower(addTweak), FfiConverterOptionalSequenceUint8INSTANCE.Lower(mulTweak), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []uint8
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceUint8INSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func (_self *LightsparkSigner) DerivePrivateKey(derivationPath string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*LightsparkSigner")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_lightsparksigner_derive_private_key(
			_pointer, FfiConverterStringINSTANCE.Lower(derivationPath), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func (_self *LightsparkSigner) DerivePublicKey(derivationPath string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*LightsparkSigner")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_lightsparksigner_derive_public_key(
			_pointer, FfiConverterStringINSTANCE.Lower(derivationPath), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func (_self *LightsparkSigner) DerivePublicKeyHex(derivationPath string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*LightsparkSigner")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_lightsparksigner_derive_public_key_hex(
			_pointer, FfiConverterStringINSTANCE.Lower(derivationPath), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func (_self *LightsparkSigner) Ecdh(publicKey []uint8) ([]uint8, error) {
	_pointer := _self.ffiObject.incrementPointer("*LightsparkSigner")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_lightsparksigner_ecdh(
			_pointer, FfiConverterSequenceUint8INSTANCE.Lower(publicKey), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []uint8
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceUint8INSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func (_self *LightsparkSigner) GeneratePreimage(nonce []uint8) ([]uint8, error) {
	_pointer := _self.ffiObject.incrementPointer("*LightsparkSigner")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_lightsparksigner_generate_preimage(
			_pointer, FfiConverterSequenceUint8INSTANCE.Lower(nonce), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []uint8
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceUint8INSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func (_self *LightsparkSigner) GeneratePreimageHash(nonce []uint8) ([]uint8, error) {
	_pointer := _self.ffiObject.incrementPointer("*LightsparkSigner")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_lightsparksigner_generate_preimage_hash(
			_pointer, FfiConverterSequenceUint8INSTANCE.Lower(nonce), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []uint8
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceUint8INSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func (_self *LightsparkSigner) GeneratePreimageNonce() []uint8 {
	_pointer := _self.ffiObject.incrementPointer("*LightsparkSigner")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_lightsparksigner_generate_preimage_nonce(
			_pointer, _uniffiStatus)
	}))
}

func (_self *LightsparkSigner) GetMasterPublicKey() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*LightsparkSigner")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_lightsparksigner_get_master_public_key(
			_pointer, _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func (_self *LightsparkSigner) GetPerCommitmentPoint(derivationPath string, perCommitmentPointIdx uint64) ([]uint8, error) {
	_pointer := _self.ffiObject.incrementPointer("*LightsparkSigner")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_lightsparksigner_get_per_commitment_point(
			_pointer, FfiConverterStringINSTANCE.Lower(derivationPath), FfiConverterUint64INSTANCE.Lower(perCommitmentPointIdx), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []uint8
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceUint8INSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func (_self *LightsparkSigner) ReleasePerCommitmentSecret(derivationPath string, perCommitmentPointIdx uint64) ([]uint8, error) {
	_pointer := _self.ffiObject.incrementPointer("*LightsparkSigner")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_lightsparksigner_release_per_commitment_secret(
			_pointer, FfiConverterStringINSTANCE.Lower(derivationPath), FfiConverterUint64INSTANCE.Lower(perCommitmentPointIdx), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []uint8
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceUint8INSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func (_self *LightsparkSigner) SignInvoice(unsignedInvoice string) (*InvoiceSignature, error) {
	_pointer := _self.ffiObject.incrementPointer("*LightsparkSigner")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_lightspark_crypto_fn_method_lightsparksigner_sign_invoice(
			_pointer, FfiConverterStringINSTANCE.Lower(unsignedInvoice), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *InvoiceSignature
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInvoiceSignatureINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func (_self *LightsparkSigner) SignInvoiceHash(unsignedInvoice []uint8) (*InvoiceSignature, error) {
	_pointer := _self.ffiObject.incrementPointer("*LightsparkSigner")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_lightspark_crypto_fn_method_lightsparksigner_sign_invoice_hash(
			_pointer, FfiConverterSequenceUint8INSTANCE.Lower(unsignedInvoice), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *InvoiceSignature
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInvoiceSignatureINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func (object *LightsparkSigner) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterLightsparkSigner struct{}

var FfiConverterLightsparkSignerINSTANCE = FfiConverterLightsparkSigner{}

func (c FfiConverterLightsparkSigner) Lift(pointer unsafe.Pointer) *LightsparkSigner {
	result := &LightsparkSigner{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_lightspark_crypto_fn_free_lightsparksigner(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*LightsparkSigner).Destroy)
	return result
}

func (c FfiConverterLightsparkSigner) Read(reader io.Reader) *LightsparkSigner {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterLightsparkSigner) Lower(value *LightsparkSigner) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*LightsparkSigner")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterLightsparkSigner) Write(writer io.Writer, value *LightsparkSigner) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerLightsparkSigner struct{}

func (_ FfiDestroyerLightsparkSigner) Destroy(value *LightsparkSigner) {
	value.Destroy()
}

type Mnemonic struct {
	ffiObject FfiObject
}

func MnemonicFromEntropy(entropy []uint8) (*Mnemonic, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_lightspark_crypto_fn_constructor_mnemonic_from_entropy(FfiConverterSequenceUint8INSTANCE.Lower(entropy), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Mnemonic
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterMnemonicINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func MnemonicFromPhrase(phrase string) (*Mnemonic, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_lightspark_crypto_fn_constructor_mnemonic_from_phrase(FfiConverterStringINSTANCE.Lower(phrase), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Mnemonic
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterMnemonicINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func MnemonicRandom() (*Mnemonic, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeLightsparkSignerError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_lightspark_crypto_fn_constructor_mnemonic_random(_uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Mnemonic
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterMnemonicINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func (_self *Mnemonic) AsString() string {
	_pointer := _self.ffiObject.incrementPointer("*Mnemonic")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_mnemonic_as_string(
			_pointer, _uniffiStatus)
	}))
}

func (object *Mnemonic) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterMnemonic struct{}

var FfiConverterMnemonicINSTANCE = FfiConverterMnemonic{}

func (c FfiConverterMnemonic) Lift(pointer unsafe.Pointer) *Mnemonic {
	result := &Mnemonic{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_lightspark_crypto_fn_free_mnemonic(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*Mnemonic).Destroy)
	return result
}

func (c FfiConverterMnemonic) Read(reader io.Reader) *Mnemonic {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterMnemonic) Lower(value *Mnemonic) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Mnemonic")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterMnemonic) Write(writer io.Writer, value *Mnemonic) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerMnemonic struct{}

func (_ FfiDestroyerMnemonic) Destroy(value *Mnemonic) {
	value.Destroy()
}

type Seed struct {
	ffiObject FfiObject
}

func NewSeed(seed []uint8) *Seed {
	return FfiConverterSeedINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_lightspark_crypto_fn_constructor_seed_new(FfiConverterSequenceUint8INSTANCE.Lower(seed), _uniffiStatus)
	}))
}

func SeedFromMnemonic(mnemonic *Mnemonic) *Seed {
	return FfiConverterSeedINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_lightspark_crypto_fn_constructor_seed_from_mnemonic(FfiConverterMnemonicINSTANCE.Lower(mnemonic), _uniffiStatus)
	}))
}

func (_self *Seed) AsBytes() []uint8 {
	_pointer := _self.ffiObject.incrementPointer("*Seed")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_method_seed_as_bytes(
			_pointer, _uniffiStatus)
	}))
}

func (object *Seed) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterSeed struct{}

var FfiConverterSeedINSTANCE = FfiConverterSeed{}

func (c FfiConverterSeed) Lift(pointer unsafe.Pointer) *Seed {
	result := &Seed{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_lightspark_crypto_fn_free_seed(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*Seed).Destroy)
	return result
}

func (c FfiConverterSeed) Read(reader io.Reader) *Seed {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterSeed) Lower(value *Seed) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Seed")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterSeed) Write(writer io.Writer, value *Seed) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerSeed struct{}

func (_ FfiDestroyerSeed) Destroy(value *Seed) {
	value.Destroy()
}

type RemoteSigningResponse struct {
	Query     string
	Variables string
}

func (r *RemoteSigningResponse) Destroy() {
	FfiDestroyerString{}.Destroy(r.Query)
	FfiDestroyerString{}.Destroy(r.Variables)
}

type FfiConverterTypeRemoteSigningResponse struct{}

var FfiConverterTypeRemoteSigningResponseINSTANCE = FfiConverterTypeRemoteSigningResponse{}

func (c FfiConverterTypeRemoteSigningResponse) Lift(rb RustBufferI) RemoteSigningResponse {
	return LiftFromRustBuffer[RemoteSigningResponse](c, rb)
}

func (c FfiConverterTypeRemoteSigningResponse) Read(reader io.Reader) RemoteSigningResponse {
	return RemoteSigningResponse{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeRemoteSigningResponse) Lower(value RemoteSigningResponse) RustBuffer {
	return LowerIntoRustBuffer[RemoteSigningResponse](c, value)
}

func (c FfiConverterTypeRemoteSigningResponse) Write(writer io.Writer, value RemoteSigningResponse) {
	FfiConverterStringINSTANCE.Write(writer, value.Query)
	FfiConverterStringINSTANCE.Write(writer, value.Variables)
}

type FfiDestroyerTypeRemoteSigningResponse struct{}

func (_ FfiDestroyerTypeRemoteSigningResponse) Destroy(value RemoteSigningResponse) {
	value.Destroy()
}

type Response struct {
	CommitmentTx               string
	SweepTx                    string
	HtlcInboundTx              []StringTuple
	HtlcOutboundTx             []StringTuple
	CounterpartySweepTx        string
	CounterpartyHtlcInboundTx  []string
	CounterpartyHtlcOutboundTx []string
}

func (r *Response) Destroy() {
	FfiDestroyerString{}.Destroy(r.CommitmentTx)
	FfiDestroyerString{}.Destroy(r.SweepTx)
	FfiDestroyerSequenceTypeStringTuple{}.Destroy(r.HtlcInboundTx)
	FfiDestroyerSequenceTypeStringTuple{}.Destroy(r.HtlcOutboundTx)
	FfiDestroyerString{}.Destroy(r.CounterpartySweepTx)
	FfiDestroyerSequenceString{}.Destroy(r.CounterpartyHtlcInboundTx)
	FfiDestroyerSequenceString{}.Destroy(r.CounterpartyHtlcOutboundTx)
}

type FfiConverterTypeResponse struct{}

var FfiConverterTypeResponseINSTANCE = FfiConverterTypeResponse{}

func (c FfiConverterTypeResponse) Lift(rb RustBufferI) Response {
	return LiftFromRustBuffer[Response](c, rb)
}

func (c FfiConverterTypeResponse) Read(reader io.Reader) Response {
	return Response{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterSequenceTypeStringTupleINSTANCE.Read(reader),
		FfiConverterSequenceTypeStringTupleINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterSequenceStringINSTANCE.Read(reader),
		FfiConverterSequenceStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeResponse) Lower(value Response) RustBuffer {
	return LowerIntoRustBuffer[Response](c, value)
}

func (c FfiConverterTypeResponse) Write(writer io.Writer, value Response) {
	FfiConverterStringINSTANCE.Write(writer, value.CommitmentTx)
	FfiConverterStringINSTANCE.Write(writer, value.SweepTx)
	FfiConverterSequenceTypeStringTupleINSTANCE.Write(writer, value.HtlcInboundTx)
	FfiConverterSequenceTypeStringTupleINSTANCE.Write(writer, value.HtlcOutboundTx)
	FfiConverterStringINSTANCE.Write(writer, value.CounterpartySweepTx)
	FfiConverterSequenceStringINSTANCE.Write(writer, value.CounterpartyHtlcInboundTx)
	FfiConverterSequenceStringINSTANCE.Write(writer, value.CounterpartyHtlcOutboundTx)
}

type FfiDestroyerTypeResponse struct{}

func (_ FfiDestroyerTypeResponse) Destroy(value Response) {
	value.Destroy()
}

type StringTuple struct {
	First  string
	Second string
}

func (r *StringTuple) Destroy() {
	FfiDestroyerString{}.Destroy(r.First)
	FfiDestroyerString{}.Destroy(r.Second)
}

type FfiConverterTypeStringTuple struct{}

var FfiConverterTypeStringTupleINSTANCE = FfiConverterTypeStringTuple{}

func (c FfiConverterTypeStringTuple) Lift(rb RustBufferI) StringTuple {
	return LiftFromRustBuffer[StringTuple](c, rb)
}

func (c FfiConverterTypeStringTuple) Read(reader io.Reader) StringTuple {
	return StringTuple{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeStringTuple) Lower(value StringTuple) RustBuffer {
	return LowerIntoRustBuffer[StringTuple](c, value)
}

func (c FfiConverterTypeStringTuple) Write(writer io.Writer, value StringTuple) {
	FfiConverterStringINSTANCE.Write(writer, value.First)
	FfiConverterStringINSTANCE.Write(writer, value.Second)
}

type FfiDestroyerTypeStringTuple struct{}

func (_ FfiDestroyerTypeStringTuple) Destroy(value StringTuple) {
	value.Destroy()
}

type CryptoError struct {
	err error
}

func (err CryptoError) Error() string {
	return fmt.Sprintf("CryptoError: %s", err.err.Error())
}

func (err CryptoError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrCryptoErrorSecp256k1Error = fmt.Errorf("CryptoErrorSecp256k1Error")
var ErrCryptoErrorRustSecp256k1Error = fmt.Errorf("CryptoErrorRustSecp256k1Error")
var ErrCryptoErrorInvalidPublicKeyScriptError = fmt.Errorf("CryptoErrorInvalidPublicKeyScriptError")
var ErrCryptoErrorKeyDerivationError = fmt.Errorf("CryptoErrorKeyDerivationError")
var ErrCryptoErrorKeyTweakError = fmt.Errorf("CryptoErrorKeyTweakError")

// Variant structs
type CryptoErrorSecp256k1Error struct {
	message string
}

func NewCryptoErrorSecp256k1Error() *CryptoError {
	return &CryptoError{
		err: &CryptoErrorSecp256k1Error{},
	}
}

func (err CryptoErrorSecp256k1Error) Error() string {
	return fmt.Sprintf("Secp256k1Error: %s", err.message)
}

func (self CryptoErrorSecp256k1Error) Is(target error) bool {
	return target == ErrCryptoErrorSecp256k1Error
}

type CryptoErrorRustSecp256k1Error struct {
	message string
}

func NewCryptoErrorRustSecp256k1Error() *CryptoError {
	return &CryptoError{
		err: &CryptoErrorRustSecp256k1Error{},
	}
}

func (err CryptoErrorRustSecp256k1Error) Error() string {
	return fmt.Sprintf("RustSecp256k1Error: %s", err.message)
}

func (self CryptoErrorRustSecp256k1Error) Is(target error) bool {
	return target == ErrCryptoErrorRustSecp256k1Error
}

type CryptoErrorInvalidPublicKeyScriptError struct {
	message string
}

func NewCryptoErrorInvalidPublicKeyScriptError() *CryptoError {
	return &CryptoError{
		err: &CryptoErrorInvalidPublicKeyScriptError{},
	}
}

func (err CryptoErrorInvalidPublicKeyScriptError) Error() string {
	return fmt.Sprintf("InvalidPublicKeyScriptError: %s", err.message)
}

func (self CryptoErrorInvalidPublicKeyScriptError) Is(target error) bool {
	return target == ErrCryptoErrorInvalidPublicKeyScriptError
}

type CryptoErrorKeyDerivationError struct {
	message string
}

func NewCryptoErrorKeyDerivationError() *CryptoError {
	return &CryptoError{
		err: &CryptoErrorKeyDerivationError{},
	}
}

func (err CryptoErrorKeyDerivationError) Error() string {
	return fmt.Sprintf("KeyDerivationError: %s", err.message)
}

func (self CryptoErrorKeyDerivationError) Is(target error) bool {
	return target == ErrCryptoErrorKeyDerivationError
}

type CryptoErrorKeyTweakError struct {
	message string
}

func NewCryptoErrorKeyTweakError() *CryptoError {
	return &CryptoError{
		err: &CryptoErrorKeyTweakError{},
	}
}

func (err CryptoErrorKeyTweakError) Error() string {
	return fmt.Sprintf("KeyTweakError: %s", err.message)
}

func (self CryptoErrorKeyTweakError) Is(target error) bool {
	return target == ErrCryptoErrorKeyTweakError
}

type FfiConverterTypeCryptoError struct{}

var FfiConverterTypeCryptoErrorINSTANCE = FfiConverterTypeCryptoError{}

func (c FfiConverterTypeCryptoError) Lift(eb RustBufferI) error {
	return LiftFromRustBuffer[error](c, eb)
}

func (c FfiConverterTypeCryptoError) Lower(value *CryptoError) RustBuffer {
	return LowerIntoRustBuffer[*CryptoError](c, value)
}

func (c FfiConverterTypeCryptoError) Read(reader io.Reader) error {
	errorID := readUint32(reader)

	message := FfiConverterStringINSTANCE.Read(reader)
	switch errorID {
	case 1:
		return &CryptoError{&CryptoErrorSecp256k1Error{message}}
	case 2:
		return &CryptoError{&CryptoErrorRustSecp256k1Error{message}}
	case 3:
		return &CryptoError{&CryptoErrorInvalidPublicKeyScriptError{message}}
	case 4:
		return &CryptoError{&CryptoErrorKeyDerivationError{message}}
	case 5:
		return &CryptoError{&CryptoErrorKeyTweakError{message}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterTypeCryptoError.Read()", errorID))
	}

}

func (c FfiConverterTypeCryptoError) Write(writer io.Writer, value *CryptoError) {
	switch variantValue := value.err.(type) {
	case *CryptoErrorSecp256k1Error:
		writeInt32(writer, 1)
	case *CryptoErrorRustSecp256k1Error:
		writeInt32(writer, 2)
	case *CryptoErrorInvalidPublicKeyScriptError:
		writeInt32(writer, 3)
	case *CryptoErrorKeyDerivationError:
		writeInt32(writer, 4)
	case *CryptoErrorKeyTweakError:
		writeInt32(writer, 5)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterTypeCryptoError.Write", value))
	}
}

type FundsRecoveryKitError struct {
	err error
}

func (err FundsRecoveryKitError) Error() string {
	return fmt.Sprintf("FundsRecoveryKitError: %s", err.err.Error())
}

func (err FundsRecoveryKitError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrFundsRecoveryKitErrorError = fmt.Errorf("FundsRecoveryKitErrorError")

// Variant structs
type FundsRecoveryKitErrorError struct {
	Message string
}

func NewFundsRecoveryKitErrorError(
	message string,
) *FundsRecoveryKitError {
	return &FundsRecoveryKitError{
		err: &FundsRecoveryKitErrorError{
			Message: message,
		},
	}
}

func (err FundsRecoveryKitErrorError) Error() string {
	return fmt.Sprint("Error",
		": ",

		"Message=",
		err.Message,
	)
}

func (self FundsRecoveryKitErrorError) Is(target error) bool {
	return target == ErrFundsRecoveryKitErrorError
}

type FfiConverterTypeFundsRecoveryKitError struct{}

var FfiConverterTypeFundsRecoveryKitErrorINSTANCE = FfiConverterTypeFundsRecoveryKitError{}

func (c FfiConverterTypeFundsRecoveryKitError) Lift(eb RustBufferI) error {
	return LiftFromRustBuffer[error](c, eb)
}

func (c FfiConverterTypeFundsRecoveryKitError) Lower(value *FundsRecoveryKitError) RustBuffer {
	return LowerIntoRustBuffer[*FundsRecoveryKitError](c, value)
}

func (c FfiConverterTypeFundsRecoveryKitError) Read(reader io.Reader) error {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &FundsRecoveryKitError{&FundsRecoveryKitErrorError{
			Message: FfiConverterStringINSTANCE.Read(reader),
		}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterTypeFundsRecoveryKitError.Read()", errorID))
	}
}

func (c FfiConverterTypeFundsRecoveryKitError) Write(writer io.Writer, value *FundsRecoveryKitError) {
	switch variantValue := value.err.(type) {
	case *FundsRecoveryKitErrorError:
		writeInt32(writer, 1)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Message)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterTypeFundsRecoveryKitError.Write", value))
	}
}

type LightsparkSignerError struct {
	err error
}

func (err LightsparkSignerError) Error() string {
	return fmt.Sprintf("LightsparkSignerError: %s", err.err.Error())
}

func (err LightsparkSignerError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrLightsparkSignerErrorBip39Error = fmt.Errorf("LightsparkSignerErrorBip39Error")
var ErrLightsparkSignerErrorSecp256k1Error = fmt.Errorf("LightsparkSignerErrorSecp256k1Error")
var ErrLightsparkSignerErrorKeyDerivationError = fmt.Errorf("LightsparkSignerErrorKeyDerivationError")
var ErrLightsparkSignerErrorKeyTweakError = fmt.Errorf("LightsparkSignerErrorKeyTweakError")
var ErrLightsparkSignerErrorEntropyLengthError = fmt.Errorf("LightsparkSignerErrorEntropyLengthError")

// Variant structs
type LightsparkSignerErrorBip39Error struct {
	message string
}

func NewLightsparkSignerErrorBip39Error() *LightsparkSignerError {
	return &LightsparkSignerError{
		err: &LightsparkSignerErrorBip39Error{},
	}
}

func (err LightsparkSignerErrorBip39Error) Error() string {
	return fmt.Sprintf("Bip39Error: %s", err.message)
}

func (self LightsparkSignerErrorBip39Error) Is(target error) bool {
	return target == ErrLightsparkSignerErrorBip39Error
}

type LightsparkSignerErrorSecp256k1Error struct {
	message string
}

func NewLightsparkSignerErrorSecp256k1Error() *LightsparkSignerError {
	return &LightsparkSignerError{
		err: &LightsparkSignerErrorSecp256k1Error{},
	}
}

func (err LightsparkSignerErrorSecp256k1Error) Error() string {
	return fmt.Sprintf("Secp256k1Error: %s", err.message)
}

func (self LightsparkSignerErrorSecp256k1Error) Is(target error) bool {
	return target == ErrLightsparkSignerErrorSecp256k1Error
}

type LightsparkSignerErrorKeyDerivationError struct {
	message string
}

func NewLightsparkSignerErrorKeyDerivationError() *LightsparkSignerError {
	return &LightsparkSignerError{
		err: &LightsparkSignerErrorKeyDerivationError{},
	}
}

func (err LightsparkSignerErrorKeyDerivationError) Error() string {
	return fmt.Sprintf("KeyDerivationError: %s", err.message)
}

func (self LightsparkSignerErrorKeyDerivationError) Is(target error) bool {
	return target == ErrLightsparkSignerErrorKeyDerivationError
}

type LightsparkSignerErrorKeyTweakError struct {
	message string
}

func NewLightsparkSignerErrorKeyTweakError() *LightsparkSignerError {
	return &LightsparkSignerError{
		err: &LightsparkSignerErrorKeyTweakError{},
	}
}

func (err LightsparkSignerErrorKeyTweakError) Error() string {
	return fmt.Sprintf("KeyTweakError: %s", err.message)
}

func (self LightsparkSignerErrorKeyTweakError) Is(target error) bool {
	return target == ErrLightsparkSignerErrorKeyTweakError
}

type LightsparkSignerErrorEntropyLengthError struct {
	message string
}

func NewLightsparkSignerErrorEntropyLengthError() *LightsparkSignerError {
	return &LightsparkSignerError{
		err: &LightsparkSignerErrorEntropyLengthError{},
	}
}

func (err LightsparkSignerErrorEntropyLengthError) Error() string {
	return fmt.Sprintf("EntropyLengthError: %s", err.message)
}

func (self LightsparkSignerErrorEntropyLengthError) Is(target error) bool {
	return target == ErrLightsparkSignerErrorEntropyLengthError
}

type FfiConverterTypeLightsparkSignerError struct{}

var FfiConverterTypeLightsparkSignerErrorINSTANCE = FfiConverterTypeLightsparkSignerError{}

func (c FfiConverterTypeLightsparkSignerError) Lift(eb RustBufferI) error {
	return LiftFromRustBuffer[error](c, eb)
}

func (c FfiConverterTypeLightsparkSignerError) Lower(value *LightsparkSignerError) RustBuffer {
	return LowerIntoRustBuffer[*LightsparkSignerError](c, value)
}

func (c FfiConverterTypeLightsparkSignerError) Read(reader io.Reader) error {
	errorID := readUint32(reader)

	message := FfiConverterStringINSTANCE.Read(reader)
	switch errorID {
	case 1:
		return &LightsparkSignerError{&LightsparkSignerErrorBip39Error{message}}
	case 2:
		return &LightsparkSignerError{&LightsparkSignerErrorSecp256k1Error{message}}
	case 3:
		return &LightsparkSignerError{&LightsparkSignerErrorKeyDerivationError{message}}
	case 4:
		return &LightsparkSignerError{&LightsparkSignerErrorKeyTweakError{message}}
	case 5:
		return &LightsparkSignerError{&LightsparkSignerErrorEntropyLengthError{message}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterTypeLightsparkSignerError.Read()", errorID))
	}

}

func (c FfiConverterTypeLightsparkSignerError) Write(writer io.Writer, value *LightsparkSignerError) {
	switch variantValue := value.err.(type) {
	case *LightsparkSignerErrorBip39Error:
		writeInt32(writer, 1)
	case *LightsparkSignerErrorSecp256k1Error:
		writeInt32(writer, 2)
	case *LightsparkSignerErrorKeyDerivationError:
		writeInt32(writer, 3)
	case *LightsparkSignerErrorKeyTweakError:
		writeInt32(writer, 4)
	case *LightsparkSignerErrorEntropyLengthError:
		writeInt32(writer, 5)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterTypeLightsparkSignerError.Write", value))
	}
}

type Network uint

const (
	NetworkBitcoin Network = 1
	NetworkTestnet Network = 2
	NetworkRegtest Network = 3
)

type FfiConverterTypeNetwork struct{}

var FfiConverterTypeNetworkINSTANCE = FfiConverterTypeNetwork{}

func (c FfiConverterTypeNetwork) Lift(rb RustBufferI) Network {
	return LiftFromRustBuffer[Network](c, rb)
}

func (c FfiConverterTypeNetwork) Lower(value Network) RustBuffer {
	return LowerIntoRustBuffer[Network](c, value)
}
func (FfiConverterTypeNetwork) Read(reader io.Reader) Network {
	id := readInt32(reader)
	return Network(id)
}

func (FfiConverterTypeNetwork) Write(writer io.Writer, value Network) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerTypeNetwork struct{}

func (_ FfiDestroyerTypeNetwork) Destroy(value Network) {
}

type RemoteSigningError struct {
	err error
}

func (err RemoteSigningError) Error() string {
	return fmt.Sprintf("RemoteSigningError: %s", err.err.Error())
}

func (err RemoteSigningError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrRemoteSigningErrorWebhookParsingError = fmt.Errorf("RemoteSigningErrorWebhookParsingError")
var ErrRemoteSigningErrorWebhookSignatureError = fmt.Errorf("RemoteSigningErrorWebhookSignatureError")
var ErrRemoteSigningErrorSignerCreationError = fmt.Errorf("RemoteSigningErrorSignerCreationError")
var ErrRemoteSigningErrorRemoteSigningHandlerError = fmt.Errorf("RemoteSigningErrorRemoteSigningHandlerError")

// Variant structs
type RemoteSigningErrorWebhookParsingError struct {
	message string
}

func NewRemoteSigningErrorWebhookParsingError() *RemoteSigningError {
	return &RemoteSigningError{
		err: &RemoteSigningErrorWebhookParsingError{},
	}
}

func (err RemoteSigningErrorWebhookParsingError) Error() string {
	return fmt.Sprintf("WebhookParsingError: %s", err.message)
}

func (self RemoteSigningErrorWebhookParsingError) Is(target error) bool {
	return target == ErrRemoteSigningErrorWebhookParsingError
}

type RemoteSigningErrorWebhookSignatureError struct {
	message string
}

func NewRemoteSigningErrorWebhookSignatureError() *RemoteSigningError {
	return &RemoteSigningError{
		err: &RemoteSigningErrorWebhookSignatureError{},
	}
}

func (err RemoteSigningErrorWebhookSignatureError) Error() string {
	return fmt.Sprintf("WebhookSignatureError: %s", err.message)
}

func (self RemoteSigningErrorWebhookSignatureError) Is(target error) bool {
	return target == ErrRemoteSigningErrorWebhookSignatureError
}

type RemoteSigningErrorSignerCreationError struct {
	message string
}

func NewRemoteSigningErrorSignerCreationError() *RemoteSigningError {
	return &RemoteSigningError{
		err: &RemoteSigningErrorSignerCreationError{},
	}
}

func (err RemoteSigningErrorSignerCreationError) Error() string {
	return fmt.Sprintf("SignerCreationError: %s", err.message)
}

func (self RemoteSigningErrorSignerCreationError) Is(target error) bool {
	return target == ErrRemoteSigningErrorSignerCreationError
}

type RemoteSigningErrorRemoteSigningHandlerError struct {
	message string
}

func NewRemoteSigningErrorRemoteSigningHandlerError() *RemoteSigningError {
	return &RemoteSigningError{
		err: &RemoteSigningErrorRemoteSigningHandlerError{},
	}
}

func (err RemoteSigningErrorRemoteSigningHandlerError) Error() string {
	return fmt.Sprintf("RemoteSigningHandlerError: %s", err.message)
}

func (self RemoteSigningErrorRemoteSigningHandlerError) Is(target error) bool {
	return target == ErrRemoteSigningErrorRemoteSigningHandlerError
}

type FfiConverterTypeRemoteSigningError struct{}

var FfiConverterTypeRemoteSigningErrorINSTANCE = FfiConverterTypeRemoteSigningError{}

func (c FfiConverterTypeRemoteSigningError) Lift(eb RustBufferI) error {
	return LiftFromRustBuffer[error](c, eb)
}

func (c FfiConverterTypeRemoteSigningError) Lower(value *RemoteSigningError) RustBuffer {
	return LowerIntoRustBuffer[*RemoteSigningError](c, value)
}

func (c FfiConverterTypeRemoteSigningError) Read(reader io.Reader) error {
	errorID := readUint32(reader)

	message := FfiConverterStringINSTANCE.Read(reader)
	switch errorID {
	case 1:
		return &RemoteSigningError{&RemoteSigningErrorWebhookParsingError{message}}
	case 2:
		return &RemoteSigningError{&RemoteSigningErrorWebhookSignatureError{message}}
	case 3:
		return &RemoteSigningError{&RemoteSigningErrorSignerCreationError{message}}
	case 4:
		return &RemoteSigningError{&RemoteSigningErrorRemoteSigningHandlerError{message}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterTypeRemoteSigningError.Read()", errorID))
	}

}

func (c FfiConverterTypeRemoteSigningError) Write(writer io.Writer, value *RemoteSigningError) {
	switch variantValue := value.err.(type) {
	case *RemoteSigningErrorWebhookParsingError:
		writeInt32(writer, 1)
	case *RemoteSigningErrorWebhookSignatureError:
		writeInt32(writer, 2)
	case *RemoteSigningErrorSignerCreationError:
		writeInt32(writer, 3)
	case *RemoteSigningErrorRemoteSigningHandlerError:
		writeInt32(writer, 4)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterTypeRemoteSigningError.Write", value))
	}
}

type uniffiCallbackResult C.int32_t

const (
	uniffiIdxCallbackFree               uniffiCallbackResult = 0
	uniffiCallbackResultSuccess         uniffiCallbackResult = 0
	uniffiCallbackResultError           uniffiCallbackResult = 1
	uniffiCallbackUnexpectedResultError uniffiCallbackResult = 2
	uniffiCallbackCancelled             uniffiCallbackResult = 3
)

type concurrentHandleMap[T any] struct {
	leftMap       map[uint64]*T
	rightMap      map[*T]uint64
	currentHandle uint64
	lock          sync.RWMutex
}

func newConcurrentHandleMap[T any]() *concurrentHandleMap[T] {
	return &concurrentHandleMap[T]{
		leftMap:  map[uint64]*T{},
		rightMap: map[*T]uint64{},
	}
}

func (cm *concurrentHandleMap[T]) insert(obj *T) uint64 {
	cm.lock.Lock()
	defer cm.lock.Unlock()

	if existingHandle, ok := cm.rightMap[obj]; ok {
		return existingHandle
	}
	cm.currentHandle = cm.currentHandle + 1
	cm.leftMap[cm.currentHandle] = obj
	cm.rightMap[obj] = cm.currentHandle
	return cm.currentHandle
}

func (cm *concurrentHandleMap[T]) remove(handle uint64) bool {
	cm.lock.Lock()
	defer cm.lock.Unlock()

	if val, ok := cm.leftMap[handle]; ok {
		delete(cm.leftMap, handle)
		delete(cm.rightMap, val)
	}
	return false
}

func (cm *concurrentHandleMap[T]) tryGet(handle uint64) (*T, bool) {
	cm.lock.RLock()
	defer cm.lock.RUnlock()

	val, ok := cm.leftMap[handle]
	return val, ok
}

type FfiConverterCallbackInterface[CallbackInterface any] struct {
	handleMap *concurrentHandleMap[CallbackInterface]
}

func (c *FfiConverterCallbackInterface[CallbackInterface]) drop(handle uint64) RustBuffer {
	c.handleMap.remove(handle)
	return RustBuffer{}
}

func (c *FfiConverterCallbackInterface[CallbackInterface]) Lift(handle uint64) CallbackInterface {
	val, ok := c.handleMap.tryGet(handle)
	if !ok {
		panic(fmt.Errorf("no callback in handle map: %d", handle))
	}
	return *val
}

func (c *FfiConverterCallbackInterface[CallbackInterface]) Read(reader io.Reader) CallbackInterface {
	return c.Lift(readUint64(reader))
}

func (c *FfiConverterCallbackInterface[CallbackInterface]) Lower(value CallbackInterface) C.uint64_t {
	return C.uint64_t(c.handleMap.insert(&value))
}

func (c *FfiConverterCallbackInterface[CallbackInterface]) Write(writer io.Writer, value CallbackInterface) {
	writeUint64(writer, uint64(c.Lower(value)))
}

type Validation interface {
	ShouldSign(webhook string) bool
}

// foreignCallbackCallbackInterfaceValidation cannot be callable be a compiled function at a same time
type foreignCallbackCallbackInterfaceValidation struct{}

//export lightspark_crypto_cgo_Validation
func lightspark_crypto_cgo_Validation(handle C.uint64_t, method C.int32_t, argsPtr *C.uint8_t, argsLen C.int32_t, outBuf *C.RustBuffer) C.int32_t {
	cb := FfiConverterCallbackInterfaceValidationINSTANCE.Lift(uint64(handle))
	switch method {
	case 0:
		// 0 means Rust is done with the callback, and the callback
		// can be dropped by the foreign language.
		*outBuf = FfiConverterCallbackInterfaceValidationINSTANCE.drop(uint64(handle))
		// See docs of ForeignCallback in `uniffi/src/ffi/foreigncallbacks.rs`
		return C.int32_t(uniffiIdxCallbackFree)

	case 1:
		var result uniffiCallbackResult
		args := unsafe.Slice((*byte)(argsPtr), argsLen)
		result = foreignCallbackCallbackInterfaceValidation{}.InvokeShouldSign(cb, args, outBuf)
		return C.int32_t(result)

	default:
		// This should never happen, because an out of bounds method index won't
		// ever be used. Once we can catch errors, we should return an InternalException.
		// https://github.com/mozilla/uniffi-rs/issues/351
		return C.int32_t(uniffiCallbackUnexpectedResultError)
	}
}

func (foreignCallbackCallbackInterfaceValidation) InvokeShouldSign(callback Validation, args []byte, outBuf *C.RustBuffer) uniffiCallbackResult {
	reader := bytes.NewReader(args)
	result := callback.ShouldSign(FfiConverterStringINSTANCE.Read(reader))

	*outBuf = LowerIntoRustBuffer[bool](FfiConverterBoolINSTANCE, result)
	return uniffiCallbackResultSuccess
}

type FfiConverterCallbackInterfaceValidation struct {
	FfiConverterCallbackInterface[Validation]
}

var FfiConverterCallbackInterfaceValidationINSTANCE = &FfiConverterCallbackInterfaceValidation{
	FfiConverterCallbackInterface: FfiConverterCallbackInterface[Validation]{
		handleMap: newConcurrentHandleMap[Validation](),
	},
}

// This is a static function because only 1 instance is supported for registering
func (c *FfiConverterCallbackInterfaceValidation) register() {
	rustCall(func(status *C.RustCallStatus) int32 {
		C.uniffi_lightspark_crypto_fn_init_callback_validation(C.ForeignCallback(C.lightspark_crypto_cgo_Validation), status)
		return 0
	})
}

type FfiDestroyerCallbackInterfaceValidation struct{}

func (FfiDestroyerCallbackInterfaceValidation) Destroy(value Validation) {
}

type FfiConverterOptionalTypeRemoteSigningResponse struct{}

var FfiConverterOptionalTypeRemoteSigningResponseINSTANCE = FfiConverterOptionalTypeRemoteSigningResponse{}

func (c FfiConverterOptionalTypeRemoteSigningResponse) Lift(rb RustBufferI) *RemoteSigningResponse {
	return LiftFromRustBuffer[*RemoteSigningResponse](c, rb)
}

func (_ FfiConverterOptionalTypeRemoteSigningResponse) Read(reader io.Reader) *RemoteSigningResponse {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterTypeRemoteSigningResponseINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalTypeRemoteSigningResponse) Lower(value *RemoteSigningResponse) RustBuffer {
	return LowerIntoRustBuffer[*RemoteSigningResponse](c, value)
}

func (_ FfiConverterOptionalTypeRemoteSigningResponse) Write(writer io.Writer, value *RemoteSigningResponse) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterTypeRemoteSigningResponseINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalTypeRemoteSigningResponse struct{}

func (_ FfiDestroyerOptionalTypeRemoteSigningResponse) Destroy(value *RemoteSigningResponse) {
	if value != nil {
		FfiDestroyerTypeRemoteSigningResponse{}.Destroy(*value)
	}
}

type FfiConverterOptionalSequenceUint8 struct{}

var FfiConverterOptionalSequenceUint8INSTANCE = FfiConverterOptionalSequenceUint8{}

func (c FfiConverterOptionalSequenceUint8) Lift(rb RustBufferI) *[]uint8 {
	return LiftFromRustBuffer[*[]uint8](c, rb)
}

func (_ FfiConverterOptionalSequenceUint8) Read(reader io.Reader) *[]uint8 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterSequenceUint8INSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalSequenceUint8) Lower(value *[]uint8) RustBuffer {
	return LowerIntoRustBuffer[*[]uint8](c, value)
}

func (_ FfiConverterOptionalSequenceUint8) Write(writer io.Writer, value *[]uint8) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterSequenceUint8INSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalSequenceUint8 struct{}

func (_ FfiDestroyerOptionalSequenceUint8) Destroy(value *[]uint8) {
	if value != nil {
		FfiDestroyerSequenceUint8{}.Destroy(*value)
	}
}

type FfiConverterSequenceUint8 struct{}

var FfiConverterSequenceUint8INSTANCE = FfiConverterSequenceUint8{}

func (c FfiConverterSequenceUint8) Lift(rb RustBufferI) []uint8 {
	return LiftFromRustBuffer[[]uint8](c, rb)
}

func (c FfiConverterSequenceUint8) Read(reader io.Reader) []uint8 {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]uint8, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterUint8INSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceUint8) Lower(value []uint8) RustBuffer {
	return LowerIntoRustBuffer[[]uint8](c, value)
}

func (c FfiConverterSequenceUint8) Write(writer io.Writer, value []uint8) {
	if len(value) > math.MaxInt32 {
		panic("[]uint8 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterUint8INSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceUint8 struct{}

func (FfiDestroyerSequenceUint8) Destroy(sequence []uint8) {
	for _, value := range sequence {
		FfiDestroyerUint8{}.Destroy(value)
	}
}

type FfiConverterSequenceString struct{}

var FfiConverterSequenceStringINSTANCE = FfiConverterSequenceString{}

func (c FfiConverterSequenceString) Lift(rb RustBufferI) []string {
	return LiftFromRustBuffer[[]string](c, rb)
}

func (c FfiConverterSequenceString) Read(reader io.Reader) []string {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]string, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterStringINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceString) Lower(value []string) RustBuffer {
	return LowerIntoRustBuffer[[]string](c, value)
}

func (c FfiConverterSequenceString) Write(writer io.Writer, value []string) {
	if len(value) > math.MaxInt32 {
		panic("[]string is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterStringINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceString struct{}

func (FfiDestroyerSequenceString) Destroy(sequence []string) {
	for _, value := range sequence {
		FfiDestroyerString{}.Destroy(value)
	}
}

type FfiConverterSequenceTypeStringTuple struct{}

var FfiConverterSequenceTypeStringTupleINSTANCE = FfiConverterSequenceTypeStringTuple{}

func (c FfiConverterSequenceTypeStringTuple) Lift(rb RustBufferI) []StringTuple {
	return LiftFromRustBuffer[[]StringTuple](c, rb)
}

func (c FfiConverterSequenceTypeStringTuple) Read(reader io.Reader) []StringTuple {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]StringTuple, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTypeStringTupleINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTypeStringTuple) Lower(value []StringTuple) RustBuffer {
	return LowerIntoRustBuffer[[]StringTuple](c, value)
}

func (c FfiConverterSequenceTypeStringTuple) Write(writer io.Writer, value []StringTuple) {
	if len(value) > math.MaxInt32 {
		panic("[]StringTuple is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTypeStringTupleINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTypeStringTuple struct{}

func (FfiDestroyerSequenceTypeStringTuple) Destroy(sequence []StringTuple) {
	for _, value := range sequence {
		FfiDestroyerTypeStringTuple{}.Destroy(value)
	}
}

func DecryptEcies(cipherText []uint8, privateKeyBytes []uint8) ([]uint8, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeCryptoError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_func_decrypt_ecies(FfiConverterSequenceUint8INSTANCE.Lower(cipherText), FfiConverterSequenceUint8INSTANCE.Lower(privateKeyBytes), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []uint8
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceUint8INSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func DeriveAndTweakPubkey(pubkey string, derivationPath string, addTweak *[]uint8, mulTweak *[]uint8) ([]uint8, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeCryptoError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_func_derive_and_tweak_pubkey(FfiConverterStringINSTANCE.Lower(pubkey), FfiConverterStringINSTANCE.Lower(derivationPath), FfiConverterOptionalSequenceUint8INSTANCE.Lower(addTweak), FfiConverterOptionalSequenceUint8INSTANCE.Lower(mulTweak), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []uint8
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceUint8INSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func EncryptEcies(msg []uint8, publicKeyBytes []uint8) ([]uint8, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeCryptoError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_func_encrypt_ecies(FfiConverterSequenceUint8INSTANCE.Lower(msg), FfiConverterSequenceUint8INSTANCE.Lower(publicKeyBytes), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []uint8
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceUint8INSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func GenerateKeypair() (*KeyPair, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeCryptoError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_lightspark_crypto_fn_func_generate_keypair(_uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *KeyPair
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterKeyPairINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func GenerateMultisigAddress(network Network, pk1 []uint8, pk2 []uint8) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeCryptoError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_func_generate_multisig_address(FfiConverterTypeNetworkINSTANCE.Lower(network), FfiConverterSequenceUint8INSTANCE.Lower(pk1), FfiConverterSequenceUint8INSTANCE.Lower(pk2), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func HandleRemoteSigningWebhookEvent(webhookData []uint8, webhookSignature string, webhookSecret string, masterSeedBytes []uint8, validation Validation) (*RemoteSigningResponse, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeRemoteSigningError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_func_handle_remote_signing_webhook_event(FfiConverterSequenceUint8INSTANCE.Lower(webhookData), FfiConverterStringINSTANCE.Lower(webhookSignature), FfiConverterStringINSTANCE.Lower(webhookSecret), FfiConverterSequenceUint8INSTANCE.Lower(masterSeedBytes), FfiConverterCallbackInterfaceValidationINSTANCE.Lower(validation), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *RemoteSigningResponse
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterOptionalTypeRemoteSigningResponseINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func SignEcdsa(msg []uint8, privateKeyBytes []uint8) ([]uint8, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeCryptoError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_func_sign_ecdsa(FfiConverterSequenceUint8INSTANCE.Lower(msg), FfiConverterSequenceUint8INSTANCE.Lower(privateKeyBytes), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []uint8
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceUint8INSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func SignTransactions(masterSeed string, data string, network Network) (Response, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeFundsRecoveryKitError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_lightspark_crypto_fn_func_sign_transactions(FfiConverterStringINSTANCE.Lower(masterSeed), FfiConverterStringINSTANCE.Lower(data), FfiConverterTypeNetworkINSTANCE.Lower(network), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Response
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterTypeResponseINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func VerifyEcdsa(msg []uint8, signatureBytes []uint8, publicKeyBytes []uint8) (bool, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeCryptoError{}, func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_lightspark_crypto_fn_func_verify_ecdsa(FfiConverterSequenceUint8INSTANCE.Lower(msg), FfiConverterSequenceUint8INSTANCE.Lower(signatureBytes), FfiConverterSequenceUint8INSTANCE.Lower(publicKeyBytes), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue bool
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBoolINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}
