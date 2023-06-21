import * as wasm from "lightspark-crypto";
import { Base64 } from "js-base64";

function testGetMnemonicSeedPhrase() {
  const entropy = Base64.toUint8Array(
    "geVgqn+RALV+fPe1fvra9SNotfA/e2BprRqu2ub/6wg="
  );
  const mnemonic = wasm.Mnemonic.from_entropy(entropy);
  console.log(`Mnemonic: ${mnemonic.as_string()}`);
  const test1Div = document.querySelector("#test1");
  let resultString = mnemonic.as_string();
  const expected =
    "limit climb clever you avoid follow wheat page rely water repeat tumble custom foot science urge gather estate effort frozen purpose lend promote anchor";
  test1Div.classList.add(resultString === expected ? "pass" : "fail");
  resultString += resultString === expected ? "\n(OK)" : "\n(FAIL)";
  test1Div.textContent = resultString;
}

function testDeriveKeyWithDerivationPathButNoTweaks() {
  const seedBytes = hexToBytes(
    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
  );
  const seed = wasm.Seed.new(seedBytes);
  const signer = wasm.LightsparkSigner.new(seed);
  const derivationPath = "m/0/2147483647'/1";
  const pubkey = signer.derive_public_key(seed, derivationPath);
  console.log(`Public key: ${pubkey}`);
  const test2Div = document.querySelector("#test2");
  test2Div.textContent = pubkey;
  const expected =
    "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon";
  test2Div.classList.add(pubkey === expected ? "pass" : "fail");
  test2Div.textContent += pubkey === expected ? "\n(OK)" : "\n(FAIL)";
}

async function testSigningWithDerivedKey() {
  const seedBytes = hexToBytes(
    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
  );
  const messageBytes = new TextEncoder().encode("Hello Crypto World");
  const hashedMessage = new Uint8Array(
    await crypto.subtle.digest("SHA-256", messageBytes)
  );
  console.log(`Hashed message: ${Base64.fromUint8Array(hashedMessage)}`);
  const seed = wasm.Seed.new(seedBytes);
  const signer = wasm.LightsparkSigner.new(seed);
  const derivationPath = "m/0/2147483647'/1";
  const signature = Base64.fromUint8Array(
    signer.derive_key_and_sign(seed, hashedMessage, derivationPath)
  );
  console.log(`Signature: ${signature}`);
  const test3Div = document.querySelector("#test3");
  test3Div.textContent = signature;
  const expected =
    "fagpGOb9o/E8g62yL6jV5wtpTVzJ7R4rh0Xt2Uw4fPVd1Q+2ZJbkSrRBRj0bvk1qTSiCvoiCfD5CMEHZL4fAlA==";
  test3Div.classList.add(signature === expected ? "pass" : "fail");
  test3Div.textContent += signature === expected ? "\n(OK)" : "\n(FAIL)";
}

async function testDeriveRevocationSecretAndSign() {
  const seedBytes = hexToBytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  );
  const messageBytes = new TextEncoder().encode("Hello Crypto World");
  const hashedMessage = new Uint8Array(
    await crypto.subtle.digest("SHA-256", messageBytes)
  );
  const multTweak = hexToBytes(
    "efbf7ba5a074276701798376950a64a90f698997cce0dff4d24a6d2785d20963"
  );
  const addTweak = hexToBytes(
    "8be02a96a97b9a3c1c9f59ebb718401128b72ec009d85ee1656319b52319b8ce"
  );
  const seed = wasm.Seed.new(seedBytes);
  const signer = wasm.LightsparkSigner.new(seed);
  const derivationPath = "m";
  const signature = Base64.fromUint8Array(
    signer.derive_key_and_sign(
      seed,
      hashedMessage,
      derivationPath,
      addTweak,
      multTweak
    )
  );
  console.log(`Signature: ${signature}`);
  const test4Div = document.querySelector("#test4");
  test4Div.textContent = signature;
  const expected =
    "ZIp/flF8rVliQn96we+12AzWcNX2QxRN1Ma5FGv1YQVMPt9ylLfcGs0knd33jHKuOjHOD7TIkFEoKMelSi9eMA==";
  test4Div.classList.add(signature === expected ? "pass" : "fail");
  test4Div.textContent += signature === expected ? "\n(OK)" : "\n(FAIL)";
}

function hexToBytes(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return Uint8Array.from(bytes);
}

testGetMnemonicSeedPhrase();
testDeriveKeyWithDerivationPathButNoTweaks();
testSigningWithDerivedKey();
testDeriveRevocationSecretAndSign();
