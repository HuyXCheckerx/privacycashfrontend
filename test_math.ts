import { x25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { Keypair } from "@stellar/stellar-sdk";

function xorBytes(a: Buffer, b: Buffer): Buffer {
  const length = Math.min(a.length, b.length);
  const result = Buffer.alloc(length);
  for (let i = 0; i < length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

const aliceEphemeral = x25519.utils.randomPrivateKey();
const aliceEphemeralPub = Buffer.from(x25519.getPublicKey(aliceEphemeral)).toString("hex");

const bobPrivate = x25519.utils.randomPrivateKey();
const bobPublic = Buffer.from(x25519.getPublicKey(bobPrivate)).toString("hex");

const sharedAlice = x25519.getSharedSecret(aliceEphemeral, bobPublic);
const hashAlice = sha256(sharedAlice);

const stealthKp = Keypair.random();
const seed = stealthKp.rawSecretKey();
const encrypted = xorBytes(Buffer.from(seed), Buffer.from(hashAlice));

const sharedBob = x25519.getSharedSecret(bobPrivate, aliceEphemeralPub);
const hashBob = sha256(sharedBob);
const decrypted = xorBytes(encrypted, Buffer.from(hashBob));

const bobStealth = Keypair.fromRawEd25519Seed(decrypted);

console.log("Original stealth:", stealthKp.publicKey());
console.log("Bob recovered:   ", bobStealth.publicKey());
console.log("Matches:", stealthKp.publicKey() === bobStealth.publicKey());
