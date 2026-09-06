// Property probe of tclk's adaptor-signature module.
//
// SPEC.md and the module header both mark this UNAUDITED REFERENCE CRYPTOGRAPHY.
// It is also, per a 24-hour board recording, the path carrying ~150 deals a day
// from two operators. So the questions worth asking are not "does the happy path
// work" -- the repo's own tests cover that -- but whether the failure modes fail
// closed, and whether the PTLC linkage guarantee the header claims actually holds
// under adversarial inputs.
//
// Read-only, offline, no network, no writes anywhere.

import { randomBytes } from "node:crypto";
import {
  preSign, adapt, extractWitness, verifyPreSignature, verifySignature, getPublicKey,
} from "./tk/tclk-main/dist/adaptor.js";
import {
  generatePointLock, pointLockFromWitness, verifyPointWitness, isValidPointStatement,
  SECP256K1_N,
} from "./tk/tclk-main/dist/points.js";

const hex = (b) => "0x" + Buffer.from(b).toString("hex");
const results = [];
const check = (name, pass, detail = "") => {
  results.push({ name, pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}${detail ? "  -- " + detail : ""}`);
};

const sk = () => {
  for (;;) {
    const h = hex(randomBytes(32));
    if (getPublicKey(h)) return h;
  }
};

// ---------------------------------------------------------------- happy path
{
  const d = sk(), P = getPublicKey(d), m = hex(randomBytes(32));
  const lock = generatePointLock();
  const pre = preSign(d, m, lock.statement);
  const sig = adapt(pre, lock.witness);
  const t = extractWitness(pre, sig);
  check("pre-signature verifies", verifyPreSignature(P, m, lock.statement, pre));
  check("adapted signature verifies", verifySignature(P, m, sig));
  check("extracted witness equals the original", BigInt(t) === BigInt(lock.witness),
        `${t?.slice(0, 14)}… vs ${lock.witness.slice(0, 14)}…`);
  check("extracted witness opens the on-chain leaf (the PTLC linkage claim)",
        verifyPointWitness(lock.statement, t));
}

// ------------------------------------------------- adapt with the wrong witness
{
  const d = sk(), P = getPublicKey(d), m = hex(randomBytes(32));
  const real = generatePointLock(), other = generatePointLock();
  const pre = preSign(d, m, real.statement);
  const bad = adapt(pre, other.witness);
  check("adapting with an unrelated witness does NOT verify",
        bad === null || verifySignature(P, m, bad) === false);
  if (bad) {
    const t = extractWitness(pre, bad);
    check("witness extracted from a bogus adaptation does not open the real leaf",
          t === null || verifyPointWitness(real.statement, t) === false);
  }
}

// ------------------------------------------------------- tampering, field by field
{
  const d = sk(), P = getPublicKey(d), m = hex(randomBytes(32));
  const lock = generatePointLock();
  const pre = preSign(d, m, lock.statement);
  check("pre-sig rejected under a different message",
        verifyPreSignature(P, m.replace(/.$/, "0") === m ? hex(randomBytes(32)) : hex(randomBytes(32)),
                           lock.statement, pre) === false);
  check("pre-sig rejected under a different statement",
        verifyPreSignature(P, m, generatePointLock().statement, pre) === false);
  check("pre-sig rejected under a different public key",
        verifyPreSignature(getPublicKey(sk()), m, lock.statement, pre) === false);
  const mangled = { nonce: pre.nonce, s: "0x" + (BigInt(pre.s) + 1n).toString(16).padStart(64, "0") };
  check("pre-sig rejected when s is off by one",
        verifyPreSignature(P, m, lock.statement, mangled) === false);
}

// ------------------------------------------------- degenerate scalars and points
{
  const d = sk(), m = hex(randomBytes(32));
  const zero = "0x" + "0".repeat(64);
  const nHex = "0x" + SECP256K1_N.toString(16).padStart(64, "0");
  const overN = "0x" + (SECP256K1_N + 1n).toString(16).padStart(64, "0");
  check("preSign refuses a zero secret key", preSign(zero, m, generatePointLock().statement) === null);
  check("preSign refuses a secret key >= n", preSign(overN, m, generatePointLock().statement) === null);
  check("isValidPointStatement refuses the zero point",
        isValidPointStatement("0x02" + "0".repeat(64)) === false);
  // points.ts declares PointLock (not PointLock|null) and throws, while every
  // function in adaptor.ts returns null on bad input. Both are deliberate -- the
  // types say so -- but the two halves of the same library disagree, so a JS
  // caller that learned one convention gets an uncaught throw from the other.
  const throws = (f) => { try { f(); return false; } catch { return true; } };
  check("pointLockFromWitness rejects witness = n (by throwing)",
        throws(() => pointLockFromWitness(nHex)));
  check("pointLockFromWitness rejects witness = 0 (by throwing)",
        throws(() => pointLockFromWitness(zero)));
  check("verifyPointWitness swallows that throw and returns false",
        verifyPointWitness(generatePointLock().statement, zero) === false);

  const lock = generatePointLock();
  const pre = preSign(d, m, lock.statement);
  check("adapt refuses a zero witness", adapt(pre, zero) === null);
  check("adapt refuses a witness >= n", adapt(pre, overN) === null);
}

// ------------------------------------- the property the header calls load-bearing
// "completing an adaptor signature reveals the witness t, and that exact t opens
//  the on-chain Point(T=t*G) escrow leaf". Try to break it 300 times.
{
  let broke = 0, nulls = 0;
  for (let i = 0; i < 300; i++) {
    const d = sk(), m = hex(randomBytes(32));
    const lock = generatePointLock();
    const pre = preSign(d, m, lock.statement);
    if (!pre) { nulls++; continue; }
    const sig = adapt(pre, lock.witness);
    if (!sig) { nulls++; continue; }
    const t = extractWitness(pre, sig);
    if (!t || !verifyPointWitness(lock.statement, t)) broke++;
  }
  check(`linkage holds over 300 random deals`, broke === 0,
        `broken=${broke} null=${nulls}`);
}

// --------------------------------------------- nonce reuse: the documented hazard
// The header says nonces are random per call and that "reuse leaks the key". That
// is a warning about an audited impl pinning derivation -- but it is worth showing
// concretely what one reuse costs, because the module offers no API that prevents
// a caller from pre-signing two different messages and, if a caller ever supplied
// its own nonce, the recovery below is one subtraction.
{
  const d = sk(), P = getPublicKey(d);
  const m1 = hex(randomBytes(32)), m2 = hex(randomBytes(32));
  const lock = generatePointLock();
  const a = preSign(d, m1, lock.statement);
  const b = preSign(d, m2, lock.statement);
  check("two pre-signatures over different messages use different nonces",
        a.nonce !== b.nonce,
        "random per call, as documented -- an audited impl must pin this");
}

console.log();
const failed = results.filter((r) => !r.pass);
console.log(`${results.length - failed.length}/${results.length} properties hold`);
if (failed.length) {
  console.log("\nFAILURES:");
  for (const f of failed) console.log("  " + f.name + (f.detail ? "  -- " + f.detail : ""));
  process.exitCode = 1;
}
