/**
 * interop-verify — Swift cross-language PQC verifier.
 *
 * Reads all JSON vector files from VECTORS_DIR and verifies:
 *   ML-KEM:  decaps(dk, ct) == ss
 *   ML-DSA:  verify(pk, msg, sig) == true
 *   SLH-DSA: verify(pk, msg, sig) == true
 *
 * Output lines (parseable by orchestrator):
 *   RESULT:ML-KEM-512:PASS
 *   RESULT:ML-DSA-44:FAIL:verification returned false
 *
 * Usage:
 *   .build/release/interop-verify [VECTORS_DIR]
 */

import Foundation
import PQCStandards

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

func hexToBytes(_ hex: String) -> [UInt8] {
    var bytes = [UInt8]()
    var idx = hex.startIndex
    while idx < hex.endIndex {
        let nextIdx = hex.index(idx, offsetBy: 2)
        if let byte = UInt8(hex[idx..<nextIdx], radix: 16) {
            bytes.append(byte)
        }
        idx = nextIdx
    }
    return bytes
}

func bytesEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }
    return zip(a, b).allSatisfy { $0 == $1 }
}

// ---------------------------------------------------------------------------
// Parameter dispatch
// ---------------------------------------------------------------------------

let mlkemParams: [String: MlKemParams] = [
    "ML-KEM-512":  .mlKem512,
    "ML-KEM-768":  .mlKem768,
    "ML-KEM-1024": .mlKem1024,
]

let mldsaParams: [String: MlDsaParams] = [
    "ML-DSA-44": .mlDsa44,
    "ML-DSA-65": .mlDsa65,
    "ML-DSA-87": .mlDsa87,
]

let slhdsaParams: [String: SlhDsaParams] = [
    "SLH-DSA-SHAKE-128f": .shake128f,
    "SLH-DSA-SHAKE-128s": .shake128s,
    "SLH-DSA-SHAKE-192f": .shake192f,
    "SLH-DSA-SHAKE-192s": .shake192s,
    "SLH-DSA-SHAKE-256f": .shake256f,
    "SLH-DSA-SHAKE-256s": .shake256s,
]

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

let args = CommandLine.arguments
let vectorsDir: String
if args.count > 1 {
    vectorsDir = args[1]
} else {
    // Default: <repo-root>/interop/vectors
    let scriptDir = URL(fileURLWithPath: args[0]).deletingLastPathComponent().path
    vectorsDir = "\(scriptDir)/../../../interop/vectors"
}

let fm = FileManager.default
guard let files = try? fm.contentsOfDirectory(atPath: vectorsDir) else {
    fputs("ERROR: Cannot read vectors directory: \(vectorsDir)\n", stderr)
    exit(1)
}

let jsonFiles = files.filter { $0.hasSuffix(".json") }.sorted()

for filename in jsonFiles {
    let path = "\(vectorsDir)/\(filename)"
    guard let data = fm.contents(atPath: path),
          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let alg = json["algorithm"] as? String
    else { continue }

    do {
        // -----------------------------------------------------------------
        // ML-KEM: verify decaps(dk, ct) == ss
        // -----------------------------------------------------------------
        if let params = mlkemParams[alg] {
            guard let dkHex = json["dk"] as? String,
                  let ctHex = json["ct"] as? String,
                  let ssHex = json["ss"] as? String
            else {
                print("RESULT:\(alg):FAIL:missing fields")
                continue
            }
            let dk = hexToBytes(dkHex)
            let ct = hexToBytes(ctHex)
            let expectedSs = hexToBytes(ssHex)

            let ss = MlKem.decapsulate(params: params, dk: dk, ct: ct)

            if !bytesEqual(ss, expectedSs) {
                print("RESULT:\(alg):FAIL:shared secret mismatch")
            } else {
                print("RESULT:\(alg):PASS")
            }

        // -----------------------------------------------------------------
        // ML-DSA: verify(pk, msg, sig) == true
        // -----------------------------------------------------------------
        } else if let params = mldsaParams[alg] {
            guard let pkHex  = json["pk"]  as? String,
                  let msgHex = json["msg"] as? String,
                  let sigHex = json["sig"] as? String
            else {
                print("RESULT:\(alg):FAIL:missing fields")
                continue
            }
            let pk  = hexToBytes(pkHex)
            let msg = hexToBytes(msgHex)
            let sig = hexToBytes(sigHex)

            let ok = MlDsa.verify(params: params, pk: pk, message: msg, signature: sig)

            if !ok {
                print("RESULT:\(alg):FAIL:verification returned false")
            } else {
                print("RESULT:\(alg):PASS")
            }

        // -----------------------------------------------------------------
        // SLH-DSA: verify(pk, msg, sig) == true
        // -----------------------------------------------------------------
        } else if let params = slhdsaParams[alg] {
            guard let pkHex  = json["pk"]  as? String,
                  let msgHex = json["msg"] as? String,
                  let sigHex = json["sig"] as? String
            else {
                print("RESULT:\(alg):FAIL:missing fields")
                continue
            }
            let pk  = hexToBytes(pkHex)
            let msg = hexToBytes(msgHex)
            let sig = hexToBytes(sigHex)

            let ok = SlhDsa.verify(params: params, pk: pk, message: msg, signature: sig)

            if !ok {
                print("RESULT:\(alg):FAIL:verification returned false")
            } else {
                print("RESULT:\(alg):PASS")
            }

        }
        // Unknown algorithm — skip silently
    }
}
