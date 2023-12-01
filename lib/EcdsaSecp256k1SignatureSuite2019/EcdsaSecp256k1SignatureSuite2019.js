"use strict";
//@ts-ignore
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sha256digest = exports.concat = exports.w3cDate = exports.EcdsaSecp256k1SignatureSuite2019 = void 0;
const jsonld_signatures_1 = __importDefault(require("jsonld-signatures"));
// @ts-ignore
const jsonld_1 = __importDefault(require("jsonld"));
const constants = require("./constants");
const crypto_1 = __importDefault(require("crypto"));
const ecdsasecp256k1verificationkey2019_1 = require("@hypersign-protocol/ecdsasecp256k1verificationkey2019");
const { suites: { LinkedDataSignature }, } = jsonld_signatures_1.default;
const { purposes: { AssertionProofPurpose }, } = jsonld_signatures_1.default;
const cosmos_1 = require("@keplr-wallet/cosmos");
const crypto_2 = require("@keplr-wallet/crypto");
class EcdsaSecp256k1SignatureSuite2019 extends LinkedDataSignature {
    constructor(options) {
        super({
            type: "EcdsaSecp256k1Signature2019",
            LDKeyClass: ecdsasecp256k1verificationkey2019_1.EcdsaSecp256k1VerificationKey2019,
            date: w3cDate(options.date ? options.date : new Date()),
            key: options.key,
            proof: options.proof,
            signer: options.signer,
            verifier: options.verifier,
            verificationMethod: options.verificationMethod,
            useNativeCanonize: options.useNativeCanonize
                ? options.useNativeCanonize
                : false,
        });
        this.proofSignatureKey = "proofValue";
        this.verificationMethod = options.verificationMethod
            ? options.verificationMethod
            : this.LDKeyClass.verificationMethod;
        this._hashCache = {};
    }
    ensureSuiteContext(params) {
        return;
    }
    createProof(params) {
        return __awaiter(this, void 0, void 0, function* () {
            // build proof (currently known as `signature options` in spec)
            let proof;
            if (params.document.proof) {
                // shallow copy
                proof = Object.assign({}, params.document.proof);
            }
            else {
                // create proof JSON-LD document
                proof = {};
            }
            // ensure proof type is set
            proof.type = this.type;
            // set default `now` date if not given in `proof` or `options`
            let date = params.date;
            if (proof.created === undefined && date === undefined) {
                date = new Date();
            }
            // ensure date is in string format
            if (date && typeof date !== "string") {
                date = w3cDate(date);
            }
            // add API overrides
            if (date) {
                proof.created = date;
            }
            proof.verificationMethod = this.verificationMethod;
            // add any extensions to proof (mostly for legacy support)
            proof = yield params.purpose.update(proof, {
                document: params.document,
                suite: params.suite,
                documentLoader: params.documentLoader,
                expansionMap: params.expansionMap,
            });
            // allow purpose to update the proof; the `proof` is in the
            // SECURITY_CONTEXT_URL `@context` -- therefore the `purpose` must
            // ensure any added fields are also represented in that same `@context`
            // create data to sign
            const verifyData = yield this.createVerifyData({
                document: params.document,
                proof,
                documentLoader: params.documentLoader,
                expansionMap: params.expansionMap,
                skipExpansion: false,
            });
            // sign data
            proof[this.proofSignatureKey] = yield this.sign({
                verifyData,
                // document:params.document,
                proof,
                // documentLoader: params.documentLoader,
                // expansionMap: params.expansionMap,
            });
            return proof;
        });
    }
    canonize(input, { documentLoader, expansionMap, skipExpansion, }) {
        return __awaiter(this, void 0, void 0, function* () {
            return jsonld_1.default.canonize(input, {
                algorithm: "URDNA2015",
                format: "application/n-quads",
                documentLoader,
                skipExpansion,
                useNative: this.useNativeCanonize,
            });
        });
    }
    canonizeProof(proof, params) {
        return __awaiter(this, void 0, void 0, function* () {
            // `jws`,`signatureValue`,`proofValue` must not be included in the proof
            // options
            proof = Object.assign({ "@context": params.document["@context"] || constants.SECURITY_CONTEXT_URL }, proof);
            delete proof.jws;
            delete proof.signatureValue;
            delete proof.proofValue;
            return this.canonize(proof, {
                documentLoader: params.documentLoader,
                expansionMap: params.expansionMap,
                skipExpansion: false,
            });
        });
    }
    createVerifyData(params) {
        return __awaiter(this, void 0, void 0, function* () {
            const document = params.document;
            // get cached document hash
            let cachedDocHash;
            const { _hashCache } = this;
            if (_hashCache && _hashCache.document === document) {
                cachedDocHash = _hashCache.hash;
            }
            else {
                this._hashCache = {
                    document,
                    // canonize and hash document
                    hash: (cachedDocHash = this.canonize(document, {
                        documentLoader: params.documentLoader,
                        expansionMap: params.expansionMap,
                        skipExpansion: params.skipExpansion,
                    }).then((c14nDocument) => sha256digest(c14nDocument))),
                };
            }
            // await both c14n proof hash and c14n document hash
            const [proofHash, docHash] = yield Promise.all([
                // canonize and hash proof
                this.canonizeProof(params.proof, {
                    document,
                    documentLoader: params.documentLoader,
                    expansionMap: params.expansionMap,
                }).then((c14nProofOptions) => sha256digest(c14nProofOptions)),
                cachedDocHash,
            ]);
            // concatenate hash of c14n proof options and hash of c14n document
            return (0, exports.concat)(proofHash, docHash);
        });
    }
    prepareDoc(options) {
        const walletAddress = this.key.address;
        const message = options.verifyData;
        const signAminoDoc = (0, cosmos_1.makeADR36AminoSignDoc)(walletAddress, message);
        const serilizeDoc = (0, cosmos_1.serializeSignDoc)(signAminoDoc);
        const digestDoc = crypto_2.Hash.sha256(serilizeDoc);
        return digestDoc;
    }
    sign(options) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!(this.signer && typeof this.signer.sign === "function")) {
                throw new Error("A signer API has not been specified.");
            }
            const digestDoc = this.prepareDoc({ verifyData: options.verifyData });
            const signature = yield this.signer.sign({
                data: digestDoc,
            });
            const buffer = [...signature.r, ...signature.s];
            const signature1 = Buffer.from(buffer).toString("base64");
            return signature1;
        });
    }
    getVerificationMethod(params) {
        return __awaiter(this, void 0, void 0, function* () {
            let { verificationMethod } = params.proof;
            if (typeof verificationMethod === "object") {
                verificationMethod = verificationMethod.id;
            }
            if (!verificationMethod) {
                throw new Error('No "verificationMethod" found in proof.');
            }
            // Note: `expansionMap` is intentionally not passed; we can safely drop
            // properties here and must allow for it
            const framed = verificationMethod;
            // ensure verification method has not been revoked
            if (framed.revoked !== undefined) {
                throw new Error("The verification method has been revoked.");
            }
            return framed;
        });
    }
    verifyProof(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const verifyData = yield this.createVerifyData({
                document: options.document,
                proof: options.proof,
                documentLoader: options.documentLoader,
                expansionMap: options.expansionMap,
                skipExpansion: false,
            });
            let { verificationMethod } = options.proof;
            if (typeof verificationMethod === "object") {
                verificationMethod = verificationMethod.id;
            }
            if (!verificationMethod) {
                throw new Error('No "verificationMethod" found in proof.');
            }
            const verified = yield this.verifySignature({
                verifyData,
                verificationMethod,
                document: options.document,
                proof: options.proof,
                documentLoader: options.documentLoader,
                expansionMap: options.expansionMap,
            });
            if (!verified) {
                throw new Error("Signature verification Failed");
            }
            return {
                verified: verified,
                verificationMethod: {
                    id: options.proof.verificationMethod,
                    controller: this.key.controller,
                    publickeyMultibase: this.key.publickeyMultibase,
                    type: this.key.type,
                },
            };
        });
    }
    verifySignature(params) {
        return __awaiter(this, void 0, void 0, function* () {
            let { verifier } = this;
            if (!verifier) {
                const key = yield this.LDKeyClass.from(this.verificationMethod);
                verifier = key.verifier();
            }
            const digestDoc = this.prepareDoc({ verifyData: params.verifyData });
            const signature = new Uint8Array(Buffer.from(params.proof[this.proofSignatureKey], 'base64'));
            const result = yield verifier.verify({
                data: digestDoc,
                signature: signature
            });
            return result;
        });
    }
}
exports.EcdsaSecp256k1SignatureSuite2019 = EcdsaSecp256k1SignatureSuite2019;
function w3cDate(date) {
    let result = new Date();
    if (typeof date === "number" || typeof date === "string") {
        result = new Date(date);
    }
    const str = result.toISOString();
    return str.substr(0, str.length - 5) + "Z";
}
exports.w3cDate = w3cDate;
const concat = (b1, b2) => {
    const rval = new Uint8Array(b1.length + b2.length);
    rval.set(b1, 0);
    rval.set(b2, b1.length);
    return rval;
};
exports.concat = concat;
function sha256digest(data) {
    return __awaiter(this, void 0, void 0, function* () {
        return new Uint8Array(crypto_1.default.createHash("sha256").update(data).digest());
    });
}
exports.sha256digest = sha256digest;
