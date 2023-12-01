//@ts-ignore

import jsigs from "jsonld-signatures";
// @ts-ignore
import jsonld from "jsonld";
const constants = require("./constants");

import crypto from "crypto";

import { EcdsaSecp256k1VerificationKey2019 } from "@hypersign-protocol/ecdsasecp256k1verificationkey2019";
const {
  suites: { LinkedDataSignature },
} = jsigs;

const {
  purposes: { AssertionProofPurpose },
} = jsigs;

import multibase from "multibase";
import { makeADR36AminoSignDoc, serializeSignDoc } from "@keplr-wallet/cosmos";
import { Hash } from "@keplr-wallet/crypto";

export class EcdsaSecp256k1SignatureSuite2019 extends LinkedDataSignature {
  signer: any;
  verifier: any;
  LDKeyClass: any;
  useNativeCanonize: any;
  canonizeOptions: any;
  verificationMethod?: string;
  type: any;
  proofSignatureKey: string;
  _hashCache: any;
  key: any;

  constructor(options: {
    key: EcdsaSecp256k1SignatureSuite2019;
    signer?: any;
    verifier?: any;
    proof?: any;
    date?: any;
    useNativeCanonize?: any;
    canonizeOptions?: any;
    verificationMethod?: string;
  }) {
    super({
      type: "EcdsaSecp256k1Signature2019",
      LDKeyClass: EcdsaSecp256k1VerificationKey2019,
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

  ensureSuiteContext(params: { document: any; addSuiteContext: any }) {
    return;
  }

  async createProof(params: {
    document: any;
    suite: EcdsaSecp256k1SignatureSuite2019;
    purpose: any;
    documentLoader: any;
    expansionMap: any;
    date: any;
  }) {
    // build proof (currently known as `signature options` in spec)
    let proof;
    if (params.document.proof) {
      // shallow copy
      proof = { ...params.document.proof };
    } else {
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
    proof = await params.purpose.update(proof, {
      document: params.document,
      suite: params.suite,
      documentLoader: params.documentLoader,
      expansionMap: params.expansionMap,
    });

    // allow purpose to update the proof; the `proof` is in the
    // SECURITY_CONTEXT_URL `@context` -- therefore the `purpose` must
    // ensure any added fields are also represented in that same `@context`

    // create data to sign
    const verifyData = await this.createVerifyData({
      document: params.document,
      proof,
      documentLoader: params.documentLoader,
      expansionMap: params.expansionMap,
      skipExpansion: false,
    });
    // sign data
    proof[this.proofSignatureKey] = await this.sign({
      verifyData,
      // document:params.document,
      proof,
      // documentLoader: params.documentLoader,
      // expansionMap: params.expansionMap,
    });

    return proof;
  }

  async canonize(
    input: any,
    {
      documentLoader,
      expansionMap,
      skipExpansion,
    }: { documentLoader: any; expansionMap: any; skipExpansion: boolean }
  ) {
    return jsonld.canonize(input, {
      algorithm: "URDNA2015",
      format: "application/n-quads",
      documentLoader,
      skipExpansion,
      useNative: this.useNativeCanonize,
    });
  }

  async canonizeProof(
    proof: any,
    params: { document: any; documentLoader: any; expansionMap: any }
  ) {
    // `jws`,`signatureValue`,`proofValue` must not be included in the proof
    // options
    proof = {
      "@context": params.document["@context"] || constants.SECURITY_CONTEXT_URL,
      ...proof,
    };
    delete proof.jws;
    delete proof.signatureValue;
    delete proof.proofValue;
    return this.canonize(proof, {
      documentLoader: params.documentLoader,
      expansionMap: params.expansionMap,
      skipExpansion: false,
    });
  }

  async createVerifyData(params: {
    document: any;
    proof: any;
    documentLoader: any;
    expansionMap: any;
    skipExpansion: boolean;
  }) {
    const document = params.document;
    // get cached document hash
    let cachedDocHash;
    const { _hashCache } = this;
    if (_hashCache && _hashCache.document === document) {
      cachedDocHash = _hashCache.hash;
    } else {
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
    const [proofHash, docHash] = await Promise.all([
      // canonize and hash proof
      this.canonizeProof(params.proof, {
        document,
        documentLoader: params.documentLoader,
        expansionMap: params.expansionMap,
      }).then((c14nProofOptions) => sha256digest(c14nProofOptions)),
      cachedDocHash,
    ]);

    // concatenate hash of c14n proof options and hash of c14n document
    return concat(proofHash, docHash);
  }


   prepareDoc(options:{verifyData:Uint8Array}){
    
    const walletAddress = this.key.address;
    const message = options.verifyData;
    
    const signAminoDoc = makeADR36AminoSignDoc(walletAddress, message);
    const serilizeDoc = serializeSignDoc(signAminoDoc);
    const digestDoc = Hash.sha256(serilizeDoc);
    return digestDoc
  }
  async sign(options: { verifyData: Uint8Array; proof: any }) {

    if (!(this.signer && typeof this.signer.sign === "function")) {
      throw new Error("A signer API has not been specified.");
    }

    const digestDoc=this.prepareDoc({verifyData:options.verifyData})
    const signature = await this.signer.sign({
      data: digestDoc,
    });
    const buffer = [...signature.r, ...signature.s];
    const signature1 = Buffer.from(buffer).toString("base64");
    return signature1;
  }

  async getVerificationMethod(params: { proof: any }) {
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
  }

  async verifyProof(options: {
    proof: any;
    document: any;
    documentLoader: any;
    expansionMap: any;
  }) {
    const verifyData = await this.createVerifyData({
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

    const verified = await this.verifySignature({
      verifyData,
      verificationMethod,
      document:options.document,
      proof:options.proof,
      documentLoader:options.documentLoader,
      expansionMap:options.expansionMap,
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
  }
  async verifySignature(params: {
    verifyData: Uint8Array;
    verificationMethod: any;
    document: Document;
    proof: any;
    documentLoader: any;
    expansionMap: any;
  }):Promise<boolean> {

    let { verifier } = this;
    if (!verifier) {
      const key = await this.LDKeyClass.from(this.verificationMethod);
      verifier = key.verifier();
    }
    
    
    const digestDoc=this.prepareDoc({verifyData:params.verifyData})

    const signature= new Uint8Array(Buffer.from(params.proof[this.proofSignatureKey],'base64'))

    const result = await verifier.verify({
      data:digestDoc,
      signature:signature
    })

    return result

  }
}

export function w3cDate(date?: number | string): string {
  let result = new Date();
  if (typeof date === "number" || typeof date === "string") {
    result = new Date(date);
  }
  const str = result.toISOString();
  return str.substr(0, str.length - 5) + "Z";
}

export const concat = (b1: any, b2: any) => {
  const rval = new Uint8Array(b1.length + b2.length);
  rval.set(b1, 0);
  rval.set(b2, b1.length);
  return rval;
};

export async function sha256digest(data: string): Promise<Uint8Array> {
  return new Uint8Array(crypto.createHash("sha256").update(data).digest());
}
