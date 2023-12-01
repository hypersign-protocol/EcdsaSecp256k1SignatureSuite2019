declare const LinkedDataSignature: any;
export declare class EcdsaSecp256k1SignatureSuite2019 extends LinkedDataSignature {
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
    });
    ensureSuiteContext(params: {
        document: any;
        addSuiteContext: any;
    }): void;
    createProof(params: {
        document: any;
        suite: EcdsaSecp256k1SignatureSuite2019;
        purpose: any;
        documentLoader: any;
        expansionMap: any;
        date: any;
    }): Promise<any>;
    canonize(input: any, { documentLoader, expansionMap, skipExpansion, }: {
        documentLoader: any;
        expansionMap: any;
        skipExpansion: boolean;
    }): Promise<any>;
    canonizeProof(proof: any, params: {
        document: any;
        documentLoader: any;
        expansionMap: any;
    }): Promise<any>;
    createVerifyData(params: {
        document: any;
        proof: any;
        documentLoader: any;
        expansionMap: any;
        skipExpansion: boolean;
    }): Promise<Uint8Array>;
    prepareDoc(options: {
        verifyData: Uint8Array;
    }): Uint8Array;
    sign(options: {
        verifyData: Uint8Array;
        proof: any;
    }): Promise<string>;
    getVerificationMethod(params: {
        proof: any;
    }): Promise<any>;
    verifyProof(options: {
        proof: any;
        document: any;
        documentLoader: any;
        expansionMap: any;
    }): Promise<{
        verified: true;
        verificationMethod: {
            id: any;
            controller: any;
            publickeyMultibase: any;
            type: any;
        };
    }>;
    verifySignature(params: {
        verifyData: Uint8Array;
        verificationMethod: any;
        document: Document;
        proof: any;
        documentLoader: any;
        expansionMap: any;
    }): Promise<boolean>;
}
export declare function w3cDate(date?: number | string): string;
export declare const concat: (b1: any, b2: any) => Uint8Array;
export declare function sha256digest(data: string): Promise<Uint8Array>;
export {};
