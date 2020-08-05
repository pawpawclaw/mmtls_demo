
import OpenSSL
import Foundation
import Security

typealias EC_POINT = OpaquePointer
typealias EC_KEY = OpaquePointer
typealias BN_CTX = OpaquePointer
typealias EC_GROUP = OpaquePointer
typealias BIGNUM = OpaquePointer

var NID_TYPE = NID_X9_62_prime256v1

func hex2_pubkeypoint(hexkey:String) -> EC_POINT? {
    
    let ushexkey = NSString(string: hexkey).utf8String
    let eckey:EC_KEY
    
    let ecctx:BN_CTX = BN_CTX_new()
    eckey = EC_KEY_new_by_curve_name(NID_TYPE)
    
    let ecgrp:EC_GROUP = EC_KEY_get0_group(eckey)
    
    guard let ecp = EC_POINT_hex2point(ecgrp, ushexkey , nil, ecctx) else {
        //print("hex EC public key is invalid!")
        return nil
    }
    
    EC_KEY_set_public_key(eckey, ecp)
    if (EC_KEY_check_key(eckey)==1){
        //print("hex EC public key successfully checked!")
        let ecpub:EC_POINT
        ecpub = EC_KEY_get0_public_key(eckey)
        let ecctx2:BN_CTX = BN_CTX_new()
        let ecgrp2:EC_GROUP = EC_KEY_get0_group(eckey)
        let ecphex = EC_POINT_point2hex(ecgrp2, ecpub, POINT_CONVERSION_UNCOMPRESSED, ecctx2)
        let str = String(cString: ecphex!)
        //print("Uncompressed EC Public Key:\(str)\n")
    }else{
        //print("hex EC public key is invalid!")
        return nil
    }
    
    return ecp
}

func genPrivateKey() -> String{
    let eckey:EC_KEY = EC_KEY_new_by_curve_name(NID_TYPE)
    var hexKey:String = ""
    if (EC_KEY_generate_key(eckey) == 0){
        hexKey = "00"
    }else{
        var ecprikey:BIGNUM? = BN_new()
        ecprikey = EC_KEY_get0_private_key(eckey)
        let ecphex = BN_bn2hex(ecprikey)
        hexKey = String(cString: ecphex!)
    }
    return hexKey
}

func pubkeyFromPrivateKey(privKey:String) -> String {
    let usprivkey = NSString(string: privKey).utf8String
    let eckey:EC_KEY = EC_KEY_new()
    var prk:BIGNUM? = BN_new()
    
    let ecgrp:EC_GROUP = EC_GROUP_new_by_curve_name(NID_TYPE)
    EC_KEY_set_group(eckey, ecgrp)
    
    BN_hex2bn(UnsafeMutablePointer(&prk), usprivkey)
    
    EC_KEY_set_private_key(eckey, prk)
    
    let ctx:BN_CTX = BN_CTX_new()
    
    let r:EC_POINT = EC_POINT_new(ecgrp)
    EC_POINT_mul(ecgrp, r, prk, nil, nil, ctx)
    EC_KEY_set_public_key(eckey, r)
    
    
    if (EC_KEY_check_key(eckey)==1){
        //print("EC Key is valid!")
        let ecpub:EC_POINT = EC_KEY_get0_public_key(eckey)
        let ecctx:BN_CTX = BN_CTX_new()
        let ecphex = EC_POINT_point2hex(ecgrp, ecpub, POINT_CONVERSION_UNCOMPRESSED, ecctx)
        let str = String(cString: ecphex!)
        //print("EC Public Key: \(str)\n")
        return str
    }else{
        //print("EC Key is invalid!")
        return "private key is invalid"
    }
}

func createECKey(privKey:String ) -> EC_KEY? {
    let usprivkey = NSString(string: privKey).utf8String
    let eckey:EC_KEY = EC_KEY_new()
    var prk:BIGNUM? = BN_new()
    let ecgrp:EC_GROUP = EC_GROUP_new_by_curve_name(NID_TYPE)
    EC_KEY_set_group(eckey, ecgrp)
    
    BN_hex2bn(UnsafeMutablePointer(&prk), usprivkey)
    EC_KEY_set_private_key(eckey, prk)
    
    let ctx:BN_CTX = BN_CTX_new()
    
    let r:EC_POINT = EC_POINT_new(ecgrp)
    EC_POINT_mul(ecgrp, r, prk, nil, nil, ctx)
    EC_KEY_set_public_key(eckey, r)
    
    if (EC_KEY_check_key(eckey)==1){
        //print("EC Key is valid!")
        return eckey
    }else{
        //print("EC Key is invalid!")
    }
    return nil
}

func ecdh_ds(pubkey:EC_POINT,privkey:EC_KEY ) -> String {
    var secretlen:Int32 = EC_GROUP_get_degree(EC_KEY_get0_group(privkey))
    let oSecret = UnsafeMutableRawPointer.allocate(byteCount: Int(secretlen)/8,alignment: 1)
    
    secretlen = ECDH_compute_key(oSecret, Int(secretlen)/8, pubkey, privkey, nil)
    
    var fop:String = ""
    for x in 0...Int(secretlen-1) {
        let v = oSecret.load(fromByteOffset: x, as: UInt8.self)
        var s = String(v, radix:16, uppercase: false)
        if (strlen(s)==1){
            s = "0" + s
        }
        fop += s
    }
    
    return fop
}

func print<T>(address p: UnsafeMutableRawPointer, as type: T.Type) {
    let value = p.load(as: type)
    print(value)
}
