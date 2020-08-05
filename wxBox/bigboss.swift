
import Foundation
import CryptoSwift


public enum cmprDirection {
    case infl
    case defl
}

public func sha256_hash(hexStr:String) -> String{
    let str64 = Data(hex: hexStr).bytes
    return str64.sha256().toHexString()
}

public func sha256_hmac(hexStr:String,hexKey:String) -> String{
    let mhmac = HMAC(key: Array(hex:hexKey), variant: .sha256)
    let hashstring = try? mhmac.authenticate(Array(hex:hexStr))
    return hashstring!.toHexString()
}

public func int2hex(n:Int,hexBytes:Int) -> String{
    var ihex = String(n, radix: 16, uppercase: false)
    if (strlen(ihex) % 2 == 1){
        ihex = "0" + ihex
    }
    if (strlen(ihex) != hexBytes * 2){
        ihex = String(repeating: "0", count: (hexBytes * 2) - strlen(ihex)) + ihex
    }
    return ihex
}

public func xor(hex:String,n:Int)->String{
    let nhex = hex.substring(from: strlen(hex)-2)
    let ihex = Int(nhex,radix: 16)
    let ret = ihex! ^ n
    var rhex = String(ret, radix: 16, uppercase: false)
    if (strlen(rhex)==1){
        rhex = "0" + rhex
    }
    return hex.substring(to: strlen(hex)-2) + rhex
}

public func aes_cbc(isEnc:Bool,opKey:String,opIv:String,block:String) -> String{
    do{
        if (isEnc == false){
            var cipherAES:AES
            cipherAES = try AES(key: Array(hex: opKey), blockMode: CBC(iv: Array(hex: opIv)), padding: .pkcs7)
            let cipherText = try cipherAES.decrypt(Array(hex: block))
            return cipherText.toHexString()
        }else{
            var cipherText:Array<UInt8>
            let cipherAES = try AES(key: Array(hex: opKey), blockMode: CBC(iv: Array(hex: opIv)), padding: .pkcs7)
            cipherText = try cipherAES.encrypt(Array(hex: block))
            return cipherText.toHexString()
        }
    }catch{
        return "Error: (AES/CBC) Missing something or iv size is greater than 128 bit."
    }
}

public func aes_gcm(isEnc:Bool,opAAD:String,opIv:String,opKey:String,block:String,tag:String) -> String {
    do{
        if (isEnc == false){
           var cipherAES:AES
           
           let decGCM: GCM
        
            decGCM = GCM(iv: Array(hex: opIv), authenticationTag: Array(hex: tag), additionalAuthenticatedData: Array(hex: opAAD), mode: .detached)
        
           cipherAES = try AES(key: Array(hex: opKey), blockMode: decGCM, padding: .noPadding)
           
           let cipherText = try cipherAES.decrypt(Array(hex: block))//hexStringToByteArray
           
           return cipherText.toHexString() //Uint8ArrayToString
        }else{
            var cipherText:Array<UInt8>
            let encGCM = GCM(iv: Array(hex:opIv), additionalAuthenticatedData: Array(hex:opAAD), tagLength: 16, mode: .combined)
            let cipherAES = try AES(key: Array(hex: opKey), blockMode: encGCM, padding: .noPadding)
            cipherText = try cipherAES.encrypt(Array(hex: block))
            return cipherText.toHexString()
        }
       }catch{
           return "Error: (AES/GCM) Missing something or iv size is greater than 128 bit."
       }
}



func hex2str(str:String) -> String{

    var k = ""
    var kf = ""
    var chr = false
    var chrBox = "", chrCnt = 0
    var arr = [String]()
    let chunkSize = 1024
    
    if strlen(str) >= chunkSize{
        let lent = Int(ceil(Float(strlen(str)) / Float(chunkSize)))
        //print(lent)
        for x in 0...lent-1
        {
            if x != lent-1{
                let T = str.substring(from: x * chunkSize, to: (x*chunkSize)+chunkSize)
                arr.insert(T, at: x)
                //print("array_\(x):\(arr[x])")
            }else{
               // let TL = strlen(str) - (x * 8192)
                let T = str.substring(from: x * chunkSize, to: strlen(str))
                arr.insert(T, at: x)
                //print("array_\(x):\(arr[x])")
            }
        }
    }else{
        arr.insert(str, at: 0)
    }
    
    for h in arr {

        for x in 0...strlen(h)-1
        {
            // e0 - ef
            if x % 2 == 0{
                k = h.substring(from: x, to: x+2)
                if chr == false{
                    if k.substring(to: 1).lowercased() == "e"{
                        if x+6 <= strlen(h){
                            let T = h.substring(from: x, to: x+6)
                          //  print("T:\(T)")
                            chr = true
                        }
                    }
                }

                if chr == true {
                    chrCnt += 1
                    chrBox.append(k)
                    if chrCnt >= 3{
                        chrCnt = 0
                        chr = false
                       // print("chrBox:\(chrBox)")
                        if let b = chrBox.hextostring2(){
                            kf.append(b)
                        }else{
                            kf.append("......")
                        }
                        chrBox = ""
                    }
                }else{
                    if let c = k.hextostring2(){
                        kf.append(c)
                    }else{
                        kf.append(".")
                    }
                }
                //print("kkk:\(k)  k:\(k.substring(to: 1))")
                
                
            }
        }
        
    }
    
    return kf
}

func readMsg(_ msgHex:String)->String{
    if strlen(msgHex) == 0 {
        return ""
    }
    if (msgHex.substring(to: 4)=="0800"){
        if msgHex.contains("3c70757368636f6e74656e74"){
            let data_part = msgHex.substring(from: "3c70757368636f6e74656e74", stroffset: 0)
            let data_msg = data_part.substring(from: "3c70757368636f6e74656e74", stroffset: 0, to: "2f3e", stroffset2: 4)
            let msg_str = hex2str(str: data_msg)
            return msg_str
        }
    }
    return ""
}


func readMsgUrl(_ msgHex:String)->String{
    if strlen(msgHex) == 0 {
        return ""
    }
    if (msgHex.substring(to: 4)=="0800"){
        if msgHex.contains("3c75726c3e"){
            let data_part = msgHex.substring(from: "3c75726c3e", stroffset: 0)
            let data_msg = data_part.substring(from: "3c75726c3e", stroffset: 10, to: "3c2f75726c3e", stroffset2: 0)
            let msg_str = hex2str(str: data_msg).replacingOccurrences(of: "&amp;", with: "&").replacingOccurrences(of: "a3627137322d86877214ec85f04dbac1", with: "1ea0a62f9ce290e499eabc9a1f15187f")
            return msg_str
        }
    }
    return ""
}

