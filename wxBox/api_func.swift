/*
        说明：
 
 
 */
import Foundation


/// 必须是限定的整数值，不可修改，如果服务器端有增加将在网站中给出提示。
enum header_types:Int {
    case CLIENT_SEND                    = 0x18f101 // 只能由客户端发送
    case SERVER_RETURN_ERR              = 0x11f101 // 服务器端提示有错误
    case SERVER_RETURN_BYTES            = 0x12f101 // 服务器发送的内容需要由客户端发送到微信
    case SERVER_RETURN_JSON             = 0x13f101 // 服务器返回的信息数据
    case SERVER_RETURN_ENCRYPTED        = 0x14f101 // 服务器返回的加密数据，加密数据解密后是以上数据
}


/// 必须是限定的整数值，不可修改，如果服务器端有增加将在网站中给出提示。
enum target_types:Int {
    case api_entry_1_0                  = 0x0e0a // 第一层的 API 服务器路由
    case api_process_1_0                = 0x010a // 第二层的 mmtls 服务
    case api_acc_1_0                    = 0x020a // 第二层的 微信账号 服务
    case api_app_1_0                    = 0x030a // 第二层的 微信应用层 服务
}

/// 必须是限定的整数值，不可修改，且该顺序不可修改，除非全部赋值，如果服务器端有增加将在网站中给出提示。
enum param_id:Int {
    case session_ticket                 = 0x01
    case psk_ticket                     = 0x02
    case session_token                  = 0x03
    case data                           = 0x04
    case action                         = 0x05
    case secondary_action               = 0x06
    case wx_user                        = 0x07
    case wx_pass                        = 0x08
    case recipient                      = 0x09
    case message                        = 0x0a
    case arlink                         = 0x0b
    case keyword                        = 0x0c
    case add_msg                        = 0x0d
    case gzh_id                         = 0x0e
    case iv                             = 0x0f
    case data_dec                       = 0x10
    case device_id                      = 0x11
    case wx_alias                       = 0x12
    case wx_aescbckey                   = 0x13
    case wx_serverid                    = 0x14
    case wx_cli_session_key             = 0x15
    case wx_svr_session_key             = 0x16
    case wx_status                      = 0x17
    case wx_nick                        = 0x18
    case api_status                     = 0x19
    case url                            = 0x1a
    case wx_xkey                        = 0x1b
    case wx_xuin                        = 0x1c
    case wx_alias2                      = 0x1d
    case wx_city                        = 0x1e
    case wx_state                       = 0x1f
    case wx_country                     = 0x20
    case wx_image0                      = 0x21
    case wx_image1                      = 0x22
    case gzh_urlname                    = 0x23
}

/// 将枚举值转换为对应字符串
func _id_to_str(_ enum_id:Int)-> String{
    
    var r = ""
    if enum_id >= 0x14f101 && enum_id <= 0x18f101{
        r = header_types.init(rawValue: enum_id).debugDescription
    }
    if enum_id >= 0x010a && enum_id <= 0x0e0a{
        r = target_types.init(rawValue: enum_id).debugDescription
    }
    if enum_id >= 0x01 && enum_id <= 0xff{
        r = param_id.init(rawValue: enum_id).debugDescription
    }
    
    let s = r.components(separatedBy: ".")[2].replacingOccurrences(of: ")", with: "")
    return s
}

/// 根据seq签名数据
func _sign_data(seq:Int,appkey:String,access_token:String,data_enc:String,secret:String,iv:String)-> String{
    var data_sign:String = ""
    switch seq {
    case 2691:
        data_sign = sha256_hash(hexStr: appkey.bytes.toHexString() + access_token + data_enc + secret + iv)
    case 2692:
        data_sign = sha256_hash(hexStr: iv + appkey.bytes.toHexString() + access_token + data_enc + secret)
    case 2693:
        data_sign = sha256_hash(hexStr: secret + iv + appkey.bytes.toHexString() + access_token + data_enc)
    case 2694:
        data_sign = sha256_hash(hexStr: data_enc + secret + iv + appkey.bytes.toHexString() + access_token)
    case 2695:
        data_sign = sha256_hash(hexStr: access_token + data_enc + secret + iv + appkey.bytes.toHexString())
    default:
        data_sign = ""
    }
    return data_sign
}

/// 将普通数据生成为api所要求的格式，最后以字节形式表示，以减少传输压力。
func _request_builder(targetType:target_types,paramId:param_id,hexData:String) -> String{
    /*  参数值与格式说明
     
        Target Types 目标类型，要提交到的api频道选择

            0x010a          api_process 1.0
            0x020a          api_acc 1.0
            0x030a          api_app 1.0

        Parameter IDs 参数编号，如有更多参数将在网站中给出提示

            0x01            session_ticket
            0x02            psk_ticket
            0x03            session_token
            0x04            packet/data

            0x05            action
            0x06            secondary_action
            0x07            wx_username
            0x08            wx_password

            0x09            recipient
            0x0a            message
            0x0b            arlink
            0x0c            keyword
            0x0d            add_msg
            0x0e            gzh_id

        数据排列示例（多个参数可以在数据后面叠加 18f101...18f101...18f101... 以此类推）
        start   target    param_id  data_size     data
     
        18f101  010a      0001      00000020      e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        18f101  010a      0002      00000020      e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
     
        问：为什么要使用这种形式，为何不使用json？
        答：因为应用的性质，大多数时候需要传递较大的数据量，因此如果使用json那么数据部分将必须使用hex或base64，这样会造成数据量的增加，因此
           我们使用字节形式，可以减少所需传输的数据量。
    */
    
    if (strlen(hexData) == 0){
        return ""
    }
    
    let seperator:header_types = .CLIENT_SEND // 固定为此，可以用作分隔符
    let targetCode = int2hex(n: targetType.rawValue, hexBytes: 2) // 数字到十六进制的转换，输出2字节
    let paramCode = int2hex(n: paramId.rawValue, hexBytes: 2) // 数字到十六进制的转换，输出2字节
    let data_length = strlen(hexData)/2 // 因为数据是十六进制形式，因此计算字节时必须除以2
    let data_lenhex = int2hex(n: data_length, hexBytes: 4) // 数字到十六进制的转换，输出4字节
    let out = int2hex(n:seperator.rawValue,hexBytes: 3) + targetCode + paramCode + data_lenhex + hexData // 组合，最后是一个十六进制的字符串
    
    // 注意：该字符串进行加密之前，必须转换为字节形式
    
    return out
    
}

func _server_dt_unpack(return_hex:String,gcmKey_hex:String) -> Dictionary<String,String> {
    var returnUnpacked:Dictionary<String,String> = [:]
    
    //var returnUnpacked:NSMutableDictionary = [:]
    if (strlen(return_hex) < 6){
        returnUnpacked = ["decode_status":"error"]
        return returnUnpacked
    }
    
    let serverheader = return_hex.substring(to: 6)
    let dt_arr = return_hex.components(separatedBy: serverheader)
    for v in dt_arr{
        if (strlen(v) > 0) {
            let from_target = Int(v.substring(to: 4),radix: 16)!
            let parameter_id = Int(v.substring(from: 4, to: 8),radix: 16)!
            let data_size = Int(v.substring(from: 8, to: 16),radix: 16)!
            var data_body:String
            if (data_size > 0){
                data_body = v.substring(from: 16, to: data_size*2+16)
            }else{
                data_body = ""
            }
            
            returnUnpacked.updateValue(_id_to_str(from_target), forKey: "from_target")
            returnUnpacked.updateValue(data_body, forKey: _id_to_str(parameter_id))
        }
    }
    
    switch Int(serverheader, radix: 16) {
        case header_types.SERVER_RETURN_BYTES.rawValue:
            returnUnpacked.updateValue("BYTES", forKey: "server_return_type")
            // 服务器以字节形式返回数据，通常数据为应用数据。

            break
        case header_types.SERVER_RETURN_ERR.rawValue:
            returnUnpacked.updateValue("ERROR", forKey: "server_return_type")
            // 服务器认为提交信息有误，未加密字符串
            
            break
        case header_types.SERVER_RETURN_JSON.rawValue:
            returnUnpacked.updateValue("JSON", forKey: "server_return_type")
            // 正常反馈，未加密的字符串
            
            break
        case header_types.SERVER_RETURN_ENCRYPTED.rawValue:
            returnUnpacked.updateValue("ENCRYPTED", forKey: "server_return_type")
            // 服务器返回的数据经过加密，因此需要客户端解密后，再将解密后数据再次 _server_dt_unpack
            let dt = returnUnpacked["data"]
            let iv = returnUnpacked["iv"]
            
            let dt_dec = aes_gcm(isEnc: false, opAAD: "", opIv: iv!, opKey: gcmKey_hex, block: dt!, tag: "")
            returnUnpacked.updateValue(dt_dec, forKey: "decrypted")
            break
        default:
            returnUnpacked.updateValue("UNEXPECTED", forKey: "server_return_type")
            // 数据可能已经经过处理，无需再次处理，可以把这个返回当作异常。
            returnUnpacked.updateValue(return_hex, forKey: "data")
    }
    return returnUnpacked
}

/// 将数据打包
func _client_dt_pack(reqestDataHex:String,appkey:String,accesstoken:String,secret:String,gcmkey:String,seq:Int) -> String{

    // 加密数据
    let iv = sha256_hash(hexStr: String(Date.currentTimeStamp)).substring(to: 24)
    let data_encrypted = aes_gcm(isEnc: true, opAAD: "", opIv: iv, opKey: gcmkey, block: reqestDataHex, tag: "")
    
    // 签名数据
    let data_sign = _sign_data(seq: seq, appkey: appkey, access_token: accesstoken, data_enc: data_encrypted, secret: secret, iv: iv)
    
    // 请求数据，下面的排列顺序不可变。
    var postData:String = ""
    postData.append("appkey=\(appkey)".bytes.toHexString())
    postData.append("&access_token=".bytes.toHexString()+accesstoken) // 已经是hex的accesstoken不可以再进行hex处理
    postData.append("&data=".bytes.toHexString()+data_encrypted) // 已经是hex的data_encrypted不可以再进行hex处理
    postData.append("&sign=".bytes.toHexString()+data_sign) // 已经是hex的data_sign不可以再进行hex处理
    postData.append("&iv=".bytes.toHexString() + iv) // 已经是hex的iv不可以再进行hex处理
    
    return postData
}
