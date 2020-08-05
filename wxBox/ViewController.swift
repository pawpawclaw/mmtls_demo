/*
 
 
    mmtls:（这里指mmtls的ecdh密钥机制）
    用于第一次握手，握手完成后，进行 psk 握手，然后使用psk通道进行业务数据发送。
    虽然mmtls也可以发送业务数据，但是建立握手时资源消耗较大，所以应使用psk通道。
    但在建立psk握手之前必须建立mmtls握手。
 
    psk:（这里指mmtls的pre-shared密钥机制）
    支持多线程多任务同时进行，但对于每一个线程，每一个不同的任务，需要建立一个psk
    连接，如果应用较长时间不与微信进行通讯，psk通道会自动关闭，关闭后再发送数据会收到
    连接错误提示，如：["server_return_type": "ERROR"]，这时重新进行psk握手即可。
 
    临时密钥机制：
    微信的临时密钥机制用于发送系统数据或容易被利用的软件功能，如账号退出，公众号关注等，
    对与临时密钥机制我们的api也有很好的支持。在wireshark下你看到的以19f103开头的数据
    就是临时密钥机制。
 
    关于演示：
    演示代码在很多细节方面并没有做过多的处理，因此在测试时如果遇到任何连接错误，重启测试
    即可。这些错误需要开发者在开发自己的应用逻辑时再做处理，有任何问题，可以在我们的论坛
    中提问。
 
    其它编程语言的支持：
    任何编程语言都可以调用我们的api，我们也会对我们的api所支持的项目与项目内容持续更新。
 
    官网：https://www.bytls.com/
    api地址1: http://api.bytls.com/api_box.php
    api地址2: https://api.bytls.com/api_box.php
    
 */

import Cocoa
import CryptoSwift
import WebKit

protocol deleRegister:AnyObject {
    var url:String{get set}
}
enum logType {
    case START
    case CONTENT
    case END
}

let API_URL = "http://api.bytls.com/api_box.php"
var session_ticket:String = ""
var psk_ticket:String = ""
var extshort = "szextshort.weixin.qq.com"
var mmtls_host = "szlong.weixin.qq.com" //szlong.weixin.qq.com" //"58.251.111.105" //"157.255.174.105" //"116.128.133.100" //"58.251.111.105"
var mmtls_port:UInt16 = 8080

var appkey:String = "",accesstoken:String = "",secret:String = "",gcmkey:String = "",session_token:String = ""
var mmtls_svr = RunTCP(host: mmtls_host, port: mmtls_port) // mmtls 请求必须是 TCP 而且在后续微信登录时使用的连接也必须是已经建立过mmtls的连接
var psk_svr = RunTCP(host: mmtls_host, port: mmtls_port) // psk 请求必须是 TCP 而且在后续微信登录时使用的连接也必须是已经建立过psk的连接

func pskHandshake(_ log:(_ data:String,_ logtype:logType)->(),
                  _ mmtls_handshake:(_ appkey:String,_ accesstoken:String,_ secret:String,_ gcmkey:String,_ seq:Int,_ session_ticket:String,_ hexdata:String, _ psk_ticket:String)->Dictionary<String,String>?) -> Dictionary<String,String>? {
    
    psk_svr.stop()
    psk_svr = RunTCP(host: mmtls_host, port: mmtls_port)
    
    // ******** 发送 psk 初始化请求，hexdata是固定值不要修改
    log("向 api 发送初始化请求", .CONTENT)
    var dict = mmtls_handshake(appkey, accesstoken, secret,gcmkey, 2691,  session_ticket, "0000000416010300", "")
    var dt_4_psk = dict!["data"]!
    log( "api 返回 握手请求数据 ：\(dt_4_psk)",  .CONTENT)
    print("psk data:\(dt_4_psk)")
    
            // ******** 向 psk 服务器发送第一次握手请求
            log("向 psk 发送握手数据", .CONTENT)
            var dt = Data(hex:dt_4_psk)
            psk_svr.send(data: dt)
            var psk_resp = psk_svr.getData_ex()
            print("psk_resp:\(psk_resp)")
            log("psk 返回 握手数据 ：\(psk_resp)",  .CONTENT)
    
    // ******** 向 api 发送解析，返回数据中将包含 psk_ticket
    log("向 api 发送解析请求", .CONTENT)
    dict = mmtls_handshake( appkey, accesstoken, secret, gcmkey, 2691, session_ticket, psk_resp,  "")
    psk_ticket = dict!["psk_ticket"]!
    dt_4_psk = dict!["data"]!
    log( "api 返回 psk_ticket ：\(psk_ticket)", .CONTENT)
    log("api 返回 握手请求数据 ：\(dt_4_psk)", .CONTENT)
    print("psk data:\(dt_4_psk)")
            
            // ******** 向 psk 发送完成握手
            dt = Data(hex:dt_4_psk)
            psk_svr.send(data: dt)
            psk_resp = psk_svr.getData_ex()
            print("psk_resp:\(psk_resp)")
            log("psk 返回 完成握手数据 ：\(psk_resp)", .CONTENT)
            
    // ******** 向 api 发送解析请求，将收到是否成功的数据
    log("向 api 发送解析请求", .CONTENT)
    dict = mmtls_handshake( appkey, accesstoken, secret, gcmkey, 2691,  session_ticket, psk_resp, psk_ticket)
    //let tls_state = dict!["data"]!
    return dict
}


func mmtls_handshake(appkey:String,accesstoken:String,secret:String,gcmkey:String,seq:Int,session_ticket:String,hexdata:String, psk_ticket:String) -> Dictionary<String,String>?{
    // 握手数据请求
    var reqestDataHex:String = ""
    reqestDataHex.append(_request_builder(targetType: .api_process_1_0, paramId: .action, hexData: "handshake".bytes.toHexString()))
    if (strlen(session_ticket) > 0){ // 如果有的话
        reqestDataHex.append(_request_builder(targetType: .api_process_1_0, paramId: .session_ticket, hexData: session_ticket))
    }
    if (strlen(hexdata) > 0){ // 如果有的话
        reqestDataHex.append(_request_builder(targetType: .api_process_1_0, paramId: .data, hexData: hexdata))
    }
    if (strlen(psk_ticket) > 0){ // 如果有的话，当进行psk握手时，得到psk之后使用。
        reqestDataHex.append(_request_builder(targetType: .api_process_1_0, paramId: .psk_ticket, hexData: psk_ticket))
    }
    
    // 请求数据
    let postData:String = _client_dt_pack(reqestDataHex: reqestDataHex, appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: seq)

    
    // 发送数据到 api 服务器
    let request = RunTCP(http_url: API_URL, method: .POST)
    let requestBody = request.sendHTTP(hData: postData)
    
    print("requestBody:\(requestBody)")
    
    // 收到返回数据
    let dataReturn = request.getData_ex()
    
    // 返回数据处理，如果返回了握手数据，将会得到解密过后的数据
    let dict = _server_dt_unpack(return_hex: dataReturn, gcmKey_hex: gcmkey)
    print("dataReturn:\(dataReturn)")
    print("dict:\(dict)")
    if dict["server_return_type"] == "ENCRYPTED"{
        // 在所有的数据中只需要关心 decrypted 数据即可。
        let dict2 = _server_dt_unpack(return_hex: dict["decrypted"]!, gcmKey_hex: gcmkey)
        // session_ticket 这个值将会在 mmtls 握手过程中以及在之后的应用数据中用到。
        // data 这个是需要传递给 mmtls 服务器的数据。
        //let session_ticket = dict2["session_ticket"]
        //let dt_4_mmtls = dict2["data"]
        print("dict2:\(dict2)")
        
        return dict2
    }
    
    // 为了简化演示程序，这里不做更多的异常信息处理，所以遇到问题直接返回 nil
    return nil
}


class ViewController: NSViewController,deleRegister {
    
    @IBOutlet weak var tAppKey: NSTextField!
    @IBOutlet weak var tAccessToken: NSTextField!
    @IBOutlet weak var tSecret: NSTextField!
    @IBOutlet weak var tGCMKey: NSTextField!
    @IBOutlet weak var wvWebView: WKWebView!
    @IBOutlet weak var mmtlsHS: NSButton!
    @IBOutlet weak var pskHS: NSButton!
    @IBOutlet weak var wcGO: NSButton!
    
    var url:String = ""
    var htmllog:String = ""
    
    override func viewDidLoad(){
        super.viewDidLoad()
        
        // 测试时你可以将appkey access_token secret gcmkey等信息输入到这里，这样你就无需每次打开软件都要输入一遍。
        // 以下内容请输入自己在bytls.com账户中申请的应用，请勿直接使用下面的，因为不存在。
        // 请搜索所有2691这个seq数字，并替换成你自己的seq，在网页账户中可以看到。
        tAppKey.stringValue = "55500000"
        tAccessToken.stringValue = "ba363c3a631e54f8528c562fe699fccb911267d5024408893b33d660f631b246"
        tSecret.stringValue = "d9c209ae2aae808cdddc9d9dfbedacebf22a8241bbb01e0792983870add0a8e7"
        tGCMKey.stringValue = "e46877a8bd21dcaa3faa6371fb3b68ef"
        
        
        let html = "<html><body style='background-color:black;color:white; font-size:12px; margin:5px;'>ready!</body></html>"
        wvWebView.loadHTMLString(html, baseURL: nil)
        
    }
    
    private func log(data:String,logtype:logType){
        if logtype == .START{
            htmllog = ""
            htmllog.append("<html><body style='background-color:black;color:white; font-size:12px; margin:5px;'>")
            htmllog.append(data+"<br>")
        }
        if logtype == .CONTENT{
            htmllog.append(data+"<br>")
        }
        if logtype == .END{
            htmllog.append(data+"<br>")
            htmllog.append("</body></html>")
            wvWebView.loadHTMLString(htmllog, baseURL: nil)
        }
    }
    
    @IBAction func panelButtons(_ sender: NSButton) {
        if sender.title == "测试连接"{
            // appkey=0&access_token=0&data_encrypted=0x00&data_signature=0x00&iv=0
            log(data: ">>>连接测试参数", logtype: .START)
            appkey = tAppKey.stringValue
            log(data: "appkey应用编号: \(appkey)", logtype: .CONTENT)
            accesstoken = tAccessToken.stringValue
            log(data: "access_token: \(accesstoken)", logtype: .CONTENT)
            secret = tSecret.stringValue
            log(data: "secret签名密钥： \(secret)", logtype: .CONTENT)
            
            // 发送的数据请求，也是需要
            var reqestDataHex:String = ""
            reqestDataHex.append(_request_builder(targetType: .api_entry_1_0, paramId: .action, hexData: "test".bytes.toHexString()))
            
            log(data: "未加密应用数据: \(reqestDataHex)", logtype: .CONTENT)
            
            gcmkey = tGCMKey.stringValue
            log(data: "AES-GCM加密密钥（16字节128位）: \(gcmkey)", logtype: .CONTENT)
            let iv = sha256_hash(hexStr: String(Date.currentTimeStamp)).substring(to: 24)  // "acb911267d5024408893b33e" // 随机iv，必须是字节长度为12的hex（hex字符长度24）
            log(data: "iv初始化向量（必须随机，长度为12字节）: \(iv)", logtype: .CONTENT)
            let data_encrypted:String = aes_gcm(isEnc: true, opAAD: "", opIv: iv, opKey: gcmkey, block: reqestDataHex , tag: "")
            log(data: "加密数据: \(data_encrypted)", logtype: .CONTENT)
            
            // 所有参数必须是hex
            // 当seq为2691时，顺序为：appkey access_token data_encrypted secret iv
            // seq值的获取：在api账户中添加一个应用之后将会自动显示。
            let data_sign = _sign_data(seq: 2691, appkey: appkey, access_token: accesstoken, data_enc: data_encrypted, secret: secret, iv: iv)
            log(data: "数据验证签名（sha256）: \(data_sign)", logtype: .CONTENT)
            
            // 提交数据时的参数顺序排列必须按照如下所示（appkey access_token data sign iv）
            // 将参数名和值以字节形式发送时，在服务器端可能出现多余的特殊符号如&，这将造成值读取不正确，
            // 因此在服务器端进行了特别的处理，而这里提交的参数顺序必须正确，否则将出现无法预测的问题。
            var postData:String = ""
            postData.append("appkey=\(appkey)".bytes.toHexString())
            postData.append("&access_token=".bytes.toHexString()+accesstoken) // 已经是hex的accesstoken不可以再进行hex处理
            postData.append("&data=".bytes.toHexString()+data_encrypted) // 已经是hex的data_encrypted不可以再进行hex处理
            postData.append("&sign=".bytes.toHexString()+data_sign) // 已经是hex的data_sign不可以再进行hex处理
            postData.append("&iv=".bytes.toHexString() + iv) // 已经是hex的iv不可以再进行hex处理
            print("iv:\(iv)")
            
            log(data: ">>>开始测试提交数据", logtype: .CONTENT)
            let request = RunTCP(http_url: API_URL, method: .POST)
            let requestBody = request.sendHTTP(hData: postData)
            
            print("requestBody:\(requestBody)")
            
            let dataReturn = request.getData_ex()
            print("dataReturn:\(dataReturn)")
            
            let DT = _server_dt_unpack(return_hex: dataReturn, gcmKey_hex: gcmkey)
            
            log(data: "服务器返回内容：\(DT)", logtype: .CONTENT)
            log(data: ">>>测试完成", logtype: .END)
            
            mmtlsHS.isEnabled = true
            
        }else if sender.title == "mmtls 握手测试"{
            
            mmtls_svr.stop()
            mmtls_svr = RunTCP(host: mmtls_host, port: mmtls_port)
            
            log(data: ">>>mmtls 握手测试", logtype: .START)
            appkey = tAppKey.stringValue
            log(data: "appkey应用编号: \(appkey)", logtype: .CONTENT)
            accesstoken = tAccessToken.stringValue
            log(data: "access_token: \(accesstoken)", logtype: .CONTENT)
            secret = tSecret.stringValue
            log(data: "secret签名密钥： \(secret)", logtype: .CONTENT)
            gcmkey = tGCMKey.stringValue
            log(data: "AES-GCM加密密钥（16字节128位）: \(gcmkey)", logtype: .CONTENT)
            
            // mmtls 的 host 与端口
            log(data: "mmtls服务器地址与端口: \(mmtls_host):\(mmtls_port)", logtype: .CONTENT)
            
            // ******** 发送初始化请求，最后两个参数留空，服务器将返回这两个参数。
            log(data: "向 api 发送初始化请求", logtype: .CONTENT)
            var dict = mmtls_handshake(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, session_ticket: "", hexdata: "", psk_ticket: "")
            session_ticket = dict!["session_ticket"]!
            var dt_4_mmtls = dict!["data"]!
            log(data: "api 返回 session_ticket ：\(session_ticket)", logtype: .CONTENT)
            log(data: "api 返回 握手请求数据 ：\(dt_4_mmtls)", logtype: .CONTENT)
            
            print("session_ticket:\(session_ticket) data:\(dt_4_mmtls)")
            
                    // ******** 向 mmtls 服务器发送第一次握手请求
                    log(data: "向 mmtls 发送握手数据", logtype: .CONTENT)
                    
                    var dt = Data(hex:dt_4_mmtls)
                    mmtls_svr.send(data: dt)
                    var mmtls_resp = mmtls_svr.getData_ex()
                    print("mmtls_resp:\(mmtls_resp)")
                    log(data: "mmtls 返回 握手数据 ：\(mmtls_resp)", logtype: .CONTENT)
            
            // ******** 发送第二次请求，最后两个参数必须输入。
            log(data: "向 api 发送数据解析请求", logtype: .CONTENT)
            let reqpack = dt_4_mmtls + mmtls_resp // 将你发送的数据与收到的数据合并发送到 api
            dict = mmtls_handshake(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, session_ticket:session_ticket, hexdata: reqpack, psk_ticket: "")
            dt_4_mmtls = dict!["data"]! // 这次我们只关心这一个数据
            log(data: "api 返回数据:\(dt_4_mmtls)", logtype: .CONTENT)
            
                    // ******** 向 mmtls 服务器发送最后一次握手请求，并完成握手过程。
                    log(data: "向 mmtls 发送完成握手数据", logtype: .CONTENT)
                    dt = Data(hex:dt_4_mmtls)
                    mmtls_svr.send(data: dt)
                    mmtls_resp = mmtls_svr.getData_ex()
                    print("mmtls_resp:\(mmtls_resp)")
                    log(data: "mmtls 返回 数据 ：\(mmtls_resp)", logtype: .CONTENT)
            
            // ******** 向 api 发送收到的数据，看看是否握手成功。
            // 这次不需要合并数据，只发送收到的数据即可，但是session_ticket不变
            log(data: "向 api 发送数据解析请求", logtype: .CONTENT)
            dict = mmtls_handshake(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, session_ticket:session_ticket, hexdata: mmtls_resp, psk_ticket: "")
            let tls_state = dict!["data"]! // 是否成功，还是只看这个数据
            log(data: "api 返回数据:\(tls_state)", logtype: .CONTENT)
            
            print("tls_state:\(tls_state)")
            
            if tls_state.contains("01874411373f3d3992d2600e3b51c7cc"){
                log(data: ">>>mmtls 握手成功", logtype: .END)
                pskHS.isEnabled = true
            }else{
                log(data: ">>>mmtls 握手失败或 api 服务器不可用", logtype: .END)
            }
            
        }else if sender.title == "psk 握手测试"{
            print(sender.title)
            // 在进行 psk 握手前，必须已经得到 api 服务器的 session_ticket，否则必须先进行 mmtls 握手
            // psk 的作用：如果你的软件需要使用多线程来完成多个任务时，比如同时与多人聊天，阅读文章时，每一个
            // 新建的连接将使用一个psk session。
            //let bin:UInt64 = 18446744073709551615
            log(data: ">>>psk 握手测试", logtype: .START)
            appkey = tAppKey.stringValue
            log(data: "appkey应用编号: \(appkey)", logtype: .CONTENT)
            accesstoken = tAccessToken.stringValue
            log(data: "access_token: \(accesstoken)", logtype: .CONTENT)
            secret = tSecret.stringValue
            log(data: "secret签名密钥： \(secret)", logtype: .CONTENT)
            gcmkey = tGCMKey.stringValue
            log(data: "AES-GCM加密密钥（16字节128位）: \(gcmkey)", logtype: .CONTENT)
            
            // psk 的地址与 mmtls 的 host 与端口相同
            log(data: "psk服务器地址与端口: \(mmtls_host):\(mmtls_port)", logtype: .CONTENT)
            
            
            
            let dict = pskHandshake(log,mmtls_handshake)
            let tls_state = dict!["data"]!
            log(data: "api 返回数据 ：\(tls_state)", logtype: .CONTENT)
            print("psk data:\(tls_state)")
            
            if tls_state.contains("01874411373f3d3992d2600e3b51c7cc"){
                log(data: ">>>psk 握手成功", logtype: .END)
                wcGO.isEnabled = true
            }else{
                log(data: ">>>mmtls 握手失败或 api 服务器不可用", logtype: .END)
            }
            
        }else if sender.title == "登录微信"{
            print(sender.title) // 将弹出另一个窗口，它的VC类在下面 ViewController_login
        }
    }
    
    
    
    override func prepare(for segue: NSStoryboardSegue, sender: Any?) {
        if segue.destinationController is ViewController_login{
            print("login")
        }
        if segue.destinationController is ViewController_register{
            print("register")
            let vcRegister = segue.destinationController as? ViewController_register
            vcRegister?.delegate = self
            vcRegister?.url = "https://www.bytls.com/signup.html"
            
        }
    }
    
    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }

}







        class ViewController_login: NSViewController, tcpDataChecker{
            
            @IBOutlet weak var tWXUser: NSTextField!
            @IBOutlet weak var tWXPassword: NSSecureTextField!
            @IBOutlet weak var t_sendmsg: NSButton!
            @IBOutlet weak var t_wxmsg: NSTextField!
            @IBOutlet weak var t_getmsg: NSButton!
            @IBOutlet weak var t_exit:NSButton!
            @IBOutlet weak var t_gzh: NSButton!
            @IBOutlet weak var t_ar:NSButton!
            @IBOutlet weak var t_friend:NSButton!
            @IBOutlet weak var wvWebView: WKWebView!
            
            @IBOutlet weak var t_UserArGZH: NSTextField!
            @IBOutlet weak var t_WXChatMsg: NSTextField!
            
            var htmllog:String = ""
            var currentWXUser:String = ""
            var currentWXPwd:String = ""
            var currentWXDevId:Int = 1
            var recipientWX:String = ""
            
            func incomming(data:String) {
                print(">>>>>>>>> new msg : \(data)")
                
                if (data.substring(to: 6) != "17f103"){//如果返回的消息不是应用层则不进入下面的逻辑。
                    return
                }
                
                // 17f1030024
                // 17f10301ed
                let dataHead = data.substring(to: 10)
                
                let psk_resp = data
                
                if (strlen(psk_resp) > 0){
                    print("****收到网络消息，下一步可以通过读取消息来查看内容。")
                    
                    var reqestDataHex:String = ""
                    if (dataHead == "17f1030024"){
                        // 只是提示你收到了一条新的消息，没有消息内容，需要调用send_push_decode查看
                        reqestDataHex.append(_request_builder(targetType: .api_process_1_0, paramId: .session_ticket, hexData: session_ticket))
                        reqestDataHex.append(_request_builder(targetType: .api_process_1_0, paramId: .psk_ticket, hexData: psk_ticket))
                        reqestDataHex.append(_request_builder(targetType: .api_process_1_0, paramId: .data, hexData: psk_resp))
                    }else{
                        // 直接是需要进行send_push_decode的
                        reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .session_ticket, hexData: session_ticket))
                        reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .psk_ticket, hexData: psk_ticket))
                        reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .action, hexData: "send_push_decode".bytes.toHexString()))
                        reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .wx_user, hexData: currentWXUser.bytes.toHexString()))
                        reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .data, hexData: psk_resp))
                    }

                    
                    // 请求数据
                    let postData = _client_dt_pack(reqestDataHex: reqestDataHex, appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691)
                    
                    
                    // 发送数据到 api 服务器
                    let request = RunTCP(http_url: API_URL, method: .POST)
                    let requestBody = request.sendHTTP(hData: postData)
                    
                    print("requestBody:\(requestBody)")
                    
                    // 收到返回数据
                    let dataReturn = request.getData_ex()
                    print("dataReturn:\(dataReturn)")
                    
                    // 返回数据处理，如果返回了握手数据，将会得到解密过后的数据
                    let dict = _server_dt_unpack(return_hex: dataReturn, gcmKey_hex: gcmkey)
                    if dict["server_return_type"] == "ENCRYPTED"{
                        // 在所有的数据中只需要关心 decrypted 数据即可。
                        let dict2 = _server_dt_unpack(return_hex: dict["decrypted"]!, gcmKey_hex: gcmkey)
                        
                        print("dict2:\(dict2)")
                        if (dataHead == "17f1030024"){
                            //                 0000001400100001000000180000000000000002
                            // dict2:["data": "0000001400100001000000180000000000000002", "server_return_type": "BYTES", "session_ticket": "f2f49cc9eabb854cf5e1c47da0ccd6ec472fbd3004179d6988f8fcf09be558bb", "from_target": "api_process_1_0"]
                            wx_chat_getmsg_wrapper()
                            
                            //error 0000002f001000013b9aca79000001457e0ffffffff300000000ac021801000000000877049ed19f008a0100000000
                            //error 0000002f001000013b9aca79000001457e0ffffffff300000000ac021801000000000877049ed19f008a0100000000
                        }else{
                            let data_dec = readMsg(dict2["data_dec"]!)
                            print("message from remote:\(data_dec)")
                            if (strlen(data_dec)>0){
                                if data_dec.contains("[链接]") {
                                    print("------> 链接 <------\r\n\(readMsgUrl(dict2["data_dec"]!))")
                                }
                                //log(data: "<a style='font-weight:bold; color:grey;'>来自WX的消息</a>", logtype: .START)
                                //log(data: "<a style='font-weight:bold; color:grey;'>===================================================================================</a>", logtype: .CONTENT)
                                //log(data: data_dec, logtype: .END)
                            }
                        }
                    }
                    
                }else{
                    print("****未收到消息")
                }
                
            }
            
            /// 仅用于前台记录，不可以用于后台函数。
            private func log(data:String,logtype:logType){
                if logtype == .START{
                    htmllog = ""
                    htmllog.append("<html><body style='background-color:black;color:white; font-size:12px; margin:5px; width:100%;'>")
                    htmllog.append(data+"<br>")
                }
                if logtype == .CONTENT{
                    htmllog.append(data+"<br>")
                }
                if logtype == .END{
                    htmllog.append(data+"<br>")
                    htmllog.append("</body></html>")
                    wvWebView.loadHTMLString(htmllog, baseURL: nil)
                }
            }
            
            /// 这里会被后台线程调用，因此不可以使用log
            func wx_chat_getmsg(appkey:String,accesstoken:String,secret:String,gcmkey:String,seq:Int,wxuser:String,action:String,hexdata:String) -> Dictionary<String,String>?{
                
                var reqestDataHex:String = ""
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .session_ticket, hexData: session_ticket))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .psk_ticket, hexData: psk_ticket))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .action, hexData: action.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .wx_user, hexData: wxuser.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .data, hexData: hexdata))
                
                
                // 请求数据
                let postData:String = _client_dt_pack(reqestDataHex: reqestDataHex, appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: seq)

                // 发送数据到 api 服务器
                let request = RunTCP(http_url: API_URL, method: .POST)
                let requestBody = request.sendHTTP(hData: postData)
                
                print("requestBody:\(requestBody)")
                
                // 收到返回数据
                let dataReturn = request.getData_ex()
                print("dataReturn:\(dataReturn)")
                
                // 返回数据处理，如果返回了握手数据，将会得到解密过后的数据
                let dict = _server_dt_unpack(return_hex: dataReturn, gcmKey_hex: gcmkey)
                if dict["server_return_type"] == "ENCRYPTED"{
                    // 在所有的数据中只需要关心 decrypted 数据即可。
                    let dict2 = _server_dt_unpack(return_hex: dict["decrypted"]!, gcmKey_hex: gcmkey)
                    
                    print("dict2:\(dict2)")
                    
                    if var data_dec = dict2["data_dec"]{
                        data_dec = readMsg(data_dec)
                        print("message from remote:\(data_dec)")
                        if (strlen(data_dec)>0){
                            if data_dec.contains("[链接]") {
                                print("------> 链接 <------\r\n\(readMsgUrl(dict2["data_dec"]!))")
                            }
                            //log(data: "<a style='font-weight:bold; color:grey;'>来自WX的消息</a>", logtype: .START)
                            //log(data: "<a style='font-weight:bold; color:grey;'>===================================================================================</a>", logtype: .CONTENT)
                            //log(data: data_dec, logtype: .END)
                        }
                    }
                    
                    return dict2
                }
                
                // 为了简化演示程序，这里不做更多的异常信息处理，所以遇到问题直接返回 nil
                return nil
                
            }
            
            /// 添加微信好友步骤：先进行手机号搜索，找到后再进行好友添加申请，如果对方开启了验证，则发送验证消息。剩下的就是等对方通过了。（整个过程都需要发送对方的账号信息 -- 手机号）
            func wx_addstranger(appkey:String,accesstoken:String,secret:String,gcmkey:String,seq:Int,wxuser:String,action:String,wxPhoneNo:String,sayHello:String,hexdata:String) -> Dictionary<String,String>?{
                
                var reqestDataHex:String = ""
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .session_ticket, hexData: session_ticket))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .psk_ticket, hexData: psk_ticket))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .action, hexData: action.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .keyword, hexData: wxPhoneNo.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .wx_user, hexData: wxuser.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .add_msg, hexData: sayHello.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .data, hexData: hexdata))
                
                
                // 请求数据
                let postData:String = _client_dt_pack(reqestDataHex: reqestDataHex, appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: seq)
                
                
                // 发送数据到 api 服务器
                let request = RunTCP(http_url: API_URL, method: .POST)
                let requestBody = request.sendHTTP(hData: postData)
                
                print("requestBody:\(requestBody)")
                
                // 收到返回数据
                let dataReturn = request.getData_ex()
                print("dataReturn:\(dataReturn)")
                
                // 返回数据处理，如果返回了握手数据，将会得到解密过后的数据
                let dict = _server_dt_unpack(return_hex: dataReturn, gcmKey_hex: gcmkey)
                if dict["server_return_type"] == "ENCRYPTED"{
                    // 在所有的数据中只需要关心 decrypted 数据即可。
                    let dict2 = _server_dt_unpack(return_hex: dict["decrypted"]!, gcmKey_hex: gcmkey)
                    
                    print("dict2:\(dict2)")
                    
                    return dict2
                }
                
                return nil
            }
            
            /// 添加微信公众号（整个过程都需要有公众号编号）
            func wx_gzh(appkey:String,accesstoken:String,secret:String,gcmkey:String,seq:Int,wxuser:String,action:String,gzh_id:String,hexdata:String) -> Dictionary<String,String>?{

                 var reqestDataHex:String = ""
                 reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .session_ticket, hexData: session_ticket))
                 reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .psk_ticket, hexData: psk_ticket))
                 reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .action, hexData: action.bytes.toHexString()))
                 reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .gzh_id, hexData: gzh_id.bytes.toHexString()))
                 reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .wx_user, hexData: wxuser.bytes.toHexString()))
                 reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .data, hexData: hexdata))
                 
                 // 请求数据
                 let postData:String = _client_dt_pack(reqestDataHex: reqestDataHex, appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: seq)

                 
                 // 发送数据到 api 服务器
                 let request = RunTCP(http_url: API_URL, method: .POST)
                 let requestBody = request.sendHTTP(hData: postData)
                 
                 print("requestBody:\(requestBody)")
                 
                 // 收到返回数据
                 let dataReturn = request.getData_ex()
                 print("dataReturn:\(dataReturn)")
                 
                 // 返回数据处理，如果返回了握手数据，将会得到解密过后的数据
                 let dict = _server_dt_unpack(return_hex: dataReturn, gcmKey_hex: gcmkey)
                 if dict["server_return_type"] == "ENCRYPTED"{
                     // 在所有的数据中只需要关心 decrypted 数据即可。
                     let dict2 = _server_dt_unpack(return_hex: dict["decrypted"]!, gcmKey_hex: gcmkey)
                     
                     print("dict2:\(dict2)")
                     
                     return dict2
                 }
                 
                 // 为了简化演示程序，这里不做更多的异常信息处理，所以遇到问题直接返回 nil
                 return nil
                
            }
            
            
            func wx_logout(appkey:String,accesstoken:String,secret:String,gcmkey:String,seq:Int,wxuser:String,action:String,hexdata:String) -> Dictionary<String,String>?{
                
                var reqestDataHex:String = ""
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .session_ticket, hexData: session_ticket))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .psk_ticket, hexData: psk_ticket))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .action, hexData: action.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .wx_user, hexData: wxuser.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .data, hexData: hexdata))
                
                // 请求数据
                let postData:String = _client_dt_pack(reqestDataHex: reqestDataHex, appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: seq)

                
                // 发送数据到 api 服务器
                let request = RunTCP(http_url: API_URL, method: .POST)
                let requestBody = request.sendHTTP(hData: postData)
                
                print("requestBody:\(requestBody)")
                
                // 收到返回数据
                let dataReturn = request.getData_ex()
                print("dataReturn:\(dataReturn)")
                
                // 返回数据处理，如果返回了握手数据，将会得到解密过后的数据
                let dict = _server_dt_unpack(return_hex: dataReturn, gcmKey_hex: gcmkey)
                if dict["server_return_type"] == "ENCRYPTED"{
                    // 在所有的数据中只需要关心 decrypted 数据即可。
                    let dict2 = _server_dt_unpack(return_hex: dict["decrypted"]!, gcmKey_hex: gcmkey)
                    
                    print("dict2:\(dict2)")
                    
                    return dict2
                }
                
                // 为了简化演示程序，这里不做更多的异常信息处理，所以遇到问题直接返回 nil
                return nil
            }
            
            func wx_read(appkey:String,accesstoken:String,secret:String,gcmkey:String,seq:Int,wxuser:String,action:String,arlink:String,hexdata:String) -> Dictionary<String,String>?{
             
                var reqestDataHex:String = ""
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .session_ticket, hexData: session_ticket))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .psk_ticket, hexData: psk_ticket))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .action, hexData: action.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .arlink, hexData: arlink.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .wx_user, hexData: wxuser.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .data, hexData: hexdata))
                
                // 请求数据
                let postData:String = _client_dt_pack(reqestDataHex: reqestDataHex, appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: seq)

                
                // 发送数据到 api 服务器
                let request = RunTCP(http_url: API_URL, method: .POST)
                let requestBody = request.sendHTTP(hData: postData)
                
                print("requestBody:\(requestBody)")
                
                // 收到返回数据
                let dataReturn = request.getData_ex()
                print("dataReturn:\(dataReturn)")
                
                // 返回数据处理，如果返回了握手数据，将会得到解密过后的数据
                let dict = _server_dt_unpack(return_hex: dataReturn, gcmKey_hex: gcmkey)
                if dict["server_return_type"] == "ENCRYPTED"{
                    // 在所有的数据中只需要关心 decrypted 数据即可。
                    let dict2 = _server_dt_unpack(return_hex: dict["decrypted"]!, gcmKey_hex: gcmkey)
                    
                    print("dict2:\(dict2)")
                    
                    return dict2
                }
                
                // 为了简化演示程序，这里不做更多的异常信息处理，所以遇到问题直接返回 nil
                return nil
            }
            
            func wx_chat(appkey:String,accesstoken:String,secret:String,gcmkey:String,seq:Int,wxuser:String,action:String,recipient:String,msg:String,hexdata:String) -> Dictionary<String,String>?{
                var reqestDataHex:String = ""
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .session_ticket, hexData: session_ticket))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .psk_ticket, hexData: psk_ticket))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .action, hexData: action.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .recipient, hexData: recipient.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .message, hexData: msg.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .wx_user, hexData: wxuser.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_app_1_0, paramId: .data, hexData: hexdata))
                
                // 请求数据
                let postData:String = _client_dt_pack(reqestDataHex: reqestDataHex, appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: seq)

                
                // 发送数据到 api 服务器
                let request = RunTCP(http_url: API_URL, method: .POST)
                let requestBody = request.sendHTTP(hData: postData)
                
                print("requestBody:\(requestBody)")
                
                // 收到返回数据
                let dataReturn = request.getData_ex()
                print("dataReturn:\(dataReturn)")
                
                // 返回数据处理，如果返回了握手数据，将会得到解密过后的数据
                let dict = _server_dt_unpack(return_hex: dataReturn, gcmKey_hex: gcmkey)
                if dict["server_return_type"] == "ENCRYPTED"{
                    // 在所有的数据中只需要关心 decrypted 数据即可。
                    let dict2 = _server_dt_unpack(return_hex: dict["decrypted"]!, gcmKey_hex: gcmkey)
                    
                    print("dict2:\(dict2)")
                    
                    return dict2
                }
                
                // 为了简化演示程序，这里不做更多的异常信息处理，所以遇到问题直接返回 nil
                return nil
                
            }
            
            func wx_login(appkey:String,accesstoken:String,secret:String,gcmkey:String,seq:Int,deviceId:Int,wxuser:String,wxpwd:String,action:String,secondaryAction:String,hexdata:String) -> Dictionary<String,String>?{
                // 登录之前必须已经握手成功（可以不进行psk握手），并且已经得到session_ticket（如果psk握手也必须有psk_ticket）
                var reqestDataHex:String = ""
                reqestDataHex.append(_request_builder(targetType: .api_acc_1_0, paramId: .session_ticket, hexData: session_ticket))
                reqestDataHex.append(_request_builder(targetType: .api_acc_1_0, paramId: .psk_ticket, hexData: psk_ticket))
                reqestDataHex.append(_request_builder(targetType: .api_acc_1_0, paramId: .session_token, hexData: session_token))
                reqestDataHex.append(_request_builder(targetType: .api_acc_1_0, paramId: .data, hexData: hexdata))
                reqestDataHex.append(_request_builder(targetType: .api_acc_1_0, paramId: .action, hexData: action.bytes.toHexString())) // mix
                reqestDataHex.append(_request_builder(targetType: .api_acc_1_0, paramId: .device_id, hexData: String(deviceId).bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_acc_1_0, paramId: .secondary_action, hexData: secondaryAction.bytes.toHexString()))// "create_login"
                reqestDataHex.append(_request_builder(targetType: .api_acc_1_0, paramId: .wx_user, hexData: wxuser.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_acc_1_0, paramId: .wx_pass, hexData: wxpwd.bytes.toHexString()))
                
                                
                // 请求数据
                let postData:String = _client_dt_pack(reqestDataHex: reqestDataHex, appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: seq)

                // 发送数据到 api 服务器
                let request = RunTCP(http_url: API_URL, method: .POST)
                let requestBody = request.sendHTTP(hData: postData)
                
                print("requestBody:\(requestBody)")
                
                // 收到返回数据
                let dataReturn = request.getData_ex()
                print("dataReturn:\(dataReturn)")
                
                // 返回数据处理，如果返回了握手数据，将会得到解密过后的数据
                let dict = _server_dt_unpack(return_hex: dataReturn, gcmKey_hex: gcmkey)
                
                print("dict:\(dict)")
                if dict["server_return_type"] == "ENCRYPTED"{
                    // 在所有的数据中只需要关心 decrypted 数据即可。
                    let dict2 = _server_dt_unpack(return_hex: dict["decrypted"]!, gcmKey_hex: gcmkey)
                    
                    print("dict2:\(dict2)")
                    
                    return dict2
                }
                
                // 为了简化演示程序，这里不做更多的异常信息处理，所以遇到问题直接返回 nil
                return nil
            }
            
            func wx_resume(appkey:String,accesstoken:String,secret:String,gcmkey:String,seq:Int,deviceId:Int,wxuser:String,wxpass:String,action:String) -> Dictionary<String,String>?{
                var reqestDataHex:String = ""
                reqestDataHex.append(_request_builder(targetType: .api_acc_1_0, paramId: .session_ticket, hexData: session_ticket))
                reqestDataHex.append(_request_builder(targetType: .api_acc_1_0, paramId: .psk_ticket, hexData: psk_ticket))
                reqestDataHex.append(_request_builder(targetType: .api_acc_1_0, paramId: .device_id, hexData: String(deviceId).bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_acc_1_0, paramId: .action, hexData: action.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_acc_1_0, paramId: .wx_user, hexData: wxuser.bytes.toHexString()))
                reqestDataHex.append(_request_builder(targetType: .api_acc_1_0, paramId: .wx_pass, hexData: wxpass.bytes.toHexString()))
                
                // 请求数据
                let postData:String = _client_dt_pack(reqestDataHex: reqestDataHex, appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: seq)

                
                // 发送数据到 api 服务器
                let request = RunTCP(http_url: API_URL, method: .POST)
                let requestBody = request.sendHTTP(hData: postData)
                
                print("requestBody:\(requestBody)")
                
                // 收到返回数据
                let dataReturn = request.getData_ex()
                print("dataReturn:\(dataReturn)")
                
                // 返回数据处理，如果返回了握手数据，将会得到解密过后的数据
                let dict = _server_dt_unpack(return_hex: dataReturn, gcmKey_hex: gcmkey)
                
                print("dict:\(dict)")
                if dict["server_return_type"] == "ENCRYPTED"{
                    // 在所有的数据中只需要关心 decrypted 数据即可。
                    let dict2 = _server_dt_unpack(return_hex: dict["decrypted"]!, gcmKey_hex: gcmkey)
                    
                    print("dict2:\(dict2)")
                    
                    return dict2
                }
                
                return nil
            }
            
            @IBAction func btnWCLogin(_ sender: NSButton) {
                
                // 简单的开关，根据微信账号的不同，设置不同的登录地址与端口。你自己的程序应该根据api返回判断是否应该切换地址。
                // 你自己的数据库中应该有保存登录地址的字段，目前api服务器中不保存该值。
                var k = 0
                
                if (k == 1){
                    // 有些账号必须使用extshort和long域名
                    extshort = "extshort.weixin.qq.com"
                    mmtls_host = "long.weixin.qq.com" //szlong.weixin.qq.com" //"58.251.111.105" //"157.255.174.105" //"116.128.133.100" //"58.251.111.105"
                    mmtls_port = 443
                    currentWXUser = tWXUser.stringValue //微信账号
                    currentWXPwd = tWXPassword.stringValue //微信密码
                    currentWXDevId = 200410 //这里必须输入你在api管理页面生成的设备编号
                }else{
                    // 有些账号则必须使用szextshort和szlong域名
                    extshort = "szextshort.weixin.qq.com"
                    mmtls_host = "szlong.weixin.qq.com" //szlong.weixin.qq.com" //"58.251.111.105" //"157.255.174.105" //"116.128.133.100" //"58.251.111.105"
                    mmtls_port = 8080
                    currentWXUser = tWXUser.stringValue //微信账号
                    currentWXPwd = tWXPassword.stringValue //微信密码
                    currentWXDevId = 1 //这里必须输入你在api管理页面生成的设备编号
                }

                print("session:\(session_ticket)")
                
                // 因为szlong和long两个地址的切换是在加载此对话框之后才有效的，因此在这里
                // 再进行一次psk连接，在你的应用程序中可以通过逻辑设计避开这种重复。
                print("重新建立 psk")
                log(data: ">>>psk 握手", logtype: .START)
                let dict = pskHandshake(log,mmtls_handshake)
                let tls_state = dict!["data"]!
                psk_svr.tcp_data_delegate = self // 重建psk也必须同步建立delegate
                log(data: "api 返回数据 ：\(tls_state)", logtype: .CONTENT)
                print("psk握手数据:\(tls_state)")
                
                
                // ******** 查看是否曾经登录过，如果登录过就使用以前的信息
                var is_LoggedIn = false
                let dict0 = wx_resume(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691,deviceId: currentWXDevId, wxuser: currentWXUser,wxpass: currentWXPwd, action: "read")
                if let wx_status = dict0!["wx_status"]{
                    if wx_status == "73756363657373"{
                        is_LoggedIn = true
                        // ******* 这里需要更新api账户中该微信号的握手信息
                        let dict1 = wx_resume(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691,deviceId: currentWXDevId,wxuser: currentWXUser,wxpass: currentWXPwd, action: "mix")
                        if let update_ret_dt = dict1!["data"]{
                            if (update_ret_dt == "73756363657373"){
                                print("微信已登录，信息更新完成，检测登录是否有效...")
                                psk_svr.isLoginComplete = true // 开启消息推送
                                t_sendmsg.isEnabled = true
                                t_getmsg.isEnabled = true
                                t_exit.isEnabled = true
                                t_ar.isEnabled = true
                                t_gzh.isEnabled = true
                                t_friend.isEnabled = true
                                
                                if wx_chat_getmsg_wrapper() == true {
                                    print("微信登录有效。")
                                    psk_svr.isLoginComplete = true // 开启消息推送
                                    t_sendmsg.isEnabled = true
                                    t_getmsg.isEnabled = true
                                    t_exit.isEnabled = true
                                    t_ar.isEnabled = true
                                    t_gzh.isEnabled = true
                                    t_friend.isEnabled = true
                                }else{
                                    print("微信登录过期。")
                                    is_LoggedIn = false
                                }
                            }
                        }
                    }
                }
            
                
                if (is_LoggedIn == false){
                    print("开始全新登录，先重新建立 psk")
                    log(data: ">>>psk 握手", logtype: .START)
                    let dict = pskHandshake(log,mmtls_handshake)
                    let tls_state = dict!["data"]!
                    psk_svr.tcp_data_delegate = self // 重建psk也必须同步建立delegate
                    log(data: "api 返回数据 ：\(tls_state)", logtype: .CONTENT)
                    print("psk握手数据:\(tls_state)")
                    
                    
                    if tls_state.contains("01874411373f3d3992d2600e3b51c7cc"){
                        log(data: ">>>psk 握手成功", logtype: .END)
                        print("psk握手成功")
                        
                        // ******** 进行全新登录
                        let dict = wx_login(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, deviceId: currentWXDevId, wxuser: currentWXUser, wxpwd: currentWXPwd, action: "mix", secondaryAction: "create_login",hexdata: "")
                        session_token = dict!["session_token"]!
                        let loginData = dict!["data"]!
                        
                        
                        // wechat
                        let dt = Data(hex:loginData)
                        psk_svr.send(data: dt)
                        let psk_resp = psk_svr.getData_ex()
                        print("psk返回数据：\(psk_resp)")
                        
                        
                        let dict2 = wx_login(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, deviceId: currentWXDevId, wxuser: currentWXUser, wxpwd: currentWXPwd, action: "secondary", secondaryAction: "process_login_data",hexdata: psk_resp)
                        
                        if let api_status = dict2!["api_status"]{
                            if (api_status == "73756363657373"){
                                print("登录成功，你可以选择在此进行登录状态检测。")
                                
                                 /*
                                // 通常在登录成功之后，推荐重新建立新的psk握手连接用于业务数据收发。
                                // 在任何时候，如果api返回了无法解密消息，重新建立psk握手并更新到
                                // 用户账号下即可，步骤如下：
                                print("重新建立 psk")
                                log(data: ">>>psk 握手", logtype: .START)
                                let dict = pskHandshake(log,mmtls_handshake)
                                let tls_state = dict!["data"]!
                                psk_svr.tcp_data_delegate = self // 重建psk也必须同步建立delegate
                                log(data: "api 返回数据 ：\(tls_state)", logtype: .CONTENT)
                                print("psk握手数据:\(tls_state)")
                                // 将psk状态更新到账号：（注意secondaryAction必须留空）
                                _ = wx_login(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, deviceId: currentWXDevId, wxuser: currentWXUser, wxpwd: currentWXPwd, action: "mix", secondaryAction: "",hexdata: "")
                                */
                                
                                psk_svr.isLoginComplete = true // 开启消息推送
                                t_sendmsg.isEnabled = true
                                t_getmsg.isEnabled = true
                                t_exit.isEnabled = true
                                t_ar.isEnabled = true
                                t_gzh.isEnabled = true
                                t_friend.isEnabled = true
                                /*
                                if wx_chat_getmsg_wrapper() == true {
                                    print("微信登录有效。")
                                    psk_svr.isLoginComplete = true // 开启消息推送
                                    t_sendmsg.isEnabled = true
                                    t_getmsg.isEnabled = true
                                    t_exit.isEnabled = true
                                }
 */
                            }else if (api_status == "6368616e67655f7763636970"){
                                print("需要更换HOST地址，该账号不可以通过\(mmtls_host)登录。")
                            }
                        }else if let wx_status = dict2!["wx_status"]{
                            if (wx_status == "6364617461"){
                                print(dict2!["message"]!)
                            }
                        }

                        
                        
                    }else{
                        log(data: ">>>mmtls 握手失败或 api 服务器不可用", logtype: .END)
                    }
                    
                    
                }
                
            }
            
            
            @IBAction func buttonGroup(_ sender: NSButton) {
                
                
                if sender.title == "向微信好友或群发送消息"{
                    let newMsg = t_wxmsg.stringValue
                    recipientWX = t_UserArGZH.stringValue
                    print("发送消息：\(newMsg)")
                    
                    log(data: "发送消息：\(newMsg)", logtype: .START)
                    log(data: "<a style='font-weight:bold; color:grey;'>===================================================================================</a>", logtype: .CONTENT)
                    
                    let dict = wx_chat(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, wxuser: currentWXUser, action: "send_msg", recipient: recipientWX, msg: newMsg, hexdata: "")
                    
                    if let chat_data = dict!["data"]{
                        
                        
                        // wechat
                        var dt = Data(hex:chat_data)
                        psk_svr.send(data: dt)
                        var psk_resp = psk_svr.getData_ex()
                        print("psk_resp:\(psk_resp)")
                        
                        
                        let dict1 = wx_chat(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, wxuser: currentWXUser, action: "send_msg_decode", recipient: "", msg: "", hexdata: psk_resp)
                        if let chat_ret = dict1!["data_dec"]{
                            if chat_ret.contains(recipientWX.bytes.toHexString()){
                                if chat_ret.contains("ffffff"){
                                    print("消息已发送，但对方未收到。")
                                    log(data: "<a style='font-weight:bold; color:grey;'>消息已发送，但对方未收到。</a>", logtype: .CONTENT)
                                }else{
                                    print("消息已发送，对方已收到。")
                                    log(data: "<a style='font-weight:bold; color:grey;'>消息已发送，对方已收到。</a>", logtype: .CONTENT)
                                }
                            }else{
                                print("消息发送失败")
                                log(data: "<a style='font-weight:bold; color:grey;'>消息发送失败</a>", logtype: .CONTENT)
                            }
                        }
                    }
                    
                    log(data: "", logtype: .END)
                    
                }else if sender.title == "读取微信收到的消息" {
                    
                    log(data: "读取微信收到的消息", logtype: .START)
                    log(data: "<a style='font-weight:bold; color:grey;'>===================================================================================</a>", logtype: .CONTENT)
                    
                    _ = wx_chat_getmsg_wrapper()
                    
                    log(data: "<a style='font-weight:bold; color:grey;'>该内容只在debug输出框内显示。</a>", logtype: .END)
                    
                }else if sender.title == "添加微信好友" {
                    
                    // 下面默认使用手机号添加好友，所以第一步会验证stranger的长度必须是11，但也可以使用用户名，将==11改成>=6即可
                    // 添加好友的逻辑略微复杂，为了简化演示，省去了很多验证逻辑步骤，下面的逻辑假设手机用户是存在的。
                    let stranger = t_UserArGZH.stringValue
                    
                    log(data: "添加微信好友：\(stranger)", logtype: .START)
                    log(data: "<a style='font-weight:bold; color:grey;'>===================================================================================</a>", logtype: .CONTENT)
                    // kuangren
                    if strlen(stranger) == 11 {
                        // 准备搜索手机好友的数据
                        let dict = wx_addstranger(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, wxuser: currentWXUser, action: "send_search_user", wxPhoneNo: stranger, sayHello: "", hexdata: "")
                        
                        if let search_data = dict!["data"]{
                            
                            // 发送给 wechat
                            let dt = Data(hex:search_data)
                            psk_svr.send(data: dt)
                            let psk_resp = psk_svr.getData_ex()
                            print("psk_resp:\(psk_resp)")
                            
                            
                            if psk_resp != "" {
                                   // 看一下返回的数据
                                   let dict = wx_addstranger(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, wxuser: currentWXUser, action: "send_search_user_decode", wxPhoneNo: stranger, sayHello: "", hexdata: psk_resp)
                                
                                if dict!["wx_alias"] != nil{ // 有此信息说明正确
                                        // 开始准备添加好友请求
                                        let dict = wx_addstranger(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, wxuser: currentWXUser, action: "send_add_request", wxPhoneNo: stranger, sayHello: "", hexdata: "")
                                    
                                    
                                    //return
                                    if var addurl = dict!["gzh_urlname"]{
                                        addurl = "http://\(extshort)/mmtls/" + addurl
                                        
                                        // 发送请求数据
                                        let http_mmtls = RunTCP(http_url:addurl, method: .POST)
                                        _ = http_mmtls.sendHTTP(f19Data: dict!["data"]!)
                                        let svr_resp = http_mmtls.getData()
                                        print("svr_resp:\(svr_resp)")

                                        // 看下返回数据
                                        let dict = wx_addstranger(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, wxuser: currentWXUser, action: "send_add_request_decode", wxPhoneNo: stranger, sayHello: "您好", hexdata: svr_resp)
                                        
                                        // 如果收到这个消息，说明已经添加完成
                                        if let wx_status = dict!["wx_status"]{
                                            if strlen(wx_status) > 0 {
                                                print("api_status:\(hex2str(str: dict!["api_status"]!))")
                                                print("wx_status:\(hex2str(str: wx_status))")
                                            }
                                        }
                                        
                                        // 如果没有添加将会执行这里
                                        if let r_data = dict!["data"]{
                                            // 如果数据中包含19f103，说明对方需要验证，在数据中包含了验证信息，将该数据发送至下面地址
                                            if r_data.contains("19f103"){
                                                addurl = dict!["gzh_urlname"]!
                                                addurl = "http://\(extshort)/mmtls/" + addurl
                                                

                                                let http_mmtls = RunTCP(http_url:addurl, method: .POST)
                                                _ = http_mmtls.sendHTTP(f19Data: dict!["data"]!)
                                                let svr_resp = http_mmtls.getData()
                                                print("19f1_http_return2:\(svr_resp)")

                                                
                                                // 看下返回数据是否正确
                                                let dict = wx_addstranger(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, wxuser: currentWXUser, action: "send_add_request_decode", wxPhoneNo: stranger, sayHello: "", hexdata: svr_resp)
                                                
                                                if let wx_status = dict!["wx_status"]{
                                                    if strlen(wx_status) > 0 {
                                                        // 这里提示好友申请是否成功
                                                        print("api_status:\(hex2str(str: dict!["api_status"]!))")
                                                        print("wx_status:\(hex2str(str: wx_status))")
                                                    }
                                                }
                                            }
                                        }
                                        
                                    }
                                    
                                        
                                }
            
                            }
                            
                            
                        }
                        
                    }
                    
                    
                    
                    
                }else if sender.title == "关注微信公众号" {
                    
                    let gzh = t_UserArGZH.stringValue
                    
                    log(data: "关注微信公众号：\(gzh)", logtype: .START)
                    log(data: "<a style='font-weight:bold; color:grey;'>===================================================================================</a>", logtype: .CONTENT)
                    
                    if (gzh.contains("gh_") || gzh.contains("wxid_")){
                        // 添加公众号返回的信息需要通过http发送，而不是tcp
                        let dict = wx_gzh(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, wxuser: currentWXUser, action: "send_add_gzh", gzh_id: gzh, hexdata: "")
                        
                        if let gzh_data = dict!["data"]{
                            if let gzh_urlname = dict!["gzh_urlname"]{
                                let gzh_url = "http://\(extshort)/mmtls/" + gzh_urlname
                                log(data: gzh_url, logtype: .CONTENT)
                                
                                let http_mmtls = RunTCP(http_url:gzh_url, method: .POST)
                                _ = http_mmtls.sendHTTP(f19Data: gzh_data)
                                let svr_resp = http_mmtls.getData()
                                print("svr_resp:\(svr_resp)")

                                let dict1 = wx_gzh(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, wxuser: currentWXUser, action: "send_add_gzh_decode", gzh_id: gzh, hexdata: svr_resp)
                                
                                if let api_status = dict1!["api_status"]{
                                    print("添加公众号_API状态:\(hex2str(str: api_status))")
                                    log(data: "添加公众号_API状态:\(hex2str(str: api_status))", logtype: .CONTENT)
                                }
                                if let wx_status = dict1!["wx_status"]{
                                    if (wx_status == ""){
                                        print("添加公众号_微信反馈结果:已经添加")
                                        log(data: "添加公众号_微信反馈结果:已经添加或微信服务器未响应", logtype: .CONTENT)
                                    }else{
                                        print("添加公众号_微信反馈结果:\(hex2str(str: wx_status))")
                                        log(data: "添加公众号_微信反馈结果:\(hex2str(str: wx_status))", logtype: .CONTENT)
                                    }
                                    
                                }
                            }

                        }
                        
                    }
                    
                    log(data: "", logtype: .END)
                    
                }else if sender.title == "阅读微信文章" {
                        
                    let articleUrl = t_UserArGZH.stringValue
                    
                    log(data: "阅读微信文章：\(articleUrl)", logtype: .START)
                    log(data: "<a style='font-weight:bold; color:grey;'>===================================================================================</a>", logtype: .CONTENT)
                    
                    
                    if articleUrl.contains("https://mp.weixin.qq.com"){
                        // 通过http访问mp.weixin.qq.com时需要使用证书，证书位置在wxBox/functions/mp.weixin.qq.com.der
                        // 如果你用浏览器打开文章链接会发现没有评论、阅读量等信息，因此你必须在http头中加入一个x-wechat-key和x-wechat-uin参数
                        // 这样文章html代码中会包含很多你所需要的参数，这些属于http范畴，因此不在此做示范演示。
                        let dict = wx_read(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, wxuser: currentWXUser, action: "read_article", arlink: articleUrl, hexdata: "")
                        
                        if let read_data = dict!["data"]{
                            
                            
                            // wechat
                            let dt = Data(hex:read_data)
                            psk_svr.send(data: dt)
                            let psk_resp = psk_svr.getData_ex()
                            print("psk_resp:\(psk_resp)")
                            

                            let dict1 = wx_read(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, wxuser: currentWXUser, action: "read_article_decode", arlink: articleUrl, hexdata: psk_resp)
                            
                            // 返回的内容会有如下内容是你会感兴趣的：
                            //      wx_xkey     对应 x-wechat-key
                            //      wx_xuin     对应 x-wechat-uin
                            //      url         对应 文章地址，该地址包含pass_ticket参数
                            // 在进行阅读开发时，建议使用firefox浏览器，并下载http标头修改插件：https://mybrowseraddon.com/modify-header-value.html
                            // 在插件中加入上面提到的两个参数并将user-agent改为MicroMessenger，打开文章链接时你会看到与在微信中阅读文章相同的布局与内容。
                            // 通过firefox的开发者工具，可以看到网络发送内容，无需抓包工具。
                            
                            if let wx_xkey = dict1!["wx_xkey"]{
                                print("----> 部分阅读参数 <----\r\n\(hex2str(str: wx_xkey))\r\n\(hex2str(str: dict1!["url"]!))")
                                log(data: "<a style='font-weight:bold; color:grey;'>\(hex2str(str: wx_xkey))<br>\(hex2str(str: dict1!["url"]!))</a>", logtype: .CONTENT)
                                
                            }
                            
                        }
                    }
                    
                    log(data: "", logtype: .END)
                    
                }else if sender.title == "退出登录" {
                    
                    log(data: "退出登录账号：\(currentWXUser)", logtype: .START)
                    log(data: "<a style='font-weight:bold; color:grey;'>===================================================================================</a>", logtype: .CONTENT)

                    let dict = wx_logout(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, wxuser: currentWXUser
                        , action: "send_logout", hexdata: "")

                    if let logout_data = dict!["data"]{
                        let logout_url = "http://\(extshort)/mmtls/" + dict!["gzh_urlname"]!
                        log(data: logout_url, logtype: .CONTENT)

                        let http_mmtls = RunTCP(http_url:logout_url, method: .POST)
                        _ = http_mmtls.sendHTTP(f19Data: logout_data)
                        let svr_resp = http_mmtls.getData()
                        print("svr_resp:\(svr_resp)")
                        
                        let dict1 = wx_logout(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, wxuser: currentWXUser, action: "send_logout_decode", hexdata: svr_resp)
                        
                        
                        if let logout_data = dict1!["wx_status"]{
                            if logout_data == "6c6f676f75745f73756363657373" {
                                log(data: "账号已退出", logtype: .CONTENT)
                            }else{
                                log(data: "未能退出", logtype: .CONTENT)
                            }
                        }else{
                            log(data: "退出失败", logtype: .CONTENT)
                        }
                    }
                    
                    log(data: "", logtype: .END)
                    
                    
                }
                
            }
            
            /// 用于微信配置数据（好友、群、公众号等信息）下载、消息推送、登录有效检测。
            func wx_chat_getmsg_wrapper()->Bool{

                let dict = wx_chat_getmsg(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, wxuser: currentWXUser, action: "send_push", hexdata: "")
                
                if let push_data = dict!["data"]{
                    
                    
                    // wechat
                    let dt = Data(hex:push_data)
                    psk_svr.send(data: dt)
                    let psk_resp = psk_svr.getData_ex()
                    print("psk_resp:\(psk_resp)")
                    
                    if (psk_resp == ""){
                        print("?????????? wechat didnt respond to a push request")
                        return false
                    }
                    
                    let dict1 = wx_chat_getmsg(appkey: appkey, accesstoken: accesstoken, secret: secret, gcmkey: gcmkey, seq: 2691, wxuser: currentWXUser, action: "send_push_decode", hexdata: psk_resp)
                    
                    if let data_dec = dict1!["data_dec"]{
                        if data_dec.substring(to: 4) == "0800"{
                            return true
                        }
                    }
                    
                }
                
                return false
            }
            
            
            override func viewDidLoad(){
                super.viewDidLoad()
                //[链接]猫喜欢睡在主人身上，于是想了这个办法，猫还睡得挺舒服的...
                log(data: "mmtls psk 连接已建立。", logtype: .START)
                log(data: "<a style='font-weight:bold; color:white;'>提示：为了保密，该测试已经将用户名密码等私人信息写入代码，因此这些数据在本次测试中将不再输入。</a>", logtype: .CONTENT)
                log(data: "<a style='font-weight:bold; color:grey;'>===================================================================================</a>", logtype: .END)
                psk_svr.tcp_data_delegate = self
                
            }
            
            override var representedObject: Any? {
                didSet {
                // Update the view, if already loaded.
                }
            }
        }







class ViewController_register: NSViewController{//, WKNavigationDelegate
    
    @IBOutlet var webBox: WKWebView!
    
    weak var delegate:deleRegister?
    var url:String = ""
    
    @IBAction func btnSurf(_ sender: NSButtonCell) {
        print("goto:\(self.url)")

    }
    
    //override func loadView() {
       // webBox = WKWebView()
       // webBox.navigationDelegate = self
        //view = webBox
    //}
    
    override func viewDidLoad(){
        super.viewDidLoad()
        //view = webBox
        print("registration_url:\(self.url)")
       // webBox.url = url
        //let URLRO = NSURL(
        
        //let webConfiguration = WKWebViewConfiguration()
        //webBox.navigationDelegate = self
        
        //webBox = WKWebView(frame: .zero, configuration: webConfiguration)
        let myURL = URL(string:self.url)
        let myRequest = URLRequest(url: myURL!)
        webBox.load(myRequest)
        
        //webBox.loadHTMLString("<b>hello</b>", baseURL: nil)
        webBox.allowsBackForwardNavigationGestures = true
        print(webBox.isLoading)
        
    }
    
    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }
}
