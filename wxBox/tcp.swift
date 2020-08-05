

import Foundation
import Network

protocol tcpDataChecker:AnyObject {
    func incomming(data:String)
}



@available(macOS 10.14, *)
class RunTCP{
    
    enum method {
        case GET
        case POST
        case TCP
    }
    
    let nwConnection: NWConnection
    let host:NWEndpoint.Host
    let port:NWEndpoint.Port
    var queue = DispatchQueue(label: "RunTCP Connection")
    
    typealias getReturn = (_ data:Data) -> Void
    typealias fireState = (_ state:NWConnection.State) -> Void
    var outputData: ((NSData) -> Void)? = nil
    var q: String
    var t: method
    var initialized: Bool
    var tripcount:Int
    
    var asyn_data: String
    var asyn_data_done: Bool
    var asyn_data_count: Int
    var isLoginComplete: Bool
    
    weak var tcp_data_delegate: tcpDataChecker?
    
    init(host: String, port: UInt16){
        self.host = NWEndpoint.Host(host)
        self.port = NWEndpoint.Port(rawValue: port)!
        self.nwConnection = NWConnection(host: self.host, port: self.port, using: .tcp)
        self.q = ""
        self.t = .TCP
        self.initialized = true
        self.tripcount = 0
        self.asyn_data = ""
        self.asyn_data_done = false
        self.asyn_data_count = 0
        self.isLoginComplete = false
    }
    
    init(http_url: String, method: method){
        self.t = method
        let a = http_url.components(separatedBy: "/")
        var port:UInt16 = 80
        if a[0] == "https:" {
            port = 443
        }
        if a[0] == "http:" {
            port = 80
        }
        let host = a[2]
        //let q = a[3]
        let q = http_url.substring(from: host, stroffset: strlen(host)+1, len: strlen(http_url)-(strlen(host)+1+strlen(a[0])+2))
        
        var param:NWParameters
        if port == 443{
            if host == "mp.weixin.qq.com" {
                let options = NWProtocolTLS.Options()
               sec_protocol_options_set_verify_block(options.securityProtocolOptions, { (sec_protocol_metadata, sec_trust, sec_protocol_verify_complete) in
                   let trust = sec_trust_copy_ref(sec_trust).takeRetainedValue()
                   
                   if let url = Bundle.main.url(forResource: "mp.weixin.qq.com", withExtension: "der"),
                       let data = try? Data(contentsOf: url),
                       let cert = SecCertificateCreateWithData(nil, data as CFData){
                       if SecTrustSetAnchorCertificates(trust, [cert] as CFArray) != errSecSuccess{
                           sec_protocol_verify_complete(false)
                           return
                       }
                   }
                   
                   let policy = SecPolicyCreateSSL(true, "mp.weixin.qq.com" as CFString)
                   SecTrustSetPolicies(trust, policy)
                   SecTrustSetAnchorCertificatesOnly(trust, true)
                   
                   var error: CFError?
                   if SecTrustEvaluateWithError(trust, &error) {
                       sec_protocol_verify_complete(true)
                       print("cer good")
                   } else {
                       sec_protocol_verify_complete(false)
                       print(error!)
                   }
               }, queue)
               
               param = NWParameters(tls: options)
            }else{
                param = .tcp
            }
        }else{
            param = .tcp
        }
        
        
        self.q = q
        self.host = NWEndpoint.Host(host)
        self.port = NWEndpoint.Port(rawValue: port)!
        self.nwConnection = NWConnection(host: self.host, port: self.port, using: param)
        self.initialized = true
        self.tripcount = 0
        self.asyn_data = ""
        self.asyn_data_done = false
        self.asyn_data_count = 0
        self.isLoginComplete = false
    }
    
    /// postData: send wc http
    func sendHTTP(wcData:String, xKey:String, xUin:String) -> String {
        
        if self.t == .TCP {
            return "TCP does not support sending by HTTP protocol."
        }
        
        var header:String = ""
        var body:String = ""
        var final:String = ""
        
        if self.t == .POST {
            header += "POST /\(self.q) HTTP/1.1\r\n"
            header += "Host: \(self.host)\r\n"
            header += xKey + "\r\n"
            header += xUin + "\r\n"
            header += "Connection: keep-alive\r\n"
            header += "Content-Length: \(strlen(wcData))\r\n"
            header += "Pragma: no-cache\r\n"
            header += "Content-Type: application/json\r\n"
            header += "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36\r\n"
            header += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
            header += "Accept-Encoding: gzip, deflate\r\n"
            header += "Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7\r\n\r\n"
            
            body = wcData
        }
        
        if self.t == .GET {
            header += "GET /\(self.q) HTTP/1.1\r\n"
            header += "Host: \(self.host)\r\n"
            header += "Connection: keep-alive\r\n"
            header += "Pragma: no-cache\r\n"
            header += xKey + "\r\n"
            header += xUin + "\r\n"
            header += "Content-Type: application/json\r\n"
            header += "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36\r\n"
            header += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
            header += "Accept-Encoding: gzip, deflate\r\n"
            header += "Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7\r\n\r\n"
        }
        
        
        final = (header + body).bytes.toHexString()
        let dt = Data(hex: final)
        send(data: dt)
        return final
    }
    
    /// postData: send http get or post to http server.
    func sendHTTP(postData: String) -> String {
        
        if self.t == .TCP {
            return "TCP does not support sending by HTTP protocol."
        }
        
        var header:String = ""
        var body:String = ""
        var final:String = ""
        
        if self.t == .POST {
            header += "POST /\(self.q) HTTP/1.1\r\n"
            header += "Host: \(self.host)\r\n"
            header += "Connection: keep-alive\r\n"
            header += "Content-Length: \(strlen(postData))\r\n"
            header += "Pragma: no-cache\r\n"
            header += "Content-Type: application/x-www-form-urlencoded\r\n"
            header += "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36\r\n"
            header += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
            header += "Accept-Encoding: gzip, deflate\r\n"
            header += "Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7\r\n\r\n"
            
            body = postData
        }
        
        if self.t == .GET {
            header += "GET /\(self.q) HTTP/1.1\r\n"
            header += "Host: \(self.host)\r\n"
            header += "Connection: keep-alive\r\n"
            header += "Pragma: no-cache\r\n"
            header += "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36\r\n"
            header += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
            header += "Accept-Encoding: gzip, deflate\r\n"
            header += "Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7\r\n\r\n"
        }
        
        
        final = (header + body).bytes.toHexString()
        let dt = Data(hex: final)
        send(data: dt)
        return final
    }
    
    func sendHTTP(f19Data: String) -> String {
        
        if self.t == .TCP {
            return "TCP does not support sending by HTTP protocol."
        }
        
        var header:String = ""
        var final:String = ""
        
        if self.t == .POST {
            header += "POST /\(self.q) HTTP/1.1\r\n"
            header += "Host: \(self.host)\r\n"
            header += "Cache-Control: no-cache\r\n"
            header += "Connection: Keep-Alive\r\n"
            header += "Content-Length: \(strlen(f19Data)/2)\r\n"
            header += "Content-Type: application/octet-stream\r\n"
            header += "User-Agent: MicroMessenger Client\r\n"
            header += "Accept: */*\r\n"
            header += "Upgrade: mmtls\r\n\r\n"
            
        }
        
        final = header.bytes.toHexString() + f19Data
        let dt = Data(hex: final)
        send(data: dt)
        return final
    }
    /// hData(hex data): post byte arrays to http server
    func sendHTTP(hData: String) -> String {
        
        if self.t == .TCP {
            return "TCP does not support sending by HTTP protocol."
        }
        
        var header:String = ""
        var final:String = ""
        
        if self.t == .POST {
            header += "POST /\(self.q) HTTP/1.1\r\n"
            header += "Host: \(self.host)\r\n"
            header += "Connection: keep-alive\r\n"
            header += "Content-Length: \(strlen(hData)/2)\r\n"
            header += "Pragma: no-cache\r\n"
            header += "Content-Type: application/x-www-form-urlencoded\r\n"
            header += "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36\r\n"
            header += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
            header += "Accept-Encoding: gzip, deflate\r\n"
            header += "Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7\r\n\r\n"
            
        }
        
        final = (header).bytes.toHexString() + hData
        let dt = Data(hex: final)
        send(data: dt)
        return final
    }
    
    /// data: send tcp raw data as a byte array
    func send(data: Data) {
        
        if (self.tripcount == 0){
            nwConnection.start(queue: queue)
        }
        
        nwConnection.send(content: data, completion: .contentProcessed( { error in
            if let error = error {
                print("Connection Error: \(error)")
                return
            }
        }))
        self.tripcount += 1
    }
    
    private func uncompress_data(dataHex:String) -> String {
        
        if dataHex.contains("1f8b08"){
            // 这里可以判断是否是gzip，如果是进行解压缩，但是在本演示中并不需要，因此移除，同时移除zlib
        }

        return dataHex
    }
    
    
    func getData_ex() -> String{
            
        let timeout = 5.0
        let startTime = CFAbsoluteTimeGetCurrent()
        print(">>>>>>>>>>>>>data_fetching_start")
        
        self.asyn_data = ""
        self.asyn_data_done = false
        self.asyn_data_count = 0
        var rtrip = 0
        
        while self.asyn_data_done == false {
            
            rtrip += 1
            
            for x in 1...5{
                self.getData_asyn()
            }
            
            while self.asyn_data_count == 0 {
                usleep(100)
                if (CFAbsoluteTimeGetCurrent() - startTime >= timeout){
                    print(">>>>>>>>>>>>>data_fetching_quit_timeout_1")
                    self.asyn_data_done = true
                    break
                }
            }
            
            if (rtrip == 1){
                usleep(100000) // wait ms, can be bigger the first round
            }else{
                usleep(100000) // wait ms
            }
            
            
            if self.asyn_data_count < 5 {
                self.asyn_data_done = true
            }
            
            print("roundtrip:\(rtrip)   asyn_data_count=\(self.asyn_data_count)    time:\(CFAbsoluteTimeGetCurrent() - startTime)")
            self.asyn_data_count = 0
            
            // timeout
            if (CFAbsoluteTimeGetCurrent() - startTime >= timeout){
                print(">>>>>>>>>>>>>data_fetching_quit_timeout_2")
                self.asyn_data_done = true
            }
        }
        
        var d = self.asyn_data
        
        
        // when getting large data chunks, it may loop over boundary, so a check is due
        if strlen(d) > 8192 {
            let k = d.substring(from: strlen(d)-14)
            if k == "0d0a300d0a0d0a"{
                d = d.substring(from: 0, to: strlen(d)-14)
            }
        }
        
        print(">>>>>>>>>>>>>data_fetching_complete")
        
        
        if (self.t == .POST || self.t == .GET) {
            if strlen(d) > 0 {
                if d.contains("0d0a0d0a") {
                    let parts = d.components(separatedBy: "0d0a0d0a")
                    
                    if (strlen(parts[1])==0){
                        return ""
                    }
                    
                    // 32306266300d0a13f1010e0a000400020be57b226d7367223a22617574685f6f6b5f7369676e5f6f6b2
                    if (parts[1].substring(from: 2, to: 6) == "f101"){
                        return parts[1]
                    }
                    
                    
                    let r = self.uncompress_data(dataHex: parts[1]).hextostring2()!
                    
                    if strlen(r) == 0{
                        
                    }
                    return r
                }else{
                    let r = d.hextostring2()!
                    return r
                }
            }
        }
        
        return d
    }
    func getData_asyn() -> Void {
        nwConnection.receive(minimumIncompleteLength: 1, maximumLength: 4096, completion: getData_get )
    }
    func getData_get(data:Data?,ctx:NWConnection.ContentContext?,isComplete:Bool,error:NWError?) -> Void{
        
        if let data = data, !data.isEmpty {
            let h = data.bytes.toHexString()
            //if (self.isLoginComplete == true){
                //print(">>>>>>got_new_data:\(data as NSData)  >>>>>>\(self.asyn_data_done)")
            //}
            if (self.asyn_data_done == true && self.isLoginComplete == true){
                tcp_data_delegate?.incomming(data: h)
            }
            self.asyn_data.append(h)
        }

        if isComplete {
            self.stop()
        } else if let error = error {
            self.stop()
        } else {
            if self.nwConnection.state == .ready && isComplete == false {
            }else{
                
            }
            
        }
        
        self.asyn_data_count += 1
        
    }
    
    
    func getData() -> String {
        
        var d:String = ""
        var b:Bool = false
        var i:Int = 0
        var ic:Int = 0
        
        let maxR = 8192 * 2
        var startTime = CFAbsoluteTimeGetCurrent()
        var endTime = CFAbsoluteTimeGetCurrent()
        var timeElapsed = CFAbsoluteTimeGetCurrent()
        
        usleep(600000) // wait for 600 miliseconds
        
        func do_r(){
            ic += 1
            startTime = CFAbsoluteTimeGetCurrent()
            nwConnection.receive(minimumIncompleteLength: 1, maximumLength: maxR){
                (data, _, isComplete, error) in
                
                if let data = data, !data.isEmpty {

                    b = false
                    i += 1
                    
                    if i == 1 {
                        d = data.bytes.toHexString()
                    }else{
                        d.append(data.bytes.toHexString())
                    }
                    
                }
                
                if isComplete {
                    b=true
                    self.stop()
                } else if let error = error {
                    b=true
                    print("getData: connection fail with error: \(error)")
                    self.stop()
                } else {
                    b=true
                    if self.nwConnection.state == .ready && isComplete == false {
                        
                    }else{
                        
                    }
                    
                }
                //return nil
            }

        }
        
        do_r()
        
        while (b == false) {
            usleep(100)
        }
        
        
        if (self.t == .POST || self.t == .GET) {
            if strlen(d) > 0 {
                if d.contains("0d0a0d0a") {
                    let parts = d.components(separatedBy: "0d0a0d0a")
                    
                    if hex2str(str: parts[0]).contains("application/octet-stream"){
                        return parts[1]
                    }
                    
                    if (strlen(parts[1])==0){
                        return ""
                    }
                    if (parts[1].substring(from: 2, to: 6) == "f101"){
                        return parts[1]
                    }
                    
                    let sr = self.uncompress_data(dataHex: parts[1])
                    let r = hex2str(str: sr)
                    
                    return r
                }else{
                    let r = d.hextostring2()!
                    return r
                }
            }
        }
        
        return d
    }
    
    
    
    func stop(){
        self.initialized = false
        self.nwConnection.stateUpdateHandler = nil
        self.nwConnection.cancel()
        print("Connection stopped.")
    }
    
    deinit {
        //print("RunTCP deinitialized.")
    }
    
}
