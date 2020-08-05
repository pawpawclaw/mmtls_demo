
import Foundation


extension String{
    func encodebase64() -> String? {
        return data(using: .utf8)?.base64EncodedString()
    }
    func decodebase64() -> String? {
        let data = Data(base64Encoded: self)!
        return String(data: data, encoding: .utf8)
    }
    func decodebase64_hex() -> String? {
        let datab = Array(base64: self)
        return datab.toHexString()
    }
    func hextostring2() -> String? {
        let str64 = Data(hex: self).base64EncodedString()
        return str64.decodebase64()
    }
    func hextostring() -> String? {
        let str = self
        let strlen = str.count
        
        var numbers = [UInt8]()
        
        for x in stride(from: 0, to: strlen-1, by: 2){
            let end = str.index(str.startIndex, offsetBy: x+2)
            let start = str.index(str.startIndex, offsetBy: x)
            let substring = str[start..<end]
            numbers.append(UInt8(substring, radix: 16) ?? 0)
        }
        var final = ""
        var i = 0

        while i < numbers.count {
            final.append(Character(UnicodeScalar(Int(numbers[i])) ?? "."))
            i+=1
        }

        return final
    }
    func hex2int() -> Int{
        let s = String(self)
        if let i = Int(s, radix: 16){
            return i
        }
        return 0
    }
    func substring(from: Int) -> String {
        let s = String(self)
        let end = s.endIndex
       // let end = s.index(s.endIndex, offsetBy: -4)
        let start = s.index(s.startIndex, offsetBy: from)
        let substring = s[start..<end] // www.stackoverflow
        return String(substring)
    }
    func substring(to: Int) -> String{
        let s = String(self)
        let start = s.startIndex
        let end = s.index(s.startIndex, offsetBy: to)
        let substring = s[start..<end]
        return String(substring)
    }
    func substring(from: Int, to: Int) -> String {
        let s = String(self)
        let start = s.index(s.startIndex, offsetBy: from)
        let end = s.index(s.startIndex, offsetBy: to)
        let substring = s[start..<end]
        return String(substring)
    }
    func substring(from: String, stroffset:Int, len: Int) -> String {
        let s = String(self)
        let q = s.index(of:from)!.utf16Offset(in:s)
        var length = q+stroffset+len
        if len <= 0{
            length = strlen(s)+len
        }
        let substr = s.substring(from: q+stroffset, to: length)
        return substr
    }
    func substring(from: String, stroffset:Int, to: String, stroffset2: Int) -> String {
        let s = String(self)
        let q = s.index(of:from)!.utf16Offset(in: s)
        let p = s.index(of:to)!.utf16Offset(in: s)
        let substr = s.substring(from: q+stroffset, to: p+stroffset2)
        return substr
    }
    func substring(from: String, stroffset:Int) -> String {
        let s = String(self)
        let q = s.index(of:from)!.utf16Offset(in: s)
        let p = s.index(s.endIndex, offsetBy: 0).utf16Offset(in: s)
        let substr = s.substring(from: q+stroffset, to: p)
        return substr
    }
    
    func toUnsafePointer() -> UnsafePointer<UInt8>? {
        guard let data = self.data(using: .utf8) else {
            return nil
        }
        
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        let stream = OutputStream(toBuffer: buffer, capacity: data.count)
        stream.open()
        let value = data.withUnsafeBytes {
            $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
        }
        guard let val = value else {
            return nil
        }
        stream.write(val, maxLength: data.count)
        stream.close()
        
        return UnsafePointer<UInt8>(buffer)
    }
    
    static var rand32Bytes: String{
        let randn = String(Int(arc4random_uniform(UINT32_MAX))).bytes.sha256().toHexString()
        return randn
    }
}

extension Date {
    static var currentTimeStamp: Int32{
        let k = String(Date().timeIntervalSince1970).substring(to: 10)
        return Int32(k)!
    }
}

extension StringProtocol {
    func index<S: StringProtocol>(of string: S, options: String.CompareOptions = []) -> Index? {
        range(of: string, options: options)?.lowerBound
    }
    func endIndex<S: StringProtocol>(of string: S, options: String.CompareOptions = []) -> Index? {
        range(of: string, options: options)?.upperBound
    }
    func indices<S: StringProtocol>(of string: S, options: String.CompareOptions = []) -> [Index] {
        var indices: [Index] = []
        var startIndex = self.startIndex
        while startIndex < endIndex,
            let range = self[startIndex...]
                .range(of: string, options: options) {
                indices.append(range.lowerBound)
                startIndex = range.lowerBound < range.upperBound ? range.upperBound :
                    index(range.lowerBound, offsetBy: 1, limitedBy: endIndex) ?? endIndex
        }
        return indices
    }
    func ranges<S: StringProtocol>(of string: S, options: String.CompareOptions = []) -> [Range<Index>] {
        var result: [Range<Index>] = []
        var startIndex = self.startIndex
        while startIndex < endIndex,
            let range = self[startIndex...]
                .range(of: string, options: options) {
                result.append(range)
                startIndex = range.lowerBound < range.upperBound ? range.upperBound :
                    index(range.lowerBound, offsetBy: 1, limitedBy: endIndex) ?? endIndex
        }
        return result
    }
}
