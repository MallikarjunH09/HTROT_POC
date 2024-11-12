//
//  SupportingClasses.swift
//  HROT_CryptoPOC
//
//  Created by Mallikarjun Hanagandi on 11/11/24.
//

import Foundation

//MARK: Split Secret into 5 parts
func splitSecret(message: String) -> Array<Secret.Share> {
  let data = message.data(using: .utf8)!
  
  do {
    let secret = try Secret(data: data, threshold: 3, shares: 5)
    let shares = try secret.split()
    
    print("-----------------")
    print("Shared Share - 5/3")
    for share in shares {
      print(share.description)
    }
    print("-----------------")
    return shares
  } catch {
    print("Error: \(error)")
  }
  
  return []
}

/**
 Shamir's Secret Sharing.
 
 A threshold secret sharing scheme to split data into N secret shares such that
 at least K secret shares must be combined to reconstruct the data.
 
 This is scheme is information-theortic secure; An adversary with K-1
 or fewer secret shares would produce any data with equal probability,
 meaning fewer than K-1 shares reveal nothing about the secret data.
 
 https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
 */

public class Secret {
  
  /**
   The number of secret shares to create (N)
   */
  public let shares: UInt8
  
  /**
   The number of secret shares requried to reconstruct the secret
   */
  public let threshold: UInt8
  
  /**
   The secret data
   */
  public let data: Data
  
  /**
   Secret Sharing Errors
   */
  public enum Errors: Error {
    case unsupportedLength
    case thresholdLargerThanShares
    case thresholdTooLow
    case splitOnZero
    case shareDataLengthMismatch
    case shareDataTooShort
    case invalidStringRepresentation
  }
  
  /**
   An Invidivual Secret Share
   */
  public struct Share: CustomStringConvertible, Hashable {
    
    let point: UInt8
    var bytes: [UInt8]
    
    init(point: UInt8, bytes: [UInt8]) {
      self.point = point
      self.bytes = bytes
    }
    
    public init(data: Data) throws {
      guard data.count >= 1 else {
        throw Errors.shareDataTooShort
      }
      
      let dataBytes = data.bytes
      
      self.point = dataBytes[0]
      self.bytes = [UInt8](dataBytes[1 ..< dataBytes.count])
    }
    
    public init(string: String) throws {
      
      let components = string.components(separatedBy: "-")
      
      guard let pointComponent = components.first,
            let point = UInt8(pointComponent)  else {
        throw Errors.invalidStringRepresentation
      }
      
      guard let bytesComponent = components.last,
            let bytes = Data(hex: bytesComponent)?.bytes  else {
        throw Errors.invalidStringRepresentation
      }
      
      self.point = point
      self.bytes = bytes
    }
    
    public init(closure: (Any) throws -> (point: UInt8, bytes: Data), value: Any) throws {
      
      let resultTuple = try closure(value)
      let point = resultTuple.point
      let data = resultTuple.bytes
      
      self.point = point
      self.bytes = data.bytes
    }
    
    public func description(closure: (UInt8, Data) -> String) -> String {
      return closure(point, Data(bytes))
    }
    
    public var data: Data {
      return Data([point] + bytes)
    }
    
    public var description: String {
      return "\(point)-\(Data(bytes).hexEncodedString())"
    }
  }
  
  /**
   Initialize a secret `data` with a `threshold` and the number
   of `shares` to create.
   */
  public init(data: Data, threshold: Int, shares: Int) throws {
    
    guard threshold <= Int(UInt8.max), shares <= Int(UInt8.max)
    else {
      throw Errors.unsupportedLength
    }
    
    guard threshold > 1 else {
      throw Errors.thresholdTooLow
    }
    
    guard threshold <= shares else {
      throw Errors.thresholdLargerThanShares
    }
    
    self.threshold = UInt8(threshold)
    self.shares = UInt8(shares)
    self.data = data
  }
  
  /**
   Split the secret data into `shares` shares
   */
  public func split() throws -> [Share] {
    let bytes = data.bytes
    var secretShares = [Share]()
    
    // initialize the shares
    for x in 1...shares {
      secretShares.append(Share(point: x, bytes: []))
    }
    
    for byte in bytes {
      let poly = try PolyGF256.random(zeroAt: GF256(byte), degree: Int(threshold - 1))
      
      for x in 1...shares {
        let v = try poly.evaluate(at: GF256(x)).byte
        secretShares[Int(x) - 1].bytes.append(v)
      }
    }
    
    return secretShares
  }
  
  /**
   Combine `shares` to reconstruct a secret data
   */
  public static func combine(shares: [Share]) throws -> Data { //3 recontruct securre string using 5 shares
    guard shares.count > 0 else {
      return Data()
    }
    
    let dataLength = shares[0].bytes.count
    
    // count the resulting byte length or throw if
    // they mismatch
    try shares.forEach({
      guard $0.bytes.count == dataLength else {
        throw Errors.shareDataLengthMismatch
      }
    })
    
    let uniqueShares = Array(Set(shares))
    
    var combinedBytes = [UInt8]()
    
    for i in 0 ..< dataLength {
      let points = uniqueShares.map({ (GF256($0.point),  GF256($0.bytes[i])) })
      let result = try PolyGF256.interpolate(points: points, at: GF256.zero)
      combinedBytes.append(result.byte)
    }
    
    return Data(combinedBytes)
  }
}

//MARK: Reconstruct Key From Chunks/Shares
func recKeyFromChunks(keyChunk:[String]) -> String{
    
    let sharesObjects = keyChunk.compactMap { try? Secret.Share(string: $0) }
    let someShares = [Secret.Share](sharesObjects[1...3])
    let secretData = try!  Secret.combine(shares: someShares)
    let secret = String(data: secretData, encoding: .utf8)!
    print("-----------------")
    print("Reconstructed String: \(secret)")
    
    return secret
}

//MARK: PolyGF256
class PolyGF256:Equatable, CustomDebugStringConvertible {
  
  var coefficients:[GF256]
  
  var degree:Int {
    return coefficients.count - 1
  }
  
  var length:Int {
    return coefficients.count
  }
  
  init(coefficients:[GF256]) {
    self.coefficients = coefficients
  }
  
  convenience init(bytes:[UInt8]) {
    var theBytes = bytes
    if theBytes.isEmpty {
      theBytes.append(0x00)
    }
    
    self.init(coefficients: [GF256](bytes: bytes))
  }
  
  /// A random polynomial with degree `degree`
  static func random(zeroAt:GF256, degree:Int) throws -> PolyGF256 {
    var coefficients = [GF256]()
    coefficients.append(zeroAt)
    coefficients.append(contentsOf: [GF256](bytes: try Data.random(size: degree).bytes))
    
    // degreeth'th coefficient cannot be zero
    while coefficients[degree] == GF256.zero {
      coefficients[degree] = try GF256(Data.random(size: 1).bytes[0])
    }
    
    return PolyGF256(coefficients: coefficients)
  }
  
  /// Horner's Method: https://en.wikipedia.org/wiki/Horner%27s_method
  func evaluate(at x:GF256) throws -> GF256 {
    var p:GF256 = GF256.zero
    
    for i in 1...length {
      p = try p*x + coefficients[length - i]
    }
    
    return p
  }
  
  /// Lagrange polynomial interpolation
  static func interpolate(points:[(x:GF256, y:GF256)], at value:GF256) throws -> GF256 {
    
    let n = points.count
    var out = GF256.zero
    
    for i in 0 ..< n {
      let y = points[i].y
      var l = GF256(1)
      
      for j in 0 ..< n {
        guard i != j else {
          continue
        }
        
        let numer = try value - points[j].x
        let denom = try points[i].x - points[j].x
        
        l = try l * (numer / denom)
      }
      
      out = try out + (y * l)
    }
    
    return out
  }
  
  var debugDescription: String {
    guard length > 0 else {
      return "0"
    }
    
    var out = "\(coefficients[0].byte)"
    
    if length >= 2 {
      out += " + \(coefficients[1].byte)x"
    }
    
    guard length >= 3 else {
      return out
    }
    
    for i in 2 ..< length {
      out += " + \(coefficients[i].byte)x^\(i)"
    }
    return out
  }
}

func ==(p:PolyGF256, q:PolyGF256) -> Bool{
  return true
}

//MARK: GF256
public struct GF256: Equatable, CustomDebugStringConvertible {
  let byte:UInt8
  
  init(_ byte:UInt8) {
    self.byte = byte
  }
  
  public var debugDescription:String {
    return "\(self.byte)"
  }
  
  static var zero: GF256 {
    return GF256(0x00)
  }
  
  /**
   GF256 Arithmetic Errors
   */
  public enum Errors:Error {
    case missingExponent(Int)
    case missingLogarithm(Int)
    case divideByZero
  }
  
  static func exp(of value: GF256) throws -> GF256 {
    let index = Int(value.byte)
    
    guard index < expTable.count else {
      throw Errors.missingExponent(index)
    }
    
    return GF256(expTable[index])
  }
  
  /// Exponents table courtesy of http://www.cs.utsa.edu/~wagner/laws/FFM.html
  static var expTable: [UInt8] {
    return [
      0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
      0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
      0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
      0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
      0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
      0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
      0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
      0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
      0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
      0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
      0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
      0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
      0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
      0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
      0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
      0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01
    ]
  }
  
  static func log(of value: GF256) throws -> GF256 {
    let index = Int(value.byte)
    
    guard index < expTable.count else {
      throw Errors.missingLogarithm(index)
    }
    
    return GF256(logTable[index])
  }
  
  /// Logarithms table courtesy http://www.cs.utsa.edu/~wagner/laws/FFM.html
  static var logTable: [UInt8] {
    return [
      0xff, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6, 0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03,
      0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef, 0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1,
      0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a, 0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78,
      0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24, 0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e,
      0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94, 0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38,
      0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62, 0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10,
      0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42, 0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
      0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca, 0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57,
      0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74, 0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8,
      0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5, 0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0,
      0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec, 0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
      0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86, 0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d,
      0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc, 0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1,
      0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47, 0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
      0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89, 0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5,
      0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18, 0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07
    ]
  }
  
  
}

/// An array of GF256 elements
extension Array where Element == GF256 {
  init(bytes: [UInt8]) {
    self = bytes.map({ GF256($0) })
  }
}


/// Operators +, *, /, ==
func -(a: GF256, b: GF256) throws -> GF256 {
  return GF256(a.byte ^ b.byte)
}


func +(a: GF256, b: GF256) throws -> GF256 {
  return GF256(a.byte ^ b.byte)
}


func *(a: GF256, b: GF256) throws -> GF256 {
  if a == GF256.zero || b == GF256.zero {
    return GF256.zero
  }
  
  let v = try (Int(GF256.log(of: a).byte) + Int(GF256.log(of: b).byte)) % 255
  return try GF256.exp(of: GF256(UInt8(v)))
}

func /(a: GF256, b: GF256) throws -> GF256 {
  guard b != GF256.zero else {
    throw GF256.Errors.divideByZero
  }
  
  guard a != GF256.zero else {
    return GF256.zero
  }
  
  var v = try Int(GF256.log(of: a).byte) - Int(GF256.log(of: b).byte)
  if v < 0 {
    v += 255
  }
  
  return try GF256.exp(of: GF256(UInt8(v)))
}

/**
 Compare two GF256 elements
 */
public func ==(a:GF256, b:GF256) -> Bool {
  return a.byte == b.byte
}


//MARK: Required Utils method

extension UInt8 {
  var hex:String {
    return "0x" + String(format: "%02x", self)
  }
}

enum DataError : Error {
  case encoding
  case cryptoRandom
  case range(Range<Int>)
  case utfEncoding
}

extension String: Error {}

extension Data {
  static func random(size:Int) throws -> Data {
    var result = [UInt8](repeating: 0, count: size)
    let res = SecRandomCopyBytes(kSecRandomDefault, size, &result)
    
    guard res == 0 else {
      throw DataError.cryptoRandom
    }
    
    return Data(result)
  }
  
  func utf8String() throws -> String {
    guard let utf8String = String(data: self, encoding: String.Encoding.utf8) else {
      throw DataError.utfEncoding
    }
    return utf8String
  }
  
  var bytes: [UInt8] {
    return self.toArray(type: UInt8.self)
  }
  
  struct HexEncodingOptions: OptionSet {
    let rawValue: Int
    static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
  }
  
  func hexEncodedString(options: HexEncodingOptions = []) -> String {
    let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
    return map { String(format: format, $0) }.joined()
  }
  
  public init?(hex: String) {
    
    let len = hex.count / 2
    var data = Data(capacity: len)
    for indexI in 0..<len {
      let indexJ = hex.index(hex.startIndex, offsetBy: indexI * 2)
      let indexK = hex.index(indexJ, offsetBy: 2)
      let bytes = hex[indexJ..<indexK]
      if var num = UInt8(bytes, radix: 16) {
        data.append(&num, count: 1)
      } else {
        return nil
      }
    }
    self = data
  }
  
  init<T>(fromArray values: [T]) {
    self = values.withUnsafeBytes { Data($0) }
  }
  
  func toArray<T>(type: T.Type) -> [T] where T: ExpressibleByIntegerLiteral {
    var array = Array<T>(repeating: 0, count: self.count/MemoryLayout<T>.stride)
    _ = array.withUnsafeMutableBytes { copyBytes(to: $0) }
    return array
  }
}
