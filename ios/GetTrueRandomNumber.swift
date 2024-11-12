//
//  GetTrueRandomNumber.swift
//  HROT_CryptoPOC
//
//  Created by Mallikarjun Hanagandi on 11/11/24.
//

import Foundation
import React

@objc(GetTrueRandomNumber)
class GetTrueRandomNumber: NSObject {
  
  
  // MARK: - Generate True Random Number
  @objc
  func getTrueRandomNumber(_ resolve:@escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    
    var combinedData = Data()
    // Generate 6 blocks of 4 random bytes each
    for _ in 0..<6 {
      var randomData = Data(repeating: 0, count: 4)
      let status = SecRandomCopyBytes(kSecRandomDefault, randomData.count, &randomData)
      
      // Check status for each call
      if status != errSecSuccess {
        let error = NSError(domain: "", code: 200, userInfo: nil)
        reject("ERROR", "Failed to generate true random number.", error)
        return
      }
      combinedData.append(randomData)
    }
    
    // Convert combined data to hex string
    let trngString = combinedData.hexEncodedString()
    resolve(trngString)
  }
  
  
  // MARK: - Split the True Random Number and retun back
  @objc
  func splitSecret(_ plaintext: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    Task {
      do {
        
        let share = HROT_CryptoPOC.splitSecret(message: plaintext)
        print("share: \(share)")
        let shareString = share.map { $0.description }
        print("shareString: \(shareString)")
        
        if shareString.isEmpty {
          throw NSError(domain: "", code: 200, userInfo: [NSLocalizedDescriptionKey: "Failed to Split shares"])
        } else {
          resolve(shareString)
        }
      } catch {
        reject("ERROR", "Failed to split secret", error)
      }
    }
  }
  
  
  
  // MARK: - Retrieve True Random Number from Encrypted Secret
  @objc
  func retriveTrueRandomNumber(_ shareString: [String], resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    
    Task {
      do {
     
        let trueRandomNumber = recKeyFromChunks(keyChunk: shareString)
        
        if trueRandomNumber.isEmpty {
          throw NSError(domain: "", code: 200, userInfo: [NSLocalizedDescriptionKey: "Failed to retrieve true random number"])
        } else {
          resolve(trueRandomNumber)
        }
      } catch {
        reject("ERROR", "Failed to decrypt and retrieve the true random number", error)
      }
    }
  }
  
}
