//
//  GetTrueRandomNumberBridge.m
//  HROT_CryptoPOC
//
//  Created by Mallikarjun Hanagandi on 11/11/24.
//

#import <Foundation/Foundation.h>
#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(GetTrueRandomNumber, NSObject)

// Declare the method that can be called from React Native
RCT_EXTERN_METHOD(getTrueRandomNumber:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(splitSecret: (NSString *)plaintext resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(retriveTrueRandomNumber: (NSArray<NSString *> *)shareString resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

@end
