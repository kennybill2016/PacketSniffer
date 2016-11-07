//
//  PacketSniffer.h
//  PacketSniffer
//
//  Created by lijinwei on 2016/11/2.
//  Copyright © 2016年 ljw. All rights reserved.
//

#import <Foundation/Foundation.h>

extern NSString * _Nonnull sharedGroupIdentifier;

@interface PacketSniffer : NSObject
+ (NSURL * _Nonnull)sharedUrl;
+ (NSURL * _Nonnull)sharedDatabaseUrl;
+ (NSUserDefaults * _Nonnull)sharedUserDefaults;

+ (NSURL * _Nonnull)sharedGeneralConfUrl;
+ (NSURL * _Nonnull)sharedSocksConfUrl;
+ (NSURL * _Nonnull)sharedProxyConfUrl;
+ (NSURL * _Nonnull)sharedHttpProxyConfUrl;
+ (NSURL * _Nonnull)sharedLogUrl;
@end
