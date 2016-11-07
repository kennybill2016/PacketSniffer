//
//  PacketSniffer.m
//  packetsniffer
//
//  Created by lijinwei on 2016/11/2.
//  Copyright © 2016年 ljw. All rights reserved.
//

#import "PacketSniffer.h"

NSString *sharedGroupIdentifier = @"group.com.ljw.packettunnel";

@implementation PacketSniffer

+ (NSURL *)sharedUrl {
    return [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:sharedGroupIdentifier];
}

+ (NSURL *)sharedDatabaseUrl {
    return [[self sharedUrl] URLByAppendingPathComponent:@"PacketSniffer.realm"];
}

+ (NSUserDefaults *)sharedUserDefaults {
    return [[NSUserDefaults alloc] initWithSuiteName:sharedGroupIdentifier];
}

+ (NSURL * _Nonnull)sharedGeneralConfUrl {
    return [[PacketSniffer sharedUrl] URLByAppendingPathComponent:@"general.xxx"];
}

+ (NSURL *)sharedSocksConfUrl {
    return [[PacketSniffer sharedUrl] URLByAppendingPathComponent:@"socks.xxx"];
}

+ (NSURL *)sharedProxyConfUrl {
    return [[PacketSniffer sharedUrl] URLByAppendingPathComponent:@"proxy.xxx"];
}

+ (NSURL *)sharedHttpProxyConfUrl {
    return [[PacketSniffer sharedUrl] URLByAppendingPathComponent:@"http.xxx"];
}

+ (NSURL * _Nonnull)sharedLogUrl {
    return [[PacketSniffer sharedUrl] URLByAppendingPathComponent:@"tunnel.log"];
}

@end
