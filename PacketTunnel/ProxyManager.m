//
//  ProxyManager.m
//  PacketSniffer
//
//  Created by LEI on 2/23/16.
//  Copyright © 2016 TouchingApp. All rights reserved.
//

#import "ProxyManager.h"
#import <ShadowPath/ShadowPath.h>
#import <netinet/in.h>
#import "PacketSnifferBase.h"
#import "MMWormhole.h"

@interface ProxyManager ()
@property (nonatomic) BOOL socksProxyRunning;
@property (nonatomic) int socksProxyPort;
@property (nonatomic) BOOL httpProxyRunning;
@property (nonatomic) int httpProxyPort;
@property (nonatomic) BOOL shadowsocksProxyRunning;
@property (nonatomic) int shadowsocksProxyPort;
@property (nonatomic, copy) SocksProxyCompletion socksCompletion;
@property (nonatomic, copy) HttpProxyCompletion httpCompletion;
@property (nonatomic, copy) ShadowsocksProxyCompletion shadowsocksCompletion;
- (void)onSocksProxyCallback: (int)fd;
- (void)onHttpProxyCallback: (int)fd;
- (void)onShadowsocksCallback:(int)fd;

@property (nonatomic) MMWormhole *wormhole;

@end

void http_proxy_handler(int fd, void *udata) {
    ProxyManager *provider = (__bridge ProxyManager *)udata;
    [provider onHttpProxyCallback:fd];
}

void shadowsocks_handler(int fd, void *udata) {
    ProxyManager *provider = (__bridge ProxyManager *)udata;
    [provider onShadowsocksCallback:fd];
}

int sock_port (int fd) {
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    if (getsockname(fd, (struct sockaddr *)&sin, &len) < 0) {
        NSLog(@"getsock_port(%d) error: %s",
              fd, strerror (errno));
        return 0;
    }else{
        return ntohs(sin.sin_port);
    }
}

@implementation ProxyManager

+ (ProxyManager *)sharedManager {
    static dispatch_once_t onceToken;
    static ProxyManager *manager;
    dispatch_once(&onceToken, ^{
        manager = [ProxyManager new];
        [manager setupWormhole];
    });
    return manager;
}
/*
<?xml version="1.0" encoding="UTF-8"?>
<antinatconfig>
<interface value="127.0.0.1">
<port value="0">
<maxbindwait value="10">
<chain name="shadowsocks proxy name">
<uri value="socks5://127.0.0.1:${ssport}">
<authscheme value="anonymous">
<authchoice>
<select mechanism="anonymous">
</antinatconfig>*/
//<antinatconfig><interface value="127.0.0.1"/><port value="0"/><maxbindwait value="10"/><authchoice><select mechanism="anonymous"/></authchoice><filter><accept/></filter></antinatconfig>

- (void)startSocksProxy:(SocksProxyCompletion)completion {
    self.socksCompletion = [completion copy];
    char *path = strdup([[[NSBundle mainBundle] pathForResource:@"test" ofType:@"xml"] UTF8String]);
    NSString *confContent = [NSString stringWithCString:path encoding:NSUTF8StringEncoding];
//    NSString *confContent = [NSString stringWithContentsOfURL:[PacketSniffer sharedSocksConfUrl] encoding:NSUTF8StringEncoding error:nil];
    NSData *data = [[NSData alloc] initWithContentsOfFile:confContent];
    confContent = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    confContent = [confContent stringByReplacingOccurrencesOfString:@"${ssport}" withString:[NSString stringWithFormat:@"%d", [self shadowsocksProxyPort]]];
    NSLog(@"startSocksProxy content=%@,port=%d",confContent,[self shadowsocksProxyPort]);
    int fd = [[AntinatServer sharedServer] startWithConfig:confContent];
    [self onSocksProxyCallback:fd];
}

- (void)stopSocksProxy {
    [[AntinatServer sharedServer] stop];
    self.socksProxyRunning = NO;
}

- (void)onSocksProxyCallback:(int)fd {
    NSError *error;
    if (fd > 0) {
        self.socksProxyPort = sock_port(fd);
        self.socksProxyRunning = YES;
    }else {
        error = [NSError errorWithDomain:@"com.touchingapp.potatso" code:100 userInfo:@{NSLocalizedDescriptionKey: @"Fail to start socks proxy"}];
    }
    if (self.socksCompletion) {
        self.socksCompletion(self.socksProxyPort, error);
    }
}

# pragma mark - Shadowsocks

- (void)startShadowsocks: (ShadowsocksProxyCompletion)completion {
    self.shadowsocksCompletion = [completion copy];
    [NSThread detachNewThreadSelector:@selector(_startShadowsocks) toTarget:self withObject:nil];
}

- (void)_startShadowsocks {
    NSString *confContent = [NSString stringWithContentsOfURL:[PacketSniffer sharedProxyConfUrl] encoding:NSUTF8StringEncoding error:nil];
    NSDictionary *json = [confContent jsonDictionary];
    NSString *host = json[@"host"];
    host = @"vpnmanager.com";
    NSNumber *port = json[@"port"];
    port = [NSNumber numberWithInteger:0];
    NSString *password = json[@"password"];
    password = @"12345";
    NSString *authscheme = json[@"authscheme"];
    authscheme = @"bf-cfb";
    NSString *protocol = json[@"protocol"];
    NSString *obfs = json[@"obfs"];
    NSString *obfs_param = json[@"obfs_param"];
    BOOL ota = [json[@"ota"] boolValue];
    ota = 0;
    if (0 &&host && port && password && authscheme) {
        profile_t profile;
        memset(&profile, 0, sizeof(profile_t));
        profile.remote_host = strdup([host UTF8String]);
        profile.remote_port = [port intValue];
        profile.password = strdup([password UTF8String]);
        profile.method = strdup([authscheme UTF8String]);
        profile.local_addr = "127.0.0.1";
        profile.local_port = 0;
        profile.timeout = 600;
        profile.auth = ota;
        if (protocol.length > 0) {
            profile.protocol = strdup([protocol UTF8String]);
        }
        if (obfs.length > 0) {
            profile.obfs = strdup([obfs UTF8String]);
        }
        if (obfs_param.length > 0) {
            profile.obfs_param = strdup([obfs_param UTF8String]);
        }
        int nRet = start_ss_local_server(profile, shadowsocks_handler, (__bridge void *)self);
        int k = 1;
    }else {
        if (self.shadowsocksCompletion) {
            self.shadowsocksCompletion(0, nil);
        }
        return;
    }
}

- (void)stopShadowsocks {
    // Do nothing
}

- (void)onShadowsocksCallback:(int)fd {
    NSError *error;
    if (fd > 0) {
        self.shadowsocksProxyPort = sock_port(fd);
        self.shadowsocksProxyRunning = YES;
    }else {
        error = [NSError errorWithDomain:@"com.touchingapp.potatso" code:100 userInfo:@{NSLocalizedDescriptionKey: @"Fail to start http proxy"}];
    }
    if (self.shadowsocksCompletion) {
        self.shadowsocksCompletion(self.shadowsocksProxyPort, error);
    }
}

# pragma mark - Http Proxy

- (void)startHttpProxy:(HttpProxyCompletion)completion {
    self.httpCompletion = [completion copy];
    // Do any additional setup after loading the view, typically from a nib.
    NSURL *confURL = [PacketSniffer sharedUrl];

    NSString *httpPath = [[NSBundle mainBundle] pathForResource:@"http" ofType:@"xxx"];
    NSString *httpContent = [NSString stringWithContentsOfFile:httpPath encoding:NSUTF8StringEncoding error:nil];
    
    NSURL* confDirUrl = [confURL URLByAppendingPathComponent:@"httpconf"];
    NSString* templateDirPath = [confURL URLByAppendingPathComponent:@"httptemplate"].path;
    NSString* logDir = [confURL URLByAppendingPathComponent:@"log"].path;
    NSURL* actionUrl = [confDirUrl URLByAppendingPathComponent:@"PacketSniffer.action"];
    NSURL* logfileUrl = [[confURL URLByAppendingPathComponent:@"log"] URLByAppendingPathComponent:@"privoxy.log"];
    
    [[NSFileManager defaultManager] createDirectoryAtPath:confDirUrl.path withIntermediateDirectories:TRUE attributes:nil error:nil];
    [[NSFileManager defaultManager] createDirectoryAtPath:templateDirPath withIntermediateDirectories:TRUE attributes:nil error:nil];
    [[NSFileManager defaultManager] createDirectoryAtPath:logDir withIntermediateDirectories:TRUE attributes:nil error:nil];
    [[NSFileManager defaultManager] createFileAtPath:logfileUrl.path contents:nil attributes:nil];
    
    NSString* packetPath= [NSString stringWithFormat:@"%@", [NSString stringWithString:[NSBundle mainBundle].bundlePath]].copy;

    NSError* err;
    NSString* sourcePath = [packetPath stringByAppendingPathComponent:@"httptemplate"];
    NSArray* fileArray = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:sourcePath error:nil];
    for(NSString* filesItem in fileArray) {
        if(![[NSFileManager defaultManager] fileExistsAtPath:[templateDirPath stringByAppendingPathComponent:filesItem]]) {
            [[NSFileManager defaultManager] copyItemAtPath:[sourcePath stringByAppendingPathComponent:filesItem] toPath:[templateDirPath stringByAppendingPathComponent:filesItem] error:&err];
            if(err)
                NSLog(@"sourcePath=%@,error=%@",[sourcePath stringByAppendingPathComponent:filesItem],err);
        }
    }
    
    sourcePath = [packetPath stringByAppendingPathComponent:@"GeoLite2-Country.mmdb"];
    NSString* destCountryPath = [confURL.path stringByAppendingPathComponent:@"GeoLite2-Country.mmdb"];
    if(![[NSFileManager defaultManager] fileExistsAtPath:destCountryPath]) {
        [[NSFileManager defaultManager] copyItemAtPath:sourcePath toPath:destCountryPath error:&err];
        if(err)
            NSLog(@"sourcePath=%@,error=%@",sourcePath,err);
    }

    //generator action file
    NSString* confPath = [packetPath stringByAppendingPathComponent:@"httpconf"];
    NSString* actionFile = [confPath stringByAppendingPathComponent:@"potatso.action"];
    NSString *actionContent = [NSString stringWithContentsOfFile:actionFile encoding:NSUTF8StringEncoding error:nil];
    [actionContent writeToURL:actionUrl atomically:YES encoding:NSUTF8StringEncoding error:nil];
    
    // 这里拿出来的是如上所示的数组拼出来的字符串
    httpContent = [httpContent stringByReplacingOccurrencesOfString:@"${confdir}" withString:confDirUrl.path];
    httpContent = [httpContent stringByReplacingOccurrencesOfString:@"${ssport}" withString:[NSString stringWithFormat:@"%d", self.shadowsocksProxyPort]];
    httpContent = [httpContent stringByReplacingOccurrencesOfString:@"${templdir}" withString:templateDirPath];
    httpContent = [httpContent stringByReplacingOccurrencesOfString:@"${actionsfile}" withString:actionUrl.path];
    httpContent = [httpContent stringByReplacingOccurrencesOfString:@"${logdir}" withString:logDir];
    httpContent = [httpContent stringByReplacingOccurrencesOfString:@"${logfile}" withString:logfileUrl.path];
    httpContent = [httpContent stringByReplacingOccurrencesOfString:@"${mmdbpath}" withString:destCountryPath];
    

    [httpContent writeToURL:[PacketSniffer sharedHttpProxyConfUrl] atomically:YES encoding:NSUTF8StringEncoding error:&err];
    if(err) {
        NSLog(@"startHttpProxy err =%@",err);
    }
    NSLog(@"httpContent=%@",httpContent);
    [NSThread detachNewThreadSelector:@selector(_startHttpProxy:) toTarget:self withObject:[PacketSniffer sharedHttpProxyConfUrl]];
}

- (void)_startHttpProxy: (NSURL *)confURL {
    struct forward_spec *proxy = NULL;
    if (self.shadowsocksProxyPort > 0) {
        proxy = (malloc(sizeof(struct forward_spec)));
        memset(proxy, 0, sizeof(struct forward_spec));
        proxy->type = SOCKS_5;
        proxy->gateway_host = "127.0.0.1";
        proxy->gateway_port = self.shadowsocksProxyPort;
    }
    NSLog(@"_startHttpProxy path=%s", [[confURL path] UTF8String]);
    shadowpath_main(strdup([[confURL path] UTF8String]), proxy,http_proxy_handler, (__bridge void *)self);
}

- (void)stopHttpProxy {
    //    polipoExit();
    //    self.httpProxyRunning = NO;
}

- (void)onHttpProxyCallback:(int)fd {
    NSError *error;
    if (fd > 0) {
        self.httpProxyPort = sock_port(fd);
        self.httpProxyRunning = YES;
    }else {
        error = [NSError errorWithDomain:@"com.touchingapp.potatso" code:100 userInfo:@{NSLocalizedDescriptionKey: @"Fail to start http proxy"}];
    }
    if (self.httpCompletion) {
        self.httpCompletion(self.httpProxyPort, error);
    }
}

- (void)setupWormhole {
    NSLog(@"test setupWormhole begin");
    self.wormhole = [[MMWormhole alloc] initWithApplicationGroupIdentifier:@"group.com.vpn.agent" optionalDirectory:@"wormhole"];
    __weak typeof(self) weakSelf = self;
    [self.wormhole listenForMessageWithIdentifier:@"getTunnelStatus" listener:^(id  _Nullable messageObject) {
        [weakSelf.wormhole passMessageObject:@"ok" identifier:@"tunnelStatus"];
    }];
    [self.wormhole listenForMessageWithIdentifier:@"stopTunnel" listener:^(id  _Nullable messageObject) {
//        [weakSelf stop];
    }];
    [self.wormhole listenForMessageWithIdentifier:@"getTunnelConnectionRecords" listener:^(id  _Nullable messageObject) {
        NSMutableArray *records = [NSMutableArray array];
          struct log_client_states *p = log_clients;
         while (p) {
         struct client_state *client = p->csp;
         NSMutableDictionary *d = [NSMutableDictionary dictionary];
         char *url = client->http->url;
         if (url ==  NULL) {
         p = p->next;
         continue;
         }
         d[@"url"] = [NSString stringWithCString:url encoding:NSUTF8StringEncoding];
         d[@"method"] = @(client->http->gpc);
         for (int i=0; i < STATUS_COUNT; i++) {
         d[[NSString stringWithFormat:@"time%d", i]] = @(client->timestamp[i]);
         }
         d[@"version"] = @(client->http->ver);
         if (client->rule && client->rule->rule) {
         d[@"rule"] = [NSString stringWithCString:client->rule->rule encoding:NSUTF8StringEncoding];
         }
         d[@"global"] = @(global_mode);
         //            if (p->headers) {
         //                d[@"headers"] = [NSString stringWithCString:p->headers->string encoding:NSUTF8StringEncoding];
         //            }
         //            if (p->rule) {
         //                d[@"ruleType"] = @(p->rule->type),
         //                d[@"ruleAction"] = @(p->rule->action),
         //                d[@"ruleValue"] = [NSString stringWithCString:p->rule->value encoding:NSUTF8StringEncoding];
         //            }
         
         d[@"responseCode"] = @(client->http->status);
         [records addObject:d];
         p = p->next;
         }
        NSString *result = [records jsonString];
        NSLog(@"testMMWormhole result=%@",result);
        [weakSelf.wormhole passMessageObject:result identifier:@"tunnelConnectionRecords"];
    }];
    NSLog(@"test setupWormhole end");
}

@end

