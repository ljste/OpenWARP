#import <Foundation/Foundation.h>
#import <SystemConfiguration/SystemConfiguration.h>

void *openwarp_dns_open(const char *interface) {
    @autoreleasepool {
        NSDictionary *options = @{ (__bridge NSString *)kSCDynamicStoreUseSessionKeys: @YES };
        SCDynamicStoreRef store = SCDynamicStoreCreateWithOptions(NULL, CFSTR("OpenWARP"), (__bridge CFDictionaryRef)options, NULL, NULL);
        if (!store) return NULL;
        NSString *name = [NSString stringWithUTF8String:interface];
        NSDictionary *dns = @{ @"ServerAddresses": @[@"1.1.1.1", @"1.0.0.1", @"2606:4700:4700::1111", @"2606:4700:4700::1001"],
                               @"SupplementalMatchDomains": @[@""], @"SupplementalMatchOrders": @[@1],
                               @"SearchOrder": @1, @"InterfaceName": name };
        if (!SCDynamicStoreSetValue(store, CFSTR("State:/Network/Service/io.github.ljste.openwarp/DNS"), (__bridge CFDictionaryRef)dns)) {
            CFRelease(store);
            return NULL;
        }
        return (void *)store;
    }
}

void openwarp_dns_close(void *store) {
    CFRelease(store);
}

char *openwarp_wifi_dns(void) {
    @autoreleasepool {
        SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("OpenWARP Wi-Fi"), NULL, NULL);
        if (!store) return NULL;
        NSArray *devices = CFBridgingRelease(SCNetworkInterfaceCopyAll());
        NSArray *keys = CFBridgingRelease(SCDynamicStoreCopyKeyList(store, CFSTR("State:/Network/Service/[^/]+/IP(v4|v6)")));
        char *result = NULL;
        for (id device in devices) {
            SCNetworkInterfaceRef interface = (__bridge SCNetworkInterfaceRef)device;
            if (!CFEqual(SCNetworkInterfaceGetInterfaceType(interface), kSCNetworkInterfaceTypeIEEE80211)) continue;
            NSString *name = (__bridge NSString *)SCNetworkInterfaceGetBSDName(interface);
            for (NSString *key in keys) {
                NSDictionary *ip = CFBridgingRelease(SCDynamicStoreCopyValue(store, (__bridge CFStringRef)key));
                if (![ip[@"InterfaceName"] isEqual:name]) continue;
                NSString *dnsKey = [[key stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"DNS"];
                NSDictionary *dns = CFBridgingRelease(SCDynamicStoreCopyValue(store, (__bridge CFStringRef)dnsKey));
                NSArray *servers = dns[@"ServerAddresses"];
                if (!servers.count) continue;
                NSData *data = [NSJSONSerialization dataWithJSONObject:@{@"interface":name, @"servers":servers} options:0 error:nil];
                if (data) result = strndup(data.bytes, data.length);
                break;
            }
            if (result) break;
        }
        CFRelease(store);
        return result;
    }
}
