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
