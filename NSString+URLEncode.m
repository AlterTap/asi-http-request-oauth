//
//  NSString+URLEncode.m
//
//  Created by Scott James Remnant on 6/1/11.
//  Copyright 2011 Scott James Remnant <scott@netsplit.com>. All rights reserved.
//

#import "NSString+URLEncode.h"


@implementation NSString (NSString_URLEncode)

- (NSString *)encodeForURL
{
    // See http://en.wikipedia.org/wiki/Percent-encoding and RFC3986
    // Hyphen, Period, Understore & Tilde are expressly legal
    const CFStringRef legalURLCharactersToBeEscaped = CFSTR("!*'();:@&=+$,/?#[]<>\"{}|\\`^% ");

    return NSMakeCollectable(CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (CFStringRef)self, NULL, legalURLCharactersToBeEscaped, kCFStringEncodingUTF8));
}

- (NSString *)encodeForURLReplacingSpacesWithPlus;
{
    // Same as encodeForURL, just without +
    const CFStringRef legalURLCharactersToBeEscaped = CFSTR("!*'();:@&=$,/?#[]<>\"{}|\\`^% ");
    
    NSString *replaced = [self stringByReplacingOccurrencesOfString:@" " withString:@"+"];
    return NSMakeCollectable(CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (CFStringRef)replaced, NULL, legalURLCharactersToBeEscaped, kCFStringEncodingUTF8));
}

- (NSString *)decodeFromURL
{
    NSString *decoded = NSMakeCollectable(CFURLCreateStringByReplacingPercentEscapesUsingEncoding(kCFAllocatorDefault, (CFStringRef)self, CFSTR(""), kCFStringEncodingUTF8));
    return [decoded stringByReplacingOccurrencesOfString:@"+" withString:@" "];
}

@end

NSDictionary *NSDictionaryFromURLParamString(NSString *params)
{
    NSArray *params1 = [[params stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] 
                                    componentsSeparatedByString:@"&"];
    NSMutableDictionary *ret = [NSMutableDictionary dictionaryWithCapacity:[params1 count]];
    for (NSString *param in params1) {
        NSArray *pair = [[param stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]    
                         componentsSeparatedByString:@"="];
        if ([pair count] != 2) continue;
        [ret setObject:[[pair objectAtIndex:1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]
                forKey:[[pair objectAtIndex:0] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]];
    }
    return ret;
} 