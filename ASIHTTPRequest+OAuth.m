//
//  ASIHTTPRequest+OAuth.m
//
//  Created by Scott James Remnant on 6/1/11.
//  Copyright 2011 Scott James Remnant <scott@netsplit.com>. All rights reserved.
//

#include <sys/time.h>

#import <CommonCrypto/CommonHMAC.h>

#import "ASIHTTPRequest+OAuth.h"
#import "NSData+Base64.h"
#import "NSString+URLEncode.h"
#import "NSString+UUID.h"


// Signature Method strings, keep in sync with ASIOAuthSignatureMethod
static const NSString *oauthSignatureMethodName[] = {
    @"PLAINTEXT",
    @"HMAC-SHA1",
};

// OAuth version implemented here
static const NSString *oauthVersion = @"1.0";


@implementation ASIHTTPRequest (ASIHTTPRequest_OAuth)

#pragma mark -
#pragma mark Timestamp and nonce handling

- (NSArray *)oauthGenerateTimestampAndNonce
{
    struct timeval tv;
    NSString *timestamp;

    gettimeofday(&tv, NULL);
    timestamp = [NSString stringWithFormat:@"%d", tv.tv_sec];
    // nonce might as well be a uuid, they are smaller
    NSString *randomString = [[[NSString stringWithUUID] stringByReplacingOccurrencesOfString:@"-" withString:@""]
                              lowercaseString];
    
    return [NSArray arrayWithObjects:[NSDictionary dictionaryWithObjectsAndKeys:@"oauth_timestamp", @"key", timestamp, 
                                      @"value", nil], [NSDictionary dictionaryWithObjectsAndKeys:@"oauth_nonce", @"key", 
                                                       randomString, @"value", nil], nil];
}


#pragma mark -
#pragma mark Signature base string construction

- (NSString *)oauthBaseStringURI
{
    NSAssert([self.url host] != nil, @"URL host missing: %@", [self.url absoluteString]);

    // Port need only be present if it's not the default
    NSString *hostString;
    if (([self.url port] == nil)
        || ([[[self.url scheme] lowercaseString] isEqualToString:@"http"] && ([[self.url port] integerValue] == 80))
        || ([[[self.url scheme] lowercaseString] isEqualToString:@"https"] && ([[self.url port] integerValue] == 443))) {
        hostString = [[self.url host] lowercaseString];
    } else {
        hostString = [NSString stringWithFormat:@"%@:%@", [[self.url host] lowercaseString], [self.url port]];
    }
    
    // Annoyingly [self.url path] is decoded and has trailing slashes stripped, so we have to manually extract the path without the query or fragment
    NSString *pathString = [[self.url absoluteString] substringFromIndex:[[self.url scheme] length] + 3];
    NSRange pathStart = [pathString rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]];
    NSRange pathEnd = [pathString rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"?#"]];
    if (pathEnd.location != NSNotFound) {
        pathString = [pathString substringWithRange:NSMakeRange(pathStart.location, pathEnd.location - pathStart.location)];
    } else {
        pathString = [pathString substringFromIndex:pathStart.location];
    }
    
    return [NSString stringWithFormat:@"%@://%@%@", [[self.url scheme] lowercaseString], hostString, pathString];
}

- (NSArray *)oauthPostBodyParameters
{
    // For sub-classes to override
    return nil;
}

- (NSArray *)oauthAdditionalParametersForMethod:(ASIOAuthSignatureMethod)signatureMethod
{
    // For sub-classes to override
    return nil;
}

- (NSString *)oauthRequestParameterString:(NSArray *)oauthParameters
{
    NSMutableArray *parameters = [NSMutableArray array];

    // Decode the parameters given in the query string, and add their encoded counterparts
    NSArray *pairs = [[self.url query] componentsSeparatedByString:@"&"];
    for (NSString *pair in pairs) {
        NSString *key, *value;
        NSRange separator = [pair rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"="]];
        if (separator.location != NSNotFound) {
            key = [[pair substringToIndex:separator.location] decodeFromURL];
            value = [[pair substringFromIndex:separator.location + 1] decodeFromURL];
        } else {
            key = [pair decodeFromURL];
            value = @"";
        }

        [parameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:[key encodeForURL], @"key", [value encodeForURL], @"value", nil]];
    }

    // Add the encoded counterparts of the parameters in the OAuth header
    for (NSDictionary *param in oauthParameters) {
        NSString *key = [param objectForKey:@"key"];
        if ([key hasPrefix:@"oauth_"]
            && ![key isEqualToString:@"oauth_signature"])
            [parameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:[key encodeForURL], @"key", [[param objectForKey:@"value"] encodeForURL], @"value", nil]];
    }
    
    // Add encoded counterparts of any additional parameters from the body
    NSArray *postBodyParameters = [self oauthPostBodyParameters];
    for (NSDictionary *param in postBodyParameters)
        [parameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:[[param objectForKey:@"key"] encodeForURL], @"key", [[param objectForKey:@"value"]  encodeForURL], @"value", nil]];
        
    // Sort by name and value
    [parameters sortUsingComparator:^(id obj1, id obj2) {
        NSDictionary *val1 = obj1, *val2 = obj2;
        NSComparisonResult result = [[val1 objectForKey:@"key"] compare:[val2 objectForKey:@"key"] options:NSLiteralSearch];
        if (result != NSOrderedSame)
            return result;

        return [[val1 objectForKey:@"value"] compare:[val2 objectForKey:@"value"] options:NSLiteralSearch];
    }];
    
    // Join components together
    NSMutableArray *parameterStrings = [NSMutableArray array];
    for (NSDictionary *parameter in parameters)
        [parameterStrings addObject:[NSString stringWithFormat:@"%@=%@", [parameter objectForKey:@"key"], [parameter objectForKey:@"value"]]];

    return [parameterStrings componentsJoinedByString:@"&"];
}


#pragma mark -
#pragma mark Signing algorithms

- (NSString *)oauthGeneratePlaintextSignatureFor:(NSString *)baseString
                                withClientSecret:(NSString *)clientSecret
                                  andTokenSecret:(NSString *)tokenSecret
{
    // Construct the signature key
    return [NSString stringWithFormat:@"%@&%@", clientSecret != nil ? [clientSecret encodeForURL] : @"", tokenSecret != nil ? [tokenSecret encodeForURL] : @""];
}

- (NSString *)oauthGenerateHMAC_SHA1SignatureFor:(NSString *)baseString
                                withClientSecret:(NSString *)clientSecret
                                  andTokenSecret:(NSString *)tokenSecret
{
	
    NSString *key = [self oauthGeneratePlaintextSignatureFor:baseString withClientSecret:clientSecret andTokenSecret:tokenSecret];
    
    const char *keyBytes = [key cStringUsingEncoding:NSUTF8StringEncoding];
    const char *baseStringBytes = [baseString cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned char digestBytes[CC_SHA1_DIGEST_LENGTH];

	CCHmacContext ctx;
    CCHmacInit(&ctx, kCCHmacAlgSHA1, keyBytes, strlen(keyBytes));
	CCHmacUpdate(&ctx, baseStringBytes, strlen(baseStringBytes));
	CCHmacFinal(&ctx, digestBytes);

	NSData *digestData = [NSData dataWithBytes:digestBytes length:CC_SHA1_DIGEST_LENGTH];
    return [digestData base64EncodedString];
}


#pragma mark -
#pragma mark Public methods

- (void)signRequestWithClientIdentifier:(NSString *)clientIdentifier
                                 secret:(NSString *)clientSecret
                        tokenIdentifier:(NSString *)tokenIdentifier
                                 secret:(NSString *)tokenSecret
                            usingMethod:(ASIOAuthSignatureMethod)signatureMethod
{
    [self signRequestWithClientIdentifier:clientIdentifier secret:clientSecret tokenIdentifier:tokenIdentifier 
                                   secret:tokenSecret verifier:nil usingMethod:signatureMethod];
}

- (void)signRequestWithClientIdentifier:(NSString *)clientIdentifier
                                 secret:(NSString *)clientSecret
                        tokenIdentifier:(NSString *)tokenIdentifier
                                 secret:(NSString *)tokenSecret
                               verifier:(NSString *)verifier
                            usingMethod:(ASIOAuthSignatureMethod)signatureMethod
{
    [self buildPostBody];
    
    NSMutableArray *oauthParameters = [NSMutableArray array];
    
    // Add what we know now to the OAuth parameters
    if (self.authenticationRealm)
        [oauthParameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:@"realm", @"key", self.authenticationRealm, @"value", nil]];
    [oauthParameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:@"oauth_version", @"key", oauthVersion, @"value", nil]];
    [oauthParameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:@"oauth_consumer_key", @"key", clientIdentifier, @"value", nil]];
    if (tokenIdentifier != nil)
        [oauthParameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:@"oauth_token", @"key", tokenIdentifier, @"value", nil]];
    if (verifier != nil)
        [oauthParameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:@"oauth_verifier", @"key", verifier, @"value", nil]];
    [oauthParameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:@"oauth_signature_method", @"key", oauthSignatureMethodName[signatureMethod], @"value", nil]];
    [oauthParameters addObjectsFromArray:[self oauthGenerateTimestampAndNonce]];    
    [oauthParameters addObjectsFromArray:[self oauthAdditionalParametersForMethod:signatureMethod]];
    
    // Construct the signature base string
    NSString *baseStringURI = [self oauthBaseStringURI];
    NSString *requestParameterString = [self oauthRequestParameterString:oauthParameters];
    NSString *baseString = [NSString stringWithFormat:@"%@&%@&%@", [[self requestMethod] uppercaseString], [baseStringURI encodeForURL], [requestParameterString encodeForURL]];
    
    // Generate the signature
    NSString *signature;
    switch (signatureMethod) {
        case ASIOAuthPlaintextSignatureMethod:
            signature = [self oauthGeneratePlaintextSignatureFor:baseString withClientSecret:clientSecret andTokenSecret:tokenSecret];
            break;
        case ASIOAuthHMAC_SHA1SignatureMethod:
            signature = [self oauthGenerateHMAC_SHA1SignatureFor:baseString withClientSecret:clientSecret andTokenSecret:tokenSecret];
            break;
    }
    [oauthParameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:@"oauth_signature", @"key", signature, @"value", nil]];
    
    // Set the Authorization header
    NSMutableArray *oauthHeader = [NSMutableArray array];
    for (NSDictionary *param in oauthParameters)
        [oauthHeader addObject:[NSString stringWithFormat:@"%@=\"%@\"", [[param objectForKey:@"key"] encodeForURL], [[param objectForKey:@"value"] encodeForURL]]];
    
    [self addRequestHeader:@"Authorization" value:[NSString stringWithFormat:@"OAuth %@", [oauthHeader componentsJoinedByString:@", "]]];
}

@end
