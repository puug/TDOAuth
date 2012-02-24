/*
 Copyright 2011 TweetDeck Inc. All rights reserved.

 Design and implementation, Max Howell, @mxcl.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY TweetDeck Inc. ``AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 EVENT SHALL TweetDeck Inc. OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 The views and conclusions contained in the software and documentation are
 those of the authors and should not be interpreted as representing official
 policies, either expressed or implied, of TweetDeck Inc.
*/

#import "TDOAuth.h"
#import <CommonCrypto/CommonHMAC.h>

#ifndef TDOAuthURLRequestTimeout
#define TDOAuthURLRequestTimeout 30.0
#endif
#ifndef TDUserAgent
#warning Don't be a n00b! #define TDUserAgent!
#endif

int TDOAuthUTCTimeOffset = 0;



@implementation NSString (TweetDeck)
- (id)pcen {
    NSString* rv = (NSString *) CFURLCreateStringByAddingPercentEscapes(NULL, (CFStringRef) self, NULL, (CFStringRef) @"!*'();:@&=+$,/?%#[]", kCFStringEncodingUTF8);
    return [rv autorelease];
}
@end

@implementation NSNumber (TweetDeck)
- (id)pcen {
    // We permit NSNumbers as parameters, so we need to handle this function call
    return [self stringValue];
}
@end

@implementation NSMutableString (TweetDeck)
- (id)add:(NSString *)s {
    if ([s isKindOfClass:[NSString class]])
        [self appendString:s];
    if ([s isKindOfClass:[NSNumber class]])
        [self appendString:[(NSNumber *)s stringValue]];
    return self;
}
- (id)chomp {
    const int N = [self length] - 1;
    if (N >= 0)
        [self deleteCharactersInRange:NSMakeRange(N, 1)];
    return self;
}
@end

@implementation NSDictionary (Merge)
+ (NSDictionary *) dictionaryByMerging: (NSDictionary *) dict1 with: (NSDictionary *) dict2 {
    NSMutableDictionary * result = [NSMutableDictionary dictionaryWithDictionary:dict1];
    [dict2 enumerateKeysAndObjectsUsingBlock: ^(id key, id obj, BOOL *stop) {
        if ([dict1 objectForKey:key]) {
            if ([obj isKindOfClass:[NSDictionary class]]) {
                NSDictionary * newVal = [[dict1 objectForKey: key] dictionaryByMergingWith: (NSDictionary *) obj];
                [result setObject: newVal forKey: key];
            } else {
                [result setObject: obj forKey: key];
            }
        } else {
            [result setObject:obj forKey:key];
        }
    }];
    
    return (NSDictionary *) [[result mutableCopy] autorelease];
}
- (NSDictionary *) dictionaryByMergingWith: (NSDictionary *) dict {
    return [[self class] dictionaryByMerging: self with: dict];
}
@end


// If your input string isn't 20 characters this won't work.
static NSString* base64(const uint8_t* input) {
    static const char map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    NSMutableData* data = [NSMutableData dataWithLength:28];
    uint8_t* out = (uint8_t*) data.mutableBytes;

    for (int i = 0; i < 20;) {
        int v  = 0;
        for (const int N = i + 3; i < N; i++) {
            v <<= 8;
            v |= 0xFF & input[i];
        }
        *out++ = map[v >> 18 & 0x3F];
        *out++ = map[v >> 12 & 0x3F];
        *out++ = map[v >> 6 & 0x3F];
        *out++ = map[v >> 0 & 0x3F];
    }
    out[-2] = map[(input[19] & 0x0F) << 2];
    out[-1] = '=';
    return [[[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding] autorelease];
}

static NSString* nonce() {
    CFUUIDRef uuid = CFUUIDCreate(NULL);
    CFStringRef s = CFUUIDCreateString(NULL, uuid);
    CFRelease(uuid);
    return [(id)s autorelease];
}

static NSString* timestamp() {
    time_t t;
    time(&t);
    mktime(gmtime(&t));
    return [NSString stringWithFormat:@"%u", t + TDOAuthUTCTimeOffset];
}



@implementation TDOAuth {
    
}

- (id)initWithConsumerKey:(NSString *)consumerKey
           consumerSecret:(NSString *)consumerSecret
              accessToken:(NSString *)accessToken
              tokenSecret:(NSString *)tokenSecret
{
    oauth_params = [NSDictionary dictionaryWithObjectsAndKeys:
              consumerKey,  @"oauth_consumer_key",
              nonce(),      @"oauth_nonce",
              timestamp(),  @"oauth_timestamp",
              @"1.0",       @"oauth_version",
              @"HMAC-SHA1", @"oauth_signature_method",
              accessToken,  @"oauth_token",
              // LEAVE accessToken last or you'll break XAuth attempts
              nil];
    params = [[NSDictionary alloc] init];
    signature_secret = [NSString stringWithFormat:@"%@&%@", consumerSecret, tokenSecret ?: @""];
    return self;
}

- (NSString *)signature_base {
    NSMutableString *p3 = [NSMutableString stringWithCapacity:256];
    NSDictionary *combinedParams = [NSDictionary dictionaryByMerging:oauth_params with:params];
    
    NSArray *keys = [[combinedParams allKeys] sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *key in keys) {
        NSLog(@"Key: %@", key);
        [[[[p3 add:[key pcen]] add:@"="] add:[combinedParams objectForKey:key]] add:@"&"];
    }
    [p3 chomp];
    
    NSLog(@"Sig base before: %@", p3);
    NSLog(@"Sig base after: %@", p3.pcen);
    
    NSLog(@"Sign Path: %@", url.path);
    NSLog(@"Sign Path after: %@", url.path.pcen);

    return [NSString stringWithFormat:@"%@&%@%%3A%%2F%%2F%@&%@",
            method,
            url.scheme.lowercaseString,
            hostAndPathWithoutQueryParams.pcen,
            p3.pcen];
}

- (NSString *)signature {
    NSString *sigBaseString = [self signature_base];
    NSLog(@"Sig base: %@", sigBaseString);
    NSData *sigbase = [sigBaseString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *secret = [signature_secret dataUsingEncoding:NSUTF8StringEncoding];

    uint8_t digest[20] = {0};
    CCHmacContext cx;
    CCHmacInit(&cx, kCCHmacAlgSHA1, secret.bytes, secret.length);
    CCHmacUpdate(&cx, sigbase.bytes, sigbase.length);
    CCHmacFinal(&cx, digest);

    return base64(digest);
}

- (NSString *)authorizationHeader {
    NSMutableString *header = [NSMutableString stringWithCapacity:512];
    [header add:@"OAuth "];
    for (NSString *key in oauth_params.allKeys)
        [[[[header add:key] add:@"=\""] add:[oauth_params objectForKey:key]] add:@"\", "];
    [[[header add:@"oauth_signature=\""] add:self.signature.pcen] add:@"\""];
    return header;
}

- (NSMutableURLRequest *)request {
    //TODO timeout interval depends on connectivity status
    NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:url
                                                      cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                  timeoutInterval:TDOAuthURLRequestTimeout];
#ifdef TDUserAgent
    [rq setValue:TDUserAgent forHTTPHeaderField:@"User-Agent"];
#endif
    [rq setValue:[self authorizationHeader] forHTTPHeaderField:@"Authorization"];
    [rq setValue:@"gzip" forHTTPHeaderField:@"Accept-Encoding"];
    [rq setHTTPMethod:method];
    return rq;
}

// unencodedParameters are encoded and added to self->params, returns encoded queryString
- (id)addParameters:(NSDictionary *)unencodedParameters {
    if (!unencodedParameters.count)
        return nil;

    NSMutableString *queryString = [NSMutableString string];
    NSMutableDictionary *encodedParameters = [NSMutableDictionary dictionaryWithDictionary:params];
    for (NSString *key in unencodedParameters.allKeys) {
        NSString *enkey = key.pcen;
        NSString *envalue = [[unencodedParameters objectForKey:key] pcen];
        [encodedParameters setObject:envalue forKey:enkey];
        [[[[queryString add:enkey] add:@"="] add:envalue] add:@"&"];
    }
    [queryString chomp];

    params = encodedParameters;

    return queryString;
}

+ (NSURLRequest *)URLRequestForPath:(NSString *)unencodedPathWithoutQuery
                      GETParameters:(NSDictionary *)unencodedParameters
                               host:(NSString *)host
                        consumerKey:(NSString *)consumerKey
                     consumerSecret:(NSString *)consumerSecret
                        accessToken:(NSString *)accessToken
                        tokenSecret:(NSString *)tokenSecret
{
    return [self URLRequestForPath:unencodedPathWithoutQuery
                     GETParameters:unencodedParameters
                            scheme:@"http"
                              host:host
                       consumerKey:consumerKey
                    consumerSecret:consumerSecret
                       accessToken:accessToken
                       tokenSecret:tokenSecret];
}

+ (NSURLRequest *)URLRequestForPath:(NSString *)unencodedPathWithoutQuery
                      GETParameters:(NSDictionary *)unencodedParameters
                             scheme:(NSString *)scheme
                               host:(NSString *)host
                        consumerKey:(NSString *)consumerKey
                     consumerSecret:(NSString *)consumerSecret
                        accessToken:(NSString *)accessToken
                        tokenSecret:(NSString *)tokenSecret;
{
    if (!host || !unencodedPathWithoutQuery)
        return nil;

    TDOAuth *oauth = [[TDOAuth alloc] initWithConsumerKey:consumerKey
                                           consumerSecret:consumerSecret
                                              accessToken:accessToken
                                              tokenSecret:tokenSecret];

    // We don't use pcen as we don't want to percent encode eg. /, this
    // is perhaps not the most all encompassing solution, but in practice
    // it works everywhere and means that programmer error is *much* less
    // likely.
    NSString *encodedPathWithoutQuery = [unencodedPathWithoutQuery stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];

    NSLog(@"EncodedPathWithoutQuery: %@", encodedPathWithoutQuery);
    id path = [oauth addParameters:unencodedParameters];
    if (path) {
        [path insertString:@"?" atIndex:0];
        [path insertString:encodedPathWithoutQuery atIndex:0];
    } else {
        path = encodedPathWithoutQuery;
    }
    NSLog(@"Path: %@", path);

    oauth->method = @"GET";
    oauth->hostAndPathWithoutQueryParams = [NSString stringWithFormat:@"%@%@", host, unencodedPathWithoutQuery]; //NSUrl.path drops trailing slashes
    oauth->url = [[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@://%@%@", scheme, host, path]];

    NSURLRequest *rq = [oauth request];
    [oauth->url release];
    [oauth release];
    return rq;
}

+ (NSURLRequest *)URLRequestForPath:(NSString *)unencodedPath
                     POSTParameters:(NSDictionary *)unencodedParameters
                               host:(NSString *)host
                        consumerKey:(NSString *)consumerKey
                     consumerSecret:(NSString *)consumerSecret
                        accessToken:(NSString *)accessToken
                        tokenSecret:(NSString *)tokenSecret
{
    if (!host || !unencodedPath)
        return nil;

    TDOAuth *oauth = [[TDOAuth alloc] initWithConsumerKey:consumerKey
                                           consumerSecret:consumerSecret
                                              accessToken:accessToken
                                              tokenSecret:tokenSecret];
    
    oauth->hostAndPathWithoutQueryParams = [NSString stringWithFormat:@"%@%@", host, unencodedPath]; //NSUrl.path drops trailing slashes
    oauth->url = [[NSURL alloc] initWithScheme:@"https" host:host path:unencodedPath];
    oauth->method = @"POST";

    NSError *error = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:unencodedParameters options:NSJSONWritingPrettyPrinted error:&error];
    NSString *postbody = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    
    NSMutableURLRequest *rq = [oauth request];

    if (postbody.length) {
        [rq setHTTPBody:[postbody dataUsingEncoding:NSUTF8StringEncoding]];
        [rq setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        [rq setValue:@"application/json" forHTTPHeaderField:@"Accept"];
        [rq setValue:[NSString stringWithFormat:@"%u", rq.HTTPBody.length] forHTTPHeaderField:@"Content-Length"];
    }

    [oauth->url release];
    [oauth release];

    return rq;
}

@end
