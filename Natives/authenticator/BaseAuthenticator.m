#import <Security/Security.h>
#import "BaseAuthenticator.h"
#import "../LauncherPreferences.h"
#import "../ios_uikit_bridge.h"
#import "../utils.h"

@implementation BaseAuthenticator

static BaseAuthenticator *current = nil;

+ (id)current {
    if (current == nil) {
        [self loadSavedName:getPrefObject(@"internal.selected_account")];
    }
    return current;
}

+ (void)setCurrent:(BaseAuthenticator *)auth {
    current = auth;
}

+ (id)loadSavedName:(NSString *)name {
    NSMutableDictionary *authData = parseJSONFromFile([NSString stringWithFormat:@"%s/accounts/%@.json", getenv("AME_HOME"), name]);
    if (authData[@"NSErrorObject"] != nil) {
        NSError *error = ((NSError *)authData[@"NSErrorObject"]);
        if (error.code != NSFileReadNoSuchFileError) {
            showDialog(localize(@"Error", nil), error.localizedDescription);
        }
        return nil;
    }

    if ([authData[@"expiresAt"] longValue] == 0) {
        return [[LocalAuthenticator alloc] initWithData:authData];
    } else { 
        return [[MicrosoftAuthenticator alloc] initWithData:authData];
    }
}

- (id)initWithData:(NSMutableDictionary *)data {
    current = self = [self init];
    self.authData = data;
    return self;
}

- (id)initWithInput:(NSString *)string {
    NSMutableDictionary *data = [[NSMutableDictionary alloc] init];
    data[@"input"] = string;
    return [self initWithData:data];
}

- (void)loginWithCallback:(Callback)callback {
}

- (void)refreshTokenWithCallback:(Callback)callback {
}

- (BOOL)saveChanges {
    NSError *error;

    [self.authData removeObjectForKey:@"input"];

    NSString *username = self.authData[@"username"];
    if (username.length == 0) {
        showDialog(@"Error while saving file", @"The account has no username.");
        return NO;
    }

    NSString *accountsDir = [NSString stringWithFormat:@"%s/accounts", getenv("AME_HOME")];
    // saveChanges can run before init_setupAccounts() has created the directory
    // (and a user may have cleared it), which previously made every write fail
    // with a confusing "no such file" error.
    [NSFileManager.defaultManager createDirectoryAtPath:accountsDir
                           withIntermediateDirectories:YES
                                            attributes:nil
                                                 error:nil];

    NSString *newPath = [accountsDir stringByAppendingPathComponent:
                         [username stringByAppendingPathExtension:@"json"]];

    NSString *oldUsername = self.authData[@"oldusername"];
    if (oldUsername.length != 0 && ![oldUsername isEqualToString:username]) {
        NSString *oldPath = [accountsDir stringByAppendingPathComponent:
                             [oldUsername stringByAppendingPathExtension:@"json"]];
        NSFileManager *fsm = NSFileManager.defaultManager;
        NSError *moveError;
        // moveItemAtPath fails when the destination already exists, which left
        // the old account file behind as an unlistable duplicate. Clear the
        // destination first so a rename always converges on one file.
        if ([fsm fileExistsAtPath:newPath]) {
            [fsm removeItemAtPath:newPath error:nil];
        }
        if (![fsm moveItemAtPath:oldPath toPath:newPath error:&moveError]) {
            // Not fatal: the fresh data is written to newPath below either way.
            NSLog(@"[Account] Could not move %@ to %@: %@", oldPath, newPath, moveError.localizedDescription);
        }
    }

    [self.authData removeObjectForKey:@"oldusername"];

    error = saveJSONToFile(self.authData, newPath);

    if (error != nil) {
        showDialog(@"Error while saving file", error.localizedDescription);
    }
    return error == nil;
}

@end
