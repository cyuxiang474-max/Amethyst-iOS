#import "BaseAuthenticator.h"

@implementation LocalAuthenticator

- (void)loginWithCallback:(Callback)callback {
    // Validate before writing anything. Assigning nil to a dictionary subscript
    // removes the key, so an empty or nil input used to leave authData without
    // a "username" and saveChanges then wrote to accounts/(null).json -- an
    // account file that can never be listed, selected or deleted afterwards.
    NSString *input = self.authData[@"input"];
    NSString *username = [input stringByTrimmingCharactersInSet:
                          NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (username.length == 0) {
        callback([NSError errorWithDomain:@"org.angelauramc.amethyst.account" code:1 userInfo:@{
            NSLocalizedDescriptionKey: @"Please enter a username."
        }], NO);
        return;
    }
    // Reject path separators so a crafted name cannot escape the accounts
    // directory when it is interpolated into "accounts/<name>.json".
    if ([username rangeOfString:@"/"].location != NSNotFound ||
        [username rangeOfString:@"\\"].location != NSNotFound ||
        [username rangeOfString:@".."].location != NSNotFound) {
        callback([NSError errorWithDomain:@"org.angelauramc.amethyst.account" code:2 userInfo:@{
            NSLocalizedDescriptionKey: @"Username may not contain slashes or \"..\"."
        }], NO);
        return;
    }

    self.authData[@"oldusername"] = self.authData[@"username"] = username;
    self.authData[@"profileId"] = @"00000000-0000-0000-0000-000000000000";
    callback(nil, [super saveChanges]);
}

- (void)refreshTokenWithCallback:(Callback)callback {
    // Nothing to do
    callback(nil, YES);
}

@end
