// A tiny universal macOS launcher. Finder opens this app without Terminal.
#import <Cocoa/Cocoa.h>
#include <sys/sysctl.h>

int main(void) {
    @autoreleasepool {
        NSURL *root = [NSBundle.mainBundle.bundleURL URLByDeletingLastPathComponent];
        int arm = 0;
        size_t size = sizeof(arm);
        sysctlbyname("hw.optional.arm64", &arm, &size, NULL, 0);
        NSString *target = arm ? @"aarch64-apple-darwin" : @"x86_64-apple-darwin";
        NSURL *app = [root URLByAppendingPathComponent:[NSString stringWithFormat:@"bin/%@/VaultDrive.app", target]];
        NSError *error = nil;
        if ([NSFileManager.defaultManager fileExistsAtPath:app.path]) {
            NSWorkspaceOpenConfiguration *config = [NSWorkspaceOpenConfiguration configuration];
            config.environment = @{@"VAULTDRIVE_PORTABLE_HOME": root.path};
            __block BOOL finished = NO;
            __block NSError *launchError = nil;
            [NSWorkspace.sharedWorkspace openApplicationAtURL:app configuration:config completionHandler:^(NSRunningApplication *application, NSError *failure) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    launchError = failure;
                    finished = YES;
                });
            }];
            while (!finished) {
                [NSRunLoop.currentRunLoop runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
            }
            error = launchError;
        } else {
            error = [NSError errorWithDomain:@"VaultDrive" code:1 userInfo:@{NSLocalizedDescriptionKey: @"This package does not contain the app for this Mac. Extract the complete package and keep the app beside its bin folder."}];
        }
        if (error) {
            [NSApplication sharedApplication];
            [NSApp activateIgnoringOtherApps:YES];
            NSAlert *alert = [NSAlert new];
            alert.messageText = @"VaultDrive could not open";
            alert.informativeText = error.localizedDescription;
            [alert runModal];
            return 1;
        }
    }
    return 0;
}
