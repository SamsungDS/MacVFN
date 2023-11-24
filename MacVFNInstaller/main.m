//
//  main.m
//  MacVFNInstaller
//
//  Created by Mads Ynddal on 24/11/2023.
//
@import Foundation;
@import SystemExtensions;
#import <Cocoa/Cocoa.h>

@interface VFNSystemExtensionDelegate: NSObject<OSSystemExtensionRequestDelegate>
@end

@implementation VFNSystemExtensionDelegate
- (void)request:(OSSystemExtensionRequest *)request
didFinishWithResult:(OSSystemExtensionRequestResult)result {
    switch (result){
        case OSSystemExtensionRequestCompleted:
            NSLog(@"Installation completed");
            break;
        case OSSystemExtensionRequestWillCompleteAfterReboot:
            NSLog(@"Installation will complete after reboot");
            break;
        default:
            NSLog(@"Unknown result in 'didFinishWithResult': %ld", result);
    }
    exit(0);
}

- (void)request:(OSSystemExtensionRequest *)request didFailWithError:(NSError *)error {
    NSLog(@"Error in 'didFailWithError': %@", [error localizedDescription]);
    exit(1);
}

- (void)requestNeedsUserApproval:(OSSystemExtensionRequest *)request {
    NSLog(@"Waiting for user approval...");
    NSLog(@"If not prompted, check System Settings -> Privacy & Security");
}

- (OSSystemExtensionReplacementAction)request:(OSSystemExtensionRequest *)request
                  actionForReplacingExtension:(OSSystemExtensionProperties *)existing
                                withExtension:(OSSystemExtensionProperties *)ext {
    return OSSystemExtensionReplacementActionReplace;
}
@end

static VFNSystemExtensionDelegate* vfn_delegate;

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        vfn_delegate = [VFNSystemExtensionDelegate new];
        OSSystemExtensionRequest* request = [OSSystemExtensionRequest activationRequestForExtension:@"com.openmpdk.MacVFN" queue:dispatch_get_main_queue()];
        request.delegate = vfn_delegate;
        [OSSystemExtensionManager.sharedManager submitRequest:request];
    }
    return NSApplicationMain(argc, argv);
}
