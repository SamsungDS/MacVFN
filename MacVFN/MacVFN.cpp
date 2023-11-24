//
//  MacVFN.cpp
//  MacVFN
//
//  Created by Mads Ynddal on 24/11/2023.
//

#include <os/log.h>

#include <DriverKit/IOUserServer.h>
#include <DriverKit/IOLib.h>

#include "MacVFN.h"

kern_return_t
IMPL(MacVFN, Start)
{
    kern_return_t ret;
    ret = Start(provider, SUPERDISPATCH);
    os_log(OS_LOG_DEFAULT, "Hello World");
    return ret;
}
