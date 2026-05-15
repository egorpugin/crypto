#pragma once

#include "linux.h"
#include "macos.h"
#include "win32.h"

namespace crypto {

auto &default_io_context() {
    static executor ctx;
    return ctx;
}

}
