/*
 * Copyright (c) 2024 KDDI CORPORATION. All Rights Reserved.
 */

#if !(defined(HAVE_TMMINTRIN_H) && defined(HAVE_WMMINTRIN_H))
#include "private/rocca_simd_c.h"
#include "rocca.c"
#include "aead_roccas_core.c"
#endif