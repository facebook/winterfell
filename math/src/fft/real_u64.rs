// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

/// Real 2-FFT over u64 integers.
#[inline(always)]
pub fn fft2_real(x: [u64; 2]) -> [i64; 2] {
    [(x[0] as i64 + x[1] as i64), (x[0] as i64 - x[1] as i64)]
}

/// Real 2-iFFT over u64 integers.
/// Division by two to complete the inverse FFT is expected to be performed ***outside*** of this
/// function.
#[inline(always)]
pub fn ifft2_real_unreduced(y: [i64; 2]) -> [u64; 2] {
    [(y[0] + y[1]) as u64, (y[0] - y[1]) as u64]
}

/// Real 4-FFT over u64 integers.
#[inline(always)]
pub fn fft4_real(x: [u64; 4]) -> (i64, (i64, i64), i64) {
    let [z0, z2] = fft2_real([x[0], x[2]]);
    let [z1, z3] = fft2_real([x[1], x[3]]);
    let y0 = z0 + z1;
    let y1 = (z2, -z3);
    let y2 = z0 - z1;
    (y0, y1, y2)
}

/// Real 4-iFFT over u64 integers.
/// Division by four to complete the inverse FFT is expected to be performed ***outside*** of this
/// function.
#[inline(always)]
pub fn ifft4_real_unreduced(y: (i64, (i64, i64), i64)) -> [u64; 4] {
    let z0 = y.0 + y.2;
    let z1 = y.0 - y.2;
    let z2 = y.1 .0;
    let z3 = -y.1 .1;

    let [x0, x2] = ifft2_real_unreduced([z0, z2]);
    let [x1, x3] = ifft2_real_unreduced([z1, z3]);

    [x0, x1, x2, x3]
}
