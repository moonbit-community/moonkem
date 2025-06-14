///|
typealias Array[Byte] as ByteArray

///|
pub fn keygen(d : ByteArray) -> (ByteArray, ByteArray) {
  d.push(4)
  let (rho, sigma) = @kem.g(d)
  let mut n = 0
  let a_hat = Array::make(4, Array::make(4, Array::make(256, 0)))
  for i = 0; i < 4; i = i + 1 {
    for j = 0; j < 4; j = j + 1 {
      let seed_a = rho.copy()
      seed_a.push(j.to_byte())
      seed_a.push(i.to_byte())
      a_hat[i][j] = @kem.sample_ntt(seed_a)
    }
  }
  let s = Array::make(4, Array::make(256, 0))
  for i = 0; i < 4; i = i + 1 {
    let buf = @kem.prf(2, sigma, n.to_byte())
    s[i] = @kem.sample_poly_cbd(buf)
    n = n + 1
  }
  let e = Array::make(4, Array::make(256, 0))
  for i = 0; i < 4; i = i + 1 {
    let buf = @kem.prf(2, sigma, n.to_byte())
    e[i] = @kem.sample_poly_cbd(buf)
  }
  let s_hat = []
  for item in s {
    s_hat.push(@kem.ntt(item))
  }
  let e_hat = []
  for item in e {
    e_hat.push(@kem.ntt(item))
  }
  let t_hat = Array::make(4, Array::make(256, 0))
  for i = 0; i < 4; i = i + 1 {
    let acc = Array::make(256, 0)
    for j = 0; j < 4; j = j + 1 {
      let prod = @kem.ntt_pointwise_mul(a_hat[i][j], s_hat[j], @kem.PARAM_Q)
      if j == 0 {
        @kem.poly_copy(acc, prod)
      } else {
        @kem.poly_add(acc, acc, prod)
      }
    }
    @kem.poly_add(acc, acc, e_hat[i])
    @kem.poly_copy(t_hat[i], acc)
  }
  let ek_PKE = byte_encode12(t_hat)
  ek_PKE.append(rho)
  let dk_PKE = byte_encode12(s_hat)
  (ek_PKE, dk_PKE)
}

///|
fn byte_encode12(polys : Array[Array[Int]]) -> ByteArray {
  let out = []
  for poly in polys {
    let buf : Array[Byte] = Array::make(256 * 12 / 8, 0)
    @kem.poly_compress(buf, poly, 12)
    out.append(buf)
  }
  out
}
