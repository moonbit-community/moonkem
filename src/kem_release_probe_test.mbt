///|
test "G produces two 32-byte seed halves" {
  let (rho, sigma) = @moonkem.g([1, 2, 3])
  assert_eq(rho.length(), 32)
  assert_eq(sigma.length(), 32)
}

///|
test "NTT inverse round trip" {
  let input = Array::makei(256, i => i)
  assert_eq(@moonkem.intt(@moonkem.ntt(input)), input)
}
