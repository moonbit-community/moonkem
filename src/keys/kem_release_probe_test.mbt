///|
test "deterministic ML-KEM key generation and encapsulation round trip" {
  let (ek, dk) = @keys.keygen_internal(Array::make(32, 0), Array::make(32, 1))
  let (key, ciphertext) = @keys.encaps_internal(ek, Array::make(32, 2))
  assert_eq(@keys.decaps_internal(dk, ciphertext), key)
}
