///|
test "fromUInt64/basic" {
  let input : UInt64 = 578437695752307201 // 0x0807060504030201
  let expected = [
    b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x07', b'\x08',
  ]
  let result = fromUInt64(input)
  for i = 0; i < 8; i = i + 1 {
    inspect!(result[i], content="\{expected[i]}")
  }
}

///|
test "toUInt64/zero" {
  let bytes = Array::make(8, b'\x00')
  inspect!(toUInt64(bytes), content="0")
}

///|
test "toUInt64/basic" {
  let bytes = [
    b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x07', b'\x08',
  ]
  // Should represent 0x0807060504030201 in little-endian
  inspect!(toUInt64(bytes), content="578437695752307201")
}
