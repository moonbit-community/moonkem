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
test "concat_bytes/basic" {
  let a = [b'\x01', b'\x02', b'\x03']
  let b = [b'\x04', b'\x05']
  let result = concat_bytes(a, b)
  let expected = [b'\x01', b'\x02', b'\x03', b'\x04', b'\x05']
  assert_eq!(result.length(), 5)
  for i = 0; i < 5; i = i + 1 {
    assert_eq!(result[i], expected[i])
  }
}

///|
test "concat_bytes/empty" {
  let a = [b'\x01', b'\x02']
  let empty = []
  let result1 = concat_bytes(a, empty)
  assert_eq!(result1.length(), 2)
  assert_eq!(result1[0], b'\x01')
  assert_eq!(result1[1], b'\x02')
  let result2 = concat_bytes(empty, a)
  assert_eq!(result2.length(), 2)
  assert_eq!(result2[0], b'\x01')
  assert_eq!(result2[1], b'\x02')
}

///|
test "constant_time_compare/equal" {
  let a = [b'\x01', b'\x02', b'\x03']
  let b = [b'\x01', b'\x02', b'\x03']
  assert_true!(constant_time_compare(a, b))
}

///|
test "constant_time_compare/not_equal" {
  let a = [b'\x01', b'\x02', b'\x03']
  let b = [b'\x01', b'\x02', b'\x04']
  assert_false!(constant_time_compare(a, b))
  let c = [b'\x00', b'\x02', b'\x03']
  assert_false!(constant_time_compare(a, c))
}

///|
test "constant_time_compare/different_length" {
  let a = [b'\x01', b'\x02', b'\x03']
  let b = [b'\x01', b'\x02']
  assert_false!(constant_time_compare(a, b))
}

///|
test "constant_time_compare/empty" {
  let empty = []
  assert_true!(constant_time_compare(empty, empty))
}

///|
test "bit_length/small_values" {
  assert_eq!(bit_length(0), 1)
  assert_eq!(bit_length(1), 1)
  assert_eq!(bit_length(2), 2)
  assert_eq!(bit_length(3), 2)
  assert_eq!(bit_length(7), 3)
  assert_eq!(bit_length(8), 4)
  assert_eq!(bit_length(15), 4)
  assert_eq!(bit_length(16), 5)
}

///|
test "bit_length/powers_of_two" {
  assert_eq!(bit_length(1), 1) // 2^0
  assert_eq!(bit_length(2), 2) // 2^1
  assert_eq!(bit_length(4), 3) // 2^2
  assert_eq!(bit_length(8), 4) // 2^3
  assert_eq!(bit_length(16), 5) // 2^4
  assert_eq!(bit_length(32), 6) // 2^5
  assert_eq!(bit_length(64), 7) // 2^6
  assert_eq!(bit_length(128), 8) // 2^7
  assert_eq!(bit_length(256), 9) // 2^8
  assert_eq!(bit_length(512), 10) // 2^9
  assert_eq!(bit_length(1024), 11) // 2^10
}

///|
test "bytes_to_ints/basic" {
  let bytes = [b'\x01', b'\x02', b'\x03']
  let result = bytes_to_ints(bytes, 256)
  assert_eq!(result.length(), 3)
  assert_eq!(result[0], 1)
  assert_eq!(result[1], 2)
  assert_eq!(result[2], 3)
}

///|
test "bytes_to_ints/mod_value" {
  let bytes = [b'\xFF', b'\xFF'] // 255, 255
  let result = bytes_to_ints(bytes, 100)
  assert_eq!(result.length(), 2)
  assert_eq!(result[0], 27) // 127 % 100 = 27
  assert_eq!(result[1], 27) // 127 % 100 = 27
}

///|
test "bytes_to_ints/cross_byte_boundary" {
  let bytes = [b'\x1B', b'\x2D'] // 00011011, 00101101
  let result = bytes_to_ints(bytes, 15)
  assert_eq!(result.length(), 4)
  assert_eq!(result[0], 11) // 1011 二进制 = 11 十进制
  assert_eq!(result[1], 1) // 0001 二进制 = 1 十进制
  assert_eq!(result[2], 13) // 1101 二进制 = 13 十进制
  assert_eq!(result[3], 2) // 0010 二进制 = 2 十进制
}

///|
test "bytes_to_ints/kyber_example" {
  let bytes = [b'\x01', b'\x0F', b'\xF0'] // 00000001 00001111 11110000
  let result = bytes_to_ints(bytes, 3329)
  assert_eq!(result.length(), 2)
  assert_eq!(result[0], 3841 % 3329) // 3841 % 3329 = 512
  assert_eq!(result[1], 3840 % 3329) // 3840 % 3329 = 511
}
