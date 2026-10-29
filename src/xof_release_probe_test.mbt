///|
test "successive XOF reads continue the SHAKE128 stream" {
  let ctx = @moonkem.xof_absorb(@moonkem.xof_init(), [1, 2, 3])
  let (ctx, first) = @moonkem.xof_squeeze(ctx, 3)
  let (_, second) = @moonkem.xof_squeeze(ctx, 3)
  let expected = @moonkem.shake128([1, 2, 3], 6)
  assert_eq(@moonkem.concat_bytes(first, second), expected)
}
