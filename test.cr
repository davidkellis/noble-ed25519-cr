require "weak_ref"

def p_value(ref : WeakRef) : Nil
  p ref
  p ref.value
end

def test
  s = "oof".reverse
  ref = WeakRef.new(s)
  p_value(ref)
  ref
end

def test2
  ref = test
  
  GC.collect

  p "after test"
  
  p_value(ref)

  ref = ref.value

  GC.collect
end

def test3
  map = Hash(WeakRef(String), Int32).new
  map[WeakRef.new("foo")] = 5
end

def main
  test2

  puts "after test2"

  GC.collect
  p "*" * 80

  map = test3
  GC.collect
  p map
end

main
