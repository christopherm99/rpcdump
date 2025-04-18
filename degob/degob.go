// Copyright (c) 2025 Christopher Milan.
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package main

import "C"
import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os"
	"unsafe"
)

//export Decode
func Decode(p unsafe.Pointer, n C.int) {
  b := C.GoBytes(p, n)

  dec := gob.NewDecoder(bytes.NewReader(b))

  fmt.Fprintf(os.Stderr, "%#v ", b);

  var v any
  if err := dec.Decode(&v); err != nil {
    fmt.Fprintf(os.Stderr, "gob decode error: %v", err)
  } else {
    fmt.Fprintf(os.Stderr, "%#v", v)
  }
}

func main() {}

