package snifake

// hello.go rewrites the plaintext TLS ClientHello that the application sends
// towards a DIRECT destination. Unlike the original implementation this
// rebuilds the record instead of doing an equal-length in-place patch, so the
// fake SNI may be shorter OR longer than the original, may be a freshly
// generated random host name, or may be removed together with the whole
// server_name extension (Cealing's null form).
//
// Only the very first record is touched; anything that follows in the same
// buffer is copied through unchanged.

// readRecordLength returns the total on-wire size of the TLS record starting
// at p, or 0 when the buffer does not hold a complete record yet.
func readRecordLength(p []byte) int {
	if len(p) < 5 {
		return 0
	}
	n := int(p[3])<<8 | int(p[4])
	if n == 0 || len(p) < 5+n {
		return 0
	}
	return 5 + n
}

// clientHelloExtents locates the extension block inside a ClientHello record.
// It returns zero values when the buffer is not a ClientHello.
func clientHelloExtents(rec []byte) (body []byte, extStart, extEnd int, ok bool) {
	if len(rec) < 9 || rec[0] != 0x16 || rec[5] != 0x01 {
		return nil, 0, 0, false
	}
	hsLen := int(rec[6])<<16 | int(rec[7])<<8 | int(rec[8])
	if 9+hsLen > len(rec) {
		return nil, 0, 0, false
	}
	v := rec[9 : 9+hsLen]
	off := 2 + 32 // legacy_version + random
	if off >= len(v) {
		return nil, 0, 0, false
	}
	off += 1 + int(v[off]) // session_id
	if off+2 > len(v) {
		return nil, 0, 0, false
	}
	off += 2 + (int(v[off])<<8 | int(v[off+1])) // cipher_suites
	if off >= len(v) {
		return nil, 0, 0, false
	}
	off += 1 + int(v[off]) // compression_methods
	if off+2 > len(v) {
		return nil, 0, 0, false
	}
	total := int(v[off])<<8 | int(v[off+1])
	start := off + 2
	end := start + total
	if end > len(v) {
		return nil, 0, 0, false
	}
	return v, start, end, true
}

// findSNIExtension returns the byte range of the server_name extension inside
// the extension block [start,end), or (-1,-1) when it is absent.
func findSNIExtension(v []byte, start, end int) (int, int) {
	for e := start; e+4 <= end; {
		et := int(v[e])<<8 | int(v[e+1])
		el := int(v[e+2])<<8 | int(v[e+3])
		next := e + 4 + el
		if next > end {
			break
		}
		if et == 0 {
			return e, next
		}
		e = next
	}
	return -1, -1
}

// buildSNIExtension serialises a server_name extension carrying one entry.
func buildSNIExtension(name string) []byte {
	entryLen := 3 + len(name) // name_type + name_len + name
	ext := make([]byte, 0, 4+2+entryLen)
	ext = append(ext, 0x00, 0x00) // type server_name
	ext = append(ext, byte((2+entryLen)>>8), byte(2+entryLen))
	ext = append(ext, byte(entryLen>>8), byte(entryLen))
	ext = append(ext, 0x00) // host_name
	ext = append(ext, byte(len(name)>>8), byte(len(name)))
	ext = append(ext, name...)
	return ext
}

// rewriteFirstClientHello rebuilds the first TLS record in p so that it
// carries the requested SNI. mode sniNone strips the extension, every other
// mode installs name (which may be empty only for sniNone).
func rewriteFirstClientHello(p []byte, name string, mode Mode) ([]byte, bool) {
	total := readRecordLength(p)
	if total == 0 {
		return p, false
	}
	rec := p[:total]
	rest := p[total:]

	v, extStart, extEnd, ok := clientHelloExtents(rec)
	if !ok {
		return p, false
	}
	sniStart, sniEnd := findSNIExtension(v, extStart, extEnd)

	var replacement []byte
	switch {
	case mode == ModeRemove:
		if sniStart < 0 {
			return p, false // already absent
		}
		replacement = nil
	case sniStart < 0:
		replacement = buildSNIExtension(name)
	default:
		replacement = buildSNIExtension(name)
	}

	var extBlock []byte
	if sniStart < 0 {
		// no existing extension: append the new one when installing
		if replacement != nil {
			extBlock = make([]byte, 0, extEnd-extStart+len(replacement))
			extBlock = append(extBlock, v[extStart:extEnd]...)
			extBlock = append(extBlock, replacement...)
		} else {
			return p, false
		}
	} else {
		extBlock = make([]byte, 0, extEnd-extStart-(sniEnd-sniStart)+len(replacement))
		extBlock = append(extBlock, v[extStart:sniStart]...)
		extBlock = append(extBlock, replacement...)
		extBlock = append(extBlock, v[sniEnd:extEnd]...)
	}

	// ClientHello body with the rebuilt extension block.
	body := make([]byte, 0, len(v)-(extEnd-extStart)+len(extBlock))
	body = append(body, v[:extStart-2]...) // up to the extensions length field
	body = append(body, byte(len(extBlock)>>8), byte(len(extBlock)))
	body = append(body, extBlock...)
	body = append(body, v[extEnd:]...)

	hsLen := len(body)
	recLen := 4 + hsLen // handshake header + body
	out := make([]byte, 0, 5+recLen+len(rest))
	out = append(out, 0x16, rec[1], rec[2], byte(recLen>>8), byte(recLen))
	out = append(out, 0x01, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	out = append(out, body...)
	out = append(out, rest...)
	return out, true
}
