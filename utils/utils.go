package utils

// safeSlice returns a subslice of data from start (inclusive) to end (exclusive)
// in a panic-free manner.
//
// The function performs explicit bounds checking before slicing and returns
// (nil, false) if the requested range is invalid. A range is considered invalid
// if any of the following conditions hold:
//   - start or end is negative
//   - start is greater than end
//   - end exceeds the length of the input slice
//
// When the range is valid, the returned slice aliases the underlying data and
// no copying is performed.
//
// This helper is intended for use in low-level parsing code (e.g. precompile
// input decoding), where slice bounds violations must be handled explicitly
// rather than causing a runtime panic.
//
// Example usage:
//
//	data, ok := safeSlice(input, offset, offset+n)
//	if !ok {
//	    return errorInvalidInput
//	}
func SafeSlice(data []byte, start, end int) ([]byte, bool) {
	if start < 0 || end < 0 || start > end || end > len(data) {
		return nil, false
	}

	return data[start:end], true
}
