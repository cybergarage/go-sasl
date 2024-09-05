// Copyright (C) 2022 The go-sasl Authors All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package safecast

// From casts an interface to an interface type.
func From(from any, to any) {
	switch from := from.(type) {
	case int:
		FromInt(from, to)
	case int8:
		FromInt8(from, to)
	case int16:
		FromInt16(from, to)
	case int32:
		FromInt32(from, to)
	case int64:
		FromInt64(from, to)
	case uint:
		FromUint(from, to)
	case uint8:
		FromUint8(from, to)
	case uint16:
		FromUint16(from, to)
	case uint32:
		FromUint32(from, to)
	case uint64:
		FromUint64(from, to)
	case float32:
		FromFloat32(from, to)
	case float64:
		FromFloat64(from, to)
	case string:
		FromString(from, to)
	case bool:
		FromBool(from, to)
	case []byte:
		FromBytes(from, to)
	default:
		newErrorCast(from, to)
	}
}
