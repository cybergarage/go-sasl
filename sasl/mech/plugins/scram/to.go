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

// To casts an interface to an interface type.
func To(from any, to any) {
	switch to := to.(type) {
	case *int:
		ToInt(from, to)
	case *int8:
		ToInt8(from, to)
	case *int16:
		ToInt16(from, to)
	case *int32:
		ToInt32(from, to)
	case *int64:
		ToInt64(from, to)
	case *uint:
		ToUint(from, to)
	case *uint8:
		ToUint8(from, to)
	case *uint16:
		ToUint16(from, to)
	case *uint32:
		ToUint32(from, to)
	case *uint64:
		ToUint64(from, to)
	case *float32:
		ToFloat32(from, to)
	case *float64:
		ToFloat64(from, to)
	case *string:
		ToString(from, to)
	case *bool:
		ToBool(from, to)
	case *[]byte:
		ToBytes(from, to)
	default:
		newErrorCast(from, to)
	}
}
