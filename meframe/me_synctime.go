/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 * Copyright 2020-present Open Networking Foundation

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package meframe

import (
	"errors"
	"github.com/google/gopacket"
	. "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"time"
)

func SynchronizeTimeRequestFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	// Common for all MEs
	meLayer := &SynchronizeTimeRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
	}
	// Decode payload option. If nil, no timestamp provided
	if timestamp, ok := opt.payload.(int64); ok {
		tm := time.Unix(timestamp, 0)
		meLayer.Year = uint16(tm.UTC().Year())
		meLayer.Month = uint8(tm.UTC().Month())
		meLayer.Day = uint8(tm.UTC().Day())
		meLayer.Hour = uint8(tm.UTC().Hour())
		meLayer.Minute = uint8(tm.UTC().Minute())
		meLayer.Second = uint8(tm.UTC().Second())
	}
	return meLayer, nil
}

func SynchronizeTimeResponseFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	// Common for all MEs
	meLayer := &SynchronizeTimeResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
		Result:         opt.result,
		SuccessResults: opt.mode,
	}
	return meLayer, nil
}
