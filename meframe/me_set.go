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
	"fmt"
	"github.com/google/gopacket"
	. "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
)

func SetRequestFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	mask, err := checkAttributeMask(m, opt.attributeMask)
	if err != nil {
		return nil, err
	}
	mask, err = calculateAttributeMask(m, mask)
	if err != nil {
		return nil, err
	}
	meDefinition := m.GetManagedEntityDefinition()
	attrDefs := meDefinition.GetAttributeDefinitions()
	attrMap := m.GetAttributeValueMap()

	// Get payload space available
	maxPayload := maxPacketAvailable(m, opt)
	payloadAvailable := int(maxPayload) - 2 // Less attribute mask
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
		// payloadAvailable -= 2				// Less length
	}
	meLayer := &SetRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
		AttributeMask: 0,
		Attributes:    make(me.AttributeValueMap),
	}
	for mask != 0 {
		// Iterate down the attributes (Attribute 0 is the ManagedEntity ID)
		var attrIndex uint
		for attrIndex = 1; attrIndex <= 16; attrIndex++ {
			// Is this attribute requested
			if mask&(1<<(16-attrIndex)) != 0 {
				// Get definitions since we need the name
				attrDef, ok := attrDefs[attrIndex]
				if !ok {
					msg := fmt.Sprintf("Unexpected error, index %v not valued for ME %v",
						attrIndex, meDefinition.GetName())
					return nil, errors.New(msg)
				}
				var attrValue interface{}
				attrValue, ok = attrMap[attrDef.Name]
				if !ok {
					msg := fmt.Sprintf("Unexpected error, attribute %v not provided in ME %v: %v",
						attrDef.GetName(), meDefinition.GetName(), m)
					return nil, errors.New(msg)
				}
				// Is space available?
				if attrDef.Size <= payloadAvailable {
					// Mark bit handled
					mask &= ^attrDef.Mask
					meLayer.AttributeMask |= attrDef.Mask
					meLayer.Attributes[attrDef.Name] = attrValue
					payloadAvailable -= attrDef.Size
				} else {
					// TODO: Should we set truncate?
					msg := fmt.Sprintf("out-of-space. Cannot fit attribute %v into SetRequest message",
						attrDef.GetName())
					return nil, me.NewMessageTruncatedError(msg)
				}
			}
		}
	}
	if meLayer.AttributeMask == 0 {
		// TODO: Is a set request with no attributes valid?
		return nil, errors.New("no attributes encoded for SetRequest")
	}
	return meLayer, nil
}

func SetResponseFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	meLayer := &SetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
		Result: opt.result,
	}
	if meLayer.Result == me.AttributeFailure {
		meLayer.UnsupportedAttributeMask = opt.unsupportedMask
		meLayer.FailedAttributeMask = opt.attrExecutionMask
	}
	return meLayer, nil
}
