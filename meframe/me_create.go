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
)

func CreateRequestFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	// NOTE: The OMCI parser does not extract the default values of set-by-create attributes
	//       and are the zero 'default' (or nil) at this time.  For this reason, make sure
	//       you specify all non-zero default values and pass them in appropriate
	meLayer := &CreateRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
		Attributes: m.GetAttributeValueMap(),
	}
	// Add any missing SetByCreate options if requested
	if opt.addDefaults {
		if attrDefs, err := me.GetAttributesDefinitions(m.GetClassID()); err.StatusCode() == me.Success {
			for index, attr := range attrDefs {
				if me.SupportsAttributeAccess(attr, me.SetByCreate) {
					if index == 0 {
						continue // Skip Entity ID, if it is SetByCreate, they should always specify it
					}
					if _, found := meLayer.Attributes[attr.GetName()]; !found {
						meLayer.Attributes[attr.GetName()] = attr.DefValue
					}
				}
			}
		}
	}
	return meLayer, nil
}

func CreateResponseFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	meLayer := &CreateResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
		Result: opt.result,
	}
	if meLayer.Result == me.ParameterError {
		meLayer.AttributeExecutionMask = opt.attrExecutionMask
	}
	return meLayer, nil
}
