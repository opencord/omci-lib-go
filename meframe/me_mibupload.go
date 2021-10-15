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

func MibUploadRequestFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	// Common for all MEs
	meLayer := &MibUploadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: 0,
			Extended:       opt.frameFormat == ExtendedIdent,
		},
	}
	return meLayer, nil
}

func MibUploadResponseFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	// Common for all MEs
	meLayer := &MibUploadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: 0,
			Extended:       opt.frameFormat == ExtendedIdent,
		},
		NumberOfCommands: opt.sequenceNumberCountOrSize,
	}
	return meLayer, nil
}

func MibUploadNextRequestFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	// Common for all MEs
	meLayer := &MibUploadNextRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: 0,
			Extended:       opt.frameFormat == ExtendedIdent,
		},
		CommandSequenceNumber: opt.sequenceNumberCountOrSize,
	}
	return meLayer, nil
}

func MibUploadNextResponseFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	// Common for all MEs
	meLayer := &MibUploadNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
	}
	if opt.payload == nil {
		// Shortcut used to specify the request sequence number is out of range, encode
		// a ME instance with class ID of zero to specify this per ITU G.988
		meDef := me.ManagedEntityDefinition{
			Name:                 "InvalidSequenceNumberManagedEntity",
			ClassID:              me.ClassID(0),
			MessageTypes:         nil,
			AttributeDefinitions: make(me.AttributeDefinitionMap),
		}
		opt.payload, _ = me.NewManagedEntity(meDef)
	}
	if _, ok := opt.payload.(*[]me.ManagedEntity); ok {
		if opt.frameFormat == BaselineIdent {
			return nil, errors.New("invalid payload for Baseline message")
		}
		// TODO: List of MEs. valid for extended messages only
	} else if managedEntity, ok := opt.payload.(*me.ManagedEntity); ok {
		// Single ME
		meLayer.ReportedME = *managedEntity
	} else {
		return nil, errors.New("invalid payload for MibUploadNextResponse frame")
	}
	return meLayer, nil
}
