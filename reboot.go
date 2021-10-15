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

package omci

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	me "github.com/opencord/omci-lib-go/v2/generated"
)

type RebootRequest struct {
	MeBasePacket
	RebootCondition byte
}

func (omci *RebootRequest) String() string {
	return fmt.Sprintf("%v, Reboot Condition: %v",
		omci.MeBasePacket.String(), omci.RebootCondition)
}

// LayerType returns LayerTypeRebootRequest
func (omci *RebootRequest) LayerType() gopacket.LayerType {
	return LayerTypeRebootRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *RebootRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeRebootRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *RebootRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Reboot Request into this layer
func (omci *RebootRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		hdrSize = 6 + 1
	} else {
		hdrSize = 4 + 1
	}
	err := omci.MeBasePacket.DecodeFromBytes(data, p, hdrSize)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Reboot
	if !me.SupportsMsgType(meDefinition, me.Reboot) {
		return me.NewProcessingError("managed entity does not support Reboot Message-Type")
	}
	offset := hdrSize - 1
	omci.RebootCondition = data[offset]
	if omci.RebootCondition > 3 {
		msg := fmt.Sprintf("invalid reboot condition code: %v, must be 0..3", omci.RebootCondition)
		return errors.New(msg)
	}
	return nil
}

func decodeRebootRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &RebootRequest{}
	omci.MsgLayerType = LayerTypeRebootRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeRebootRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &RebootRequest{}
	omci.MsgLayerType = LayerTypeRebootRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Reboot Request message
func (omci *RebootRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Reboot
	if !me.SupportsMsgType(entity, me.Reboot) {
		return me.NewProcessingError("managed entity does not support the Synchronize Time Message-Type")
	}
	var offset int
	if omci.Extended {
		offset = 2
	} else {
		offset = 0
	}
	bytes, err := b.AppendBytes(offset + 1)
	if err != nil {
		return err
	}
	if omci.RebootCondition > 3 {
		return me.NewProcessingError(fmt.Sprintf("invalid reboot condition code: %v, must be 0..3",
			omci.RebootCondition))
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, 1)
	}
	bytes[offset] = omci.RebootCondition
	return nil
}

type RebootResponse struct {
	MeBasePacket
	Result me.Results
}

// DecodeFromBytes decodes the given bytes of a Reboot Response into this layer
func (omci *RebootResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v)",
		omci.MeBasePacket.String(), omci.Result, omci.Result)
}

// LayerType returns LayerTypeRebootResponse
func (omci *RebootResponse) LayerType() gopacket.LayerType {
	return LayerTypeRebootResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *RebootResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeRebootResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *RebootResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Reboot Response into this layer
func (omci *RebootResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		hdrSize = 6 + 1
	} else {
		hdrSize = 4 + 1
	}
	err := omci.MeBasePacket.DecodeFromBytes(data, p, hdrSize)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Reboot
	if !me.SupportsMsgType(meDefinition, me.Reboot) {
		return me.NewProcessingError("managed entity does not support Reboot Message-Type")
	}
	if omci.Result > 6 {
		msg := fmt.Sprintf("invalid reboot results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	offset := hdrSize - 1
	omci.Result = me.Results(data[offset])
	return nil
}

func decodeRebootResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &RebootResponse{}
	omci.MsgLayerType = LayerTypeRebootResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeRebootResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &RebootResponse{}
	omci.MsgLayerType = LayerTypeRebootResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Reboot Response message
func (omci *RebootResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Reboot
	if !me.SupportsMsgType(entity, me.Reboot) {
		return me.NewProcessingError("managed entity does not support the Synchronize Time Message-Type")
	}
	var offset int
	if omci.Extended {
		offset = 2
	} else {
		offset = 0
	}
	bytes, err := b.AppendBytes(offset + 1)
	if err != nil {
		return err
	}
	if omci.Result > 6 {
		msg := fmt.Sprintf("invalid reboot results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, 1)
	}
	bytes[offset] = byte(omci.Result)
	return nil
}
