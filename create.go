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

// CreateRequest message apply only to attributes that are defined to be set by create.
// Writeable attributes that are not set by create are not permitted in a create message
type CreateRequest struct {
	MeBasePacket
	Attributes me.AttributeValueMap
}

func (omci *CreateRequest) String() string {
	return fmt.Sprintf("%v, attributes: %v", omci.MeBasePacket.String(), omci.Attributes)
}

// LayerType returns LayerTypeCreateRequest
func (omci *CreateRequest) LayerType() gopacket.LayerType {
	return LayerTypeCreateRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *CreateRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeCreateRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *CreateRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Create Request into this layer
func (omci *CreateRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		hdrSize = 6
	} else {
		hdrSize = 4
	}
	err := omci.MeBasePacket.DecodeFromBytes(data, p, hdrSize)
	if err != nil {
		return err
	}
	// Create attribute mask for all set-by-create entries
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Create
	if !me.SupportsMsgType(meDefinition, me.Create) {
		return me.NewProcessingError("managed entity does not support Create Message-Type")
	}
	var sbcMask uint16
	for index, attr := range meDefinition.GetAttributeDefinitions() {
		if me.SupportsAttributeAccess(attr, me.SetByCreate) {
			if index == 0 {
				continue // Skip Entity ID
			}
			sbcMask |= attr.Mask
		}
	}
	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(sbcMask, data[hdrSize:], p, byte(CreateRequestType))
	if err != nil {
		return err
	}
	if eidDef, eidDefOK := meDefinition.GetAttributeDefinitions()[0]; eidDefOK {
		omci.Attributes[eidDef.GetName()] = omci.EntityInstance
		return nil
	}
	return me.NewProcessingError("All Managed Entities have an EntityID attribute")
}

func decodeCreateRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &CreateRequest{}
	omci.MsgLayerType = LayerTypeCreateRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeCreateRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &CreateRequest{}
	omci.MsgLayerType = LayerTypeCreateRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Create Request Message
func (omci *CreateRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// Create attribute mask of SetByCreate attributes that should be present in the provided
	// attributes.
	var sbcMask uint16
	for index, attr := range meDefinition.GetAttributeDefinitions() {
		if me.SupportsAttributeAccess(attr, me.SetByCreate) {
			if index == 0 {
				continue // Skip Entity ID
			}
			sbcMask |= attr.Mask
		}
	}
	// Attribute serialization
	var bytesAvailable int
	var bytes []byte
	if omci.Extended {
		bytesAvailable = MaxExtendedLength - 10 - 4
		bytes, err = b.AppendBytes(2)
		if err != nil {
			return err
		}
	} else {
		bytesAvailable = MaxBaselineLength - 8 - 8
	}
	attributeBuffer := gopacket.NewSerializeBuffer()
	if err, _ = meDefinition.SerializeAttributes(omci.Attributes, sbcMask,
		attributeBuffer, byte(CreateRequestType), bytesAvailable, false); err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(len(attributeBuffer.Bytes())))
	}
	bytes, err = b.AppendBytes(len(attributeBuffer.Bytes()))
	if err != nil {
		return err
	}
	copy(bytes, attributeBuffer.Bytes())
	return nil
}

// CreateResponse returns the result of a CreateRequest
type CreateResponse struct {
	MeBasePacket
	Result                 me.Results
	AttributeExecutionMask uint16 // Used when Result == ParameterError
}

func (omci *CreateResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v), Mask: %#x",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.AttributeExecutionMask)
}

// LayerType returns LayerTypeCreateResponse
func (omci *CreateResponse) LayerType() gopacket.LayerType {
	return LayerTypeCreateResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *CreateResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeCreateResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *CreateResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Create Response into this layer
func (omci *CreateResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize, offset int
	if omci.Extended {
		offset = 6
		hdrSize = offset + 1 // Plus 2 more if result = 3
	} else {
		offset = 4
		hdrSize = offset + 3
	}
	err := omci.MeBasePacket.DecodeFromBytes(data, p, hdrSize)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Create
	if !me.SupportsMsgType(entity, me.Create) {
		return me.NewProcessingError("managed entity does not support the Create Message-Type")
	}
	omci.Result = me.Results(data[offset])
	if omci.Result == me.ParameterError {
		// Optional attribute execution mask (2 octets) is required
		if len(data) < hdrSize+2 {
			p.SetTruncated()
			return errors.New("frame too small")
		}
		omci.AttributeExecutionMask = binary.BigEndian.Uint16(data[offset+1:])
	}
	return nil
}

func decodeCreateResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &CreateResponse{}
	omci.MsgLayerType = LayerTypeCreateResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeCreateResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &CreateResponse{}
	omci.MsgLayerType = LayerTypeCreateResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Create Response message
func (omci *CreateResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Create
	if !me.SupportsMsgType(entity, me.Create) {
		return me.NewProcessingError("managed entity does not support the Create Message-Type")
	}
	var offset, extra int
	if omci.Extended {
		offset = 2
	}
	if omci.Result == me.ParameterError {
		extra = 2
	}
	bytes, err := b.AppendBytes(offset + 1 + extra)
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(1+extra))
	}
	bytes[offset] = byte(omci.Result)
	if omci.Result == me.ParameterError {
		binary.BigEndian.PutUint16(bytes[offset+1:], omci.AttributeExecutionMask)
	}
	return nil
}
