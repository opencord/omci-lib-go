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

type SetRequest struct {
	MeBasePacket
	AttributeMask uint16
	Attributes    me.AttributeValueMap
}

func (omci *SetRequest) String() string {
	return fmt.Sprintf("%v, Mask: %#x, attributes: %v",
		omci.MeBasePacket.String(), omci.AttributeMask, omci.Attributes)
}

// LayerType returns LayerTypeSetRequest
func (omci *SetRequest) LayerType() gopacket.LayerType {
	return LayerTypeSetRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *SetRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeSetRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *SetRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Set Request into this layer
func (omci *SetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		hdrSize = 6 + 2
	} else {
		hdrSize = 4 + 2
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
	// ME needs to support Set
	if !me.SupportsMsgType(meDefinition, me.Set) {
		return me.NewProcessingError("managed entity does not support Set Message-Type")
	}
	offset := hdrSize - 2
	omci.AttributeMask = binary.BigEndian.Uint16(data[offset:])

	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[hdrSize:], p, byte(SetRequestType))
	if err != nil {
		return err
	}
	// Validate all attributes support write
	for attrName := range omci.Attributes {
		attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		if attr.Index != 0 && !me.SupportsAttributeAccess(*attr, me.Write) {
			msg := fmt.Sprintf("attribute '%v' does not support write access", attrName)
			return me.NewProcessingError(msg)
		}
	}
	if eidDef, eidDefOK := meDefinition.GetAttributeDefinitions()[0]; eidDefOK {
		omci.Attributes[eidDef.GetName()] = omci.EntityInstance
		return nil
	}
	return me.NewProcessingError("All Managed Entities have an EntityID attribute")
}

func decodeSetRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetRequest{}
	omci.MsgLayerType = LayerTypeSetRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeSetRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetRequest{}
	omci.MsgLayerType = LayerTypeSetRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Set Request message
func (omci *SetRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Set
	if !me.SupportsMsgType(meDefinition, me.Set) {
		return me.NewProcessingError("managed entity does not support Set Message-Type")
	}
	// Validate all attributes support write
	for attrName := range omci.Attributes {
		attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		// Do not test for write of Entity ID in the attribute list
		if attr.Index != 0 && !me.SupportsAttributeAccess(*attr, me.Write) {
			// TODO: Check ITU spec to see if this should be listed as a failed
			//       attribute and not a processing error.
			msg := fmt.Sprintf("attribute '%v' does not support write access", attrName)
			return me.NewProcessingError(msg)
		}
	}
	var maskOffset int
	var bytesAvailable int
	if omci.Extended {
		maskOffset = 2
		bytesAvailable = MaxExtendedLength - 12 - 4
	} else {
		maskOffset = 0
		bytesAvailable = MaxBaselineLength - 10 - 8
	}
	// Attribute serialization
	attributeBuffer := gopacket.NewSerializeBuffer()
	err, _ = meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask, attributeBuffer,
		byte(SetRequestType), bytesAvailable, false)

	bytes, err := b.AppendBytes(maskOffset + 2 + len(attributeBuffer.Bytes()))
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(len(attributeBuffer.Bytes())+2))
	}
	binary.BigEndian.PutUint16(bytes[maskOffset:], omci.AttributeMask)
	copy(bytes[maskOffset+2:], attributeBuffer.Bytes())
	return nil
}

type SetResponse struct {
	MeBasePacket
	Result                   me.Results
	UnsupportedAttributeMask uint16
	FailedAttributeMask      uint16
}

func (omci *SetResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v), Unsupported Mask: %#x, Failed Mask: %#x",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.UnsupportedAttributeMask,
		omci.FailedAttributeMask)
}

// LayerType returns LayerTypeSetResponse
func (omci *SetResponse) LayerType() gopacket.LayerType {
	return LayerTypeSetResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *SetResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeSetResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *SetResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Set Response into this layer
func (omci *SetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		hdrSize = 6 + 1 // Plus 4 more if result = 9
	} else {
		hdrSize = 4 + 5
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
	// ME needs to support Set
	if !me.SupportsMsgType(entity, me.Set) {
		return me.NewProcessingError("managed entity does not support the Set Message-Type")
	}
	offset := hdrSize - 5
	omci.Result = me.Results(data[offset])

	if omci.Result == me.AttributeFailure {
		// Optional attribute masks (4 octets) is required
		if len(data) < hdrSize+4 {
			p.SetTruncated()
			return errors.New("frame too small")
		}
		omci.UnsupportedAttributeMask = binary.BigEndian.Uint16(data[offset+1:])
		omci.FailedAttributeMask = binary.BigEndian.Uint16(data[offset+3:])
	}
	return nil
}

func decodeSetResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetResponse{}
	omci.MsgLayerType = LayerTypeSetResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeSetResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetResponse{}
	omci.MsgLayerType = LayerTypeSetResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Set Response message
func (omci *SetResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Set
	if !me.SupportsMsgType(entity, me.Set) {
		return me.NewProcessingError("managed entity does not support the Set Message-Type")
	}
	var offset, length int
	if omci.Extended {
		offset = 2
		length = 1
		if omci.Result == me.AttributeFailure {
			length += 4
		}
	} else {
		offset = 0
		length = 5
	}
	bytes, err := b.AppendBytes(offset + length)
	if err != nil {
		return err
	}

	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(length))
		bytes[offset] = byte(omci.Result)
		if omci.Result == me.AttributeFailure {
			binary.BigEndian.PutUint16(bytes[offset+1:], omci.UnsupportedAttributeMask)
			binary.BigEndian.PutUint16(bytes[offset+3:], omci.FailedAttributeMask)
		}
	} else {
		bytes[offset] = byte(omci.Result)
		binary.BigEndian.PutUint16(bytes[offset+1:], omci.UnsupportedAttributeMask)
		binary.BigEndian.PutUint16(bytes[offset+3:], omci.FailedAttributeMask)
	}
	return nil
}
