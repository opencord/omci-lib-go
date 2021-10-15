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

type GetNextRequest struct {
	MeBasePacket
	AttributeMask  uint16
	SequenceNumber uint16
}

func (omci *GetNextRequest) String() string {
	return fmt.Sprintf("%v, Attribute Mask: %#x, Sequence Number: %v",
		omci.MeBasePacket.String(), omci.AttributeMask, omci.SequenceNumber)
}

// LayerType returns LayerTypeGetNextRequest
func (omci *GetNextRequest) LayerType() gopacket.LayerType {
	return LayerTypeGetNextRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *GetNextRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeGetNextRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *GetNextRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Get Next Request into this layer
func (omci *GetNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		//start here
		hdrSize = 6 + 4
	} else {
		hdrSize = 4 + 4
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
	// ME needs to support GetNext
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support Get Next Message-Type")
	}
	// Note: G.988 specifies that an error code of (3) should result if more
	//       than one attribute is requested
	// TODO: Return error.  Have flag to optionally allow it to be encoded
	// TODO: Check that the attribute is a table attribute.  Issue warning or return error
	omci.AttributeMask = binary.BigEndian.Uint16(data[hdrSize-4:])
	omci.SequenceNumber = binary.BigEndian.Uint16(data[hdrSize-2:])
	return nil
}

func decodeGetNextRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetNextRequest{}
	omci.MsgLayerType = LayerTypeGetNextRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeGetNextRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetNextRequest{}
	omci.MsgLayerType = LayerTypeGetNextRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get Next Message Type Request
func (omci *GetNextRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support GetNext
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support Get Next Message-Type")
	}
	maskOffset := 0
	if omci.Extended {
		maskOffset = 2
	}
	bytes, err := b.AppendBytes(4 + maskOffset)
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(4))
	}
	binary.BigEndian.PutUint16(bytes[maskOffset:], omci.AttributeMask)
	binary.BigEndian.PutUint16(bytes[maskOffset+2:], omci.SequenceNumber)
	return nil
}

type GetNextResponse struct {
	MeBasePacket
	Result        me.Results
	AttributeMask uint16
	Attributes    me.AttributeValueMap
}

// SerializeTo provides serialization of an Get Next Message Type Response
func (omci *GetNextResponse) String() string {
	return fmt.Sprintf("%v, Result: %v, Attribute Mask: %#x, Attributes: %v",
		omci.MeBasePacket.String(), omci.Result, omci.AttributeMask, omci.Attributes)
}

// LayerType returns LayerTypeGetNextResponse
func (omci *GetNextResponse) LayerType() gopacket.LayerType {
	return LayerTypeGetNextResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *GetNextResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeGetNextResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *GetNextResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Get Next Response into this layer
func (omci *GetNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		//start here
		hdrSize = 6 + 3
	} else {
		hdrSize = 4 + 3
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
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support Get Next Message-Type")
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	omci.Result = me.Results(data[4+offset])
	if omci.Result > 6 {
		msg := fmt.Sprintf("invalid get next results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	omci.AttributeMask = binary.BigEndian.Uint16(data[4+offset+1:])

	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[4+offset+3:], p, byte(GetNextResponseType))
	if err != nil {
		return err
	}
	// Validate all attributes support read
	for attrName := range omci.Attributes {
		attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		if attr.Index != 0 && !me.SupportsAttributeAccess(*attr, me.Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attrName)
			return me.NewProcessingError(msg)
		}
	}
	if eidDef, eidDefOK := meDefinition.GetAttributeDefinitions()[0]; eidDefOK {
		omci.Attributes[eidDef.GetName()] = omci.EntityInstance
		return nil
	}
	panic("All Managed Entities have an EntityID attribute")
}

func decodeGetNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetNextResponse{}
	omci.MsgLayerType = LayerTypeGetNextResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeGetNextResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetNextResponse{}
	omci.MsgLayerType = LayerTypeGetNextResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get Next Message Type Response
func (omci *GetNextResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Get
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support the Get Next Message-Type")
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	bytes, err := b.AppendBytes(offset + 3)
	if err != nil {
		return err
	}
	bytes[offset] = byte(omci.Result)
	if omci.Result > 6 {
		msg := fmt.Sprintf("invalid get next results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	binary.BigEndian.PutUint16(bytes[offset+1:], omci.AttributeMask)

	// Validate all attributes support read
	for attrName := range omci.Attributes {
		attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		if attr.Index != 0 && !me.SupportsAttributeAccess(*attr, me.Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attrName)
			return me.NewProcessingError(msg)
		}
	}
	// Attribute serialization
	switch omci.Result {
	default:
		break

	case me.Success:
		// TODO: Only Baseline supported at this time
		if omci.Extended {
			bytesAvailable := MaxExtendedLength - 13 - 4
			attributeBuffer := gopacket.NewSerializeBuffer()
			err, _ = meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask,
				attributeBuffer, byte(GetNextResponseType), bytesAvailable, false)
			if err != nil {
				return err
			}
			binary.BigEndian.PutUint16(bytes, uint16(len(attributeBuffer.Bytes())+3))
			var newSpace []byte

			newSpace, err = b.AppendBytes(len(attributeBuffer.Bytes()))
			if err != nil {
				return err
			}
			copy(newSpace, attributeBuffer.Bytes())
		} else {
			bytesAvailable := MaxBaselineLength - 11 - 8

			err, _ = meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask, b,
				byte(GetNextResponseType), bytesAvailable, false)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
